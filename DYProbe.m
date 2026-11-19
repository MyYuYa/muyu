#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>

/*
 * DYProbe v6 - 发布链路全 hook + 请求体 dump 版
 *
 * v5 结论：hook AWETextExtra setType: 命中的是【展示链路】——
 *   每条 [SET-TYPE] 前都紧跟 [展示] setTextExtras:，
 *   那是服务端回包解析出的回显对象，请求早就发出去了，所以网页端全不红。
 *
 * v6 改法（一次性覆盖，不再逐个试）：
 *   1) 运行时扫描所有类，hook 一切"textExtra -> 字典/请求"的候选方法：
 *      getTextExtraDictArray: / setTextExtraDict: / setTextExtraArray:
 *      setTextExtraModelArray: / setTextExtraModel: / setCommentTextExtra:
 *      setContentTextExtraModelArray: / appendTextExtraWithExtra:
 *      updateTextExtra:type:
 *      命中即把其中字典的 type 改成当前轮询值，并打印命中类名。
 *   2) hook AWECommentSwiftImpl.CommentPublishRequestProvider 的全部无参方法，
 *      dump 命中 —— 这是发布请求的真正 provider（静态扫描确认存在）。
 *   3) 保留 AWETextExtra setType: 注入作对照。
 *
 * 防闪退（继承 v3/v4/v5）：
 *   - 方法名精确白名单，零 ivar 遍历，零深度反射
 *   - 每个 selector 最多 hook 12 个类
 *   - 频率闸门 + 日志上限 + 全程 try/catch
 *
 * 用法：装好后打开抖音，发一条带 @ 或 # 的评论，
 *       日志自动复制到剪贴板，粘贴发回即可。
 */

#define DY_TYPE_FROM 15
#define DY_TYPE_TO   30
#define DY_INTERVAL  2.0
#define DY_MAX_CLASSES_PER_SEL 12

static NSMutableString *gBuf = nil;
static NSMutableDictionary *gOrigByHook = nil;   /* key -> NSValue(IMP) */
static NSMutableSet *gHookedKeys = nil;
static NSMutableDictionary *gHookCount = nil;    /* selector -> 命中次数 */
static NSInteger gHit = 0;
static NSDate *gLastDump = nil;
static NSInteger gDumpCount = 0;
static NSInteger gCurrentType = DY_TYPE_FROM;
static NSTimer *gPollTimer = nil;
static IMP gOrigSetType = NULL;
static BOOL gHookWarned = NO;
static BOOL gHookUnsupported = NO;
static NSInteger gSetTypeCalls = 0;

static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    if (gBuf.length > 90000) return;
    [gBuf appendFormat:@"%@\n", line];
    NSLog(@"[DYPROBE] %@", line);
}

static NSString *DYSafe(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 600 ? [[d substringToIndex:600] stringByAppendingString:@" ...(trunc)"] : d;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"<desc threw:%@>", e.name];
    }
}

static void DYSave(void) {
    @try {
        NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (!doc) return;
        [gBuf writeToFile:[doc stringByAppendingPathComponent:@"dyprobe_dump.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (...) {}
}

static void DYCopyToPasteboard(void) {
    @try { UIPasteboard *pb = [UIPasteboard generalPasteboard]; if (pb) pb.string = (gBuf ?: @""); } @catch (...) {}
}

static void DYFlushLog(void) {
    DYSave();
    dispatch_async(dispatch_get_main_queue(), ^{ DYCopyToPasteboard(); });
}

static UIViewController *DYTopVC(void) {
    @try {
        UIWindow *win = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]] && scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in ((UIWindowScene *)scene).windows) if (w.isKeyWindow) { win = w; break; }
            }
        }
        if (!win) win = [UIApplication sharedApplication].keyWindow;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        return vc;
    } @catch (...) { return nil; }
}

static BOOL DYGate(void) {
    if (gDumpCount >= 120) return NO;
    NSDate *now = [NSDate date];
    if (gLastDump && [now timeIntervalSinceDate:gLastDump] < 0.15) return NO;
    gLastDump = now;
    gDumpCount++;
    return YES;
}

/* ---------- 改写 textExtra 字典里的 type ---------- */
static int DYPatchExtras(id obj) {
    int n = 0;
    @try {
        if ([obj isKindOfClass:[NSMutableDictionary class]]) {
            NSMutableDictionary *d = (NSMutableDictionary *)obj;
            if ([d objectForKey:@"type"]) {
                [d setObject:@(gCurrentType) forKey:@"type"];
                n++;
            }
        } else if ([obj isKindOfClass:[NSArray class]]) {
            for (id e in (NSArray *)obj) n += DYPatchExtras(e);
        }
    } @catch (...) {}
    return n;
}

/* 返回可变副本，用于改掉不可变返回值 */
static id DYMutableExtras(id obj, int *changed) {
    *changed = 0;
    @try {
        if ([obj isKindOfClass:[NSArray class]]) {
            NSMutableArray *out = [NSMutableArray array];
            for (id e in (NSArray *)obj) {
                if ([e isKindOfClass:[NSDictionary class]]) {
                    NSMutableDictionary *m = [(NSDictionary *)e mutableCopy];
                    if ([m objectForKey:@"type"]) { [m setObject:@(gCurrentType) forKey:@"type"]; (*changed)++; }
                    [out addObject:m];
                } else {
                    [out addObject:e];
                }
            }
            return out;
        } else if ([obj isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *m = [(NSDictionary *)obj mutableCopy];
            if ([m objectForKey:@"type"]) { [m setObject:@(gCurrentType) forKey:@"type"]; (*changed)++; }
            return m;
        }
    } @catch (...) {}
    return obj;
}

static IMP DYOrigFor(id self, SEL _cmd) {
    /* hook 装在父类、self 是子类时，[self class] 查不到 key —— 沿继承链向上找 */
    NSString *sel = NSStringFromSelector(_cmd);
    Class c = [self class];
    while (c) {
        NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass(c), sel];
        IMP o = [gOrigByHook[key] pointerValue];
        if (o) return o;
        c = class_getSuperclass(c);
    }
    return NULL;
}

static void DYLogHit(id self, SEL _cmd, NSString *tag, int patched) {
    if (!DYGate()) return;
    NSString *sel = NSStringFromSelector(_cmd);
    NSInteger cnt = [[gHookCount objectForKey:sel] integerValue] + 1;
    gHookCount[sel] = @(cnt);
    DYAppend([NSString stringWithFormat:@"[HIT#%ld] %@ | %@ on %@ | patchedType=%d",
              (long)cnt, tag, sel, NSStringFromClass([self class]), patched]);
    if (patched > 0) DYAppend([NSString stringWithFormat:@"    >>> 已把 %d 处 type 改成 %ld", patched, (long)gCurrentType]);
    DYFlushLog();
}

/* ---------- 通用 trampoline ---------- */
static void dy_hook_void1(id self, SEL _cmd, id arg) {
    int patched = DYPatchExtras(arg);
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
    DYLogHit(self, _cmd, @"PUB-VOID1", patched);
}

static id dy_hook_obj0(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    int patched = 0;
    id out = DYMutableExtras(r, &patched);
    DYLogHit(self, _cmd, @"PUB-OBJ0", patched);
    return out;
}

static id dy_hook_obj1(id self, SEL _cmd, id arg) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
    int patched = DYPatchExtras(arg);
    int patched2 = 0;
    id out = DYMutableExtras(r, &patched2);
    DYLogHit(self, _cmd, @"PUB-OBJ1", patched + patched2);
    return out;
}

/* 网络层：dump 请求体参数字典，专找 text_extra / textExtra，只读不改 */
static void dy_hook_body(id self, SEL _cmd, id arg) {
    BOOL interesting = NO;
    @try {
        if ([arg isKindOfClass:[NSDictionary class]]) {
            NSDictionary *d = (NSDictionary *)arg;
            for (NSString *k in d) {
                NSString *lk = [k lowercaseString];
                if ([lk rangeOfString:@"extr"].location != NSNotFound ||
                    [lk rangeOfString:@"comment"].location != NSNotFound ||
                    [lk rangeOfString:@"content"].location != NSNotFound) {
                    interesting = YES;
                    break;
                }
            }
        }
    } @catch (...) {}
    if (interesting && DYGate()) {
        DYAppend(@"========== [BODY-DUMP] 含 extra/comment/content 的请求参数 ==========");
        DYAppend([NSString stringWithFormat:@"  class=%@ sel=%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)]);
        @try {
            for (NSString *k in (NSDictionary *)arg) {
                NSString *lk = [k lowercaseString];
                if ([lk rangeOfString:@"extr"].location != NSNotFound ||
                    [lk rangeOfString:@"content"].location != NSNotFound ||
                    [lk rangeOfString:@"type"].location != NSNotFound) {
                    DYAppend([NSString stringWithFormat:@"    %@ = %@", k, DYSafe([(NSDictionary *)arg objectForKey:k])]);
                }
            }
        } @catch (...) {}
        DYFlushLog();
    }
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
}

static void dy_hook_update_type(id self, SEL _cmd, id extra, long long t) {
    IMP orig = DYOrigFor(self, _cmd);
    DYAppend([NSString stringWithFormat:@"[HIT] updateTextExtra:type: 原type=%lld -> %ld on %@",
              t, (long)gCurrentType, NSStringFromClass([self class])]);
    if (orig) { @try { ((void(*)(id,SEL,id,long long))orig)(self, _cmd, extra, (long long)gCurrentType); } @catch (...) {} }
    DYLogHit(self, _cmd, @"PUB-UPDATE-TYPE", 1);
}

/* ---------- 展示链路对照：AWETextExtra setType: ---------- */
static int DYSetTypeArgKind(const char *enc) {
    if (!enc) return 0;
    const char *colon = strchr(enc, ':');
    if (!colon) return 0;
    for (const char *p = colon + 1; *p; p++) {
        if (*p >= '0' && *p <= '9') continue;
        if (*p == '@') return 2;
        if (*p=='i'||*p=='l'||*p=='q'||*p=='I'||*p=='L'||*p=='Q') return 1;
        if (*p=='"') break;
    }
    return 0;
}

static void dy_setType_int(id self, SEL _cmd, long long v) {
    @try {
        gSetTypeCalls++;
        DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%lld -> 注入=%ld on %@",
                  (long)gSetTypeCalls, v, (long)gCurrentType, NSStringFromClass([self class])]);
        DYFlushLog();
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_int) {
        @try { ((void(*)(id,SEL,long long))gOrigSetType)(self, _cmd, (long long)gCurrentType); } @catch (...) {}
    }
}

static void dy_setType_obj(id self, SEL _cmd, id v) {
    @try {
        gSetTypeCalls++;
        DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%@ -> 注入=%ld on %@",
                  (long)gSetTypeCalls, DYSafe(v), (long)gCurrentType, NSStringFromClass([self class])]);
        DYFlushLog();
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_obj) {
        @try { ((void(*)(id,SEL,id))gOrigSetType)(self, _cmd, @(gCurrentType)); } @catch (...) {}
    }
}

/* ---------- hook 安装 ---------- */
static void DYInstallSetTypeHook(void) {
    if (gOrigSetType || gHookUnsupported) return;
    @try {
        Class ec = objc_getClass("AWETextExtra");
        if (!ec) { if (!gHookWarned) { DYAppend(@"[HOOK] AWETextExtra 未注册"); gHookWarned = YES; } return; }
        Method m = class_getInstanceMethod(ec, @selector(setType:));
        if (!m) return;
        const char *enc = method_getTypeEncoding(m);
        DYAppend([NSString stringWithFormat:@"[HOOK] AWETextExtra setType: enc=%s", enc ? enc : "?"]);
        int kind = DYSetTypeArgKind(enc);
        if (kind == 1) {
            gOrigSetType = method_setImplementation(m, (IMP)dy_setType_int);
            DYAppend(@"[HOOK] setType 已挂钩(标量)");
        } else if (kind == 2) {
            gOrigSetType = method_setImplementation(m, (IMP)dy_setType_obj);
            DYAppend(@"[HOOK] setType 已挂钩(对象)");
        } else {
            gHookUnsupported = YES;
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK] setType 异常 %@", e.name]);
    }
}

/* 按 selector 名扫描并 hook 发布候选 */
static void DYHookPublishCandidates(void) {
    NSArray *names = @[
        @"getTextExtraDictArray:",
        @"setTextExtraDict:",
        @"setTextExtraArray:",
        @"setTextExtraModelArray:",
        @"setTextExtraModel:",
        @"setCommentTextExtra:",
        @"setContentTextExtraModelArray:",
        @"appendTextExtraWithExtra:",
        @"updateTextExtra:type:"
    ];
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    @try {
        for (NSString *target in names) {
            int hooked = 0;
            for (unsigned int i = 0; i < cc && hooked < DY_MAX_CLASSES_PER_SEL; i++) {
                Class cls = classes[i];
                NSString *cn = NSStringFromClass(cls);
                if ([cn hasPrefix:@"UI"] || [cn hasPrefix:@"NS"]) continue;
                unsigned int mc = 0;
                Method *ml = class_copyMethodList(cls, &mc);
                BOOL consumed = NO;
                for (unsigned int j = 0; j < mc; j++) {
                    SEL sel = method_getName(ml[j]);
                    if (![NSStringFromSelector(sel) isEqualToString:target]) continue;
                    consumed = YES;
                    NSString *key = [NSString stringWithFormat:@"%@|%@", cn, target];
                    if ([gHookedKeys containsObject:key]) break;
                    const char *enc = method_getTypeEncoding(ml[j]);
                    NSMutableString *t = [NSMutableString string];
                    for (const char *p = enc; p && *p; p++) if (*p < '0' || *p > '9') [t appendFormat:@"%c", *p];
                    NSString *sig = t;
                    IMP orig = NULL;
                    if ([target isEqualToString:@"updateTextExtra:type:"]) {
                        if ([sig isEqualToString:@"v@:@q"] || [sig isEqualToString:@"v@:@i"] || [sig isEqualToString:@"v@:@l"]) {
                            orig = method_setImplementation(ml[j], (IMP)dy_hook_update_type);
                        }
                    } else if ([sig isEqualToString:@"v@:@"]) {
                        orig = method_setImplementation(ml[j], (IMP)dy_hook_void1);
                    } else if ([sig isEqualToString:@"@@:"]) {
                        orig = method_setImplementation(ml[j], (IMP)dy_hook_obj0);
                    } else if ([sig isEqualToString:@"@@:@"]) {
                        orig = method_setImplementation(ml[j], (IMP)dy_hook_obj1);
                    }
                    if (orig) {
                        gOrigByHook[key] = [NSValue valueWithPointer:orig];
                        [gHookedKeys addObject:key];
                        hooked++;
                        DYAppend([NSString stringWithFormat:@"[HOOK-PUB] %@ enc=%s", key, enc ? enc : "?"]);
                    }
                    break;
                }
                if (ml) free(ml);
                if (consumed) { /* 继续下一个类 */ }
            }
            if (hooked) DYAppend([NSString stringWithFormat:@"[HOOK-PUB] %@ 共挂 %d 个类", target, hooked]);
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-PUB] 异常 %@", e.name]);
    }
    free(classes);
    DYFlushLog();
}

/* hook 发布请求 provider 的方法（只读 dump，不改行为） */
static void dy_dump_pub(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    if (!DYGate()) return;
    DYAppend([NSString stringWithFormat:@"[PUB-PROVIDER] void %@ on %@", NSStringFromSelector(_cmd), NSStringFromClass([self class])]);
    DYFlushLog();
}

/* 无参返回对象的方法：调用原实现，dump 返回值（通常就是请求参数字典） */
static id dy_dump_pub_ret(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    if (DYGate()) {
        DYAppend([NSString stringWithFormat:@"[PUB-PROVIDER] RET %@ on %@ = %@",
                  NSStringFromSelector(_cmd), NSStringFromClass([self class]), DYSafe(r)]);
        DYFlushLog();
    }
    return r;
}

static void DYHookPublishProvider(void) {
    NSArray *prefixes = @[@"CommentPublishRequestProvider"];
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    @try {
        for (unsigned int i = 0; i < cc; i++) {
            Class cls = classes[i];
            NSString *cn = NSStringFromClass(cls);
            BOOL match = NO;
            for (NSString *p in prefixes) if ([cn rangeOfString:p].location != NSNotFound) { match = YES; break; }
            if (!match) continue;
            unsigned int mc = 0;
            Method *ml = class_copyMethodList(cls, &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL sel = method_getName(ml[j]);
                NSString *key = [NSString stringWithFormat:@"%@|%@", cn, NSStringFromSelector(sel)];
                if ([gHookedKeys containsObject:key]) continue;
                const char *enc = method_getTypeEncoding(ml[j]);
                NSMutableString *t = [NSMutableString string];
                for (const char *p = enc; p && *p; p++) if (*p < '0' || *p > '9') [t appendFormat:@"%c", *p];
                IMP orig = NULL;
                if ([t isEqualToString:@"v@:"]) {
                    orig = method_setImplementation(ml[j], (IMP)dy_dump_pub);
                } else if ([t isEqualToString:@"@@:"]) {
                    orig = method_setImplementation(ml[j], (IMP)dy_dump_pub_ret);
                }
                if (orig) {
                    gOrigByHook[key] = [NSValue valueWithPointer:orig];
                    [gHookedKeys addObject:key];
                    DYAppend([NSString stringWithFormat:@"[HOOK-PROVIDER] %@ enc=%s", key, enc ? enc : "?"]);
                }
            }
            free(ml);
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-PROVIDER] 异常 %@", e.name]);
    }
    free(classes);
    DYFlushLog();
}

/* 网络层请求体 dump：hook 设置请求体参数的方法，只读 */
static void DYHookNetworkBody(void) {
    NSArray *names = @[
        @"setRequestBodyParams:",
        @"setBodyParams:",
        @"addCommonBodyParams:",
        @"setExtraBodyParams:"
    ];
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    @try {
        for (NSString *target in names) {
            int hooked = 0;
            for (unsigned int i = 0; i < cc && hooked < DY_MAX_CLASSES_PER_SEL; i++) {
                Class cls = classes[i];
                NSString *cn = NSStringFromClass(cls);
                if ([cn hasPrefix:@"UI"] || [cn hasPrefix:@"NS"]) continue;
                unsigned int mc = 0;
                Method *ml = class_copyMethodList(cls, &mc);
                BOOL consumed = NO;
                for (unsigned int j = 0; j < mc; j++) {
                    SEL sel = method_getName(ml[j]);
                    if (![NSStringFromSelector(sel) isEqualToString:target]) continue;
                    consumed = YES;
                    NSString *key = [NSString stringWithFormat:@"%@|%@", cn, target];
                    if ([gHookedKeys containsObject:key]) break;
                    const char *enc = method_getTypeEncoding(ml[j]);
                    NSMutableString *t = [NSMutableString string];
                    for (const char *p = enc; p && *p; p++) if (*p < '0' || *p > '9') [t appendFormat:@"%c", *p];
                    if ([t isEqualToString:@"v@:@"]) {
                        IMP orig = method_setImplementation(ml[j], (IMP)dy_hook_body);
                        gOrigByHook[key] = [NSValue valueWithPointer:orig];
                        [gHookedKeys addObject:key];
                        hooked++;
                        DYAppend([NSString stringWithFormat:@"[HOOK-BODY] %@ enc=%s", key, enc ? enc : "?"]);
                    }
                    break;
                }
                if (ml) free(ml);
                (void)consumed;
            }
            if (hooked) DYAppend([NSString stringWithFormat:@"[HOOK-BODY] %@ 共挂 %d 个类", target, hooked]);
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-BODY] 异常 %@", e.name]);
    }
    free(classes);
    DYFlushLog();
}

#pragma mark - 轮询

static void DYStartPolling(void) {
    gCurrentType = DY_TYPE_FROM;
    DYAppend([NSString stringWithFormat:@"[POLL] type %d->%d 每 %.0f 秒 +1", DY_TYPE_FROM, DY_TYPE_TO, DY_INTERVAL]);
    @try {
        gPollTimer = [NSTimer scheduledTimerWithTimeInterval:DY_INTERVAL repeats:YES block:^(NSTimer *t) {
            @autoreleasepool {
                gCurrentType++;
                if (gCurrentType > DY_TYPE_TO) gCurrentType = DY_TYPE_FROM;
                DYAppend([NSString stringWithFormat:@"[POLL] === type = %ld ===", (long)gCurrentType]);
                DYSave();
            }
        }];
        if (gPollTimer) [[NSRunLoop mainRunLoop] addTimer:gPollTimer forMode:NSRunLoopCommonModes];
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[POLL] 定时器失败 %@", e.name]);
    }
}

#pragma mark - 入口

static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v6 发布链路"
                message:[NSString stringWithFormat:@"发一条带 @ 或 # 的评论。日志自动复制到剪贴板，粘贴发回。\n\n轮询 type %d→%d", DY_TYPE_FROM, DY_TYPE_TO]
                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"复制日志" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){ DYCopyToPasteboard(); }]];
            [ac addAction:[UIAlertAction actionWithTitle:@"开始" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

__attribute__((constructor)) static void DYInit(void) {
    @autoreleasepool {
        gBuf = [NSMutableString string];
        gOrigByHook = [NSMutableDictionary dictionary];
        gHookedKeys = [NSMutableSet set];
        gHookCount = [NSMutableDictionary dictionary];
        DYAppend(@"DYProbe v6 init (publish-chain hook + body dump)");
        DYSave();
    }
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            @autoreleasepool {
                DYBootAlert();
                for (int r = 0; r < 3; r++) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(r * 1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        @autoreleasepool {
                            DYAppend([NSString stringWithFormat:@"--- hook round %d ---", r]);
                            DYInstallSetTypeHook();
                            DYHookPublishCandidates();
                            DYHookPublishProvider();
                            DYHookNetworkBody();
                        }
                    });
                }
                DYStartPolling();
            }
        }];
}
