#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>

/*
 * DYProbe v7 - 只读抓参 + 调用栈定性版
 *
 * v6 结论：hook 的 9 个候选 + 网络 body 方法全部打偏（命中类都是发作品/播放页），
 *         真正的评论发布走 AWECommentSwiftImpl.CommentPublishRequestProvider（Swift，
 *         ObjC runtime 够不到）+ KMP serializer。
 *
 * 既然“别人做出来了、服务端红字别人可见”，说明一定有 ObjC 可达的注入点。
 * v7 不猜了，只做两件观察，一次定性：
 *   1) AWETextExtra setType: 里打【符号化调用栈】——看清楚是谁在发布时调用它，
 *      栈里会出现真正的上游类/方法（比如 contentModel / publishRequest 的构造处），
 *      这是定位注入点的金钥匙。v5/v6 只记了值，从没记过栈。
 *   2) hook 发布参数模型 AWECommentPublishParameterModel 和输入内容模型
 *      AWECommentInputContentModel 的全部方法，dump 方法名 + 参数/返回值，
 *      看发布参数里到底有没有 textExtra / type 可改。
 *   3) 只读！不改任何值、不调任何 setter 注入，绝不破坏功能。
 *
 * 防闪退（继承 v3-v6）：类白名单、零 ivar 遍历、频率闸门、日志上限、全程 try/catch。
 * 用法：装上→发一条带 @ 或 # 的评论→把自动复制的日志发回。
 */

#define DY_MAX_CLASSES_PER_SEL 12
#define DY_DUMP_LIMIT 160
#define DY_GATE_SEC 0.15

static NSMutableString *gBuf = nil;
static NSMutableDictionary *gOrigByHook = nil;
static NSMutableDictionary *gOrigBySel = nil;
static NSMutableSet *gHookedKeys = nil;
static NSMutableDictionary *gHookCount = nil;
static NSTimer *gPollTimer = nil;
static NSInteger gDumpCount = 0;
static NSDate *gLastDump = nil;
static IMP gOrigSetType = NULL;
static BOOL gHookWarned = NO;
static BOOL gHookUnsupported = NO;
static NSInteger gSetTypeCalls = 0;
static NSInteger gStackCount = 0;   /* 最多打 3 次调用栈，避免刷屏 */

static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    if (gBuf.length > 120000) return;
    [gBuf appendFormat:@"%@\n", line];
    NSLog(@"[DYPROBE] %@", line);
}

static NSString *DYSafe(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 500 ? [[d substringToIndex:500] stringByAppendingString:@" ...(trunc)"] : d;
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

static BOOL DYGate(void) {
    if (gDumpCount >= DY_DUMP_LIMIT) return NO;
    NSDate *now = [NSDate date];
    if (gLastDump && [now timeIntervalSinceDate:gLastDump] < DY_GATE_SEC) return NO;
    gLastDump = now;
    gDumpCount++;
    return YES;
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

/* 沿继承链找原始 IMP：hook 装父类、self 是子类时也能找到。
 * 兜底：记录时也按 selector 存一份（gOrigBySel），确保任何子类实例都能拿到 orig，
 * 绝不让原方法被吞（否则 obj0/obj1 返回 nil 会破坏发布流程）。 */
static IMP DYOrigFor(id self, SEL _cmd) {
    NSString *sel = NSStringFromSelector(_cmd);
    Class c = [self class];
    while (c) {
        NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass(c), sel];
        IMP o = [gOrigByHook[key] pointerValue];
        if (o) return o;
        c = class_getSuperclass(c);
    }
    /* 兜底：按 selector 取最后安装的 orig */
    IMP o2 = [gOrigBySel[sel] pointerValue];
    if (o2) return o2;
    return NULL;
}

/* ---------- 金钥匙：符号化调用栈 ---------- */
static void DYLogCallStack(NSString *tag) {
    if (gStackCount >= 3) return;
    gStackCount++;
    @try {
        NSArray *syms = [NSThread callStackSymbols];
        DYAppend([NSString stringWithFormat:@"===== %@ 调用栈 #%ld =====", tag, (long)gStackCount]);
        int shown = 0;
        for (NSUInteger i = 2; i < [syms count] && shown < 16; i++) {
            NSString *s = [syms objectAtIndex:i];
            NSString *ls = [s lowercaseString];
            BOOL biz = ([ls rangeOfString:@"awemecore"].location != NSNotFound ||
                        [ls rangeOfString:@"comment"].location != NSNotFound ||
                        [ls rangeOfString:@"publish"].location != NSNotFound ||
                        [ls rangeOfString:@"text"].location != NSNotFound ||
                        [ls rangeOfString:@"kmp"].location != NSNotFound ||
                        [ls rangeOfString:@"swift"].location != NSNotFound);
            if (biz || shown < 4) {
                DYAppend([NSString stringWithFormat:@"   %@", s]);
                shown++;
            }
        }
        DYFlushLog();
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[STACK] 异常 %@", e.name]);
    }
}

/* ---------- setType: 只读观察 + 调用栈（不改值） ---------- */
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
        if (gSetTypeCalls <= 8 || gSetTypeCalls % 10 == 0) {
            DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%lld on %@ (只读，不改)",
                      (long)gSetTypeCalls, v, NSStringFromClass([self class])]);
            DYFlushLog();
            if (gStackCount < 3) DYLogCallStack(@"setType:");
        }
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_int) {
        @try { ((void(*)(id,SEL,long long))gOrigSetType)(self, _cmd, v); } @catch (...) {}
    }
}

static void dy_setType_obj(id self, SEL _cmd, id v) {
    @try {
        gSetTypeCalls++;
        if (gSetTypeCalls <= 8 || gSetTypeCalls % 10 == 0) {
            DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%@ on %@ (只读，不改)",
                      (long)gSetTypeCalls, DYSafe(v), NSStringFromClass([self class])]);
            DYFlushLog();
            if (gStackCount < 3) DYLogCallStack(@"setType:");
        }
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_obj) {
        @try { ((void(*)(id,SEL,id))gOrigSetType)(self, _cmd, v); } @catch (...) {}
    }
}

/* ---------- 通用只读 dump trampoline（调 orig，不改参数） ---------- */
static void dy_dump_void1(id self, SEL _cmd, id arg) {
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
    if (DYGate()) {
        DYAppend([NSString stringWithFormat:@"[HIT] void %@ on %@ arg=%@",
                  NSStringFromSelector(_cmd), NSStringFromClass([self class]), DYSafe(arg)]);
        DYFlushLog();
    }
}

static id dy_dump_obj0(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    if (DYGate()) {
        DYAppend([NSString stringWithFormat:@"[HIT] ret %@ on %@ = %@",
                  NSStringFromSelector(_cmd), NSStringFromClass([self class]), DYSafe(r)]);
        DYFlushLog();
    }
    return r;
}

static id dy_dump_obj1(id self, SEL _cmd, id arg) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
    if (DYGate()) {
        DYAppend([NSString stringWithFormat:@"[HIT] %@ on %@ arg=%@ ret=%@",
                  NSStringFromSelector(_cmd), NSStringFromClass([self class]), DYSafe(arg), DYSafe(r)]);
        DYFlushLog();
    }
    return r;
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
            DYAppend(@"[HOOK] setType 已挂钩(标量，只读+栈)");
        } else if (kind == 2) {
            gOrigSetType = method_setImplementation(m, (IMP)dy_setType_obj);
            DYAppend(@"[HOOK] setType 已挂钩(对象，只读+栈)");
        } else {
            gHookUnsupported = YES;
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK] setType 异常 %@", e.name]);
    }
}

/* 按精确类名 hook 一个类的全部安全签名方法（只读 dump） */
static void DYHookClassMethods(Class cls, const char *clsName, int *outCount) {
    if (!cls) { DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] %s 未注册", clsName]); return; }
    unsigned int mc = 0;
    Method *ml = class_copyMethodList(cls, &mc);
    int hooked = 0;
    @try {
        for (unsigned int j = 0; j < mc; j++) {
            SEL sel = method_getName(ml[j]);
            NSString *sn = NSStringFromSelector(sel);
            if ([sn isEqualToString:@"init"] || [sn isEqualToString:@".cxx_destruct"] ||
                [sn isEqualToString:@"dealloc"] || [sn isEqualToString:@"description"] ||
                [sn isEqualToString:@"copy"] || [sn isEqualToString:@"hash"]) continue;
            NSString *key = [NSString stringWithFormat:@"%s|%@", clsName, sn];
            if ([gHookedKeys containsObject:key]) continue;
            const char *enc = method_getTypeEncoding(ml[j]);
            NSMutableString *t = [NSMutableString string];
            for (const char *p = enc; p && *p; p++) if (*p < '0' || *p > '9') [t appendFormat:@"%c", *p];
            NSString *sig = t;
            IMP orig = NULL;
            if ([sig isEqualToString:@"v@:@"]) {
                orig = method_setImplementation(ml[j], (IMP)dy_dump_void1);
            } else if ([sig isEqualToString:@"@@:"]) {
                orig = method_setImplementation(ml[j], (IMP)dy_dump_obj0);
            } else if ([sig isEqualToString:@"@@:@"]) {
                orig = method_setImplementation(ml[j], (IMP)dy_dump_obj1);
            }
            if (orig) {
                gOrigByHook[key] = [NSValue valueWithPointer:orig];
                gOrigBySel[sn] = [NSValue valueWithPointer:orig];   /* 兜底按 selector 存 */
                [gHookedKeys addObject:key];
                hooked++;
                DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] %s|%@ enc=%s", clsName, sn, enc ? enc : "?"]);
            }
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] %s 异常 %@", clsName, e.name]);
    }
    if (ml) free(ml);
    *outCount += hooked;
}

static void DYHookPublishModels(void) {
    int total = 0;
    DYHookClassMethods(objc_getClass("AWECommentPublishParameterModel"), "AWECommentPublishParameterModel", &total);
    DYHookClassMethods(objc_getClass("AWECommentInputContentModel"), "AWECommentInputContentModel", &total);
    DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] 发布参数/内容模型共挂 %d 个方法", total]);
    DYFlushLog();
}

/* 兜底：运行时扫类名含 CommentPublishParameter / CommentInputContent 的动态子类 */
static void DYHookModelVariants(void) {
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    @try {
        for (unsigned int i = 0; i < cc; i++) {
            Class cls = classes[i];
            NSString *cn = NSStringFromClass(cls);
            if ([cn rangeOfString:@"CommentPublishParameter"].location != NSNotFound ||
                [cn rangeOfString:@"CommentInputContentModel"].location != NSNotFound) {
                int dummy = 0;
                DYHookClassMethods(cls, [cn UTF8String], &dummy);
            }
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-MODEL-VAR] 异常 %@", e.name]);
    }
    free(classes);
    DYFlushLog();
}

#pragma mark - 轮询（仅重复补挂 setType，不打 type 日志）
static void DYStartPolling(void) {
    @try {
        gPollTimer = [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *t) {
            @autoreleasepool { DYInstallSetTypeHook(); }
        }];
        if (gPollTimer) [[NSRunLoop mainRunLoop] addTimer:gPollTimer forMode:NSRunLoopCommonModes];
    } @catch (NSException *e) {}
}

#pragma mark - 入口
static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v7 抓参定性"
                message:@"只读观察，不改任何值。\n发一条带 @ 或 # 的评论，日志自动复制到剪贴板，粘贴发回。"
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
        gOrigBySel = [NSMutableDictionary dictionary];
        gHookedKeys = [NSMutableSet set];
        gHookCount = [NSMutableDictionary dictionary];
        DYAppend(@"DYProbe v7 init (只读抓参 + 调用栈定性)");
        DYSave();
    }
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            @autoreleasepool {
                DYBootAlert();
                for (int r = 0; r < 4; r++) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(r * 1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        @autoreleasepool {
                            DYAppend([NSString stringWithFormat:@"--- hook round %d ---", r]);
                            DYInstallSetTypeHook();
                            DYHookPublishModels();
                            if (r == 1) DYHookModelVariants();
                        }
                    });
                }
                DYStartPolling();
            }
        }];
}
