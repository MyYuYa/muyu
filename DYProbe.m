#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>

/*
 * DYProbe v8 - 抓到发布参数字典 extraParams，抓全 + 定点注入 type=21
 *
 * v7 决定性发现：
 *   - [SET-TYPE #2] 原值=0 紧跟 setContent: -> 列表选人@时 App 生成 textExtra type=0（发布链路）
 *   - [HIT] ret extraParams on AWECommentPublishParameterModel -> 抓到了真正要发出的发布参数字典
 *     （author_secuid / common_flags / hashtag ...），但被 600 字符截断，看不到 textExtra 结构
 *   - setType:21 x3 / setType:1 出现在 extraParams 之后 -> 那些是评论列表展示回显，不是发布
 *
 * v8 结论与打法：
 *   真正进请求体的是 AWECommentPublishParameterModel 的 extraParams 字典。
 *   hook 它的 getter(extraParams, @@:) 和 setter(setExtraParams:, v@:@)：
 *     1) 完整 dump（上限 6000，不再 600 截断）—— 看清 textExtra / text_extra 到底在哪
 *     2) 定点注入：字典里若有 textExtra/text_extra 数组，把每个元素 type 改成 @21；
 *        若完全没有，按网页端格式插一个 text_extra=[{start:0,end:内容长度,type:21}]
 *   这最接近油猴脚本在网页端 /aweme/v1/web/comment/publish/ 请求体里加 text_extra type=21 的做法。
 *
 * 防闪退（继承 v3-v7）：类白名单、零 ivar 遍历、内容去重、日志上限、全程 try/catch、只在确认有字典时才改。
 * 用法：装上->用抖音@功能选一个人发评论->看网页端是否变红->把剪贴板日志发回。
 */

#define DY_DUMP_LIMIT 400

static NSMutableString *gBuf = nil;
static NSMutableDictionary *gOrigByHook = nil;
static NSMutableDictionary *gOrigBySel = nil;
static NSMutableSet *gHookedKeys = nil;
static NSMutableSet *gSeenHits = nil;
static NSTimer *gPollTimer = nil;
static NSInteger gDumpCount = 0;
static IMP gOrigSetType = NULL;
static BOOL gHookWarned = NO;
static BOOL gHookUnsupported = NO;
static NSInteger gSetTypeCalls = 0;
static NSInteger gStackCount = 0;
static NSInteger gParamDumpCount = 0;
static NSInteger gLastContentLen = 0;

static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    if (gBuf.length > 200000) return;
    [gBuf appendFormat:@"%@\n", line];
    NSLog(@"[DYPROBE] %@", line);
}

static NSString *DYSafe(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 600 ? [[d substringToIndex:600] stringByAppendingString:@" ...(trunc600)"] : d;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"<desc threw:%@>", e.name];
    }
}

static NSString *DYSafeFull(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 6000 ? [[d substringToIndex:6000] stringByAppendingString:@" ...(trunc6000)"] : d;
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

/* 内容去重：不同 (类|方法|参数) 都记录，完全相同才跳过（v7 全局 0.15s 节流会吞掉紧随的方法） */
static BOOL DYGate(NSString *key) {
    if (gDumpCount >= DY_DUMP_LIMIT) return NO;
    if (!key) return NO;
    @try {
        if ([gSeenHits containsObject:key]) return NO;
        [gSeenHits addObject:key];
    } @catch (...) { return YES; }
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

static IMP DYOrigFor(id self, SEL _cmd) {
    NSString *sel = NSStringFromSelector(_cmd);
    Class c = [self class];
    while (c) {
        NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass(c), sel];
        IMP o = [gOrigByHook[key] pointerValue];
        if (o) return o;
        c = class_getSuperclass(c);
    }
    IMP o2 = [gOrigBySel[sel] pointerValue];
    if (o2) return o2;
    return NULL;
}

static void DYLogCallStack(NSString *tag) {
    if (gStackCount >= 1) return;   /* 重签环境多为假符号，只打一次做参考 */
    gStackCount++;
    @try {
        NSArray *syms = [NSThread callStackSymbols];
        DYAppend([NSString stringWithFormat:@"===== %@ 调用栈 (重签多为假符号) =====", tag]);
        int shown = 0;
        for (NSUInteger i = 2; i < [syms count] && shown < 8; i++) {
            NSString *s = [syms objectAtIndex:i];
            NSString *ls = [s lowercaseString];
            BOOL biz = ([ls rangeOfString:@"awemecore"].location != NSNotFound ||
                        [ls rangeOfString:@"comment"].location != NSNotFound ||
                        [ls rangeOfString:@"publish"].location != NSNotFound ||
                        [ls rangeOfString:@"extraparams"].location != NSNotFound ||
                        [ls rangeOfString:@"kmp"].location != NSNotFound);
            if (biz || shown < 3) { DYAppend([NSString stringWithFormat:@"   %@", s]); shown++; }
        }
        DYFlushLog();
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[STACK] 异常 %@", e.name]);
    }
}

/* ---------- setType: 只读观察（发布时 type=0 的@ 构造点，保留作对照） ---------- */
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
        if (gSetTypeCalls <= 10 || gSetTypeCalls % 10 == 0) {
            DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%lld on %@ (只读)",
                      (long)gSetTypeCalls, v, NSStringFromClass([self class])]);
            DYFlushLog();
        }
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_int) {
        @try { ((void(*)(id,SEL,long long))gOrigSetType)(self, _cmd, v); } @catch (...) {}
    }
}

static void dy_setType_obj(id self, SEL _cmd, id v) {
    @try {
        gSetTypeCalls++;
        if (gSetTypeCalls <= 10 || gSetTypeCalls % 10 == 0) {
            DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%@ on %@ (只读)",
                      (long)gSetTypeCalls, DYSafe(v), NSStringFromClass([self class])]);
            DYFlushLog();
        }
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_obj) {
        @try { ((void(*)(id,SEL,id))gOrigSetType)(self, _cmd, v); } @catch (...) {}
    }
}

/* ---------- 核心：发布参数字典 抓全 + 定点注入 type=21 ---------- */
static id DYMutateExtraParams(id params, NSString *tag) {
    @try {
        if (!params) return params;
        /* 完整 dump（前 4 次，不截断到 600） */
        if (gParamDumpCount < 4) {
            gParamDumpCount++;
            DYAppend([NSString stringWithFormat:@"===== [PARAMS-FULL %@] =====", tag]);
            DYAppend(DYSafeFull(params));
            DYFlushLog();
        }
        BOOL isDict = [params isKindOfClass:[NSDictionary class]] || [params isKindOfClass:[NSMutableDictionary class]];
        if (!isDict) return params;
        NSMutableDictionary *md = ([params isKindOfClass:[NSMutableDictionary class]]) ? params : [params mutableCopy];
        if (!md) return params;
        BOOL changed = NO;
        NSArray *keys = [md allKeys];
        for (id k in keys) {
            if (![k isKindOfClass:[NSString class]]) continue;
            NSString *ks = (NSString *)k;
            NSString *kl = [ks lowercaseString];
            BOOL isExtraKey = ([kl rangeOfString:@"textextra"].location != NSNotFound ||
                               [kl rangeOfString:@"text_extra"].location != NSNotFound);
            if (!isExtraKey) continue;
            id val = [md objectForKey:k];
            DYAppend([NSString stringWithFormat:@"[PARAMS-TEXTEXTRA] %@ key=%@ val=%@", tag, ks, DYSafeFull(val)]);
            DYFlushLog();
            if ([val isKindOfClass:[NSArray class]]) {
                NSMutableArray *ma = [val mutableCopy];
                for (NSUInteger i = 0; i < [ma count]; i++) {
                    id e = [ma objectAtIndex:i];
                    if ([e isKindOfClass:[NSDictionary class]] || [e isKindOfClass:[NSMutableDictionary class]]) {
                        NSMutableDictionary *me = ([e isKindOfClass:[NSMutableDictionary class]]) ? e : [e mutableCopy];
                        [me setObject:@21 forKey:@"type"];
                        [ma replaceObjectAtIndex:i withObject:me];
                        changed = YES;
                    }
                }
                if (changed) [md setObject:ma forKey:k];
            }
        }
        /* 完全没有 textExtra 键：按网页端格式插一个（模仿油猴脚本请求体） */
        if (!changed) {
            NSUInteger endLen = (gLastContentLen > 0) ? (NSUInteger)gLastContentLen : 14;
            NSArray *one = @[ @{ @"start": @0, @"end": @(endLen), @"type": @21 } ];
            [md setObject:one forKey:@"text_extra"];
            [md setObject:one forKey:@"textExtra"];
            DYAppend([NSString stringWithFormat:@"[INJECT] %@ 无 textExtra 键，已插入 text_extra=[{start:0,end:%lu,type:21}]", tag, (unsigned long)endLen]);
            DYFlushLog();
        } else {
            DYAppend([NSString stringWithFormat:@"[INJECT] %@ 已把 textExtra 元素 type 改成 21", tag]);
            DYFlushLog();
        }
        return md;
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[PARAMS] %@ 异常 %@，放弃注入", tag, e.name]);
        DYFlushLog();
        return params;
    }
}

/* extraParams getter (@@:) */
static id dy_extraParams_get(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    return DYMutateExtraParams(r, @"extraParams(get)");
}

/* setExtraParams: setter (v@:@) —— 调用 orig 前先把参数改好 */
static void dy_setExtraParams(id self, SEL _cmd, id arg) {
    id mutated = DYMutateExtraParams(arg, @"setExtraParams:");
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, mutated); } @catch (...) {} }
}

/* ---------- 通用只读 dump trampoline ---------- */
static void dy_dump_void0(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    NSString *cn = NSStringFromClass([self class]);
    NSString *sn = NSStringFromSelector(_cmd);
    NSString *key = [NSString stringWithFormat:@"v0|%@|%@", cn, sn];
    if (DYGate(key)) {
        DYAppend([NSString stringWithFormat:@"[HIT] void %@ on %@", sn, cn]);
        DYFlushLog();
    }
}

static void dy_dump_void1(id self, SEL _cmd, id arg) {
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
    NSString *cn = NSStringFromClass([self class]);
    NSString *sn = NSStringFromSelector(_cmd);
    if ([sn isEqualToString:@"setContent:"] && [arg isKindOfClass:[NSString class]]) {
        gLastContentLen = [(NSString *)arg length];
    }
    NSString *key = [NSString stringWithFormat:@"v1|%@|%@|%@", cn, sn, DYSafe(arg)];
    if (DYGate(key)) {
        DYAppend([NSString stringWithFormat:@"[HIT] void %@ on %@ arg=%@", sn, cn, DYSafe(arg)]);
        DYFlushLog();
    }
}

static id dy_dump_obj0(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    NSString *cn = NSStringFromClass([self class]);
    NSString *sn = NSStringFromSelector(_cmd);
    NSString *key = [NSString stringWithFormat:@"o0|%@|%@|%@", cn, sn, DYSafe(r)];
    if (DYGate(key)) {
        DYAppend([NSString stringWithFormat:@"[HIT] ret %@ on %@ = %@", sn, cn, DYSafe(r)]);
        DYFlushLog();
    }
    return r;
}

static id dy_dump_obj1(id self, SEL _cmd, id arg) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
    NSString *cn = NSStringFromClass([self class]);
    NSString *sn = NSStringFromSelector(_cmd);
    NSString *key = [NSString stringWithFormat:@"o1|%@|%@|%@|%@", cn, sn, DYSafe(arg), DYSafe(r)];
    if (DYGate(key)) {
        DYAppend([NSString stringWithFormat:@"[HIT] %@ on %@ arg=%@ ret=%@", sn, cn, DYSafe(arg), DYSafe(r)]);
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
            DYAppend(@"[HOOK] setType 已挂钩(标量，只读)");
        } else if (kind == 2) {
            gOrigSetType = method_setImplementation(m, (IMP)dy_setType_obj);
            DYAppend(@"[HOOK] setType 已挂钩(对象，只读)");
        } else {
            gHookUnsupported = YES;
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK] setType 异常 %@", e.name]);
    }
}

/* 按精确类名 hook 全部安全签名方法；extraParams / setExtraParams: 用专用注入 trampoline */
static void DYHookClassMethods(Class cls, const char *clsName, NSString *excludeSel, int *outCount) {
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
                [sn isEqualToString:@"copy"] || [sn isEqualToString:@"hash"] ||
                [sn isEqualToString:@"retain"] || [sn isEqualToString:@"release"]) continue;
            if (excludeSel && [sn isEqualToString:excludeSel]) continue;
            NSString *key = [NSString stringWithFormat:@"%s|%@", clsName, sn];
            if ([gHookedKeys containsObject:key]) continue;
            const char *enc = method_getTypeEncoding(ml[j]);
            NSMutableString *t = [NSMutableString string];
            for (const char *p = enc; p && *p; p++) if (*p < '0' || *p > '9') [t appendFormat:@"%c", *p];
            NSString *sig = t;
            IMP orig = NULL;
            BOOL specialExtra = [sn isEqualToString:@"extraParams"] && [sig isEqualToString:@"@@:"];
            BOOL specialSetExtra = [sn isEqualToString:@"setExtraParams:"] && [sig isEqualToString:@"v@:@"];
            if (specialExtra) {
                orig = method_setImplementation(ml[j], (IMP)dy_extraParams_get);
            } else if (specialSetExtra) {
                orig = method_setImplementation(ml[j], (IMP)dy_setExtraParams);
            } else if ([sig isEqualToString:@"v@:"]) {
                orig = method_setImplementation(ml[j], (IMP)dy_dump_void0);
            } else if ([sig isEqualToString:@"v@:@"]) {
                orig = method_setImplementation(ml[j], (IMP)dy_dump_void1);
            } else if ([sig isEqualToString:@"@@:"]) {
                orig = method_setImplementation(ml[j], (IMP)dy_dump_obj0);
            } else if ([sig isEqualToString:@"@@:@"]) {
                orig = method_setImplementation(ml[j], (IMP)dy_dump_obj1);
            }
            if (orig) {
                gOrigByHook[key] = [NSValue valueWithPointer:orig];
                gOrigBySel[sn] = [NSValue valueWithPointer:orig];
                [gHookedKeys addObject:key];
                hooked++;
                DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] %s|%@ enc=%s%s", clsName, sn, enc ? enc : "?",
                          specialExtra || specialSetExtra ? "  <<INJECT>>" : ""]);
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
    DYHookClassMethods(objc_getClass("AWECommentPublishParameterModel"), "AWECommentPublishParameterModel", nil, &total);
    DYHookClassMethods(objc_getClass("AWECommentInputContentModel"), "AWECommentInputContentModel", nil, &total);
    DYHookClassMethods(objc_getClass("AWETextExtra"), "AWETextExtra", @"setType:", &total);
    DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] 发布/内容/textExtra 模型共挂 %d 个方法", total]);
    DYFlushLog();
}

static void DYHookModelVariants(void) {
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    @try {
        for (unsigned int i = 0; i < cc; i++) {
            Class cls = classes[i];
            NSString *cn = NSStringFromClass(cls);
            if ([cn rangeOfString:@"CommentPublishParameter"].location != NSNotFound ||
                [cn rangeOfString:@"CommentInputContentModel"].location != NSNotFound ||
                [cn isEqualToString:@"AWETextExtra"]) {
                int dummy = 0;
                DYHookClassMethods(cls, [cn UTF8String], @"setType:", &dummy);
            }
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-MODEL-VAR] 异常 %@", e.name]);
    }
    free(classes);
    DYFlushLog();
}

#pragma mark - 轮询（仅重复补挂 setType）
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
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v8 注入测试"
                message:@"抓发布参数 extraParams 并注入 type=21。\n用抖音 @ 功能选一个人发评论，去网页端看是否变红。\n日志自动复制到剪贴板，粘贴发回。"
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
        gSeenHits = [NSMutableSet set];
        DYAppend(@"DYProbe v8 init (抓发布参数 extraParams + 注入 type=21)");
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
