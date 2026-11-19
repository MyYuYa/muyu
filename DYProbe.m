#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>

/*
 * DYProbe v5 - 抖音 41.0.0 评论 type 批量轮询注入版
 * 纯 Objective-C runtime swizzle，不依赖 Cydia Substrate / Logos。
 *
 * 原理（对齐油猴脚本的批量测试）：
 *  - 网页脚本: 自己构造 body, type 想填多少填多少 -> 轮询测出 21=红
 *  - App 脚本: body 由 App(Swift/KMP)构造, 我们只能 hook 它现成的
 *              AWETextExtra 对象的 setType:, 在 App 构造 @/# textExtra 时
 *              把 type 改成「当前轮询值」。
 *
 * 用法:
 *  1) 装上后打开抖音, 弹窗显示「DYProbe v5 批量测试」
 *  2) 发一条带 @ 或 # 的评论 (纯文字评论 App 不构造 textExtra, 无效)
 *  3) 每隔 2 秒再发一条 —— type 会自动 +1 (15->30 循环)
 *  4) 到【网页端】看哪条评论变红/变色 (网页端不受本插件影响, 结果最准)
 *  5) 导出 dyprobe_dump.txt 发回: 里面有每条评论发出时刻的 type 值
 *
 * 防闪退 (继承 v3/v4):
 *  - 只 hook 类名精确等于 AWETextExtra 的 setType:, 不碰其它类
 *  - 参数按 type encoding 自适应 (标量 int / NSNumber 对象)
 *  - 展示链路只读 dump, 不遍历 ivar, 不深度反射 self
 *  - 全程 try/catch + 频率闸门 + 日志上限
 */

/* ---------- 配置 ---------- */
#define DY_TYPE_FROM 15
#define DY_TYPE_TO   30
#define DY_INTERVAL  2.0

static NSMutableString *gBuf = nil;
static NSMutableDictionary *gOrigByKey = nil;
static NSMutableSet *gHookedKeys = nil;
static NSInteger gHit = 0;
static NSDate *gLastPop = nil;
static NSDate *gLastDump = nil;
static NSInteger gDumpCount = 0;
static NSInteger gCurrentType = DY_TYPE_FROM;
static NSTimer *gPollTimer = nil;

/* setType: 原始 IMP 与参数种类 */
static IMP gOrigSetType = NULL;
static int  gSetTypeKind = 0;   /* 1=标量int  2=NSNumber对象 */
static NSInteger gSetTypeCalls = 0;

static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    if (gBuf.length > 60000) return;
    [gBuf appendFormat:@"%@\n", line];
    NSLog(@"[DYPROBE] %@", line);
}

static NSString *DYSafe(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 800 ? [[d substringToIndex:800] stringByAppendingString:@" ...(truncated)"] : d;
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

static void DYCopyToPasteboard(void) {
    @try { UIPasteboard *pb = [UIPasteboard generalPasteboard]; if (pb) pb.string = (gBuf ?: @""); } @catch (...) {}
}

static void DYPop(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        DYCopyToPasteboard();
        NSDate *now = [NSDate date];
        if (gLastPop && [now timeIntervalSinceDate:gLastPop] < 5.0) return;
        gLastPop = now;
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        @try {
            NSString *preview = gBuf ? (gBuf.length > 400 ? [gBuf substringToIndex:400] : gBuf) : @"(empty)";
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v5 批量测试"
                message:[NSString stringWithFormat:@"type 每 2 秒 +1。发一条带 @ 或 # 的评论，间隔 2 秒再发下一条。已复制到剪贴板。\n\n当前 type=%ld\n\n---- 预览 ----\n%@", (long)gCurrentType, preview]
                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"再复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){ DYCopyToPasteboard(); }]];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

static BOOL DYGate(void) {
    if (gDumpCount >= 80) return NO;
    NSDate *now = [NSDate date];
    if (gLastDump && [now timeIntervalSinceDate:gLastDump] < 0.2) return NO;
    gLastDump = now;
    gDumpCount++;
    return YES;
}

#pragma mark - 发布链路：hook AWETextExtra setType:

/* 判断 setType: 的参数种类：1=标量整型 2=NSNumber 对象 */
static int DYSetTypeArgKind(const char *enc) {
    if (!enc) return 0;
    const char *colon = strchr(enc, ':');
    if (!colon) return 0;
    for (const char *p = colon + 1; *p; p++) {
        if (*p >= '0' && *p <= '9') continue;
        if (*p == '@') return 2;                       /* NSNumber */
        if (*p=='i'||*p=='l'||*p=='q'||*p=='I'||*p=='L'||*p=='Q') return 1;  /* int/long */
        if (*p=='"') break;
    }
    return 0;
}

/* 标量 int 版 setType: */
static void dy_setType_int(id self, SEL _cmd, int v) {
    @try {
        gSetTypeCalls++;
        gHit++;
        DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%d  ->  注入=%ld (当前轮询值) on %@",
                  (long)gSetTypeCalls, v, (long)gCurrentType, NSStringFromClass([self class]))];
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_int) {
        @try { ((void(*)(id,SEL,int))gOrigSetType)(self, _cmd, (int)gCurrentType); } @catch (...) {}
    }
}

/* NSNumber 对象版 setType: */
static void dy_setType_obj(id self, SEL _cmd, id v) {
    @try {
        gSetTypeCalls++;
        gHit++;
        DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%@  ->  注入=%ld (当前轮询值) on %@",
                  (long)gSetTypeCalls, DYSafe(v), (long)gCurrentType, NSStringFromClass([self class]))];
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_obj) {
        @try { ((void(*)(id,SEL,id))gOrigSetType)(self, _cmd, @(gCurrentType)); } @catch (...) {}
    }
}

#pragma mark - 展示链路：只读 dump（观察服务端存回的 type）

static void dy_dump_1(id self, SEL _cmd, id arg) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    IMP orig = [gOrigByKey[key] pointerValue];
    if (orig && orig != (IMP)dy_dump_1) { @try { ((void(*)(id,SEL,id))orig)(self,_cmd,arg); } @catch (...) {} }
    @try {
        if (!DYGate()) return;
        gHit++;
        DYAppend([NSString stringWithFormat:@"========== [展示] %@ on %@ ==========", NSStringFromSelector(_cmd), NSStringFromClass([self class])]);
        if ([arg isKindOfClass:[NSArray class]]) {
            NSArray *arr = (NSArray *)arg;
            DYAppend([NSString stringWithFormat:@"  textExtras 数量: %lu", (unsigned long)arr.count]);
            for (id e in arr) {
                NSString *et = @"?";
                @try { et = [NSString stringWithFormat:@"%@", [e valueForKey:@"type"] ?: @"(nil)"]; } @catch (...) {}
                NSString *st = @"?", *en = @"?";
                @try { st = [NSString stringWithFormat:@"%@", [e valueForKey:@"start"] ?: @"(nil)"]; } @catch (...) {}
                @try { en = [NSString stringWithFormat:@"%@", [e valueForKey:@"end"] ?: @"(nil)"]; } @catch (...) {}
                DYAppend([NSString stringWithFormat:@"    extra: type=%@ start=%@ end=%@  class=%@", et, st, en, NSStringFromClass([e class])]);
            }
        }
        DYSave();
    } @catch (...) {}
}

#pragma mark - hook 安装

static void DYInstallSetTypeHook(void) {
    @try {
        Class ec = objc_getClass("AWETextExtra");
        if (!ec) { DYAppend(@"[HOOK] AWETextExtra 类未注册, 等下一轮"); return; }
        Method m = class_getInstanceMethod(ec, @selector(setType:));
        if (!m) { DYAppend(@"[HOOK] AWETextExtra 无 setType:, 等下一轮"); return; }
        if (gSetTypeCalls < 0) return;
        const char *enc = method_getTypeEncoding(m);
        DYAppend([NSString stringWithFormat:@"[HOOK] AWETextExtra setType: enc=%s", enc ? enc : "?"]);
        int kind = DYSetTypeArgKind(enc);
        if (kind == 1) {
            gOrigSetType = method_setImplementation(m, (IMP)dy_setType_int);
            gSetTypeKind = 1;
            DYAppend(@"[HOOK] setType: 已挂钩 (标量 int)");
        } else if (kind == 2) {
            gOrigSetType = method_setImplementation(m, (IMP)dy_setType_obj);
            gSetTypeKind = 2;
            DYAppend(@"[HOOK] setType: 已挂钩 (NSNumber 对象)");
        } else {
            DYAppend(@"[HOOK] setType: 参数种类未知, 跳过以防崩");
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK] setType: 安装异常 %@", e.name]);
    }
}

static void DYScanAndHookDisplay(void) {
    NSSet *targets = [NSSet setWithArray:@[ @"setTextExtras:" ]];
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    NSInteger hooked = 0;
    @try {
        for (unsigned int i = 0; i < cc; i++) {
            Class cls = classes[i];
            NSString *clsName = NSStringFromClass(cls);
            if (![clsName isEqualToString:@"AWECommentModel"]) continue;  /* 精确类, 不碰高频 model */
            unsigned int mc = 0;
            Method *mlist = class_copyMethodList(cls, &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL ms = method_getName(mlist[j]);
                NSString *selName = NSStringFromSelector(ms);
                if (![targets containsObject:selName]) continue;
                NSString *key = [NSString stringWithFormat:@"%@|%@", clsName, selName];
                if ([gHookedKeys containsObject:key]) continue;
                const char *enc = method_getTypeEncoding(mlist[j]);
                /* 只接单对象参 void: v@:@ */
                NSString *sig = @"";
                NSMutableString *t = [NSMutableString string];
                for (const char *p=enc; *p; p++) if (*p<'0'||*p>'9') [t appendFormat:@"%c",*p];
                sig = t;
                if (![sig isEqualToString:@"v@:@"]) continue;
                IMP orig = method_setImplementation(mlist[j], (IMP)dy_dump_1);
                gOrigByKey[key] = [NSValue valueWithPointer:orig];
                [gHookedKeys addObject:key];
                hooked++;
                DYAppend([NSString stringWithFormat:@"[HOOK-DISP] %@ enc=%s", key, enc]);
            }
            free(mlist);
        }
    } @catch (...) {}
    free(classes);
    DYAppend([NSString stringWithFormat:@"[HOOK-DISP] 本轮 +%ld (总 %lu)", (long)hooked, (unsigned long)gHookedKeys.count]);
    DYSave();
}

#pragma mark - 轮询定时器

static void DYStartPolling(void) {
    gCurrentType = DY_TYPE_FROM;
    DYAppend([NSString stringWithFormat:@"[POLL] 启动: type 从 %d 到 %d, 每 %.0f 秒 +1", DY_TYPE_FROM, DY_TYPE_TO, DY_INTERVAL]);
    @try {
        gPollTimer = [NSTimer scheduledTimerWithTimeInterval:DY_INTERVAL repeats:YES block:^(NSTimer *t) {
            @autoreleasepool {
                gCurrentType++;
                if (gCurrentType > DY_TYPE_TO) gCurrentType = DY_TYPE_FROM;
                DYAppend([NSString stringWithFormat:@"[POLL] === 当前 type = %ld === (现在发的评论用这个值)", (long)gCurrentType]);
                DYSave();
            }
        }];
        if (gPollTimer) [[NSRunLoop mainRunLoop] addTimer:gPollTimer forMode:NSRunLoopCommonModes];
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[POLL] 定时器启动失败 %@", e.name]);
    }
}

#pragma mark - 入口

static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v5 批量测试已加载"
                message:[NSString stringWithFormat:@"type 每 2 秒自动 +1 (%d→%d)。\n\n发一条带 @ 或 # 的评论，间隔 2 秒发下一条。到网页端看哪条变色，再把本插件的 dyprobe_dump.txt 发回。", DY_TYPE_FROM, DY_TYPE_TO]
                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"开始测试" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

__attribute__((constructor)) static void DYInit(void) {
    @autoreleasepool {
        gBuf = [NSMutableString string];
        gOrigByKey = [NSMutableDictionary dictionary];
        gHookedKeys = [NSMutableSet set];
        DYAppend(@"DYProbe v5 init (type-poll injection)");
        DYSave();
    }
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            @autoreleasepool {
                DYBootAlert();
                /* 分 3 轮延迟挂钩, 等 Swift/KMP 类注册完成 */
                for (int r = 0; r < 3; r++) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(r * 1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        @autoreleasepool {
                            DYAppend([NSString stringWithFormat:@"--- hook round %d ---", r]);
                            if (gSetTypeCalls == 0 && !gOrigSetType) DYInstallSetTypeHook();
                            DYScanAndHookDisplay();
                        }
                    });
                }
                DYStartPolling();
            }
        }];
}
