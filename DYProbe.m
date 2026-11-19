#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

/*
 * DYProbe v3 - 抖音 41.0.0 评论 textExtra 结构探针（防闪退版）
 * 纯 Objective-C runtime swizzle，不依赖 Cydia Substrate / Logos。
 *
 * v3 相对 v2 的关键修复（v2 因深度 dump 高频 model 导致闪退）：
 *  1) 只 hook 类名含 "Comment" / "Publish" 的对象；不再碰 AWEAwemeModel / AWEUserModel 等高频 model
 *  2) 参数只做 description + 白名单属性读取，绝不遍历 ivar（object_getIvar 是闪退元凶）
 *  3) KVC 读取加 try/catch，读不到就跳过
 *  4) 全局频率闸门：每 0.3s 最多 dump 一次，最多 dump 20 次，防止刷屏/卡顿
 *  5) 去掉会导致透传异常的 NSURLProtocol，专注 model 层
 */

static NSMutableString *gBuf = nil;
static NSInteger gHit = 0;
static NSDate *gLastPop = nil;
static NSDate *gLastDump = nil;
static NSMutableSet *gHookedKeys = nil;
static NSMutableDictionary *gOrigByKey = nil;
static NSInteger gDumpCount = 0;
static int gScanRound = 0;

static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    if (gBuf.length > 60000) return;   // 防止日志无限膨胀
    [gBuf appendFormat:@"%@\n", line];
    NSLog(@"[DYPROBE] %@", line);
}

/* 只取 description，安全，不碰 ivar */
static NSString *DYSafe(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 900 ? [[d substringToIndex:900] stringByAppendingString:@" ...(truncated)"] : d;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"<desc threw:%@>", e.name];
    }
}

/* 只 dump 安全的可读属性（白名单名字），绝不遍历 ivar */
static void DYDumpObjSafe(id obj, NSString *label) {
    if (!obj) return;
    @try {
        DYAppend([NSString stringWithFormat:@"--- %@ | class=%@ ---", label, NSStringFromClass([obj class])]);
        DYAppend([NSString stringWithFormat:@"  desc: %@", DYSafe(obj)]);
        unsigned int pc = 0;
        objc_property_t *props = class_copyPropertyList([obj class], &pc);
        NSInteger shown = 0;
        for (unsigned int i=0;i<pc && shown<25;i++) {
            NSString *name = [NSString stringWithUTF8String:property_getName(props[i])];
            NSString *low = [name lowercaseString];
            BOOL interesting = ([low rangeOfString:@"text"].location!=NSNotFound ||
                                [low rangeOfString:@"extra"].location!=NSNotFound ||
                                [low rangeOfString:@"type"].location!=NSNotFound ||
                                [low rangeOfString:@"start"].location!=NSNotFound ||
                                [low rangeOfString:@"end"].location!=NSNotFound ||
                                [low rangeOfString:@"user"].location!=NSNotFound ||
                                [low rangeOfString:@"range"].location!=NSNotFound ||
                                [low rangeOfString:@"content"].location!=NSNotFound);
            if (!interesting) continue;
            @try {
                id v = [obj valueForKey:name];
                NSString *vs = DYSafe(v);
                DYAppend([NSString stringWithFormat:@"  [prop] %@ = %@", name, vs]);
                shown++;
                if ([v isKindOfClass:[NSArray class]] && [(NSArray*)v count] && [(NSArray*)v count]<=10) {
                    NSArray *arr = (NSArray*)v;
                    DYAppend([NSString stringWithFormat:@"      array(%lu):", (unsigned long)arr.count]);
                    for (id e in arr) DYAppend([NSString stringWithFormat:@"        - %@", DYSafe(e)]);
                }
            } @catch (NSException *e) {
                DYAppend([NSString stringWithFormat:@"  [prop] %@ = <skip:%@>", name, e.name]);
            }
        }
        free(props);
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"dump safe failed: %@", e.name]);
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
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v3 已捕获"
                message:[NSString stringWithFormat:@"命中 %ld 次，已复制到剪贴板。\n\n---- 预览 ----\n%@", (long)gHit, preview]
                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"再复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){ DYCopyToPasteboard(); }]];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

/* 频率闸门：返回 YES 才允许本次 dump */
static BOOL DYGate(void) {
    if (gDumpCount >= 20) return NO;
    NSDate *now = [NSDate date];
    if (gLastDump && [now timeIntervalSinceDate:gLastDump] < 0.3) return NO;
    gLastDump = now;
    gDumpCount++;
    return YES;
}

#pragma mark - 通用 dump 触发器

/* void (id,SEL) —— 无参方法 */
static void dy_dump_0(id self, SEL _cmd) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    IMP orig = [gOrigByKey[key] pointerValue];
    if (orig && orig != (IMP)dy_dump_0) { @try { ((void(*)(id,SEL))orig)(self,_cmd); } @catch (...) {} }
    @try {
        gHit++;
        if (!DYGate()) return;
        DYAppend([NSString stringWithFormat:@"========== [void] %@ on %@ ==========", NSStringFromSelector(_cmd), NSStringFromClass([self class])]);
        DYSave(); DYPop();
    } @catch (...) {}
}

/* void (id,SEL,id) —— 单参 setter */
static void dy_dump_1(id self, SEL _cmd, id arg) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    IMP orig = [gOrigByKey[key] pointerValue];
    if (orig && orig != (IMP)dy_dump_1) { @try { ((void(*)(id,SEL,id))orig)(self,_cmd,arg); } @catch (...) {} }
    @try {
        gHit++;
        if (!DYGate()) return;
        DYAppend([NSString stringWithFormat:@"========== [obj] %@ on %@ ==========", NSStringFromSelector(_cmd), NSStringFromClass([self class])]);
        DYDumpObjSafe(arg, @"arg");
        DYSave(); DYPop();
    } @catch (...) {}
}

/* 按签名选 IMP，只 hook 返回 void + 纯对象参数的方法 */
static IMP DYPickIMP(const char *enc) {
    if (!enc) return NULL;
    NSMutableString *t = [NSMutableString string];
    for (const char *p=enc; *p; p++) if (*p < '0' || *p > '9') [t appendFormat:@"%c", *p];
    NSString *sig = t;
    if (![sig hasPrefix:@"v"]) return NULL;
    NSUInteger colons = 0;
    BOOL onlyObj = YES;
    for (NSUInteger i=1;i<sig.length;i++) {
        unichar c = [sig characterAtIndex:i];
        if (c == ':') colons++;
        else if (c == '@' || c == '"') continue;
        else if (c=='{'||c=='('||c=='['||c=='^'||c=='#'||c=='*'||c=='?'||c=='B'||c=='c'||c=='i'||c=='s'||c=='l'||c=='q'||c=='f'||c=='d'||c=='C'||c=='I'||c=='S'||c=='L'||c=='Q'||c=='D'||c=='v') { onlyObj = NO; break; }
    }
    if (!onlyObj) return NULL;
    if (colons == 1) return (IMP)dy_dump_0;
    if (colons == 2) return (IMP)dy_dump_1;
    return NULL;
}

/* 只 hook 评论/发布相关的类，避开视频/用户等高频 model */
static BOOL DYIsTargetClass(NSString *clsName) {
    NSString *low = [clsName lowercaseString];
    return ([low rangeOfString:@"comment"].location != NSNotFound ||
            [low rangeOfString:@"publish"].location != NSNotFound);
}

static void DYScanAndHook(void) {
    NSSet *targets = [NSSet setWithArray:@[
        @"setTextExtra:", @"setTextExtras:", @"setTextExtraArray:", @"setTextExtraModel:", @"setTextExtraDict:",
        @"setCommentTextExtra:", @"setContentTextExtraModelArray:",
        @"addMentionTextExtraWithModel:", @"appendTextExtraWithExtra:",
        @"submitTextExtras", @"checkSubmitTextExtras", @"updateTextExtra", @"updateTextExtras",
        @"setChangedTextExtra:", @"setRealTextExtras:", @"setMentionTextExtras:",
        @"setOriginTextExtras:"
    ]];

    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    NSInteger hooked = 0;
    for (unsigned int i = 0; i < cc; i++) {
        Class cls = classes[i];
        NSString *clsName = NSStringFromClass(cls);
        if (!DYIsTargetClass(clsName)) continue;   // 关键：类白名单
        unsigned int mc = 0;
        Method *mlist = class_copyMethodList(cls, &mc);
        for (unsigned int j = 0; j < mc; j++) {
            SEL ms = method_getName(mlist[j]);
            NSString *selName = NSStringFromSelector(ms);
            if (![targets containsObject:selName]) continue;
            NSString *key = [NSString stringWithFormat:@"%@|%@", clsName, selName];
            if ([gHookedKeys containsObject:key]) continue;
            const char *enc = method_getTypeEncoding(mlist[j]);
            IMP newIMP = DYPickIMP(enc);
            if (!newIMP) continue;
            IMP orig = method_setImplementation(mlist[j], newIMP);
            gOrigByKey[key] = [NSValue valueWithPointer:orig];
            [gHookedKeys addObject:key];
            hooked++;
            DYAppend([NSString stringWithFormat:@"HOOKED %@ enc=%s", key, enc ? enc : "?"]);
        }
        free(mlist);
    }
    free(classes);
    DYAppend([NSString stringWithFormat:@"=== scan round %d: +%ld hooks (total %lu) ===", gScanRound, (long)hooked, (unsigned long)gHookedKeys.count]);
    DYSave();
}

#pragma mark - 入口

static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v3 已加载"
                message:@"防闪退版。去发一条带 @ 或 # 的评论，探针会抓 textExtra 结构并复制到剪贴板。"
                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"开始测试" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

static void DYRoundedScan(void) {
    gScanRound++;
    DYAppend([NSString stringWithFormat:@"--- rounded scan #%d ---", gScanRound]);
    DYScanAndHook();
    if (gScanRound < 3) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            @autoreleasepool { DYRoundedScan(); }
        });
    }
}

__attribute__((constructor)) static void DYInit(void) {
    @autoreleasepool {
        gBuf = [NSMutableString string];
        gOrigByKey = [NSMutableDictionary dictionary];
        gHookedKeys = [NSMutableSet set];
        DYAppend(@"DYProbe v3 init (anti-crash)");
        DYScanAndHook();
        DYSave();
    }
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            DYBootAlert();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                @autoreleasepool { DYRoundedScan(); }
            });
        }];
}
