#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

/*
 * DYProbe v2 - 抖音 41.0.0 评论 textExtra 结构探针
 * 纯 Objective-C runtime swizzle，不依赖 Cydia Substrate / Logos。
 *
 * v2 相对 v1 的关键修复：
 *  - 评论发布走字节 TTNet/Cronet，不走 NSURLSession —— 网络层改为 NSURLProtocol 兜底
 *  - v1 在 constructor 扫类太早，AWECommentPublishParameterModel 尚未注册 —— 改为多次延迟重扫
 *  - hook 面从单一 setTextExtra: 扩展到评论发布整条 model 链的多个方法
 *  - dump KMP 枚举类型（AWEKMPCommentContentTextExtraType / SubType）
 */

static NSMutableString *gBuf = nil;
static NSInteger gHit = 0;
static NSDate *gLastPop = nil;
static NSMutableSet *gHookedKeys = nil;       // 已 hook 的 "Class|SEL"，防重复
static NSMutableDictionary *gOrigByKey = nil; // key -> NSValue(IMP)
static int gScanRound = 0;

static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    [gBuf appendFormat:@"%@\n", line];
    NSLog(@"[DYPROBE] %@", line);
}

static NSString *DYSafe(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 1500 ? [[d substringToIndex:1500] stringByAppendingString:@" ...(truncated)"] : d;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"<desc threw: %@>", e.name];
    }
}

static NSString *DYHex(NSData *data, NSUInteger limit) {
    if (!data) return @"";
    NSUInteger n = MIN(data.length, limit);
    const unsigned char *b = data.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:n*2];
    for (NSUInteger i=0;i<n;i++) [s appendFormat:@"%02x", b[i]];
    if (data.length>n) [s appendFormat:@" ...(total %lu bytes)", (unsigned long)data.length];
    return s;
}

/* 递归 dump 对象 property / ivar */
static void DYDumpObj(id obj, NSString *label, int depth) {
    if (!obj || depth > 3) return;
    DYAppend([NSString stringWithFormat:@"--- %@ | class=%@ ---", label, NSStringFromClass([obj class])]);
    DYAppend([NSString stringWithFormat:@"  description: %@", DYSafe(obj)]);

    unsigned int pc = 0;
    objc_property_t *props = class_copyPropertyList([obj class], &pc);
    for (unsigned int i=0;i<pc && i<60;i++) {
        NSString *name = [NSString stringWithUTF8String:property_getName(props[i])];
        @try {
            id v = [obj valueForKey:name];
            DYAppend([NSString stringWithFormat:@"  [p%d] %@ = %@", depth, name, DYSafe(v)]);
            // 数组元素再挖一层
            if ([v isKindOfClass:[NSArray class]] && [v count] && depth < 3) {
                NSArray *arr = (NSArray *)v;
                DYAppend([NSString stringWithFormat:@"      (array count=%lu, dumping first 3)", (unsigned long)arr.count]);
                for (NSUInteger k=0;k<MIN(arr.count,3);k++) DYDumpObj(arr[k], [NSString stringWithFormat:@"elem%lu",(unsigned long)k], depth+1);
            }
        } @catch (NSException *e) {
            DYAppend([NSString stringWithFormat:@"  [p%d] %@ = <KVC fail:%@>", depth, name, e.name]);
        }
    }
    free(props);

    unsigned int ic = 0;
    Ivar *ivars = class_copyIvarList([obj class], &ic);
    for (unsigned int i=0;i<ic && i<80;i++) {
        const char *enc = ivar_getTypeEncoding(ivars[i]);
        if (!enc || enc[0] != '@') continue;
        NSString *name = [NSString stringWithUTF8String:ivar_getName(ivars[i])];
        @try {
            id v = object_getIvar(obj, ivars[i]);
            DYAppend([NSString stringWithFormat:@"  [i%d] %@ = %@", depth, name, DYSafe(v)]);
        } @catch (NSException *e) {
            DYAppend([NSString stringWithFormat:@"  [i%d] %@ = <ivar fail:%@>", depth, name, e.name]);
        }
    }
    free(ivars);
}

static void DYSave(void) {
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!doc) return;
    NSString *path = [doc stringByAppendingPathComponent:@"dyprobe_dump.txt"];
    [gBuf writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static UIViewController *DYTopVC(void) {
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
}

static void DYCopyToPasteboard(void) {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    if (pb) pb.string = (gBuf ?: @"");
}

static void DYPop(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        DYCopyToPasteboard();
        NSDate *now = [NSDate date];
        if (gLastPop && [now timeIntervalSinceDate:gLastPop] < 3.0) return;
        gLastPop = now;
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        NSString *preview = gBuf ? (gBuf.length > 500 ? [gBuf substringToIndex:500] : gBuf) : @"(empty)";
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe 已捕获"
            message:[NSString stringWithFormat:@"命中 %ld 次。完整内容已复制到剪贴板，粘贴导出。\n\n---- 预览 ----\n%@", (long)gHit, preview]
            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"再复制一次" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){ DYCopyToPasteboard(); }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    });
}

#pragma mark - 通用 dump 触发器（按方法签名分派）

/* void (id,SEL) —— 无参方法，如 submitTextExtras / commitTextExtra */
static void dy_dump_0(id self, SEL _cmd) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    IMP orig = [gOrigByKey[key] pointerValue];
    if (orig && orig != (IMP)dy_dump_0) { @try { ((void(*)(id,SEL))orig)(self,_cmd); } @catch (...) {} }
    @try {
        gHit++;
        DYAppend([NSString stringWithFormat:@"========== [void] %@ on %@ ==========", NSStringFromSelector(_cmd), NSStringFromClass([self class])]);
        DYDumpObj(self, @"owner model", 0);
        DYSave(); DYPop();
    } @catch (NSException *e) { DYAppend([NSString stringWithFormat:@"dump0 failed: %@", e.name]); }
}

/* void (id,SEL,id) —— 单参 setter，如 setTextExtra: / setCommentTextExtra: / addTextExtraWithExtra: */
static void dy_dump_1(id self, SEL _cmd, id arg) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    IMP orig = [gOrigByKey[key] pointerValue];
    if (orig && orig != (IMP)dy_dump_1) { @try { ((void(*)(id,SEL,id))orig)(self,_cmd,arg); } @catch (...) {} }
    @try {
        gHit++;
        DYAppend([NSString stringWithFormat:@"========== [obj] %@ on %@ ==========", NSStringFromSelector(_cmd), NSStringFromClass([self class])]);
        DYDumpObj(arg, @"arg", 0);
        DYDumpObj(self, @"owner model", 0);
        DYSave(); DYPop();
    } @catch (NSException *e) { DYAppend([NSString stringWithFormat:@"dump1 failed: %@", e.name]); }
}

/*
 * 根据方法签名选 IMP。
 * 只 hook Return=void、参数都是对象的方法，避免破坏非对象参数/结构体返回。
 */
static IMP DYPickIMP(const char *enc) {
    if (!enc) return NULL;
    // 去掉数字（栈帧大小），保留类型字符
    NSMutableString *t = [NSMutableString string];
    for (const char *p=enc; *p; p++) if (*p < '0' || *p > '9') [t appendFormat:@"%c", *p];
    NSString *sig = t;
    if ([sig hasPrefix:@"v"]) {
        NSUInteger colons = 0;
        BOOL onlyObj = YES;
        for (NSUInteger i=1;i<sig.length;i++) {
            unichar c = [sig characterAtIndex:i];
            if (c == ':') colons++;
            else if (c == '@') continue;
            else if (c == '"') continue;   // 协议/类名引号内的字符会被单独处理，宽松放行
            else if (c=='{'||c=='('||c=='['||c=='^'||c=='#'||c=='*'||c=='?'||c=='B'||c=='c'||c=='i'||c=='s'||c=='l'||c=='q'||c=='f'||c=='d'||c=='C'||c=='I'||c=='S'||c=='L'||c=='Q'||c=='D'||c=='v') { onlyObj = NO; break; }
        }
        if (onlyObj) {
            if (colons == 1) return (IMP)dy_dump_0;
            if (colons == 2) return (IMP)dy_dump_1;
        }
    }
    return NULL;
}

#pragma mark - 遍历类 hook 目标方法（可重复调用，越晚扫描越全）

static void DYScanAndHook(void) {
    // 目标方法名（评论发布链 + textExtra 结构链）
    NSSet *targets = [NSSet setWithArray:@[
        @"setTextExtra:", @"setTextExtras:", @"setTextExtraArray:", @"setTextExtraModel:", @"setTextExtraDict:",
        @"setCommentTextExtra:", @"commentTextExtra", @"setContentTextExtraModelArray:",
        @"addMentionTextExtraWithModel:", @"appendTextExtraWithExtra:", @"addTextExtrasForAttributedContentText",
        @"submitTextExtras", @"checkSubmitTextExtras", @"updateTextExtra", @"updateTextExtras",
        @"dealTextExtras", @"originTextExtras", @"setOriginTextExtras:",
        @"setRealTextExtras:", @"setMentionTextExtras:", @"setChangedTextExtra:",
        @"textExtraStructKMPListSerializer", @"textExtraStructKMPDeserializer",
        @"getTextExtraDictArray", @"getTextExtraAttributes", @"setVideoTextExtraArray:"
    ]];

    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    NSInteger hooked = 0;
    for (unsigned int i = 0; i < cc; i++) {
        Class cls = classes[i];
        NSString *clsName = NSStringFromClass(cls);
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
            if (!newIMP) {
                DYAppend([NSString stringWithFormat:@"skip %@ enc=%s (signature unsupported)", key, enc ? enc : "?"]);
                continue;
            }
            IMP orig = method_setImplementation(mlist[j], newIMP);
            gOrigByKey[key] = [NSValue valueWithPointer:orig];
            [gHookedKeys addObject:key];
            hooked++;
            DYAppend([NSString stringWithFormat:@"HOOKED %@ enc=%s", key, enc ? enc : "?"]);
        }
        free(mlist);
    }
    free(classes);
    DYAppend([NSString stringWithFormat:@"=== scan round %d: +%ld new hooks (total %lu) ===", gScanRound, (long)hooked, (unsigned long)gHookedKeys.count]);
    DYSave();
}

#pragma mark - NSURLProtocol 兜底：抓所有含 comment/publish 的请求（含 TTNet 若走 URL loading）

@interface DYURLProtocol : NSURLProtocol
@end

@implementation DYURLProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *url = request.URL.absoluteString ?: @"";
    return ([url rangeOfString:@"comment/publish" options:NSCaseInsensitiveSearch].location != NSNotFound);
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSURLRequest *req = self.request;
    gHit++;
    DYAppend(@"========== NSURLProtocol: COMMENT PUBLISH ==========");
    DYAppend([NSString stringWithFormat:@"URL: %@", req.URL.absoluteString ?: @""]);
    DYAppend([NSString stringWithFormat:@"Headers: %@", DYSafe(req.allHTTPHeaderFields)]);
    NSData *body = req.HTTPBody;
    if (body.length) {
        NSString *txt = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        DYAppend(txt ? [NSString stringWithFormat:@"Body: %@", txt.length>4000?[txt substringToIndex:4000]:txt]
                     : [NSString stringWithFormat:@"Body hex: %@", DYHex(body, 2048)]);
    }
    DYSave(); DYPop();
    // 透传，不打断原请求
    NSURLSession *s = [NSURLSession sharedSession];
    NSURLSessionDataTask *task = [s dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err){
        if (data) [self.client URLProtocol:self didLoadData:data];
        if (resp) [self.client URLProtocol:self didReceiveResponse:resp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        if (err)  [self.client URLProtocol:self didFailWithError:err];
        else      [self.client URLProtocolDidFinishLoading:self];
    }];
    [task resume];
}
- (void)stopLoading {}
@end

#pragma mark - 入口

static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v2 已加载"
            message:@"注入成功。去发一条评论，探针会抓 textExtra 结构并复制到剪贴板。若没弹窗，去 Documents/dyprobe_dump.txt 看日志。\n\n请把导出内容发回给我。"
            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"开始测试" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    });
}

/* 分时机多轮扫描：类越晚注册越全 */
static void DYRoundedScan(void) {
    gScanRound++;
    DYAppend([NSString stringWithFormat:@"--- rounded scan #%d ---", gScanRound]);
    DYScanAndHook();
    // 前 3 轮继续追加扫描，覆盖 KMP/Swift 懒加载类
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
        DYAppend(@"DYProbe v2 init");

        // 1) 注册 NSURLProtocol 兜底
        @try {
            [NSURLProtocol registerClass:[DYURLProtocol class]];
            DYAppend(@"NSURLProtocol registered");
        } @catch (NSException *e) { DYAppend([NSString stringWithFormat:@"NSURLProtocol register failed: %@", e.name]); }

        // 2) 第一轮扫描（constructor，早期类）
        DYScanAndHook();
        DYSave();
    }

    // 3) App 启动后延迟多轮重扫（此时评论 model 类才注册）
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            DYBootAlert();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                @autoreleasepool { DYRoundedScan(); }
            });
        }];
}
