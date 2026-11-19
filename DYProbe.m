#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

/*
 * DYProbe - 抖音 41.0.0 评论 textExtra 结构探针
 * 纯 Objective-C runtime swizzle，不依赖 Cydia Substrate / Logos，
 * 适配「全能签 / 爱思 / Sideloadly」这类非越狱 dylib 注入。
 *
 * 用法：注入后安装，任意发一条评论。探针会：
 *   1) 抓发布请求的 body（URL/Header/Body）
 *   2) 抓 AWECommentPublishParameterModel 的 textExtra 对象结构
 *   3) 结果写入 App 沙盒 Documents/dyprobe_dump.txt
 *   4) 复制到系统剪贴板，并弹窗提示（粘贴到任意输入框即可导出）
 */

static NSMutableString *gBuf = nil;
static NSInteger gHit = 0;
static BOOL gDidPop = NO;
static NSDate *gLastPop = nil;

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
        return d.length > 1200 ? [[d substringToIndex:1200] stringByAppendingString:@" ...(truncated)"] : d;
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

/* 递归 dump 一个对象的 property / ivar —— 用来挖 KMP 的 textExtra 结构 */
static void DYDumpObj(id obj, NSString *label, int depth) {
    if (!obj || depth > 2) return;
    DYAppend([NSString stringWithFormat:@"--- %@ | class=%@ ---", label, NSStringFromClass([obj class])]);
    DYAppend([NSString stringWithFormat:@"  description: %@", DYSafe(obj)]);

    unsigned int pc = 0;
    objc_property_t *props = class_copyPropertyList([obj class], &pc);
    for (unsigned int i=0;i<pc && i<50;i++) {
        NSString *name = [NSString stringWithUTF8String:property_getName(props[i])];
        @try {
            id v = [obj valueForKey:name];
            DYAppend([NSString stringWithFormat:@"  [p%d] %@ = %@", depth, name, DYSafe(v)]);
        } @catch (NSException *e) {
            DYAppend([NSString stringWithFormat:@"  [p%d] %@ = <KVC fail:%@>", depth, name, e.name]);
        }
    }
    free(props);

    unsigned int ic = 0;
    Ivar *ivars = class_copyIvarList([obj class], &ic);
    for (unsigned int i=0;i<ic && i<60;i++) {
        const char *enc = ivar_getTypeEncoding(ivars[i]);
        if (!enc || enc[0] != '@') continue;   // 只取对象类型，避免读取标量崩
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

static void DYPop(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([UIPasteboard generalPasteboard]) [UIPasteboard generalPasteboard].string = (gBuf ?: @"");
        NSDate *now = [NSDate date];
        if (gDidPop && gLastPop && [now timeIntervalSinceDate:gLastPop] < 3.0) return;
        gDidPop = YES; gLastPop = now;
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        NSString *preview = gBuf ? (gBuf.length > 500 ? [gBuf substringToIndex:500] : gBuf) : @"(empty)";
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe 已捕获"
            message:[NSString stringWithFormat:@"命中 %ld 次。完整内容已复制到剪贴板，粘贴到任意输入框即可导出。\n\n---- 预览 ----\n%@", (long)gHit, preview]
            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"再复制一次" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){
            if ([UIPasteboard generalPasteboard]) [UIPasteboard generalPasteboard].string = (gBuf ?: @"");
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    });
}

#pragma mark - 网络层：抓发布请求 body

static void DYInspectRequest(NSURLRequest *req) {
    NSString *url = req.URL.absoluteString ?: @"";
    if ([url rangeOfString:@"comment/publish"].location == NSNotFound) return;
    gHit++;
    DYAppend(@"========== COMMENT PUBLISH REQUEST ==========");
    DYAppend([NSString stringWithFormat:@"URL: %@", url]);
    DYAppend([NSString stringWithFormat:@"Method: %@", req.HTTPMethod ?: @"?"]);
    DYAppend([NSString stringWithFormat:@"Headers: %@", DYSafe(req.allHTTPHeaderFields)]);
    NSData *body = req.HTTPBody;
    if (body.length) {
        DYAppend([NSString stringWithFormat:@"Body length: %lu", (unsigned long)body.length]);
        NSString *txt = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (txt) {
            DYAppend([NSString stringWithFormat:@"Body text: %@", txt.length>4000 ? [txt substringToIndex:4000] : txt]);
            // 若 form 里带 text_extra / textExtra，单独摘出来
            for (NSString *pair in [txt componentsSeparatedByString:@"&"]) {
                if ([pair rangeOfString:@"extra" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    DYAppend([NSString stringWithFormat:@"  >> extra pair: %@", pair]);
                }
            }
        } else {
            DYAppend([NSString stringWithFormat:@"Body hex: %@", DYHex(body, 1024)]);
        }
    } else {
        DYAppend(@"Body: (empty)");
    }
    DYSave();
    DYPop();
}

@interface NSURLSession (DYProbeSwizzle)
- (NSURLSessionDataTask *)dy_dataTaskWithRequest:(NSURLRequest *)request;
- (NSURLSessionDataTask *)dy_dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch;
- (NSURLSessionDataTask *)dy_dataTaskWithURL:(NSURL *)url;
- (NSURLSessionDataTask *)dy_dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch;
- (NSURLSessionUploadTask *)dy_uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData;
- (NSURLSessionUploadTask *)dy_uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch;
- (NSURLSessionUploadTask *)dy_uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch;
@end

@implementation NSURLSession (DYProbeSwizzle)
- (NSURLSessionDataTask *)dy_dataTaskWithRequest:(NSURLRequest *)request {
    @try { DYInspectRequest(request); } @catch (...) {}
    return [self dy_dataTaskWithRequest:request];
}
- (NSURLSessionDataTask *)dy_dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch {
    @try { DYInspectRequest(request); } @catch (...) {}
    return [self dy_dataTaskWithRequest:request completionHandler:ch];
}
- (NSURLSessionDataTask *)dy_dataTaskWithURL:(NSURL *)url {
    NSURLRequest *r = [NSURLRequest requestWithURL:url];
    @try { DYInspectRequest(r); } @catch (...) {}
    return [self dy_dataTaskWithURL:url];
}
- (NSURLSessionDataTask *)dy_dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch {
    NSURLRequest *r = [NSURLRequest requestWithURL:url];
    @try { DYInspectRequest(r); } @catch (...) {}
    return [self dy_dataTaskWithURL:url completionHandler:ch];
}
- (NSURLSessionUploadTask *)dy_uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData {
    @try { DYInspectRequest(request); } @catch (...) {}
    return [self dy_uploadTaskWithRequest:request fromData:bodyData];
}
- (NSURLSessionUploadTask *)dy_uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch {
    @try { DYInspectRequest(request); } @catch (...) {}
    return [self dy_uploadTaskWithRequest:request fromData:bodyData completionHandler:ch];
}
- (NSURLSessionUploadTask *)dy_uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch {
    @try { DYInspectRequest(request); } @catch (...) {}
    return [self dy_uploadTaskWithRequest:request fromFile:fileURL completionHandler:ch];
}
@end

#pragma mark - 模型层：抓 textExtra 对象

/* 每个类各自的原始 IMP，按 "Class|SEL" 存 */
static NSMutableDictionary *gOrigByKey = nil;

static void dy_setTextExtra(id self, SEL _cmd, id extra) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    IMP orig = [gOrigByKey[key] pointerValue];
    if (orig && orig != (IMP)dy_setTextExtra) {
        @try { ((void (*)(id, SEL, id))orig)(self, _cmd, extra); } @catch (...) {}
    }
    @try {
        gHit++;
        DYAppend([NSString stringWithFormat:@"========== %@ CALLED on %@ ==========", NSStringFromSelector(_cmd), NSStringFromClass([self class])]);
        DYDumpObj(extra, @"textExtra arg", 0);
        DYDumpObj(self, @"owner model", 0);
        DYSave();
        DYPop();
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"setTextExtra dump failed: %@", e.name]);
    }
}

/* 遍历所有已注册类，hook 所有 setTextExtra: 实现，避免 hook 落空 */
static void DYHookAllSetTextExtra(void) {
    SEL target = NSSelectorFromString(@"setTextExtra:");
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    NSInteger hooked = 0;
    for (unsigned int i = 0; i < cc; i++) {
        Class cls = classes[i];
        unsigned int mc = 0;
        Method *mlist = class_copyMethodList(cls, &mc);   // 只取本类实现，避免重复
        for (unsigned int j = 0; j < mc; j++) {
            SEL ms = method_getName(mlist[j]);
            if (ms == target) {
                const char *enc = method_getTypeEncoding(mlist[j]);
                NSString *key = [NSString stringWithFormat:@"%@|%@", NSStringFromClass(cls), NSStringFromSelector(ms)];
                if (!gOrigByKey[key]) {
                    IMP orig = method_setImplementation(mlist[j], (IMP)dy_setTextExtra);
                    gOrigByKey[key] = [NSValue valueWithPointer:orig];
                    hooked++;
                    DYAppend([NSString stringWithFormat:@"hooked setTextExtra: on class %@ enc=%s", NSStringFromClass(cls), enc ? enc : "?"]);
                }
            }
        }
        free(mlist);
    }
    free(classes);
    DYAppend([NSString stringWithFormat:@"setTextExtra: total hooked classes = %ld", (long)hooked]);
}

#pragma mark - 入口

static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe 探针已加载"
            message:@"注入成功。现在去发一条评论，探针会自动抓取 textExtra 结构并弹窗，内容同时已放入剪贴板。\n\n请把导出内容发回给我分析。"
            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"开始测试" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    });
}

__attribute__((constructor)) static void DYInit(void) {
    @autoreleasepool {
        gBuf = [NSMutableString string];
        DYAppend(@"DYProbe init");

        // 1) swizzle NSURLSession
        Method a1 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:));
        Method b1 = class_getInstanceMethod([NSURLSession class], @selector(dy_dataTaskWithRequest:));
        if (a1 && b1) { method_exchangeImplementations(a1, b1); DYAppend(@"hook NSURLSession dataTaskWithRequest: OK"); }
        else DYAppend(@"hook NSURLSession dataTaskWithRequest: MISS");

        Method a2 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
        Method b2 = class_getInstanceMethod([NSURLSession class], @selector(dy_dataTaskWithRequest:completionHandler:));
        if (a2 && b2) { method_exchangeImplementations(a2, b2); DYAppend(@"hook NSURLSession dataTaskWithRequest:completionHandler: OK"); }
        else DYAppend(@"hook NSURLSession dataTaskWithRequest:completionHandler: MISS");

        Method a3 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithURL:));
        Method b3 = class_getInstanceMethod([NSURLSession class], @selector(dy_dataTaskWithURL:));
        if (a3 && b3) { method_exchangeImplementations(a3, b3); DYAppend(@"hook dataTaskWithURL: OK"); }

        Method a4 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithURL:completionHandler:));
        Method b4 = class_getInstanceMethod([NSURLSession class], @selector(dy_dataTaskWithURL:completionHandler:));
        if (a4 && b4) { method_exchangeImplementations(a4, b4); DYAppend(@"hook dataTaskWithURL:completionHandler: OK"); }

        Method a5 = class_getInstanceMethod([NSURLSession class], @selector(uploadTaskWithRequest:fromData:));
        Method b5 = class_getInstanceMethod([NSURLSession class], @selector(dy_uploadTaskWithRequest:fromData:));
        if (a5 && b5) { method_exchangeImplementations(a5, b5); DYAppend(@"hook uploadTaskWithRequest:fromData: OK"); }

        Method a6 = class_getInstanceMethod([NSURLSession class], @selector(uploadTaskWithRequest:fromData:completionHandler:));
        Method b6 = class_getInstanceMethod([NSURLSession class], @selector(dy_uploadTaskWithRequest:fromData:completionHandler:));
        if (a6 && b6) { method_exchangeImplementations(a6, b6); DYAppend(@"hook uploadTaskWithRequest:fromData:completionHandler: OK"); }

        Method a7 = class_getInstanceMethod([NSURLSession class], @selector(uploadTaskWithRequest:fromFile:completionHandler:));
        Method b7 = class_getInstanceMethod([NSURLSession class], @selector(dy_uploadTaskWithRequest:fromFile:completionHandler:));
        if (a7 && b7) { method_exchangeImplementations(a7, b7); DYAppend(@"hook uploadTaskWithRequest:fromFile:completionHandler: OK"); }

        // 2) hook 全 App 所有 setTextExtra: 实现（含 KMP model），避免 hook 落空
        gOrigByKey = [NSMutableDictionary dictionary];
        DYHookAllSetTextExtra();

        DYSave();
    }

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) { DYBootAlert(); }];
}
