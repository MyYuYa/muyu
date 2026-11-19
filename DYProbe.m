#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>

/*
 * DYProbe v13 — 纯只读诊断探针（零注入 / 零 KVC / 零返回值修改）
 * ------------------------------------------------------------------
 * 目的：一次性抓清 iOS 抖音 41.0.0 评论发布链路的【真实 body 结构】与【有效 hook 点】。
 *
 * 根因（41.0.0 砸壳二进制静态分析实锤，不再是猜）：
 *   评论发布走 Swift/KMP 链路：
 *     AWECommentSwiftImpl.CommentPublishRequestProvider
 *     path = aweme/v1/comment/publish/?need_shark_async=1
 *     参数模型 = AWEKMPBaseCommentPublishParameters
 *     textExtra 序列化 = AWEKMPTextExtraStructKMPListSerializer
 *   v5~v12 全部 hook 的是旧 ObjC model（AWECommentPublishParameterModel 那套）
 *   ——与真正发请求的链路不是同一条，所以本地瞬间红、服务端黑。
 *
 * 为什么本版不会再闪退：
 *   v11/v12 崩溃根因是"改"对象——对 Swift/KMP model 做 KVC、mutableCopy 后替换返回值，
 *   触发信号级 EXC_BAD_ACCESS（@try 抓不住）。本版对任何对象只读不改：
 *   trampoline 仅记录参数的 description，然后原样转发给原始 IMP。
 *
 * 筛选策略：扫描全类方法，方法名命中评论/body/参数/发布关键词的才挂 hook，
 *   严格 ABI 校验（返回值 @ 或 v，业务参数必须全是对象），其余一律跳过。
 *
 * 用法：装上 -> 弹窗点"开始" -> 发一条普通评论 -> 去 Documents/dyprobe_dump.txt
 *       把日志给我。这次评论不会变红（只读版），目的是拿到 body 结构。
 */

#define DY_LIMIT 700

static NSMutableString *gBuf = nil;
static NSMutableDictionary *gOrigByHook = nil;   /* key "+-ClassName|sel" -> NSValue(IMP) */
static NSMutableDictionary *gOrigBySel = nil;    /* fallback by selector name */
static NSMutableSet *gHookedKeys = nil;
static NSMutableSet *gSeenHits = nil;
static NSInteger gDumpCount = 0;

/* ---------- 即时落盘（崩溃也不丢最后一行） ---------- */
static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    NSString *ln = [NSString stringWithFormat:@"%@\n", line];
    if (gBuf.length <= 400000) [gBuf appendString:ln];
    @try {
        NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (doc) {
            NSString *path = [doc stringByAppendingPathComponent:@"dyprobe_dump.txt"];
            NSFileManager *fm = [NSFileManager defaultManager];
            if (![fm fileExistsAtPath:path]) {
                [ln writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
            } else {
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
                if (fh) { [fh seekToEndOfFile]; [fh writeData:[ln dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
            }
        }
    } @catch (...) {}
    NSLog(@"[DYPROBE] %@", line);
}

static NSString *DYSafeFull(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *cn = NSStringFromClass([obj class]);
        if (![obj isKindOfClass:[NSString class]] &&
            ![obj isKindOfClass:[NSDictionary class]] &&
            ![obj isKindOfClass:[NSArray class]] &&
            ![obj isKindOfClass:[NSNumber class]]) {
            /* 自定义对象（Swift/KMP model）：只打类名，description 可能是垃圾或副作用 */
            return [NSString stringWithFormat:@"<obj class=%@>", cn ?: @"?"];
        }
        NSString *d = [obj description];
        if (!d) return [NSString stringWithFormat:@"<nil desc class=%@>", cn ?: @"?"];
        return d.length > 3000 ? [[d substringToIndex:3000] stringByAppendingString:@" ...(trunc)"] : d;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"<desc threw:%@>", e.name];
    }
}

static BOOL DYGate(NSString *key) {
    if (gDumpCount >= DY_LIMIT) return NO;
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

/* ---------- 找原始 IMP ---------- */
static IMP DYOrigFor(id self, SEL _cmd) {
    NSString *sel = NSStringFromSelector(_cmd);
    BOOL isMeta = class_isMetaClass(object_getClass(self));
    Class c = isMeta ? object_getClass(self) : [self class];
    while (c) {
        NSString *cn = NSStringFromClass(c);
        NSString *k1 = [NSString stringWithFormat:@"%@|%@", cn, sel];
        NSString *k2 = [NSString stringWithFormat:@"%@%@|%@", isMeta ? @"+" : @"-", cn, sel];
        IMP o = [gOrigByHook[k2] pointerValue];
        if (!o) o = [gOrigByHook[k1] pointerValue];
        if (o) return o;
        c = class_getSuperclass(c);
    }
    IMP o2 = [gOrigBySel[sel] pointerValue];
    return o2 ?: NULL;
}

/* ---------- ABI 校验：业务参数必须全是对象 ---------- */
static int DYObjectArgCount(const char *enc) {
    if (!enc) return -1;
    const char *colon = strchr(enc, ':');
    if (!colon) return -1;
    int cnt = 0;
    BOOL inQuote = NO;
    for (const char *p = colon + 1; *p; p++) {
        if (*p == '"') { inQuote = !inQuote; continue; }
        if (inQuote) continue;
        if (*p >= '0' && *p <= '9') continue;
        if (*p == ':') continue;
        if (*p == '@') { cnt++; continue; }
        return -1;   /* 标量/结构体 -> 放弃 hook */
    }
    return cnt;
}

/* ---------- 只读 trampoline：记录 + 原样转发，绝不改对象 ---------- */
#define DY_LOG_AND_CALL(idname, voidname, n) \
static id idname(id self, SEL _cmd, id a1,id a2,id a3,id a4,id a5,id a6) { \
    return DYROCore(self, _cmd, n, NO, a1,a2,a3,a4,a5,a6); \
} \
static void voidname(id self, SEL _cmd, id a1,id a2,id a3,id a4,id a5,id a6) { \
    DYROCore(self, _cmd, n, YES, a1,a2,a3,a4,a5,a6); \
}

/* 统一核心：n = 业务参数个数；wantVoid = 原方法是否返回 void。
 * 用同一个 C 函数按 n 分派调用原 IMP，避免多份宏拼接出错。 */
static id DYROCore(id self, SEL _cmd, int n, BOOL wantVoid,
                   id a1, id a2, id a3, id a4, id a5, id a6) {
    NSString *tag = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    id p[6] = { a1, a2, a3, a4, a5, a6 };

    /* 组参数摘要（只读 description） */
    NSMutableString *args = [NSMutableString string];
    for (int i = 0; i < n; i++) {
        [args appendFormat:@" arg%d=%@", i + 1, DYSafeFull(p[i])];
    }

    IMP orig = DYOrigFor(self, _cmd);
    id retObj = nil;
    if (orig) {
        @try {
            if (wantVoid) {
                if      (n==0) ((void(*)(id,SEL))orig)(self,_cmd);
                else if (n==1) ((void(*)(id,SEL,id))orig)(self,_cmd,p[0]);
                else if (n==2) ((void(*)(id,SEL,id,id))orig)(self,_cmd,p[0],p[1]);
                else if (n==3) ((void(*)(id,SEL,id,id,id))orig)(self,_cmd,p[0],p[1],p[2]);
                else if (n==4) ((void(*)(id,SEL,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3]);
                else if (n==5) ((void(*)(id,SEL,id,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3],p[4]);
                else if (n==6) ((void(*)(id,SEL,id,id,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3],p[4],p[5]);
            } else {
                if      (n==0) retObj = ((id(*)(id,SEL))orig)(self,_cmd);
                else if (n==1) retObj = ((id(*)(id,SEL,id))orig)(self,_cmd,p[0]);
                else if (n==2) retObj = ((id(*)(id,SEL,id,id))orig)(self,_cmd,p[0],p[1]);
                else if (n==3) retObj = ((id(*)(id,SEL,id,id,id))orig)(self,_cmd,p[0],p[1],p[2]);
                else if (n==4) retObj = ((id(*)(id,SEL,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3]);
                else if (n==5) retObj = ((id(*)(id,SEL,id,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3],p[4]);
                else if (n==6) retObj = ((id(*)(id,SEL,id,id,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3],p[4],p[5]);
            }
        } @catch (NSException *e) {
            DYAppend([NSString stringWithFormat:@"[RO] orig 抛异常 %@ on %@", e.name, tag]);
        }
    }

    NSString *dkey = [NSString stringWithFormat:@"ro%d|%@|%@", n, tag, [args substringToIndex:MIN((NSUInteger)80, args.length)]];
    if (DYGate(dkey)) {
        if (wantVoid) {
            DYAppend([NSString stringWithFormat:@"[RO-v] %@%@", tag, args]);
        } else {
            DYAppend([NSString stringWithFormat:@"[RO-o] %@%@ ret=%@", tag, args, DYSafeFull(retObj)]);
        }
    }
    return retObj;
}

/* 为 n=0..6 生成包装函数（名字由宏拼接，唯一；引用见 DYTrampFor 集中数组） */
DY_LOG_AND_CALL(dy_ro_id_0,  dy_ro_void_0,  0)
DY_LOG_AND_CALL(dy_ro_id_1,  dy_ro_void_1,  1)
DY_LOG_AND_CALL(dy_ro_id_2,  dy_ro_void_2,  2)
DY_LOG_AND_CALL(dy_ro_id_3,  dy_ro_void_3,  3)
DY_LOG_AND_CALL(dy_ro_id_4,  dy_ro_void_4,  4)
DY_LOG_AND_CALL(dy_ro_id_5,  dy_ro_void_5,  5)
DY_LOG_AND_CALL(dy_ro_id_6,  dy_ro_void_6,  6)

/* addCommentParams 专用：真实签名 @@:q@@@@（首业务参数 64 位标量 q） */
static id dy_ro_addCommentParams(id self, SEL _cmd, long long p1, id o2, id o3, id o4, id o5) {
    NSString *tag = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL,long long,id,id,id,id))orig)(self,_cmd,p1,o2,o3,o4,o5); } @catch (...) {} }
    if (DYGate([@"ro-add|" stringByAppendingString:tag])) {
        DYAppend([NSString stringWithFormat:@"[RO-ADDPARAMS] %@ p1=%lld o2=%@ o3=%@ o4=%@ o5=%@ ret=%@",
                  tag, p1, DYSafeFull(o2), DYSafeFull(o3), DYSafeFull(o4), DYSafeFull(o5), DYSafeFull(r)]);
    }
    return r;
}

/* 集中引用所有 trampoline，便于核对定义-引用一致 */
static IMP DYTrampFor(int n, BOOL retVoid) {
    if (n < 0 || n > 6) return NULL;
    if (retVoid) {
        IMP t[7] = { (IMP)dy_ro_void_0, (IMP)dy_ro_void_1, (IMP)dy_ro_void_2, (IMP)dy_ro_void_3,
                     (IMP)dy_ro_void_4, (IMP)dy_ro_void_5, (IMP)dy_ro_void_6 };
        return t[n];
    }
    IMP t[7] = { (IMP)dy_ro_id_0, (IMP)dy_ro_id_1, (IMP)dy_ro_id_2, (IMP)dy_ro_id_3,
                 (IMP)dy_ro_id_4, (IMP)dy_ro_id_5, (IMP)dy_ro_id_6 };
    return t[n];
}

/* ---------- 命中关键词筛选 ---------- */
static BOOL DYInterestingSEL(NSString *sn) {
    if (!sn) return NO;
    NSString *s = [sn lowercaseString];
    NSArray *kw = @[
        @"comment", @"publish", @"textextra", @"text_extra",
        @"requestparams", @"requestmodel", @"commonrequestforpost",
        @"buildrequestparams", @"datawithrequestmodel", @"bodyp",
        @"setbody", @"extraparams", @"penetrate", @"inputsnapshot"
    ];
    for (NSString *k in kw) if ([s rangeOfString:k].location != NSNotFound) return YES;
    return NO;
}

static IMP DYPickTrampoline(SEL sel, const char *enc) {
    if (!enc) return NULL;
    NSString *sn = NSStringFromSelector(sel);
    /* addCommentParams 专用签名优先 */
    if ([sn isEqualToString:@"addCommentParams:generalModel:commentModel:textExtras:params:"]) {
        /* 允许 @@:q@@@@ (DYSigOf 后) */
        NSMutableString *sig = [NSMutableString string];
        for (const char *q = enc; *q; q++) {
            if (*q >= '0' && *q <= '9') continue;
            [sig appendFormat:@"%c", *q];
        }
        if ([sig isEqualToString:@"@@:q@@@@"]) return (IMP)dy_ro_addCommentParams;
        DYAppend([NSString stringWithFormat:@"[PICK] addCommentParams 签名非预期 %@ 放弃", sig]);
        return NULL;
    }
    char ret = enc[0];
    BOOL retVoid = (ret == 'v');
    BOOL retObj  = (ret == '@');
    if (!retVoid && !retObj) return NULL;
    int objArgs = DYObjectArgCount(enc);
    if (objArgs < 0) return NULL;
    NSUInteger colonCount = [[sn componentsSeparatedByString:@":"] count] - 1;
    if (objArgs != (int)colonCount) return NULL;   /* 双保险 */
    if (colonCount == 0 && !retObj) return NULL;    /* 0 参数 void 无意义 */
    return DYTrampFor((int)colonCount, retVoid);
}

/* ---------- 扫描安装 ---------- */
static int DYScanList(Method *ml, unsigned int mc, NSString *clsName, BOOL isClassMethod) {
    int hit = 0;
    @try {
        for (unsigned int j = 0; j < mc; j++) {
            SEL sel = method_getName(ml[j]);
            NSString *sn = NSStringFromSelector(sel);
            if (!DYInterestingSEL(sn)) continue;
            NSString *key = [NSString stringWithFormat:@"%@%@|%@", isClassMethod ? @"+" : @"-", clsName, sn];
            if ([gHookedKeys containsObject:key]) continue;
            const char *enc = method_getTypeEncoding(ml[j]);
            IMP tramp = DYPickTrampoline(sel, enc);
            if (!tramp) continue;
            IMP orig = method_setImplementation(ml[j], tramp);
            if (orig) {
                gOrigByHook[key] = [NSValue valueWithPointer:orig];
                gOrigBySel[sn] = [NSValue valueWithPointer:orig];
                [gHookedKeys addObject:key];
                hit++;
            }
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[SCAN] 异常 %@", e.name]);
    }
    return hit;
}

static void DYHookAll(void) {
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    int total = 0;
    @try {
        for (unsigned int i = 0; i < cc; i++) {
            Class cls = classes[i];
            NSString *cn = NSStringFromClass(cls);
            unsigned int mc = 0;
            Method *ml = class_copyMethodList(cls, &mc);
            if (ml) { total += DYScanList(ml, mc, cn, NO); free(ml); }
            Class meta = object_getClass(cls);
            if (meta) {
                unsigned int cmc = 0;
                Method *cml = class_copyMethodList(meta, &cmc);
                if (cml) { total += DYScanList(cml, cmc, cn, YES); free(cml); }
            }
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK] 全类扫描异常 %@", e.name]);
    }
    free(classes);
    DYAppend([NSString stringWithFormat:@"[HOOK] 只读探针共挂 %d 个方法", total]);
}

static void DYCopyLog(void) {
    @try {
        NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [doc stringByAppendingPathComponent:@"dyprobe_dump.txt"];
        NSString *txt = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
        UIPasteboard *pb = [UIPasteboard generalPasteboard];
        if (pb) pb.string = (txt ?: gBuf ?: @"");
    } @catch (...) {}
}

static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v13 只读诊断"
                message:@"本版只读、不改任何对象，不会再闪退。\n发一条普通评论，然后把 Documents/dyprobe_dump.txt 给我。\n目的：抓清真实 body 结构与 hook 点（这次评论不会变红）。"
                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"复制日志" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){ DYCopyLog(); }]];
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
        DYAppend(@"DYProbe v13 init (纯只读诊断探针 type=21 参考; 零注入/零KVC/零返回值修改)");
    }
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            @autoreleasepool {
                DYBootAlert();
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    @autoreleasepool { DYHookAll(); }
                });
            }
        }];
}
