#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>

/*
 * DYProbe v11 - 【打法根本转变：从 model 层转到 body 组装层】
 *
 * ===== 为什么 v5~v10 全失败（已证伪，不再重复）=====
 *   v5  改展示回显对象        -> 服务端不读
 *   v6  盲 hook setBodyParams -> 只抓到 Feed 类
 *   v8  改 extraParams 字典   -> 那是统计/上下文字典(author_secuid/common_flags/hashtag)，服务端不读它的 text_extra
 *   v9  改 extraInfo 的 AWETextExtra.type -> 只喂本地渲染(KMP 序列化时重建)，"瞬间红、发出去黑"
 *   v10 值用 65282            -> 2023 老脚本废弃值，服务端已拒绝；21 才是白名单放行值
 *
 * ===== v11 依据（41.0.0 砸壳包静态分析 + v10 日志）=====
 *   1) type=21 是服务端白名单放行的红字值（2026-11-18 批量实测），网页脚本实测可用
 *   2) 网页脚本：text_extra=[{start:0,end:UTF8字节数,type:21}]，body 里是 JSON 字符串
 *      map.text_extra = encodeURIComponent(JSON.stringify(text_extra))
 *   3) 真正的评论发布链（ObjC 可达，静态符号实锤）：
 *      publishCommentParamsForServer       无参->NSDictionary  ← 组装发给服务端的参数
 *      getPenetrateParamsForServer         无参->NSDictionary  ← 穿透参数
 *      addCommentParams:generalModel:commentModel:textExtras:params:  ← textExtras 数组 + params 字典
 *      publishCommentWithRequest:inputSnapshot:  ← 真正发请求
 *      commentPublishRequestWithSnapshot:refer:
 *      submitTextExtras / checkSubmitTextExtras / trackSubmitTextExtras
 *
 * ===== v11 打法 =====
 *   运行时全类扫描，找到实现上述 selector 的类，按 type encoding 严格匹配签名后 hook。
 *   在每一层的"参数字典 / 返回字典 / textExtras 数组"里注入 type=21：
 *     - 数组形式的 text_extra 元素 -> 改 type=21
 *     - 同时写 text_extra=JSON字符串 与 textExtra=数组（覆盖服务端两种可能读法）
 *     - end 用 UTF-8 字节数（与网页脚本一致）
 *   全程 dump 方法签名/参数/返回值到 dyprobe_dump.txt，即使没成功也能一次看清 body 在哪层、什么格式。
 *   保留 extraParams/extraInfo 兜底（本地渲染），值全部改成 21。
 *
 * ===== 防闪退 =====
 *   签名严格匹配才 hook（参数必须全是对象、个数匹配）；全程 @try/catch；
 *   只在确认是字典/数组时才改；日志上限；内容去重；不遍历 ivar。
 * 用法：装上->发一条普通评论（不必@）->去网页端/别人手机看是否红->看 Documents/dyprobe_dump.txt。
 */

#define DY_DUMP_LIMIT 500

static NSMutableString *gBuf = nil;
static NSMutableDictionary *gOrigByHook = nil;
static NSMutableDictionary *gOrigBySel = nil;
static NSMutableSet *gHookedKeys = nil;
static NSMutableSet *gSeenHits = nil;
static NSTimer *gPollTimer = nil;
static NSInteger gDumpCount = 0;
static NSInteger gBodyHitCount = 0;      /* body 层注入命中计数 */
static NSInteger gSetTypeCalls = 0;
static NSInteger gStackCount = 0;
static NSInteger gLastContentLen = 0;    /* UTF-16 length */
static NSInteger gLastContentUTF8Len = 0;/* UTF-8 字节数 */
static IMP gOrigSetType = NULL;
static BOOL gHookWarned = NO;
static BOOL gHookUnsupported = NO;

static void DYAppend(NSString *line) {
    if (!gBuf) gBuf = [NSMutableString string];
    if (gBuf.length > 300000) return;
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

static NSString *DYSafeFull(id obj) {
    if (!obj) return @"(nil)";
    @try {
        NSString *d = [obj description];
        if (!d) return @"(nil desc)";
        return d.length > 5000 ? [[d substringToIndex:5000] stringByAppendingString:@" ...(trunc5000)"] : d;
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
    /* 类方法：self 本身是 meta-class；实例方法：走继承链 */
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
    if (o2) return o2;
    return NULL;
}

/* ---------- 规范化 type encoding：去掉数字 ---------- */
static NSString *DYSigOf(const char *enc) {
    if (!enc) return @"";
    NSMutableString *t = [NSMutableString string];
    for (const char *p = enc; *p; p++) {
        if (*p >= '0' && *p <= '9') continue;
        /* 去掉引号内类名的引号内容噪声，只保留类型字符 */
        if (*p == '"') continue;
        [t appendFormat:@"%c", *p];
    }
    return t;
}

/* 统计 encoding 里业务对象参数个数（冒号后、跳过数字/引号，只数 '@'）。
 * 返回 -1 表示存在非对象参数（不安全）。 */
static int DYObjectArgCount(const char *enc) {
    if (!enc) return -1;
    const char *colon = strchr(enc, ':');
    if (!colon) return -1;
    int cnt = 0;
    BOOL inQuote = NO;
    for (const char *p = colon + 1; *p; p++) {
        if (*p == '"') { inQuote = !inQuote; continue; }
        if (inQuote) continue;
        if (*p >= '0' && *p <= '9') continue;   /* offset 数字 */
        if (*p == ':') continue;                /* 分隔符 */
        if (*p == '@') { cnt++; continue; }     /* 一个业务对象参数 */
        return -1;                              /* 非对象(i/l/q/f/d/B...) -> 不安全 */
    }
    return cnt;
}

/* ---------- 核心注入：给任意字典塞 text_extra type=21（数组 + JSON 字符串双写） ---------- */
static NSArray *DYTextExtrasArray(void) {
    NSUInteger endLen = (gLastContentUTF8Len > 0) ? (NSUInteger)gLastContentUTF8Len :
                        ((gLastContentLen > 0) ? (NSUInteger)gLastContentLen : 14);
    return @[ @{ @"start": @0, @"end": @(endLen), @"type": @21 } ];
}

static NSString *DYTextExtrasJSON(void) {
    @try {
        NSData *d = [NSJSONSerialization dataWithJSONObject:DYTextExtrasArray() options:0 error:nil];
        if (!d) return nil;
        return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    } @catch (...) { return nil; }
}

/* 返回注入后的对象（可能是 mutableCopy 的新对象） */
static id DYInjectBody(id obj, NSString *tag) {
    @try {
        if (!obj) return obj;
        BOOL isDict = [obj isKindOfClass:[NSDictionary class]];
        if (isDict) {
            NSMutableDictionary *md = [obj isKindOfClass:[NSMutableDictionary class]] ? obj : [obj mutableCopy];
            if (!md) return obj;
            BOOL changed = NO;
            for (id k in [md allKeys]) {
                if (![k isKindOfClass:[NSString class]]) continue;
                NSString *kl = [(NSString *)k lowercaseString];
                if ([kl rangeOfString:@"textextra"].location == NSNotFound &&
                    [kl rangeOfString:@"text_extra"].location == NSNotFound) continue;
                id val = [md objectForKey:k];
                DYAppend([NSString stringWithFormat:@"[BODY] %@ 现有键 %@ = %@", tag, k, DYSafeFull(val)]);
                if ([val isKindOfClass:[NSArray class]]) {
                    NSMutableArray *ma = [val mutableCopy];
                    BOOL c2 = NO;
                    for (NSUInteger i = 0; i < [ma count]; i++) {
                        id e = [ma objectAtIndex:i];
                        if ([e isKindOfClass:[NSDictionary class]] || [e isKindOfClass:[NSMutableDictionary class]]) {
                            NSMutableDictionary *me = [e isKindOfClass:[NSMutableDictionary class]] ? e : [e mutableCopy];
                            [me setObject:@21 forKey:@"type"];
                            [ma replaceObjectAtIndex:i withObject:me];
                            c2 = YES;
                        }
                    }
                    if (c2) { [md setObject:ma forKey:k]; changed = YES; }
                } else if ([val isKindOfClass:[NSString class]]) {
                    /* 已是 JSON 字符串：重新生成 type=21 的 JSON */
                    NSString *js = DYTextExtrasJSON();
                    if (js) { [md setObject:js forKey:k]; changed = YES; }
                }
            }
            /* 无论是否已有，都双写覆盖两种读法 */
            NSArray *arr = DYTextExtrasArray();
            NSString *js = DYTextExtrasJSON();
            [md setObject:arr forKey:@"text_extra"];
            if (js) [md setObject:js forKey:@"text_extra_json"];
            [md setObject:arr forKey:@"textExtra"];
            changed = YES;
            if (changed) {
                gBodyHitCount++;
                DYAppend([NSString stringWithFormat:@"[INJECT-BODY #%ld] %@ 已注入 text_extra type=21 (数组+JSON双写, end=%ld)",
                          (long)gBodyHitCount, tag, (long)gLastContentUTF8Len]);
                DYFlushLog();
            }
            return md;
        }
        if ([obj isKindOfClass:[NSArray class]]) {
            /* textExtras 数组参数：把每个元素的 type 改 21 */
            NSMutableArray *ma = [obj isKindOfClass:[NSMutableArray class]] ? obj : [obj mutableCopy];
            BOOL c2 = NO;
            for (NSUInteger i = 0; i < [ma count]; i++) {
                id e = [ma objectAtIndex:i];
                if ([e isKindOfClass:[NSDictionary class]] || [e isKindOfClass:[NSMutableDictionary class]]) {
                    NSMutableDictionary *me = [e isKindOfClass:[NSMutableDictionary class]] ? e : [e mutableCopy];
                    [me setObject:@21 forKey:@"type"];
                    [ma replaceObjectAtIndex:i withObject:me];
                    c2 = YES;
                } else if ([e isKindOfClass:[NSObject class]]) {
                    @try {
                        NSString *cn = NSStringFromClass([e class]);
                        if ([cn rangeOfString:@"TextExtra"].location != NSNotFound) {
                            [e setValue:@21 forKey:@"type"];
                            c2 = YES;
                        }
                    } @catch (...) {}
                }
            }
            if (c2) {
                gBodyHitCount++;
                DYAppend([NSString stringWithFormat:@"[INJECT-BODY #%ld] %@ textExtras 数组元素 type->21 (count=%lu)",
                          (long)gBodyHitCount, tag, (unsigned long)[ma count]]);
                DYFlushLog();
                return ma;
            }
        }
        /* 自定义 model 对象兜底：保守地尝试 KVC 注入其字典/数组属性 */
        NSString *cn = NSStringFromClass([obj class]);
        if (![cn hasPrefix:@"NS"] && ![cn isEqualToString:@"__NSCFString"]) {
            NSArray *cand = @[@"params", @"textExtra", @"text_extra", @"commentParams",
                              @"extraParams", @"requestParams", @"publishParams", @"textExtras"];
            BOOL modelChanged = NO;
            for (NSString *k in cand) {
                id val = nil;
                @try { val = [obj valueForKey:k]; } @catch (...) { continue; }
                if (!val) continue;
                id injected = DYInjectBody(val, [[tag stringByAppendingString:@".model"] stringByAppendingFormat:@".%@", k]);
                if (injected != val) {
                    @try { [obj setValue:injected forKey:k]; modelChanged = YES; } @catch (...) {}
                }
            }
            if (modelChanged) {
                gBodyHitCount++;
                DYAppend([NSString stringWithFormat:@"[INJECT-BODY #%ld] %@ 自定义对象 %@ 的字典属性已注入 type=21",
                          (long)gBodyHitCount, tag, cn]);
                DYFlushLog();
            }
        }
        return obj;
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[INJECT-BODY] %@ 异常 %@ 放弃", tag, e.name]);
        return obj;
    }
}

/* ---------- body 层通用 trampoline（参数必须全是对象，签名已严格校验） ---------- */
/* 0 业务参数，返回对象：@@:  e.g. publishCommentParamsForServer / getPenetrateParamsForServer */
static id dy_body_0_o(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    NSString *tag = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    id out = DYInjectBody(r, tag);
    if (DYGate([NSString stringWithFormat:@"b0|%@", tag])) {
        DYAppend([NSString stringWithFormat:@"[BODY-HIT-0O] %@ ret(before)=%@ ret(after)=%@", tag, DYSafeFull(r), DYSafeFull(out)]);
        DYFlushLog();
    }
    return out;
}

/* 2 业务参数，返回对象：@@:@@ */
static id dy_body_2_o(id self, SEL _cmd, id a, id b) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL,id,id))orig)(self, _cmd, a, b); } @catch (...) {} }
    NSString *tag = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    id a2 = DYInjectBody(a, [tag stringByAppendingString:@".arg1"]);
    id b2 = DYInjectBody(b, [tag stringByAppendingString:@".arg2"]);
    id out = DYInjectBody(r, [tag stringByAppendingString:@".ret"]);
    /* 若注入改动了参数，需要重新调用一次 orig 用新参数——但可能重复副作用。
       仅当原返回被改成功时直接用 out；参数改动只记录，避免重复发请求。 */
    if (DYGate([NSString stringWithFormat:@"b2o|%@|%@|%@", tag, DYSafe(a), DYSafe(b)])) {
        DYAppend([NSString stringWithFormat:@"[BODY-HIT-2O] %@ arg1=%@ arg2=%@ ret(before)=%@ ret(after)=%@",
                  tag, DYSafeFull(a), DYSafeFull(b), DYSafeFull(r), DYSafeFull(out)]);
        DYFlushLog();
    }
    (void)a2; (void)b2;
    return out;
}

/* 2 业务参数，返回 void：v@:@@  e.g. publishCommentWithRequest:inputSnapshot: */
static void dy_body_2_v(id self, SEL _cmd, id a, id b) {
    NSString *tag = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    id a2 = DYInjectBody(a, [tag stringByAppendingString:@".arg1"]);
    id b2 = DYInjectBody(b, [tag stringByAppendingString:@".arg2"]);
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id,id))orig)(self, _cmd, a2, b2); } @catch (...) {} }
    if (DYGate([NSString stringWithFormat:@"b2v|%@|%@|%@", tag, DYSafe(a), DYSafe(b)])) {
        DYAppend([NSString stringWithFormat:@"[BODY-HIT-2V] %@ arg1=%@ arg2=%@ (已尝试注入参数)",
                  tag, DYSafeFull(a), DYSafeFull(b)]);
        DYFlushLog();
    }
}

/* 5 业务参数，返回 void：v@:@@@@@  e.g. addCommentParams:generalModel:commentModel:textExtras:params: */
static void dy_body_5_v(id self, SEL _cmd, id a, id b, id c, id d, id e) {
    NSString *tag = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    /* d=textExtras 数组, e=params 字典（按方法名顺序：addCommentParams/generalModel/commentModel/textExtras/params） */
    id d2 = DYInjectBody(d, [tag stringByAppendingString:@".textExtras"]);
    id e2 = DYInjectBody(e, [tag stringByAppendingString:@".params"]);
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id,id,id,id,id))orig)(self, _cmd, a, b, c, d2, e2); } @catch (...) {} }
    if (DYGate([NSString stringWithFormat:@"b5v|%@|%@|%@", tag, DYSafe(d), DYSafe(e)])) {
        DYAppend([NSString stringWithFormat:@"[BODY-HIT-5V] %@ addCommentParams=%@ textExtras(before)=%@ params(before)=%@",
                  tag, DYSafeFull(a), DYSafeFull(d), DYSafeFull(e)]);
        DYFlushLog();
    }
}

/* 5 业务参数，返回对象：@@:@@@@@ */
static id dy_body_5_o(id self, SEL _cmd, id a, id b, id c, id d, id e) {
    NSString *tag = [NSString stringWithFormat:@"%@|%@", NSStringFromClass([self class]), NSStringFromSelector(_cmd)];
    id d2 = DYInjectBody(d, [tag stringByAppendingString:@".textExtras"]);
    id e2 = DYInjectBody(e, [tag stringByAppendingString:@".params"]);
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL,id,id,id,id,id))orig)(self, _cmd, a, b, c, d2, e2); } @catch (...) {} }
    id out = DYInjectBody(r, [tag stringByAppendingString:@".ret"]);
    if (DYGate([NSString stringWithFormat:@"b5o|%@|%@|%@", tag, DYSafe(d), DYSafe(e)])) {
        DYAppend([NSString stringWithFormat:@"[BODY-HIT-5O] %@ textExtras=%@ params=%@ ret(before)=%@ ret(after)=%@",
                  tag, DYSafeFull(d), DYSafeFull(e), DYSafeFull(r), DYSafeFull(out)]);
        DYFlushLog();
    }
    return out;
}

/* ---------- 通用 n 对象参数 trampoline（n=1/3/4/6，宏生成，避免遗漏未知签名） ---------- */
#define DY_DEF_BODY_GN(n, ret) \
static ret dy_body_g##n##_o(id self, SEL _cmd, \
    id a1,id a2,id a3,id a4,id a5,id a6) { \
    NSString *tag=[NSString stringWithFormat:@"%@|%@",NSStringFromClass([self class]),NSStringFromSelector(_cmd)]; \
    id p[6]={a1,a2,a3,a4,a5,a6}; \
    for(int i=0;i<n;i++){ id inj=DYInjectBody(p[i],[[tag stringByAppendingFormat:@".arg%d",i+1] copy]); if(inj)p[i]=inj; } \
    IMP orig=DYOrigFor(self,_cmd); \
    ret r##n; memset(&r##n,0,sizeof(r##n)); \
    if(orig){ @try{ \
        if(n==1) r##n=(ret)((ret(*)(id,SEL,id))orig)(self,_cmd,p[0]); \
        else if(n==3) r##n=(ret)((ret(*)(id,SEL,id,id,id))orig)(self,_cmd,p[0],p[1],p[2]); \
        else if(n==4) r##n=(ret)((ret(*)(id,SEL,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3]); \
        else if(n==6) r##n=(ret)((ret(*)(id,SEL,id,id,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3],p[4],p[5]); \
    }@catch(...){} } \
    if(DYGate([NSString stringWithFormat:@"gn%d|O|%@",n,tag])){ \
        DYAppend([NSString stringWithFormat:@"[BODY-HIT-G%dO] %@ (已尝试注入%d个对象参数)",n,tag,n]); \
        DYFlushLog(); \
    } \
    return r##n; \
}
/* void 版本不能 return 值；单独用 void 展开 */
DY_DEF_BODY_GN(1, id)
DY_DEF_BODY_GN(3, id)
DY_DEF_BODY_GN(4, id)
DY_DEF_BODY_GN(6, id)

/* 上面宏对 ret=id 生成 `id r;` 合法；void 版本单独写 */
static void dy_body_g1_v(id self, SEL _cmd, id a1,id a2,id a3,id a4,id a5,id a6){
    NSString *tag=[NSString stringWithFormat:@"%@|%@",NSStringFromClass([self class]),NSStringFromSelector(_cmd)];
    id inj=DYInjectBody(a1,[tag stringByAppendingString:@".arg1"]); if(!inj)inj=a1;
    IMP orig=DYOrigFor(self,_cmd); if(orig){@try{((void(*)(id,SEL,id))orig)(self,_cmd,inj);}@catch(...){}}
    if(DYGate([NSString stringWithFormat:@"gn1v|%@",tag])){DYAppend([NSString stringWithFormat:@"[BODY-HIT-G1V] %@",tag]);DYFlushLog();}
}
static void dy_body_g3_v(id self, SEL _cmd, id a1,id a2,id a3,id a4,id a5,id a6){
    NSString *tag=[NSString stringWithFormat:@"%@|%@",NSStringFromClass([self class]),NSStringFromSelector(_cmd)];
    id p[3]={a1,a2,a3}; for(int i=0;i<3;i++){id x=DYInjectBody(p[i],[[tag stringByAppendingFormat:@".arg%d",i+1] copy]);if(x)p[i]=x;}
    IMP orig=DYOrigFor(self,_cmd); if(orig){@try{((void(*)(id,SEL,id,id,id))orig)(self,_cmd,p[0],p[1],p[2]);}@catch(...){}}
    if(DYGate([NSString stringWithFormat:@"gn3v|%@",tag])){DYAppend([NSString stringWithFormat:@"[BODY-HIT-G3V] %@",tag]);DYFlushLog();}
}
static void dy_body_g4_v(id self, SEL _cmd, id a1,id a2,id a3,id a4,id a5,id a6){
    NSString *tag=[NSString stringWithFormat:@"%@|%@",NSStringFromClass([self class]),NSStringFromSelector(_cmd)];
    id p[4]={a1,a2,a3,a4}; for(int i=0;i<4;i++){id x=DYInjectBody(p[i],[[tag stringByAppendingFormat:@".arg%d",i+1] copy]);if(x)p[i]=x;}
    IMP orig=DYOrigFor(self,_cmd); if(orig){@try{((void(*)(id,SEL,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3]);}@catch(...){}}
    if(DYGate([NSString stringWithFormat:@"gn4v|%@",tag])){DYAppend([NSString stringWithFormat:@"[BODY-HIT-G4V] %@",tag]);DYFlushLog();}
}
static void dy_body_g6_v(id self, SEL _cmd, id a1,id a2,id a3,id a4,id a5,id a6){
    NSString *tag=[NSString stringWithFormat:@"%@|%@",NSStringFromClass([self class]),NSStringFromSelector(_cmd)];
    id p[6]={a1,a2,a3,a4,a5,a6}; for(int i=0;i<6;i++){id x=DYInjectBody(p[i],[[tag stringByAppendingFormat:@".arg%d",i+1] copy]);if(x)p[i]=x;}
    IMP orig=DYOrigFor(self,_cmd); if(orig){@try{((void(*)(id,SEL,id,id,id,id,id,id))orig)(self,_cmd,p[0],p[1],p[2],p[3],p[4],p[5]);}@catch(...){}}
    if(DYGate([NSString stringWithFormat:@"gn6v|%@",tag])){DYAppend([NSString stringWithFormat:@"[BODY-HIT-G6V] %@",tag]);DYFlushLog();}
}

/* ---------- setType: 只读对照 ---------- */
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
        if (gSetTypeCalls <= 8 || gSetTypeCalls % 20 == 0) {
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
        if (gSetTypeCalls <= 8 || gSetTypeCalls % 20 == 0) {
            DYAppend([NSString stringWithFormat:@"[SET-TYPE #%ld] 原值=%@ on %@ (只读)",
                      (long)gSetTypeCalls, DYSafe(v), NSStringFromClass([self class])]);
            DYFlushLog();
        }
    } @catch (...) {}
    if (gOrigSetType && gOrigSetType != (IMP)dy_setType_obj) {
        @try { ((void(*)(id,SEL,id))gOrigSetType)(self, _cmd, v); } @catch (...) {}
    }
}

/* ---------- 通用只读 dump trampoline（model 层兜底对照） ---------- */
static void dy_dump_void0(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    NSString *cn = NSStringFromClass([self class]);
    NSString *sn = NSStringFromSelector(_cmd);
    if (DYGate([NSString stringWithFormat:@"v0|%@|%@", cn, sn])) {
        DYAppend([NSString stringWithFormat:@"[HIT] void %@ on %@", sn, cn]);
        DYFlushLog();
    }
}

static void dy_dump_void1(id self, SEL _cmd, id arg) {
    if ([NSStringFromSelector(_cmd) isEqualToString:@"setContent:"] && [arg isKindOfClass:[NSString class]]) {
        gLastContentLen = [(NSString *)arg length];
        gLastContentUTF8Len = (NSInteger)strlen([(NSString *)arg UTF8String]);
    }
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
    NSString *cn = NSStringFromClass([self class]);
    NSString *sn = NSStringFromSelector(_cmd);
    if (DYGate([NSString stringWithFormat:@"v1|%@|%@|%@", cn, sn, DYSafe(arg)])) {
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
    if (DYGate([NSString stringWithFormat:@"o0|%@|%@|%@", cn, sn, DYSafe(r)])) {
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
    if (DYGate([NSString stringWithFormat:@"o1|%@|%@|%@|%@", cn, sn, DYSafe(arg), DYSafe(r)])) {
        DYAppend([NSString stringWithFormat:@"[HIT] %@ on %@ arg=%@ ret=%@", sn, cn, DYSafe(arg), DYSafe(r)]);
        DYFlushLog();
    }
    return r;
}

/* ---------- model 层兜底注入（保留，值=21） ---------- */
static id DYInjectBodyAsExtraParams(id params, NSString *tag) {
    @try {
        if (!params) return params;
        if (!([params isKindOfClass:[NSDictionary class]])) return params;
        NSMutableDictionary *md = [params isKindOfClass:[NSMutableDictionary class]] ? params : [params mutableCopy];
        NSArray *arr = DYTextExtrasArray();
        NSString *js = DYTextExtrasJSON();
        [md setObject:arr forKey:@"text_extra"];
        [md setObject:arr forKey:@"textExtra"];
        if (js) [md setObject:js forKey:@"text_extra_json"];
        for (id k in [md allKeys]) {
            if (![k isKindOfClass:[NSString class]]) continue;
            id val = [md objectForKey:k];
            if ([val isKindOfClass:[NSArray class]]) {
                NSMutableArray *ma = [val mutableCopy];
                for (NSUInteger i = 0; i < [ma count]; i++) {
                    id ee = [ma objectAtIndex:i];
                    if ([ee isKindOfClass:[NSDictionary class]] || [ee isKindOfClass:[NSMutableDictionary class]]) {
                        NSMutableDictionary *me = [ee isKindOfClass:[NSMutableDictionary class]] ? ee : [ee mutableCopy];
                        if ([[me allKeys] containsObject:@"type"]) { [me setObject:@21 forKey:@"type"]; [ma replaceObjectAtIndex:i withObject:me]; }
                    }
                }
                [md setObject:ma forKey:k];
            }
        }
        return md;
    } @catch (...) { return params; }
}

static id dy_extraParams_get(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    return DYInjectBodyAsExtraParams(r, @"extraParams(get)");
}

static void dy_setExtraParams(id self, SEL _cmd, id arg) {
    id mutated = DYInjectBodyAsExtraParams(arg, @"setExtraParams:");
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, mutated); } @catch (...) {} }
}

static void DYMutateExtraInfo(id arr) {
    @try {
        if (!arr || ![arr isKindOfClass:[NSArray class]]) return;
        for (id e in (NSArray *)arr) {
            @try {
                if ([NSStringFromClass([e class]) isEqualToString:@"AWETextExtra"]) {
                    IMP realSetType = gOrigSetType;
                    if (realSetType && realSetType != (IMP)dy_setType_int && realSetType != (IMP)dy_setType_obj) {
                        @try { ((void(*)(id,SEL,long long))realSetType)(e, @selector(setType:), 21LL); } @catch (...) {}
                    } else {
                        @try { [e setValue:@21 forKey:@"type"]; } @catch (...) {}
                    }
                }
            } @catch (...) {}
        }
    } @catch (...) {}
}

static void dy_setExtraInfo(id self, SEL _cmd, id arg) {
    DYMutateExtraInfo(arg);
    IMP orig = DYOrigFor(self, _cmd);
    if (orig) { @try { ((void(*)(id,SEL,id))orig)(self, _cmd, arg); } @catch (...) {} }
}

static id dy_extraInfo_get(id self, SEL _cmd) {
    IMP orig = DYOrigFor(self, _cmd);
    id r = nil;
    if (orig) { @try { r = ((id(*)(id,SEL))orig)(self, _cmd); } @catch (...) {} }
    DYMutateExtraInfo(r);
    return r;
}

/* ---------- hook 安装 ---------- */
static void DYInstallSetTypeHook(void) {
    if (gOrigSetType || gHookUnsupported) return;
    @try {
        Class ec = objc_getClass("AWETextExtra");
        if (!ec) return;
        Method m = class_getInstanceMethod(ec, @selector(setType:));
        if (!m) return;
        const char *enc = method_getTypeEncoding(m);
        int kind = DYSetTypeArgKind(enc);
        if (kind == 1) gOrigSetType = method_setImplementation(m, (IMP)dy_setType_int);
        else if (kind == 2) gOrigSetType = method_setImplementation(m, (IMP)dy_setType_obj);
        else gHookUnsupported = YES;
    } @catch (...) {}
}

/* 目标 body 层 selector -> 期望参数个数 */
typedef struct { const char *sel; int nargs; } DYBizSel;
static const DYBizSel kBizSels[] = {
    { "publishCommentParamsForServer", 0 },
    { "getPenetrateParamsForServer", 0 },
    { "commentParamsWithModel:refer:", 2 },
    { "publishCommentWithRequest:inputSnapshot:", 2 },
    { "commentPublishRequestWithSnapshot:refer:", 2 },
    { "addCommentParams:generalModel:commentModel:textExtras:params:", 5 },
    { "submitTextExtras", 0 },
    { "checkSubmitTextExtras", 0 },
    { "trackSubmitTextExtras", 0 },
};

/* 根据 selector 名 + 签名选择 trampoline；NULL 表示不匹配（放弃，防崩）
 * ABI 安全：业务参数必须全是对象、返回值必须是 @(对象) 或 v(void)，否则不 hook。 */
static IMP DYPickTrampoline(SEL sel, const char *enc) {
    if (!enc) return NULL;
    char ret = enc[0];
    BOOL retVoid = (ret == 'v');
    BOOL retObj  = (ret == '@');
    if (!retVoid && !retObj) return NULL;   /* 返回BOOL/标量/结构体 -> 跳过，避免 ABI 错位闪退 */
    int objArgs = DYObjectArgCount(enc);
    if (objArgs < 0) return NULL;           /* 存在非对象参数 -> 跳过 */
    NSString *sn = NSStringFromSelector(sel);
    NSUInteger colonCount = [[sn componentsSeparatedByString:@":"] count] - 1;
    /* 对象参数个数必须与冒数一致，否则签名不符 -> 跳过（双保险） */
    if (objArgs != (int)colonCount) return NULL;
    if (colonCount == 0) {
        return retObj ? (IMP)dy_body_0_o : NULL;   /* 0 参数必须返回对象才 hook */
    }
    if (colonCount == 2) {
        return retVoid ? (IMP)dy_body_2_v : (IMP)dy_body_2_o;
    }
    if (colonCount == 5) {
        return retVoid ? (IMP)dy_body_5_v : (IMP)dy_body_5_o;
    }
    /* 其它参数个数：1/3/4/6 对象参数，用通用 trampoline 兜住 */
    if (colonCount == 1) return retVoid ? (IMP)dy_body_g1_v : (IMP)dy_body_g1_o;
    if (colonCount == 3) return retVoid ? (IMP)dy_body_g3_v : (IMP)dy_body_g3_o;
    if (colonCount == 4) return retVoid ? (IMP)dy_body_g4_v : (IMP)dy_body_g4_o;
    if (colonCount == 6) return retVoid ? (IMP)dy_body_g6_v : (IMP)dy_body_g6_o;
    return NULL;
}

/* 扫描一个 method list，命中目标 selector 则 hook。isClassMethod 仅用于日志区分。 */
static int DYScanMethodList(Method *ml, unsigned int mc, Class cls, NSString *clsName, BOOL isClassMethod) {
    int hit = 0;
    @try {
        for (unsigned int j = 0; j < mc; j++) {
            SEL sel = method_getName(ml[j]);
            NSString *sn = NSStringFromSelector(sel);
            BOOL target = NO;
            for (unsigned int k = 0; k < sizeof(kBizSels)/sizeof(kBizSels[0]); k++) {
                if ([sn isEqualToString:[NSString stringWithUTF8String:kBizSels[k].sel]]) { target = YES; break; }
            }
            if (!target) continue;
            NSString *key = [NSString stringWithFormat:@"%@%@|%@", isClassMethod ? @"+" : @"-", clsName, sn];
            if ([gHookedKeys containsObject:key]) continue;
            const char *enc = method_getTypeEncoding(ml[j]);
            IMP tramp = DYPickTrampoline(sel, enc);
            if (!tramp) {
                /* 不静默跳过：把真实签名打出来，便于一次反馈精确修正 */
                DYAppend([NSString stringWithFormat:@"[HOOK-BODY] ⚠签名不匹配 %@ enc=%s (ret=%c)", key, enc ? enc : "?", enc ? enc[0] : '?']);
                DYFlushLog();
                continue;
            }
            IMP orig = method_setImplementation(ml[j], tramp);
            if (orig) {
                gOrigByHook[key] = [NSValue valueWithPointer:orig];
                gOrigBySel[sn] = [NSValue valueWithPointer:orig];
                [gHookedKeys addObject:key];
                hit++;
                DYAppend([NSString stringWithFormat:@"[HOOK-BODY] ✅ %@ enc=%s -> 已挂", key, enc ? enc : "?"]);
                DYFlushLog();
            }
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-BODY] 扫描异常 %@", e.name]);
    }
    return hit;
}

/* 运行时全类扫描：实例方法 + 类方法都扫（目标可能是类方法） */
static void DYHookBodyLayer(void) {
    unsigned int cc = 0;
    Class *classes = objc_copyClassList(&cc);
    int hit = 0;
    @try {
        for (unsigned int i = 0; i < cc; i++) {
            Class cls = classes[i];
            NSString *clsName = NSStringFromClass(cls);
            /* 实例方法 */
            unsigned int mc = 0;
            Method *ml = class_copyMethodList(cls, &mc);
            if (ml) { hit += DYScanMethodList(ml, mc, cls, clsName, NO); free(ml); }
            /* 类方法（meta-class） */
            Class meta = object_getClass(cls);
            if (meta) {
                unsigned int cmc = 0;
                Method *cml = class_copyMethodList(meta, &cmc);
                if (cml) { hit += DYScanMethodList(cml, cmc, meta, clsName, YES); free(cml); }
            }
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-BODY] 异常 %@", e.name]);
    }
    free(classes);
    DYAppend([NSString stringWithFormat:@"[HOOK-BODY] body 层共挂 %d 个方法", hit]);
    DYFlushLog();
}

/* model 层兜底 hook */
static void DYHookModelFallback(void) {
    int total = 0;
    @try {
        NSArray *names = @[@"AWECommentPublishParameterModel", @"AWECommentInputContentModel"];
        for (NSString *nm in names) {
            Class cls = NSClassFromString(nm);
            if (!cls) continue;
            unsigned int mc = 0; Method *ml = class_copyMethodList(cls, &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL sel = method_getName(ml[j]);
                NSString *sn = NSStringFromSelector(sel);
                NSString *key = [NSString stringWithFormat:@"%@|%@", nm, sn];
                if ([gHookedKeys containsObject:key]) continue;
                const char *enc = method_getTypeEncoding(ml[j]);
                NSString *sig = DYSigOf(enc);
                IMP orig = NULL;
                if ([sn isEqualToString:@"extraParams"] && [sig isEqualToString:@"@@:"]) orig = method_setImplementation(ml[j], (IMP)dy_extraParams_get);
                else if ([sn isEqualToString:@"setExtraParams:"] && [sig isEqualToString:@"v@:@"]) orig = method_setImplementation(ml[j], (IMP)dy_setExtraParams);
                else if ([sn isEqualToString:@"setExtraInfo:"] && [sig isEqualToString:@"v@:@"]) orig = method_setImplementation(ml[j], (IMP)dy_setExtraInfo);
                else if ([sn isEqualToString:@"extraInfo"] && [sig isEqualToString:@"@@:"]) orig = method_setImplementation(ml[j], (IMP)dy_extraInfo_get);
                else if ([sig isEqualToString:@"v@:"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_void0);
                else if ([sig isEqualToString:@"v@:@"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_void1);
                else if ([sig isEqualToString:@"@@:"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_obj0);
                else if ([sig isEqualToString:@"@@:@"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_obj1);
                if (orig) {
                    gOrigByHook[key] = [NSValue valueWithPointer:orig];
                    gOrigBySel[sn] = [NSValue valueWithPointer:orig];
                    [gHookedKeys addObject:key];
                    total++;
                }
            }
            free(ml);
        }
        /* setExtraInfo 的 AWETextExtra 改写用原始 setType */
        Class tc = NSClassFromString(@"AWETextExtra");
        if (tc) {
            unsigned int mc = 0; Method *ml = class_copyMethodList(tc, &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL sel = method_getName(ml[j]);
                NSString *sn = NSStringFromSelector(sel);
                NSString *key = [NSString stringWithFormat:@"AWETextExtra|%@", sn];
                if ([gHookedKeys containsObject:key]) continue;
                const char *enc = method_getTypeEncoding(ml[j]);
                NSString *sig = DYSigOf(enc);
                IMP orig = NULL;
                if ([sn isEqualToString:@"setExtraInfo:"] && [sig isEqualToString:@"v@:@"]) orig = method_setImplementation(ml[j], (IMP)dy_setExtraInfo);
                else if ([sig isEqualToString:@"v@:"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_void0);
                else if ([sig isEqualToString:@"v@:@"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_void1);
                else if ([sig isEqualToString:@"@@:"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_obj0);
                else if ([sig isEqualToString:@"@@:@"]) orig = method_setImplementation(ml[j], (IMP)dy_dump_obj1);
                if (orig) {
                    gOrigByHook[key] = [NSValue valueWithPointer:orig];
                    gOrigBySel[sn] = [NSValue valueWithPointer:orig];
                    [gHookedKeys addObject:key];
                    total++;
                }
            }
            free(ml);
        }
    } @catch (NSException *e) {
        DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] 异常 %@", e.name]);
    }
    DYAppend([NSString stringWithFormat:@"[HOOK-MODEL] model 兜底共挂 %d 个方法", total]);
    DYFlushLog();
}

static void DYStartPolling(void) {
    @try {
        gPollTimer = [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *t) {
            @autoreleasepool { DYInstallSetTypeHook(); }
        }];
        if (gPollTimer) [[NSRunLoop mainRunLoop] addTimer:gPollTimer forMode:NSRunLoopCommonModes];
    } @catch (...) {}
}

static void DYBootAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *vc = DYTopVC();
        if (!vc) return;
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"DYProbe v11 注入测试"
                message:@"打法转到 body 组装层，type 改回 21。\n发一条普通评论（不必@），去网页端/别人手机看是否红。\n日志以 Documents/dyprobe_dump.txt 为准。"
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
        DYAppend(@"DYProbe v11 init (body层注入 type=21; 数组+JSON双写; end=UTF8字节)");
        DYFlushLog();
    }
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            @autoreleasepool {
                DYBootAlert();
                for (int r = 0; r < 5; r++) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(r * 1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        @autoreleasepool {
                            DYAppend([NSString stringWithFormat:@"--- hook round %d ---", r]);
                            DYInstallSetTypeHook();
                            if (r == 0) DYHookBodyLayer();   /* body 层只挂一次，全类扫描较重 */
                            DYHookModelFallback();
                        }
                    });
                }
                DYStartPolling();
            }
        }];
}
