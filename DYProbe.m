#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * DYProbe v19 —— 参数层探针（不 hook 任何网络函数）
 *
 * 为什么换路：
 *   v15~v18 一直在 hook SSL_write 抄明文。已证：这条路能抄到字节，但
 *     (1) HTTP/2 的 :path 被 HPACK 压掉，comment/publish 明文字节流里根本不出现；
 *     (2) 请求体可能被 zstd 压缩（v17 #52 实测 body 头 = 28 b5 2f fd），抄下来是密文；
 *     (3) 最要命：我们要改的是「参数对象」，不是网络字节。
 *
 * 二进制里挖到的事实（抖音 41.0.0 AwemeCore）：
 *   aweme/v1/comment/publish/?need_shark_async=1
 *   AWECommentSwiftImpl.CommentPublishRequestProvider
 *   AWEKMPBaseCommentPublishParameters (+Builder / +Companion)
 *   独立字符串 "text_extra" 全二进制只有 1 处，且属于「评论列表响应模型」，
 *   发布侧没有这个字面量 —— 它由 KMP 序列化层生成（属性 textExtra -> key text_extra），
 *   与 translate 接口参数 comment_text_extra 同一命名规则。
 *
 * 而 v7 早就实测到：真正要发出去的发布参数字典是
 *   AWECommentPublishParameterModel.extraParams
 * （当时看到 author_secuid / common_flags / hashtag ...，但被 600 字符截断）
 *
 * 所以 v19 只做三件事，全部不碰网络：
 *   1) 把 AWECommentPublishParameterModel 的属性表/方法表写进文件 —— 不发评论也有情报
 *   2) 挂 extraParams 的 getter / setter，完整 dump 字典（不再截断到 600）
 *   3) 影子注入：算出「如果把 type 改成 21 会长什么样」并写进日志，但**不改原对象**
 *
 * 日志：Documents/dyprobe_params.txt（每次写都 fflush，进程被杀也不丢）
 */

#define DY_MAXLEN  16000
#define DY_LOGN    30          /* getter/setter 各最多详细记 30 次 */

static FILE  *g_fp     = NULL;
static int    g_getN   = 0;
static int    g_setN   = 0;
static int    g_getLog = 0;
static int    g_setLog = 0;
static IMP    g_origGet = NULL;
static IMP    g_origSet = NULL;

/* ------------------------------ 日志 ------------------------------ */
static NSString *DYPath(void) {
    NSString *d = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!d) return nil;
    return [d stringByAppendingPathComponent:@"dyprobe_params.txt"];
}

static void L(NSString *fmt, ...) {
    if (!fmt) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!s) return;

    if (!g_fp) {
        NSString *p = DYPath();
        if (!p) return;
        g_fp = fopen(p.fileSystemRepresentation, "a");
        if (!g_fp) return;
    }
    @try {
        NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        if (d && d.length) {
            fwrite(d.bytes, 1, d.length, g_fp);
            fflush(g_fp);          /* 关键：不用等 fsync，内核已可见 */
        }
    } @catch (...) {}
}

static NSString *DYStr(id o) {
    if (!o) return @"(nil)";
    NSString *s = nil;
    @try {
        if ([o isKindOfClass:[NSString class]]) {
            s = (NSString *)o;
        } else if ([o isKindOfClass:[NSNumber class]]) {
            s = [o description];
        } else if ([NSJSONSerialization isValidJSONObject:o]) {
            NSData *d = [NSJSONSerialization dataWithJSONObject:o options:0 error:NULL];
            if (d) s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        }
        if (!s) s = [o description];
    } @catch (...) {
        s = @"(dump 抛异常)";
    }
    if (!s) s = @"(nil)";
    if (s.length > DY_MAXLEN) s = [[s substringToIndex:DY_MAXLEN] stringByAppendingString:@"…<已截断>"];
    return s;
}

/* --------------------------- 类结构导出 --------------------------- */
static void DYDumpClass(Class c, const char *tag) {
    if (!c) { L(@"[%s] 类不存在", tag); return; }
    L(@"\n---- 类 %s ----", class_getName(c));

    unsigned int pn = 0;
    objc_property_t *ps = class_copyPropertyList(c, &pn);
    NSMutableArray *pa = [NSMutableArray array];
    for (unsigned int i = 0; i < pn; i++) {
        const char *nm = property_getName(ps[i]);
        const char *at = property_getAttributes(ps[i]);
        if (nm) [pa addObject:[NSString stringWithFormat:@"%s(%s)", nm, at ? at : "?"]];
    }
    if (ps) free(ps);
    L(@"[属性 %u 个] %@", pn, [pa componentsJoinedByString:@", "]);

    unsigned int mn = 0;
    Method *ms = class_copyMethodList(c, &mn);
    NSMutableArray *ma = [NSMutableArray array];
    for (unsigned int i = 0; i < mn && i < 150; i++) {
        const char *sn = sel_getName(method_getName(ms[i]));
        const char *te = method_getTypeEncoding(ms[i]);
        if (sn) [ma addObject:[NSString stringWithFormat:@"%s [%s]", sn, te ? te : "?"]];
    }
    if (ms) free(ms);
    L(@"[方法 %u 个] %@", mn, [ma componentsJoinedByString:@", "]);
    L(@"----------------");
}

/* --------------------------- 影子注入 --------------------------- */
static void DYShadow(id dict, NSString *tag) {
    if (![dict isKindOfClass:[NSDictionary class]]) {
        L(@"[SHADOW %@] 不是字典，实际类型 %@", tag, NSStringFromClass([dict class]));
        return;
    }
    NSDictionary *d = (NSDictionary *)dict;
    NSArray *keys = [[d allKeys] sortedArrayUsingSelector:@selector(compare:)];
    L(@"[KEYS %@] %@", tag, [keys componentsJoinedByString:@", "]);

    id te = [d objectForKey:@"text_extra"];
    if (!te) te = [d objectForKey:@"textExtra"];
    if (!te) te = [d objectForKey:@"text_extras"];
    if (!te) te = [d objectForKey:@"textExtras"];
    L(@"[TEXT_EXTRA %@] %@", tag, DYStr(te));

    id txt = [d objectForKey:@"text"];
    if (!txt) txt = [d objectForKey:@"content"];
    L(@"[TEXT %@] %@", tag, DYStr(txt));

    /* 算出「注入 type=21 之后」的样子，只打印，不改真对象 */
    NSMutableArray *out = [NSMutableArray array];
    if ([te isKindOfClass:[NSArray class]]) {
        for (id e in (NSArray *)te) {
            if ([e isKindOfClass:[NSDictionary class]]) {
                NSMutableDictionary *m = [(NSDictionary *)e mutableCopy];
                m[@"type"] = @21;
                [out addObject:m];
            }
        }
    }
    if (out.count == 0 && [txt isKindOfClass:[NSString class]] && [(NSString *)txt length] > 0) {
        [out addObject:@{ @"start": @0,
                          @"end":   @([(NSString *)txt length]),
                          @"type":  @21,
                          @"user_id": @"" }];
    }
    L(@"[SHADOW %@] 若注入 type=21 -> %@", tag, DYStr(out));
}

/* ----------------------------- hook ----------------------------- */
static id dy_get(id self, SEL _cmd) {
    id r = nil;
    if (g_origGet) {
        @try { r = ((id (*)(id, SEL))g_origGet)(self, _cmd); } @catch (...) {}
    }
    g_getN++;
    if (g_getLog < DY_LOGN) {
        g_getLog++;
        @try {
            L(@"[GET #%d] -[%@ %@] = %@", g_getN,
              NSStringFromClass([self class]), NSStringFromSelector(_cmd), DYStr(r));
            DYShadow(r, [NSString stringWithFormat:@"get#%d", g_getN]);
        } @catch (...) {}
    }
    return r;
}

static void dy_set(id self, SEL _cmd, id v) {
    g_setN++;
    if (g_setLog < DY_LOGN) {
        g_setLog++;
        @try {
            L(@"[SET #%d] -[%@ %@] <=\n%@", g_setN,
              NSStringFromClass([self class]), NSStringFromSelector(_cmd), DYStr(v));
            DYShadow(v, [NSString stringWithFormat:@"set#%d", g_setN]);
        } @catch (...) {}
    }
    if (g_origSet) {
        @try { ((void (*)(id, SEL, id))g_origSet)(self, _cmd, v); } @catch (...) {}
    }
}

static BOOL DYHookSel(Class c, const char *selName, BOOL isSetter) {
    SEL s = sel_registerName(selName);
    Method m = class_getInstanceMethod(c, s);
    if (!m) return NO;

    const char *enc = method_getTypeEncoding(m);
    if (!enc) return NO;

    /* 统计 '@' 个数：setter 形如 v24@0:8@16 / v@:@，必然有两个 '@'（self + 参数） */
    int at = 0;
    for (const char *q = enc; *q; q++) if (*q == '@') at++;

    if (isSetter) {
        if (enc[0] != 'v' || at < 2) {
            L(@"[SKIP] setter %s 签名 %s 不是对象入参，跳过（不乱挂）", selName, enc);
            return NO;
        }
        g_origSet = method_setImplementation(m, (IMP)dy_set);
        L(@"[HOOK] setter %s 已挂 (enc=%s)", selName, enc);
        return g_origSet != NULL;
    }

    if (!(strlen(enc) >= 3 && enc[0] == '@' && enc[1] == '@' && enc[2] == ':')) {
        L(@"[SKIP] getter %s 签名 %s 不是 @@:，跳过", selName, enc);
        return NO;
    }
    g_origGet = method_setImplementation(m, (IMP)dy_get);
    L(@"[HOOK] getter %s 已挂 (enc=%s)", selName, enc);
    return g_origGet != NULL;
}

/* ---- 兜底：按选择器在运行时里找「谁定义了 extraParams」，不靠类名猜 ---- */
static Class DYFindBySelector(const char *selName) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return Nil;
    Class *all = (Class *)calloc((size_t)n, sizeof(Class));
    if (!all) return Nil;
    n = objc_getClassList(all, n);

    SEL want = sel_registerName(selName);
    NSMutableArray *hits = [NSMutableArray array];
    Class best = Nil;

    for (int i = 0; i < n; i++) {
        Class c = all[i];
        const char *cn = class_getName(c);
        if (!cn) continue;
        /* 只扫名字沾边的，避免遍历几万个类把启动拖慢 */
        if (!(strstr(cn, "Comment") || strstr(cn, "Publish") || strstr(cn, "Param"))) continue;

        unsigned int mn = 0;
        Method *ms = class_copyMethodList(c, &mn);
        BOOL has = NO;
        for (unsigned int j = 0; j < mn; j++) {
            if (sel_isEqual(method_getName(ms[j]), want)) { has = YES; break; }
        }
        if (ms) free(ms);
        if (has) {
            [hits addObject:[NSString stringWithUTF8String:cn]];
            if (!best) best = c;
        }
    }
    free(all);
    L(@"[SWEEP] 定义了 -%s 的类共 %lu 个：%@", selName,
      (unsigned long)hits.count, [hits componentsJoinedByString:@", "]);
    return best;
}

static void DYInstall(void) {
    /* 先无条件把 KMP 那层的参数类结构抄下来：不发评论也能拿到字段名 */
    @try {
        Class k = objc_getClass("AWEKMPBaseCommentPublishParameters");
        if (k) DYDumpClass(k, "KMPBaseCommentPublishParameters");
        else L(@"[MISS] AWEKMPBaseCommentPublishParameters 不存在");
        Class kb = objc_getClass("AWEKMPBaseCommentPublishParametersBuilder");
        if (kb) DYDumpClass(kb, "KMPBaseCommentPublishParametersBuilder");
    } @catch (...) {}

    static const char *cands[] = {
        "AWECommentPublishParameterModel",
        "AWECommentPublishParams",
        "AWECommentPublishParameter",
        "AWECommentPublishParamModel",
    };
    Class c = Nil;
    for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
        c = objc_getClass(cands[i]);
        if (c) { L(@"[FOUND] 命中类名 %s", cands[i]); break; }
    }
    if (!c) {
        L(@"[MISS] 上面几个类名都不存在。先列出运行时所有含 CommentPublish 的类：");
        int n = objc_getClassList(NULL, 0);
        if (n > 0) {
            Class *all = (Class *)calloc((size_t)n, sizeof(Class));
            if (all) {
                n = objc_getClassList(all, n);
                NSMutableArray *hit = [NSMutableArray array];
                for (int i = 0; i < n; i++) {
                    const char *nm = class_getName(all[i]);
                    if (nm && (strstr(nm, "CommentPublish") || strstr(nm, "PublishParameter"))) {
                        [hit addObject:[NSString stringWithUTF8String:nm]];
                    }
                }
                free(all);
                L(@"[CANDIDATES] %@", [hit componentsJoinedByString:@", "]);
            }
        }
        /* 不靠类名猜了，直接按选择器反查 */
        c = DYFindBySelector("extraParams");
        if (!c) {
            L(@"[MISS] 运行时没有任何类定义 -extraParams，本版拿不到参数字典");
            return;
        }
        L(@"[FOUND] 按选择器扫描命中 %s", class_getName(c));
    }

    DYDumpClass(c, "PublishParameterModel");

    BOOL ok = NO;
    if (DYHookSel(c, "extraParams", NO)) ok = YES;
    if (DYHookSel(c, "setExtraParams:", YES)) ok = YES;

    /* 兜底：按属性名找其它含 extra 的 getter */
    if (!ok) {
        unsigned int pn = 0;
        objc_property_t *ps = class_copyPropertyList(c, &pn);
        for (unsigned int i = 0; i < pn; i++) {
            const char *nm = property_getName(ps[i]);
            if (!nm) continue;
            if (strstr(nm, "extra") || strstr(nm, "Extra")) {
                if (DYHookSel(c, nm, NO)) ok = YES;
                char setter[256];
                snprintf(setter, sizeof(setter), "set%c%s:", toupper((unsigned char)nm[0]), nm + 1);
                DYHookSel(c, setter, YES);
            }
        }
        if (ps) free(ps);
    }
    L(@"[%@] 结果：%@", ok ? @"OK" : @"FAIL", ok ? @"已挂上发布参数钩子" : @"没找到可挂的方法");
}

/* ----------------------------- 入口 ----------------------------- */
__attribute__((constructor)) static void DYInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            L(@"\n\n========== [v19] 会话开始 %@ ==========", [NSDate date]);
            L(@"[v19] 本版不 hook 任何网络函数，评论该发得出去");
            @try { DYInstall(); } @catch (...) { L(@"[v19] 安装异常，已忽略"); }
            L(@"[v19] 就绪：进视频评论区发一条 tt21。发完看到评论出现在列表里就行（有没有 toast 不影响）");
            L(@"[v19] 然后杀进程，导出 Documents/dyprobe_params.txt");
            L(@"[v19] 文件：Documents/dyprobe_params.txt");
        }
    });

    for (int i = 1; i <= 5; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 15.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                L(@"[心跳 %ds] 活着 / getter %d 次 / setter %d 次 / 时间 %@",
                  i * 15, g_getN, g_setN, [NSDate date]);
            }
        });
    }
}
