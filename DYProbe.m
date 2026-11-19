#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * DYProbe v20 —— 加载信标 + 参数层探针
 *
 * v19 的致命设计缺陷（本轮教训）：
 *   唯一的"我加载了"证据，写在 constructor 里 dispatch_after(+3s) 的块中。
 *   块没跑到（App 在 3 秒内崩、或 dylib 根本没进包）→ 一个字节都不留，
 *   于是无法区分「没加载」和「加载了但没干活」。这不是探针，是盲猜。
 *
 * v20 的硬要求：**constructor 第一行就必须落盘**，且满足：
 *   1) 纯 C（getenv + fopen + fprintf），不碰 Foundation —— 不依赖任何初始化顺序
 *   2) 不依赖 dispatch —— dispatch_after 万一不触发也有证据
 *   3) 一次写 3 个路径（Documents ×2 + TMPDIR），任一存在即可读到
 *   4) 写失败不 return，继续走后面的流程
 *
 * 之后的逻辑与 v19 一致：不 hook 任何网络函数（HTTP/3 QUIC，hook SSL_write 无效已证），
 * 只抄 AWEKMPBaseCommentPublishParameters 的结构 + 挂 extraParams 全量 dump。
 */

#define DY_MAXLEN  16000
#define DY_LOGN    30
#define DY_BEACON  "[v20]"

static int g_getN = 0, g_setN = 0, g_getLog = 0, g_setLog = 0;
static IMP g_origGet = NULL, g_origSet = NULL;

/* ===================== 信标：纯 C，constructor 可用 ===================== */
static void DYBeacon(const char *msg) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char stamp[64];
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv);

    const char *home = getenv("HOME");
    const char *tmpd = getenv("TMPDIR");

    char p1[512] = {0}, p2[512] = {0}, p3[512] = {0};
    const char *paths[3];
    int n = 0;
    if (home) {
        snprintf(p1, sizeof(p1), "%s/Documents/dyprobe_params.txt", home);
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v20.txt", home);
        paths[n++] = p1;
        paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v20.txt", tmpd);
        paths[n++] = p3;
    }

    for (int i = 0; i < n; i++) {
        FILE *f = fopen(paths[i], "a");
        if (!f) continue;
        fprintf(f, "%s %s | %s\n", DY_BEACON, msg, stamp);
        fflush(f);
        fclose(f);          /* 立刻关，进程被杀也不丢 */
    }
}

/* ===================== 带格式的日志（追加到同一批文件） ===================== */
static void L(NSString *fmt, ...) {
    if (!fmt) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!s) return;

    NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (!d || !d.length) return;

    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSMutableArray<NSString *> *targets = [NSMutableArray array];
    if (docs) {
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_params.txt"]];
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v20.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v20.txt"]];

    for (NSString *p in targets) {
        FILE *f = fopen(p.fileSystemRepresentation, "a");
        if (!f) continue;
        fwrite(d.bytes, 1, d.length, f);
        fflush(f);
        fclose(f);
    }
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

/* ===================== 类结构导出 ===================== */
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
    for (unsigned int i = 0; i < mn && i < 200; i++) {
        const char *sn = sel_getName(method_getName(ms[i]));
        const char *te = method_getTypeEncoding(ms[i]);
        if (sn) [ma addObject:[NSString stringWithFormat:@"%s [%s]", sn, te ? te : "?"]];
    }
    if (ms) free(ms);
    L(@"[方法 %u 个] %@", mn, [ma componentsJoinedByString:@", "]);
    L(@"----------------");
}

/* ===================== 影子注入（只算不改） ===================== */
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

/* ===================== hook ===================== */
static id dy_get(id self, SEL _cmd) {
    id r = nil;
    if (g_origGet) { @try { r = ((id (*)(id, SEL))g_origGet)(self, _cmd); } @catch (...) {} }
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
    if (g_origSet) { @try { ((void (*)(id, SEL, id))g_origSet)(self, _cmd, v); } @catch (...) {} }
}

static BOOL DYHookSel(Class c, const char *selName, BOOL isSetter) {
    SEL s = sel_registerName(selName);
    Method m = class_getInstanceMethod(c, s);
    if (!m) return NO;

    const char *enc = method_getTypeEncoding(m);
    if (!enc) return NO;

    int at = 0;
    for (const char *q = enc; *q; q++) if (*q == '@') at++;

    if (isSetter) {
        if (enc[0] != 'v' || at < 2) {
            L(@"[SKIP] setter %s 签名 %s 不是对象入参，跳过", selName, enc);
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

/* 按选择器反查，不靠类名猜 */
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

/* 列出运行时所有含 Comment/Publish 的类名，作为情报兜底 */
static void DYListCandidates(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *all = (Class *)calloc((size_t)n, sizeof(Class));
    if (!all) return;
    n = objc_getClassList(all, n);
    NSMutableArray *hit = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        const char *nm = class_getName(all[i]);
        if (!nm) continue;
        if (strstr(nm, "CommentPublish") || strstr(nm, "PublishParameter") ||
            strstr(nm, "PublishParams") || strstr(nm, "TextExtra")) {
            [hit addObject:[NSString stringWithUTF8String:nm]];
        }
    }
    free(all);
    L(@"[类总数 %d] [CANDIDATES] %@", n, [hit componentsJoinedByString:@", "]);
}

static void DYInstall(void) {
    @try {
        Class k = objc_getClass("AWEKMPBaseCommentPublishParameters");
        if (k) DYDumpClass(k, "KMPBaseCommentPublishParameters");
        else L(@"[MISS] AWEKMPBaseCommentPublishParameters 不存在");
        Class kb = objc_getClass("AWEKMPBaseCommentPublishParametersBuilder");
        if (kb) DYDumpClass(kb, "KMPBaseCommentPublishParametersBuilder");
        else L(@"[MISS] ...Builder 不存在");
    } @catch (...) { L(@"[ERR] KMP 类 dump 异常"); }

    DYListCandidates();

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
        c = DYFindBySelector("extraParams");
        if (!c) {
            L(@"[MISS] 运行时没有任何类定义 -extraParams");
            return;
        }
        L(@"[FOUND] 按选择器扫描命中 %s", class_getName(c));
    }

    DYDumpClass(c, "PublishParameterModel");

    BOOL ok = NO;
    if (DYHookSel(c, "extraParams", NO)) ok = YES;
    if (DYHookSel(c, "setExtraParams:", YES)) ok = YES;

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

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    /* 第一行，纯 C，任何时候都留痕 */
    DYBeacon("dylib 已加载 · constructor 立即写入");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v20] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v20] 安装异常，已忽略"); }
            L(@"[v20] 就绪：进视频评论区发一条 tt21");
            L(@"[v20] 文件：Documents/dyprobe_params.txt 或 dyprobe_v20.txt（内容相同）");
        }
    });

    for (int i = 1; i <= 4; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 10.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                L(@"[心跳 %ds] getter %d / setter %d", i * 10, g_getN, g_setN);
            }
        });
    }
}
