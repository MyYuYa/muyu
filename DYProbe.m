#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

/*
 * DYProbe v21
 *
 * v20 实测结果（2026-11-20 01:08）暴露的三个问题，本版逐个修：
 *
 *  ① getter 一个都没挂上：
 *     [SKIP] getter extraParams 签名 @16@0:8 不是 @@:
 *     arm64 的 getter type encoding 是 `@16@0:8`（带偏移），不是 `@@:`
 *     → 改成 method_getNumberOfArguments + method_getReturnType 判断，不再猜字符串
 *
 *  ② AWEKMPBaseCommentPublishParameters 属性 0 / 方法 0：
 *     它是 Kotlin Multiplatform 类，字段定义在父类，class_copyMethodList 只返回本层
 *     → 新增 dump 父类链（最多 4 层）+ 类方法（KMP 枚举的 values 在类方法上）
 *
 *  ③ 发布链路的关键类只 dump 不 hook：
 *     AWECommentPublishParameterModel.extraParams 是 NSDictionary（v7 早就在这看到过真实参数）
 *     AWECommentInputContentModel 才是装正文 + text_extra 的地方
 *     AWECommentSwiftImpl.CommentPublishRequestProvider 是组请求的那一层
 *     → 全部挂上，取到真实数据
 *
 * 仍然不 hook 任何网络函数（HTTP/3 QUIC，hook SSL_write 无效，已证）。
 */

#define DY_MAXLEN   12000
#define DY_LOGN     24
#define DY_MAXLINE  1200          /* 全文件行数上限，防止日志爆炸拖死 IO */
#define DY_BEACON   "[v21]"

static int g_writes = 0;

/* hook 可能被多个线程同时进入：计数器和文件写都必须互斥，否则随机崩 */
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;

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
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v21.txt", home);
        paths[n++] = p1; paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v21.txt", tmpd);
        paths[n++] = p3;
    }
    for (int i = 0; i < n; i++) {
        FILE *f = fopen(paths[i], "a");
        if (!f) continue;
        fprintf(f, "%s %s | %s\n", DY_BEACON, msg, stamp);
        fflush(f); fclose(f);
    }
}

/* ===================== 日志 ===================== */
/* 调用者必须已持有 g_mtx */
static void LRawLocked(NSString *s) {
    if (!s) return;
    NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (!d || !d.length) return;

    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSMutableArray<NSString *> *targets = [NSMutableArray array];
    if (docs) {
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_params.txt"]];
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v21.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v21.txt"]];

    for (NSString *p in targets) {
        FILE *f = fopen(p.fileSystemRepresentation, "a");
        if (!f) continue;
        fwrite(d.bytes, 1, d.length, f);
        fflush(f); fclose(f);
    }
}

static void L(NSString *fmt, ...) {
    if (!fmt) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!s) return;

    pthread_mutex_lock(&g_mtx);
    BOOL allow = (g_writes < DY_MAXLINE);
    if (allow) {
        g_writes++;
        @try { LRawLocked(s); } @catch (...) {}
    }
    pthread_mutex_unlock(&g_mtx);
}

/* ===================== 值转字符串（支持自定义对象递归） ===================== */
static NSString *DYStrD(id o, int depth);

static NSString *DYStr(id o) {
    NSString *s = DYStrD(o, 0);
    if (s.length > DY_MAXLEN) s = [[s substringToIndex:DY_MAXLEN] stringByAppendingString:@"…<截断>"];
    return s;
}

static NSString *DYStrD(id o, int depth) {
    if (!o) return @"(nil)";
    if (depth > 3) return @"<深度截断>";
    @try {
        if ([o isKindOfClass:[NSString class]]) return (NSString *)o;
        if ([o isKindOfClass:[NSNumber class]]) return [o description];
        if ([o isKindOfClass:[NSArray class]]) {
            NSMutableArray *a = [NSMutableArray array];
            for (id e in (NSArray *)o) [a addObject:DYStrD(e, depth + 1)];
            return [NSString stringWithFormat:@"[%@]", [a componentsJoinedByString:@", "]];
        }
        if ([o isKindOfClass:[NSDictionary class]]) {
            NSMutableArray *a = [NSMutableArray array];
            NSArray *ks = [[(NSDictionary *)o allKeys] sortedArrayUsingSelector:@selector(compare:)];
            for (id k in ks) {
                [a addObject:[NSString stringWithFormat:@"%@=%@", DYStrD(k, depth + 1),
                              DYStrD([(NSDictionary *)o objectForKey:k], depth + 1)]];
            }
            return [NSString stringWithFormat:@"{%@}", [a componentsJoinedByString:@", "]];
        }
    } @catch (...) { return @"(取值异常)"; }

    NSString *cls = NSStringFromClass([o class]);
    NSString *desc = nil;
    @try { desc = [o description]; } @catch (...) {}
    /* 自定义对象：把 description 里的换行压平成一行，便于阅读 */
    if (desc) desc = [desc stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    return [NSString stringWithFormat:@"<%@>%@", cls, desc ? desc : @""];
}

/* ===================== 类结构导出 ===================== */
static void DYDumpMethods(Class c, BOOL classSide, const char *tag) {
    Class t = classSide ? object_getClass((id)c) : c;
    if (!t) return;
    unsigned int mn = 0;
    Method *ms = class_copyMethodList(t, &mn);
    NSMutableArray *ma = [NSMutableArray array];
    for (unsigned int i = 0; i < mn && i < 200; i++) {
        const char *sn = sel_getName(method_getName(ms[i]));
        const char *te = method_getTypeEncoding(ms[i]);
        if (sn) [ma addObject:[NSString stringWithFormat:@"%s [%s]", sn, te ? te : "?"]];
    }
    if (ms) free(ms);
    if (mn == 0) return;                 /* 空的就不占篇幅 */
    L(@"[%@方法 %u 个] %@", classSide ? @"类" : @"", mn, [ma componentsJoinedByString:@", "]);
}

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

    DYDumpMethods(c, NO, tag);
    DYDumpMethods(c, YES, tag);
    L(@"----------------");
}

/* 关键补充：KMP 类的字段在父类，必须沿父类链 dump */
static void DYDumpChain(Class c, const char *tag) {
    if (!c) { L(@"[%s] 类不存在", tag); return; }
    Class cur = c;
    int lvl = 0;
    while (cur && cur != [NSObject class] && lvl < 4) {
        L(@"[链 %d] %s -> %s", lvl, class_getName(c), class_getName(cur));
        DYDumpClass(cur, tag);
        cur = class_getSuperclass(cur);
        lvl++;
    }
    if (cur) L(@"[链尾] %s", class_getName(cur));
}

/* ===================== 影子注入（只算不改） ===================== */
static void DYShadow(id dict, NSString *tag) {
    if (!dict) return;
    if ([dict isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)dict;
        L(@"[KEYS %@] %@", tag,
          [[[d allKeys] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@", "]);
        id te = [d objectForKey:@"text_extra"];
        if (!te) te = [d objectForKey:@"textExtra"];
        if (te) L(@"[TEXT_EXTRA %@] %@", tag, DYStr(te));
        return;
    }
    /* 自定义对象：只要有 textExtra / textExtras 就记下来 */
    for (NSString *sel in @[@"textExtra", @"textExtras", @"text_extra"]) {
        if ([dict respondsToSelector:NSSelectorFromString(sel)]) {
            id v = nil;
            @try { v = [dict performSelector:NSSelectorFromString(sel)]; } @catch (...) {}
            if (v) L(@"[TEXT_EXTRA %@] %@.%@ = %@", tag, NSStringFromClass([dict class]), sel, DYStr(v));
        }
    }
}

/* ===================== hook（用 block 承载，支持多类多方法） ===================== */
static NSMutableDictionary<NSString *, NSNumber *> *g_cnt = nil;
static int DYBump(NSString *key) {
    pthread_mutex_lock(&g_mtx);
    if (!g_cnt) g_cnt = [NSMutableDictionary dictionary];
    int v = [g_cnt[key] intValue] + 1;
    g_cnt[key] = @(v);
    pthread_mutex_unlock(&g_mtx);
    return v;
}

static BOOL DYIsObjectGetter(Method m) {
    if (!m) return NO;
    if (method_getNumberOfArguments(m) != 2) return NO;
    char rt[32] = {0};
    method_getReturnType(m, rt, sizeof(rt));
    return rt[0] == '@';
}

static BOOL DYIsObjectSetter(Method m) {
    if (!m) return NO;
    if (method_getNumberOfArguments(m) != 3) return NO;
    char rt[32] = {0};
    method_getReturnType(m, rt, sizeof(rt));
    if (rt[0] != 'v') return NO;
    char a2[32] = {0};
    method_getArgumentType(m, 2, a2, sizeof(a2));
    return a2[0] == '@';
}

/* 通用挂载：getter 记录返回值，setter 记录入参，同时做影子注入 */
static BOOL DYHook(Class c, SEL s, BOOL isSetter, const char *tag) {
    Method m = class_getInstanceMethod(c, s);
    if (!m) { L(@"[MISS] %s -%s 不存在", tag, sel_getName(s)); return NO; }
    if (isSetter ? !DYIsObjectSetter(m) : !DYIsObjectGetter(m)) {
        L(@"[SKIP] %s %s 签名 %s 不合要求", tag, sel_getName(s), method_getTypeEncoding(m));
        return NO;
    }

    IMP orig = method_getImplementation(m);
    NSString *selName = NSStringFromSelector(s);
    NSString *tagS = [NSString stringWithUTF8String:tag];

    if (isSetter) {
        id blk = ^(id self, id arg) {
            @try {
                int n = DYBump([tagS stringByAppendingFormat:@"|%@|S", selName]);
                if (n <= DY_LOGN) {
                    L(@"[S %@ %@ #%d] %@", tagS, selName, n, DYStr(arg));
                    DYShadow(arg, [NSString stringWithFormat:@"S-%@#%d", selName, n]);
                }
            } @catch (...) {}
            ((void (*)(id, SEL, id))orig)(self, s, arg);
        };
        IMP ni = imp_implementationWithBlock(blk);
        if (!class_addMethod(c, s, ni, method_getTypeEncoding(m))) {
            method_setImplementation(class_getInstanceMethod(c, s), ni);
        }
    } else {
        id blk = ^id(id self) {
            id r = nil;
            @try { r = ((id (*)(id, SEL))orig)(self, s); } @catch (...) {}
            @try {
                int n = DYBump([tagS stringByAppendingFormat:@"|%@|G", selName]);
                if (n <= DY_LOGN) {
                    L(@"[G %@ %@ #%d] %@", tagS, selName, n, DYStr(r));
                    DYShadow(r, [NSString stringWithFormat:@"G-%@#%d", selName, n]);
                }
            } @catch (...) {}
            return r;
        };
        IMP ni = imp_implementationWithBlock(blk);
        if (!class_addMethod(c, s, ni, method_getTypeEncoding(m))) {
            method_setImplementation(class_getInstanceMethod(c, s), ni);
        }
    }
    L(@"[HOOK] %s -%s (%@)", tag, sel_getName(s), isSetter ? @"setter" : @"getter");
    return YES;
}

static BOOL DYHookNamed(Class c, const char *selName, BOOL isSetter, const char *tag) {
    if (!c || !selName) return NO;
    return DYHook(c, sel_registerName(selName), isSetter, tag);
}

/* 挂一个类的所有「纯对象参数」实例方法，用来抓发布链路的组包过程 */
static void DYHookAllSimple(Class c, const char *tag) {
    if (!c) return;
    unsigned int mn = 0;
    Method *ms = class_copyMethodList(c, &mn);
    int hooked = 0;
    for (unsigned int i = 0; i < mn && hooked < 14; i++) {
        const char *sn = sel_getName(method_getName(ms[i]));
        if (!sn) continue;
        /* 跳过明显的危险/噪音方法 */
        if (strncmp(sn, "init", 4) == 0 || strncmp(sn, "dealloc", 7) == 0 ||
            strncmp(sn, ".cxx", 4) == 0 || strncmp(sn, "set", 3) == 0 ||
            strcmp(sn, "description") == 0 || strcmp(sn, "class") == 0) continue;

        Method m = ms[i];
        unsigned int ac = method_getNumberOfArguments(m);
        if (ac < 2 || ac > 4) continue;

        char rt[32] = {0};
        method_getReturnType(m, rt, sizeof(rt));
        if (rt[0] != '@' && rt[0] != 'v') continue;

        BOOL okArgs = YES;
        for (unsigned int k = 2; k < ac; k++) {
            char at[32] = {0};
            method_getArgumentType(m, k, at, sizeof(at));
            if (at[0] != '@') { okArgs = NO; break; }
        }
        if (!okArgs) continue;

        if (ac == 2 && rt[0] == '@') { if (DYHook(c, method_getName(m), NO, tag)) hooked++; }
        else if (ac == 3)            { if (DYHook(c, method_getName(m), YES, tag)) hooked++; }
    }
    if (ms) free(ms);
    L(@"[HOOKALL] %s 挂了 %d 个方法", tag, hooked);
}

/* ===================== KMP 枚举取值 ===================== */
static void DYDumpEnumValues(Class c, const char *tag) {
    if (!c) { L(@"[%s] 类不存在", tag); return; }
    for (NSString *selName in @[@"values", @"entries", @"companion"]) {
        SEL s = NSSelectorFromString(selName);
        if (![c respondsToSelector:s]) continue;
        id v = nil;
        @try { v = [c performSelector:s]; } @catch (...) {}
        L(@"[枚举 %s] %@ = %@", tag, selName, DYStr(v));
    }
}

/* ===================== 安装 ===================== */
static void DYInstall(void) {
    Class c = Nil;

    /* ---- 1) KMP 参数层：沿父类链 dump，字段基本都在父类 ---- */
    c = objc_getClass("AWEKMPBaseCommentPublishParameters");
    DYDumpChain(c, "KMPParams");
    DYDumpChain(objc_getClass("AWEKMPBaseCommentPublishParametersBuilder"), "KMPParamsBuilder");
    DYDumpChain(objc_getClass("AWEKMPBaseCommentPublishParametersCompanion"), "KMPParamsCompanion");

    /* ---- 2) 正文 + text_extra 的真正载体 ---- */
    DYDumpChain(objc_getClass("AWECommentInputContentModel"), "InputContentModel");

    /* ---- 3) type 的枚举值（type=21 就在这里） ---- */
    DYDumpClass(objc_getClass("AWEKMPCommentContentTextExtraType"), "TextExtraType");
    DYDumpEnumValues(objc_getClass("AWEKMPCommentContentTextExtraType"), "TextExtraType");
    DYDumpClass(objc_getClass("AWEKMPCommentContentTextExtraSubType"), "TextExtraSubType");
    DYDumpClass(objc_getClass("AWEKMPCommentPublishScene"), "PublishScene");

    /* ---- 4) 序列化层 + 结构体 ---- */
    DYDumpClass(objc_getClass("AWEKMPTextExtraStructKMPListSerializer"), "TESerializer");
    DYDumpChain(objc_getClass("TextExtraStructV2"), "TextExtraStructV2");
    DYDumpChain(objc_getClass("AWECommentPanelListSwiftImpl.CommentContentTextExtra"), "ContentTextExtra");

    /* ---- 5) 请求层 ---- */
    DYDumpChain(objc_getClass("AWECommentPublishRequest"), "PublishRequest");
    DYDumpChain(objc_getClass("AWECommentPublishParameterModel"), "ParameterModel");

    /* ---- 6) 挂发布参数模型 ---- */
    Class pm = objc_getClass("AWECommentPublishParameterModel");
    if (pm) {
        DYHookNamed(pm, "extraParams", NO, "PM");
        DYHookNamed(pm, "setExtraParams:", YES, "PM");
        DYHookNamed(pm, "contentModel", NO, "PM");
        DYHookNamed(pm, "setContentModel:", YES, "PM");
    }

    /* ---- 7) 挂正文模型上的 textExtra 等字段 ---- */
    Class icm = objc_getClass("AWECommentInputContentModel");
    if (icm) {
        DYHookNamed(icm, "textExtra", NO, "ICM");
        DYHookNamed(icm, "setTextExtra:", YES, "ICM");
        DYHookNamed(icm, "textExtras", NO, "ICM");
        DYHookNamed(icm, "setTextExtras:", YES, "ICM");
        DYHookNamed(icm, "text", NO, "ICM");
        DYHookNamed(icm, "setText:", YES, "ICM");
    }

    /* ---- 8) 挂组包/回调层，抓真实流转对象 ---- */
    DYHookAllSimple(objc_getClass("AWECommentSwiftImpl.CommentPublishRequestProvider"), "Provider");
    DYHookAllSimple(objc_getClass("AWECommentSwiftService.CommentPublishNetWorkLifeCycleObserver"), "LifeCycle");

    L(@"[%@] 参数层探针安装完成", @"DONE");
}

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    DYBeacon("dylib 已加载 · constructor 立即写入");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v21] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v21] 安装异常，已忽略"); }
            L(@"[v21] 就绪：进视频评论区发一条 tt21，然后杀进程导出 dyprobe_v21.txt");
        }
    });

    for (int i = 1; i <= 4; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 10.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                pthread_mutex_lock(&g_mtx);
                int wr = g_writes;
                NSUInteger cnt = g_cnt.count;
                pthread_mutex_unlock(&g_mtx);
                L(@"[心跳 %ds] 已写 %d 行 / 计数项 %lu 个", i * 10, wr, (unsigned long)cnt);
            }
        });
    }
}
