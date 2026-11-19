#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

/*
 * DYProbe v22 —— 只做一件事：把正文与富文本片段的真实内容打出来
 *
 * v21 实测（2026-11-20 01:15）得到的确切结论：
 *  ① extraParams 里没有 text_extra。22 个 key 全是统计上报字段
 *     (author_secuid / author_uid / common_flags / time_from_input_to_send / unique_key ...)
 *     → 发布参数字典这条路排除，不要再碰
 *  ② AWECommentInputContentModel 的字段是：
 *       content      NSString   正文
 *       extraInfo    NSArray    富文本片段（@ / # / 变色片段应该在这）
 *       sticker / imageSource / imageModels / audioModel
 *     v21 猜的 textExtra / textExtras / text 全部 [MISS] 不存在 → 已证实
 *  ③ AWECommentPublishRequest 有 parameterModel + inputExtraParams(NSDictionary)
 *     inputExtraParams 是"输入层带出的参数"，是 text_extra 的另一个强候选
 *  ④ Swift 的 Provider / LifeCycle 在 ObjC 方法表里是 0 个方法 → 不可 hook，已放弃
 *
 * 所以 v22 只在三处取值并展开：
 *     PM.extraParams  读到时 → 顺手把 self.contentModel 展开
 *     ICM.content / ICM.extraInfo
 *     Req.inputExtraParams
 *
 * 取值一律走 NSInvocation 并按真实返回类型读寄存器——
 * v21 那种 performSelector + 当 id 用的写法，遇到 int 返回值（start/end/type）
 * 会把整数当指针解引用，必崩。这是本版必须换掉的地方。
 */

#define DY_MAXLEN   10000
#define DY_LOGN     8
#define DY_MAXLINE  500
#define DY_BEACON   "[v22]"

static int g_writes = 0;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;

/* ===================== 信标 ===================== */
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
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v22.txt", home);
        paths[n++] = p1; paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v22.txt", tmpd);
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
static void LRawLocked(NSString *s) {
    if (!s) return;
    NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (!d || !d.length) return;
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSMutableArray<NSString *> *targets = [NSMutableArray array];
    if (docs) {
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_params.txt"]];
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v22.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v22.txt"]];
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
    if (allow) { g_writes++; @try { LRawLocked(s); } @catch (...) {} }
    pthread_mutex_unlock(&g_mtx);
}

/* ===================== 安全取值：按真实返回类型读 ===================== */
static NSString *DYStrD(id o, int depth);
static NSString *DYStr(id o) {
    NSString *s = DYStrD(o, 0);
    if (s.length > DY_MAXLEN) s = [[s substringToIndex:DY_MAXLEN] stringByAppendingString:@"…<截断>"];
    return s;
}
static NSString *DYStrD(id o, int depth) {
    if (!o) return @"(nil)";
    if (depth > 2) return @"<深>";
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
            for (id k in [[(NSDictionary *)o allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
                [a addObject:[NSString stringWithFormat:@"%@=%@", k, DYStrD([(NSDictionary *)o objectForKey:k], depth + 1)]];
            }
            return [NSString stringWithFormat:@"{%@}", [a componentsJoinedByString:@", "]];
        }
        NSString *desc = nil;
        @try { desc = [o description]; } @catch (...) {}
        if (desc) desc = [desc stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
        return [NSString stringWithFormat:@"<%@>%@", NSStringFromClass([o class]), desc ? desc : @""];
    } @catch (...) { return @"(取值异常)"; }
}

/* 关键：NSInvocation 按 methodReturnType 取，绝不用 performSelector 当 id 用 */
static NSString *DYCall(id o, SEL sel) {
    if (!o || ![o respondsToSelector:sel]) return nil;
    NSMethodSignature *sig = [o methodSignatureForSelector:sel];
    if (!sig) return nil;
    const char *rt = [sig methodReturnType];
    if (!rt) return nil;

    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    inv.target = o;
    inv.selector = sel;
    @try { [inv invoke]; } @catch (...) { return @"(调用异常)"; }

    if (rt[0] == '@') {
        __unsafe_unretained id v = nil;
        [inv getReturnValue:&v];
        return DYStr(v);
    }
    if (rt[0] == 'i') { int32_t v = 0; [inv getReturnValue:&v]; return [NSString stringWithFormat:@"%d", v]; }
    if (rt[0] == 'q') { int64_t v = 0; [inv getReturnValue:&v]; return [NSString stringWithFormat:@"%lld", v]; }
    if (rt[0] == 'Q') { uint64_t v = 0; [inv getReturnValue:&v]; return [NSString stringWithFormat:@"%llu", v]; }
    if (rt[0] == 'B') { uint8_t v = 0; [inv getReturnValue:&v]; return v ? @"YES" : @"NO"; }
    if (rt[0] == 's') { int16_t v = 0; [inv getReturnValue:&v]; return [NSString stringWithFormat:@"%d", v]; }
    if (rt[0] == 'I') { uint32_t v = 0; [inv getReturnValue:&v]; return [NSString stringWithFormat:@"%u", v]; }
    return [NSString stringWithFormat:@"<%s>", rt];
}

/* 候选选择器逐个安全取值 */
static NSString *DYProbeSelectors(id o) {
    if (!o) return @"(nil)";
    NSArray *sels = @[@"start", @"end", @"type", @"subType", @"userId", @"secUid",
                      @"name", @"hashtagName", @"hashTagName", @"hashtagId",
                      @"text", @"content", @"challengeId", @"openURL", @"hotspotText"];
    NSMutableArray *a = [NSMutableArray array];
    for (NSString *s in sels) {
        SEL sel = NSSelectorFromString(s);
        if (![o respondsToSelector:sel]) continue;
        NSString *v = DYCall(o, sel);
        if (v) [a addObject:[NSString stringWithFormat:@"%@=%@", s, v]];
    }
    return [a componentsJoinedByString:@", "];
}

/* ivar 展开：Swift/KMP 类常常 0 个属性但有 ivar */
static void DYDumpIvars(id o, NSString *tag) {
    if (!o) return;
    Class c = object_getClass(o);
    int lvl = 0;
    while (c && c != [NSObject class] && lvl < 3) {
        unsigned int n = 0;
        Ivar *iv = class_copyIvarList(c, &n);
        NSMutableArray *a = [NSMutableArray array];
        for (unsigned int i = 0; i < n && i < 60; i++) {
            const char *nm = ivar_getName(iv[i]);
            const char *tp = ivar_getTypeEncoding(iv[i]);
            if (nm) [a addObject:[NSString stringWithFormat:@"%s:%s", nm, tp ? tp : "?"]];
        }
        if (iv) free(iv);
        if (n) L(@"[IVAR %@] %@ 的 %u 个: %@", tag, NSStringFromClass(c), n, [a componentsJoinedByString:@", "]);
        c = class_getSuperclass(c);
        lvl++;
    }
}

static void DYDumpClassProps(Class c, const char *tag) {
    if (!c) { L(@"[%s] 类不存在", tag); return; }
    unsigned int pn = 0;
    objc_property_t *ps = class_copyPropertyList(c, &pn);
    NSMutableArray *pa = [NSMutableArray array];
    for (unsigned int i = 0; i < pn; i++) {
        const char *nm = property_getName(ps[i]);
        const char *at = property_getAttributes(ps[i]);
        if (nm) [pa addObject:[NSString stringWithFormat:@"%s(%s)", nm, at ? at : "?"]];
    }
    if (ps) free(ps);
    L(@"[%s 属性 %u 个] %@", tag, pn, [pa componentsJoinedByString:@", "]);
}

/* ---- 展开 AWECommentInputContentModel ---- */
/* dump 过程中会去读 content / extraInfo，而它们正是本版挂的 getter，
   不防重入会一层层套下去。用线程局部标记挡住。 */
static __thread int g_inDump = 0;

static void DYDumpICMImpl(id m, NSString *tag);

static void DYDumpICM(id m, NSString *tag) {
    if (g_inDump) return;
    g_inDump = 1;
    @try { DYDumpICMImpl(m, tag); } @catch (...) { L(@"[%@] dump 异常", tag); }
    g_inDump = 0;
}

static void DYDumpICMImpl(id m, NSString *tag) {
    if (!m) { L(@"[%@] contentModel = nil", tag); return; }
    L(@"[%@] contentModel 类 = %@", tag, NSStringFromClass([m class]));
    L(@"[%@] content    = %@", tag, DYCall(m, NSSelectorFromString(@"content")));
    L(@"[%@] imageSource= %@", tag, DYCall(m, NSSelectorFromString(@"imageSource")));

    NSString *extraDump = DYCall(m, NSSelectorFromString(@"extraInfo"));
    L(@"[%@] extraInfo  = %@", tag, extraDump ? extraDump : @"(无)");

    id extra = nil;
    @try { if ([m respondsToSelector:NSSelectorFromString(@"extraInfo")]) extra = [m valueForKey:@"extraInfo"]; } @catch (...) {}
    if (![extra isKindOfClass:[NSArray class]]) {
        L(@"[%@] extraInfo 不是数组，类型 %@", tag, extra ? NSStringFromClass([extra class]) : @"nil");
        return;
    }
    NSArray *arr = (NSArray *)extra;
    L(@"[%@] extraInfo 共 %lu 个元素", tag, (unsigned long)arr.count);
    long idx = 0;
    for (id e in arr) {
        NSString *t = [NSString stringWithFormat:@"%@#%ld", tag, idx];
        L(@"[%@] --- 元素 %ld 类 = %@ ---", tag, idx, NSStringFromClass([e class]));
        NSString *probe = DYProbeSelectors(e);
        L(@"[%@] 取值: %@", t, probe.length ? probe : @"(没有任何候选选择器)");
        DYDumpIvars(e, t);
        idx++;
    }
}

/* ===================== hook ===================== */
static NSMutableDictionary<NSString *, NSNumber *> *g_cnt = nil;
static int DYBump(NSString *key) {
    pthread_mutex_lock(&g_mtx);
    if (!g_cnt) g_cnt = [NSMutableDictionary dictionary];
    int v = [g_cnt[key] intValue] + 1;
    g_cnt[key] = @(v);
    pthread_mutex_unlock(&g_mtx);
    return v;
}

static BOOL DYIsObjGetter(Method m) {
    if (!m || method_getNumberOfArguments(m) != 2) return NO;
    char rt[32] = {0};
    method_getReturnType(m, rt, sizeof(rt));
    return rt[0] == '@';
}
static BOOL DYIsObjSetter(Method m) {
    if (!m || method_getNumberOfArguments(m) != 3) return NO;
    char rt[32] = {0};
    method_getReturnType(m, rt, sizeof(rt));
    if (rt[0] != 'v') return NO;
    char a2[32] = {0};
    method_getArgumentType(m, 2, a2, sizeof(a2));
    return a2[0] == '@';
}

/* body: 拿到 self 与可选入参后要做什么，由调用方给 */
static BOOL DYHook(Class c, const char *selC, BOOL isSetter, const char *tag,
                   void (^onCall)(id self, id arg)) {
    if (!c) return NO;
    SEL s = sel_registerName(selC);
    Method m = class_getInstanceMethod(c, s);
    if (!m) { L(@"[MISS] %s -%s 不存在", tag, selC); return NO; }
    if (isSetter ? !DYIsObjSetter(m) : !DYIsObjGetter(m)) {
        L(@"[SKIP] %s -%s 签名 %s 不合要求", tag, selC, method_getTypeEncoding(m));
        return NO;
    }

    IMP orig = method_getImplementation(m);
    NSString *key = [NSString stringWithFormat:@"%s|%s", tag, selC];

    if (isSetter) {
        id blk = ^(id self, id arg) {
            int n = DYBump(key);
            if (n <= DY_LOGN) { @try { onCall(self, arg); } @catch (...) {} }
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
            int n = DYBump(key);
            if (n <= DY_LOGN) { @try { onCall(self, r); } @catch (...) {} }
            return r;
        };
        IMP ni = imp_implementationWithBlock(blk);
        if (!class_addMethod(c, s, ni, method_getTypeEncoding(m))) {
            method_setImplementation(class_getInstanceMethod(c, s), ni);
        }
    }
    L(@"[HOOK] %s -%s", tag, selC);
    return YES;
}

/* ===================== 安装 ===================== */
static void DYInstall(void) {
    Class pm  = objc_getClass("AWECommentPublishParameterModel");
    Class icm = objc_getClass("AWECommentInputContentModel");
    Class req = objc_getClass("AWECommentPublishRequest");

    if (!pm)  L(@"[FATAL] AWECommentPublishParameterModel 不存在");
    if (!icm) L(@"[FATAL] AWECommentInputContentModel 不存在");
    if (!req) L(@"[FATAL] AWECommentPublishRequest 不存在");

    DYDumpClassProps(icm, "ICM");
    DYDumpClassProps(req, "Req");
    DYDumpClassProps(objc_getClass("TextExtraStructV2"), "TextExtraStructV2");

    /* 1) 发布参数模型：读 extraParams 时，顺手把它的 contentModel 整个展开 */
    DYHook(pm, "extraParams", NO, "PM", ^(id self, id arg) {
        L(@"\n===== [PM.extraParams 被读取] =====");
        id cm = nil;
        @try { cm = [self valueForKey:@"contentModel"]; } @catch (...) {}
        DYDumpICM(cm, @"读extraParams时");
    });
    DYHook(pm, "setExtraParams:", YES, "PM", ^(id self, id arg) {
        L(@"\n===== [PM.extraParams 被写入] keys=%lu =====", (unsigned long)[(NSDictionary *)arg count]);
    });
    DYHook(pm, "contentModel", NO, "PM", ^(id self, id arg) {
        DYDumpICM(arg, @"contentModel读取");
    });
    DYHook(pm, "setContentModel:", YES, "PM", ^(id self, id arg) {
        DYDumpICM(arg, @"contentModel写入");
    });

    /* 2) 正文模型：content / extraInfo 被读写时展开 */
    DYHook(icm, "content", NO, "ICM", ^(id self, id arg) {
        L(@"[ICM.content 读取] %@", DYStr(arg));
    });
    DYHook(icm, "setContent:", YES, "ICM", ^(id self, id arg) {
        L(@"[ICM.content 写入] %@", DYStr(arg));
    });
    DYHook(icm, "extraInfo", NO, "ICM", ^(id self, id arg) {
        L(@"\n===== [ICM.extraInfo 被读取] =====");
        DYDumpICM(self, @"读extraInfo时");
    });
    DYHook(icm, "setExtraInfo:", YES, "ICM", ^(id self, id arg) {
        L(@"\n===== [ICM.extraInfo 被写入] =====");
        DYDumpICM(self, @"写extraInfo时");
    });

    /* 3) 请求对象：inputExtraParams 是 text_extra 的另一个强候选 */
    DYHook(req, "inputExtraParams", NO, "REQ", ^(id self, id arg) {
        L(@"\n===== [REQ.inputExtraParams 被读取] =====\n%@", DYStr(arg));
    });
    DYHook(req, "setInputExtraParams:", YES, "REQ", ^(id self, id arg) {
        L(@"\n===== [REQ.inputExtraParams 被写入] =====\n%@", DYStr(arg));
    });
    DYHook(req, "parameterModel", NO, "REQ", ^(id self, id arg) {
        L(@"\n===== [REQ.parameterModel 被读取] =====");
        id cm = nil;
        @try { cm = [arg valueForKey:@"contentModel"]; } @catch (...) {}
        DYDumpICM(cm, @"REQ读parameterModel");
    });

    L(@"[DONE] v22 安装完成");
}

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    DYBeacon("dylib 已加载");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v22] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v22] 安装异常，已忽略"); }
            L(@"[v22] 就绪：进评论区发一条 tt21，杀进程导出 dyprobe_v22.txt");
        }
    });

    for (int i = 1; i <= 3; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 15.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                pthread_mutex_lock(&g_mtx);
                int wr = g_writes;
                pthread_mutex_unlock(&g_mtx);
                L(@"[心跳 %ds] 已写 %d 行", i * 15, wr);
            }
        });
    }
}
