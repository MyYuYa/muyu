#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <execinfo.h>
#include <dlfcn.h>

/*
 * DYProbe v24 —— 抓「最终发出去的请求体」
 *
 * 已知事实（全部实测）：
 *   v23 注入 extraParams["text_extra"] 后，iOS 客户端显示红色，但网页端普通
 *   → text_extra 被客户端某个消费方读到了（所以本机能渲染红）
 *   → 但服务端没有存 → 请求体里要么没这个字段，要么格式/键名不对
 *
 * v22 实测：纯文本评论时 contentModel.extraInfo = []（空）
 *   → iOS 原生纯文本评论不生成 text_extra
 *   → 带 #话题 的评论一定会生成（话题是 type=1 的 span）
 *
 * 所以本版做两件事，一次运行出全部答案：
 *   1. 抓请求体：hook 所有「设置 body」的方法，只要内容像评论请求就整段打出来
 *      → 能看到 iOS 端 text_extra 的真实键名、真实格式（JSON 字符串还是数组）
 *   2. extraInfo 被写入非空时，把每个元素的类 / ivar / 取值全部打出来
 *      → 这是原生路径的模板，照着造就能绕过 KMP 覆盖
 *
 * 注入逻辑保留（v23 已证明能本地变红，留着做对照）。
 *
 * 【操作】发一条带话题的评论：  #测试 你好
 *         （这条会生成真实的 text_extra，请求体里必然带，好定位）
 *         再发一条纯文本 tt21（看注入效果）
 *         然后杀进程，导出 Documents/dyprobe_v24.txt
 *
 * 崩溃防护：
 *   - 只 hook 参数类型编码为 '@'（对象）的方法，避免把 C 指针当对象解引用
 *   - 所有转发包 @try
 *   - 日志硬上限 900 行
 */

#define DY_MAXLEN   6000
#define DY_MAXLINE  900
#define DY_BEACON   "[v24]"
#define DY_MAXHOOK  260

static int g_writes = 0;
static int g_injectN = 0;
static int g_bodySeen = 0;
static int g_bodyHit = 0;
static int g_extraN = 0;
static int g_rawN = 0;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static IMP g_origExtraParams = NULL;

/* 同线程最近一次设置的 URL，用来给 body 配对 */
static __thread char g_tlsURL[768];

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
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v24.txt", home);
        paths[n++] = p1; paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v24.txt", tmpd);
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
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v24.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v24.txt"]];
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
    if (g_writes < DY_MAXLINE) { g_writes++; @try { LRawLocked(s); } @catch (...) {} }
    pthread_mutex_unlock(&g_mtx);
}

/* 不加锁、不计数，给 hook 内部用（避免与主日志交错死锁） */
static void LFast(NSString *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mtx);
    if (g_writes < DY_MAXLINE) { g_writes++; @try { LRawLocked(s); } @catch (...) {} }
    pthread_mutex_unlock(&g_mtx);
}

static NSString *DYStr(id o) {
    if (!o) return @"(nil)";
    NSString *s = nil;
    @try {
        if ([o isKindOfClass:[NSString class]]) s = (NSString *)o;
        else if ([o isKindOfClass:[NSNumber class]]) s = [o description];
        else if ([NSJSONSerialization isValidJSONObject:o]) {
            NSData *d = [NSJSONSerialization dataWithJSONObject:o options:0 error:NULL];
            if (d) s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        }
        if (!s) s = [o description];
    } @catch (...) { s = @"(异常)"; }
    if (!s) s = @"(nil)";
    if (s.length > DY_MAXLEN) s = [[s substringToIndex:DY_MAXLEN] stringByAppendingString:@"…<截断>"];
    return s;
}

/* ===================== 调试开关 ===================== */
static NSString *DYDocPath(NSString *name) {
    NSString *d = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return d ? [d stringByAppendingPathComponent:name] : nil;
}

static BOOL DYSwitchOff(void) {
    static int cache = -1;
    if (cache >= 0) return cache == 1;
    NSString *p = DYDocPath(@"dyprobe_off.txt");
    cache = (p && [[NSFileManager defaultManager] fileExistsAtPath:p]) ? 1 : 0;
    return cache == 1;
}

static int DYTypeValue(void) {
    static int cache = -999;
    if (cache != -999) return cache;
    NSString *p = DYDocPath(@"dyprobe_type.txt");
    if (!p) { cache = 21; return cache; }
    NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:NULL];
    if (!s) { cache = 21; return cache; }
    int v = [s intValue];
    if (v == 0 && ![s hasPrefix:@"0"]) { cache = 21; return cache; }
    cache = v;
    return cache;
}

/* ===================== 调用栈反查 ===================== */
static void DYDumpStack(const char *tag) {
    void *bt[12];
    int n = backtrace(bt, 12);
    L(@"[STACK %s] %d 帧：", tag, n);
    for (int i = 1; i < n && i < 10; i++) {
        Dl_info info;
        if (dladdr(bt[i], &info) && info.dli_fname) {
            const char *base = strrchr(info.dli_fname, '/');
            base = base ? base + 1 : info.dli_fname;
            uintptr_t off = (uintptr_t)bt[i] - (uintptr_t)info.dli_fbase;
            L(@"[STACK %s]   #%d %s+0x%lx %s", tag, i, base,
              (unsigned long)off, info.dli_sname ? info.dli_sname : "");
        } else {
            L(@"[STACK %s]   #%d %p (无符号信息)", tag, i, bt[i]);
        }
    }
}

/* ===================== 请求体探测 ===================== */
static BOOL DYInteresting(NSString *s) {
    if (s.length < 8) return NO;
    if ([s containsString:@"comment"]) return YES;
    if ([s containsString:@"text_extra"]) return YES;
    if ([s containsString:@"textExtra"]) return YES;
    if ([s containsString:@"comment_text_extra"]) return YES;
    if ([s containsString:@"aweme_id"]) return YES;
    return NO;
}

static NSString *DYBodyRepr(id arg) {
    if (!arg) return nil;
    @try {
        if ([arg isKindOfClass:[NSString class]]) {
            return (NSString *)arg;
        }
        if ([arg isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)arg;
            if (d.length == 0 || d.length > 400000) return nil;
            /* 评论 body 是 form-urlencoded / JSON，纯文本可解 */
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s.length) return s;
            /* 可能是 zstd 压缩体（v17 见过 28 b5 2f fd），只报魔数 */
            const unsigned char *b = (const unsigned char *)d.bytes;
            if (d.length >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd) {
                return @"<zstd 压缩体，无法直接读>";
            }
            return nil;
        }
        if ([arg isKindOfClass:[NSDictionary class]] || [arg isKindOfClass:[NSArray class]]) {
            NSData *d = [NSJSONSerialization dataWithJSONObject:arg options:0 error:NULL];
            if (d) return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            return [arg description];
        }
        if ([arg isKindOfClass:[NSURL class]]) return [(NSURL *)arg absoluteString];
    } @catch (...) { return @"(取值异常)"; }
    return nil;
}

/* 统一的命中处理：只打「像评论请求」的内容 */
static void DYOnBody(id arg, const char *clsName, const char *selName) {
    g_bodySeen++;
    if (g_bodySeen > 40000) return;        /* 硬闸：避免高频 setter 拖慢主线程 */
    NSString *repr = DYBodyRepr(arg);
    if (!repr.length) return;
    if (!DYInteresting(repr)) return;

    g_bodyHit++;
    if (g_bodyHit > 40) return;   /* 命中太多只留前 40 条，避免刷屏 */

    NSString *shown = repr.length > DY_MAXLEN ? [[repr substringToIndex:DY_MAXLEN] stringByAppendingString:@"…<截断>"] : repr;
    NSString *tls = g_tlsURL[0] ? [NSString stringWithUTF8String:g_tlsURL] : @"";
    LFast([NSString stringWithFormat:@"\n===== [BODY #%d] %s -%s =====", g_bodyHit, clsName, selName]);
    if (tls.length) LFast([NSString stringWithFormat:@"[BODY #%d] 同线程最近 URL: %@", g_bodyHit, tls]);
    LFast([NSString stringWithFormat:@"[BODY #%d] 长度 %lu：%@", g_bodyHit, (unsigned long)repr.length, shown]);
}

/* 显式 hook 一个单参数 setter */
static IMP g_origSetHTTPBody = NULL;
static IMP g_origSetURL = NULL;

static void dy_setHTTPBody(id self, SEL _cmd, id arg) {
    @try {
        if (g_origSetHTTPBody) ((void (*)(id, SEL, id))g_origSetHTTPBody)(self, _cmd, arg);
    } @catch (...) {}
    @try { DYOnBody(arg, "NSMutableURLRequest", "setHTTPBody:"); } @catch (...) {}
}

static void dy_setURL(id self, SEL _cmd, id arg) {
    @try {
        if ([arg isKindOfClass:[NSURL class]]) {
            const char *u = [[(NSURL *)arg absoluteString] UTF8String];
            if (u) { strncpy(g_tlsURL, u, sizeof(g_tlsURL) - 1); g_tlsURL[sizeof(g_tlsURL) - 1] = 0; }
        }
    } @catch (...) {}
    @try {
        if (g_origSetURL) ((void (*)(id, SEL, id))g_origSetURL)(self, _cmd, arg);
    } @catch (...) {}
}

/* 运行时扫描：类名含网络关键词 + 精确 setter 名 + 参数是对象 → hook */
static const char *kSetters[] = {
    "setBody:", "setPostData:", "setBodyData:", "setHttpBody:",
    "setRequestBody:", "setPostBody:", "setRequestData:",
    "setPostBodyData:", "setHttpBodyData:", "setFormData:",
    "setPostParams:", "setParameters:", "setRequestParams:"
};
static const int kSetterCount = sizeof(kSetters) / sizeof(kSetters[0]);

static const char *kClsKeys[] = {
    "Net", "Network", "Http", "Request", "Task", "Api", "Channel", "Session", "Client"
};
static const int kClsKeyCount = sizeof(kClsKeys) / sizeof(kClsKeys[0]);

/* 强网络特征：先挂这些，避免被一堆业务 Request 类占满名额 */
static const char *kStrongKeys[] = { "Net", "Network", "Http", "Channel" };
static const int kStrongCount = sizeof(kStrongKeys) / sizeof(kStrongKeys[0]);

static BOOL DYClassMatches(const char *name) {
    if (!name) return NO;
    for (int i = 0; i < kClsKeyCount; i++) {
        if (strstr(name, kClsKeys[i])) return YES;
    }
    return NO;
}

static BOOL DYStrongMatch(const char *name) {
    if (!name) return NO;
    for (int i = 0; i < kStrongCount; i++) {
        if (strstr(name, kStrongKeys[i])) return YES;
    }
    return NO;
}

static int g_hookN = 0;
static int g_scanCls = 0;
static int g_scanMatch = 0;

/* pass: 0 = 只挂强网络类；1 = 只挂弱匹配类 */
static int DYScanPass(int pass) {
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) { L(@"[SCAN] 类表读取失败"); return 0; }
    Class *list = (Class *)malloc(sizeof(Class) * total);
    if (!list) { L(@"[SCAN] 内存不足"); return 0; }
    total = objc_getClassList(list, total);
    g_scanCls = total;
    int hookedThisPass = 0;

    for (int i = 0; i < total && g_hookN < DY_MAXHOOK; i++) {
        Class c = list[i];
        if (!c) continue;
        const char *cn = class_getName(c);
        if (!DYClassMatches(cn)) continue;
        BOOL strong = DYStrongMatch(cn);
        if (pass == 0 && !strong) continue;
        if (pass == 1 && strong) continue;
        g_scanMatch++;

        for (int k = 0; k < kSetterCount && g_hookN < DY_MAXHOOK; k++) {
            SEL want = sel_registerName(kSetters[k]);

            /* 只处理「本类自己实现」的方法：用 copyMethodList 而不是 class_getInstanceMethod，
               否则会改到父类的方法，多个子类重复 hook 会串成链，最终崩溃 */
            unsigned int mcount = 0;
            Method *mlist = class_copyMethodList(c, &mcount);
            if (!mlist) continue;
            Method m = NULL;
            for (unsigned int mi = 0; mi < mcount; mi++) {
                if (method_getName(mlist[mi]) == want) { m = mlist[mi]; break; }
            }
            if (!m) { free(mlist); continue; }

            /* 关键防护：必须恰好 self/_cmd/obj 三个参数，第 3 个是对象，且返回 void */
            unsigned int argc = method_getNumberOfArguments(m);
            if (argc != 3) { free(mlist); continue; }
            char tbuf[8] = {0};
            method_getArgumentType(m, 2, tbuf, sizeof(tbuf));
            if (tbuf[0] != '@') { free(mlist); continue; }
            char rbuf[8] = {0};
            method_getReturnType(m, rbuf, sizeof(rbuf));
            if (rbuf[0] != 'v') { free(mlist); continue; }

            /* 系统库里的类已经显式处理过，跳过 */
            const char *mod = class_getImageName(c);
            if (mod && strstr(mod, "/System/Library/")) { free(mlist); continue; }

            char *dumpCls = strdup(cn);
            char *dumpSel = strdup(kSetters[k]);
            if (!dumpCls || !dumpSel) { if (dumpCls) free(dumpCls); if (dumpSel) free(dumpSel); free(mlist); continue; }

            IMP orig = method_getImplementation(m);
            SEL origSel = want;
            id block = ^(id self_, id arg) {
                /* 必须把 arg 传回原实现，否则原逻辑拿不到 body */
                @try { if (orig) ((void (*)(id, SEL, id))orig)(self_, origSel, arg); } @catch (...) {}
                @try { DYOnBody(arg, dumpCls, dumpSel); } @catch (...) {}
            };
            IMP newImp = imp_implementationWithBlock(block);
            method_setImplementation(m, newImp);
            free(mlist);
            g_hookN++;
            hookedThisPass++;
        }
    }
    free(list);
    return hookedThisPass;
}

static void DYScanAndHook(void) {
    int a = DYScanPass(0);
    int b = DYScanPass(1);
    L(@"[SCAN] 类总数 %d，强网络类命中 %d 个 hook，其它命中 %d 个 hook，合计 %d",
      g_scanCls, a, b, g_hookN);
}

/* ===================== extraInfo 结构情报 ===================== */
static void DYDumpObjectFields(id o, NSString *tag) {
    if (!o) return;
    Class c = object_getClass(o);
    if (!c) return;
    L(@"[EI] %@ 元素类 = %s", tag, class_getName(c));

    /* 候选选择器安全取值（只取能安全转成字符串/数字的） */
    NSArray *cands = @[@"start", @"end", @"type", @"subType", @"sub_type",
                       @"userId", @"user_id", @"secUid", @"sec_uid",
                       @"hashtagName", @"hashTagName", @"hashtagId",
                       @"text", @"content", @"name", @"range"];
    NSMutableArray *vals = [NSMutableArray array];
    for (NSString *sel in cands) {
        SEL s = NSSelectorFromString(sel);
        if (![o respondsToSelector:s]) continue;
        @try {
            NSMethodSignature *sig = [o methodSignatureForSelector:s];
            if (!sig) continue;
            const char *rt = sig.methodReturnType;
            if (!rt) continue;
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
            [inv setTarget:o];
            [inv setSelector:s];
            [inv invoke];
            if (rt[0] == '@') {
                __unsafe_unretained id v = nil;
                [inv getReturnValue:&v];
                if (v) [vals addObject:[NSString stringWithFormat:@"%@=%@", sel, DYStr(v)]];
            } else if (rt[0] == 'i' || rt[0] == 's') {
                int v = 0; [inv getReturnValue:&v];
                [vals addObject:[NSString stringWithFormat:@"%@=%d", sel, v]];
            } else if (rt[0] == 'q' || rt[0] == 'Q') {
                long long v = 0; [inv getReturnValue:&v];
                [vals addObject:[NSString stringWithFormat:@"%@=%lld", sel, v]];
            } else if (rt[0] == 'B') {
                BOOL v = NO; [inv getReturnValue:&v];
                [vals addObject:[NSString stringWithFormat:@"%@=%d", sel, (int)v]];
            }
        } @catch (...) {}
    }
    if (vals.count) L(@"[EI] %@ 取值: %@", tag, [vals componentsJoinedByString:@", "]);
    else L(@"[EI] %@ 候选选择器全部取不到值", tag);

    /* ivar 兜底（Swift/KMP 类属性 0 个，但 ivar 有东西） */
    int lvl = 0;
    Class cur = c;
    while (cur && cur != [NSObject class] && lvl < 2) {
        unsigned int n = 0;
        Ivar *iv = class_copyIvarList(cur, &n);
        NSMutableArray *a = [NSMutableArray array];
        for (unsigned int i = 0; i < n && i < 30; i++) {
            const char *nm = ivar_getName(iv[i]);
            const char *tp = ivar_getTypeEncoding(iv[i]);
            if (nm) [a addObject:[NSString stringWithFormat:@"%s:%s", nm, tp ? tp : "?"]];
        }
        if (iv) free(iv);
        if (n) L(@"[EI] %@ ivar(%s) %u 个: %@", tag, class_getName(cur), n, [a componentsJoinedByString:@", "]);
        cur = class_getSuperclass(cur);
        lvl++;
    }
}

/* ===================== 注入（沿用 v23） ===================== */
static NSString *DYBuildTextExtra(NSString *text, int type) {
    if (![text isKindOfClass:[NSString class]] || text.length == 0) return nil;
    NSUInteger bytes = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (bytes == 0) return nil;

    NSMutableDictionary *span = [NSMutableDictionary dictionary];
    span[@"start"] = @0;
    span[@"end"] = @(bytes);
    span[@"type"] = @(type);

    NSData *d = [NSJSONSerialization dataWithJSONObject:@[ span ] options:0 error:NULL];
    if (!d) return nil;
    return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
}

static id dy_extraParams(id self, SEL _cmd) {
    id r = nil;
    @try { if (g_origExtraParams) r = ((id (*)(id, SEL))g_origExtraParams)(self, _cmd); } @catch (...) {}

    /* 只在前 3 次打印调用栈（回答「谁在读这个字典」） */
    if (g_injectN < 3) {
        @try { DYDumpStack("G-extraParams"); } @catch (...) {}
    }

    if (![r isKindOfClass:[NSDictionary class]]) {
        if (g_injectN < 3) { g_injectN++; L(@"[INJECT] extraParams 不是字典（%@），跳过", r ? NSStringFromClass([r class]) : @"nil"); }
        return r;
    }

    /* 【最重要】原生已经有 text_extra 时（带话题/艾特的评论），原样打出来 —— 这是 iOS 端真实格式 */
    if (g_rawN < 3) {
        NSArray *keyCands = @[@"text_extra", @"textExtra", @"text_extra_list", @"comment_text_extra"];
        for (NSString *k in keyCands) {
            id v = r[k];
            if (v) {
                g_rawN++;
                L(@"[RAW #%d] extraParams 原生键「%@」类型=%@ 值=%@",
                  g_rawN, k, NSStringFromClass([v class]), DYStr(v));
                break;
            }
        }
    }

    if (DYSwitchOff()) {
        if (g_injectN < 3) { g_injectN++; L(@"[INJECT] 检测到 dyprobe_off.txt，本版不注入（对照组）"); }
        return r;
    }

    NSString *text = nil;
    @try { text = [self valueForKeyPath:@"contentModel.content"]; } @catch (...) {}

    int type = DYTypeValue();
    NSString *js = DYBuildTextExtra(text, type);
    if (!js) {
        if (g_injectN < 3) { g_injectN++; L(@"[INJECT] 正文为空或取不到（text=%@），跳过", DYStr(text)); }
        return r;
    }

    NSMutableDictionary *m = [r mutableCopy];
    m[@"text_extra"] = js;

    if (g_injectN < 6) {
        g_injectN++;
        L(@"[INJECT #%d] type=%d 正文=「%@」(%lu 字节) → text_extra=%@",
          g_injectN, type, text, (unsigned long)[text lengthOfBytesUsingEncoding:NSUTF8StringEncoding], js);
    }
    return m;
}

/* ===================== 安装 ===================== */
static void DYInstall(void) {
    /* 一、注入 */
    Class pm = objc_getClass("AWECommentPublishParameterModel");
    if (pm) {
        SEL sel = sel_registerName("extraParams");
        Method m = class_getInstanceMethod(pm, sel);
        if (m) {
            g_origExtraParams = method_setImplementation(m, (IMP)dy_extraParams);
            L(@"[HOOK] -extraParams 已接管（注入 text_extra），默认 type=%d", DYTypeValue());
        } else {
            L(@"[FATAL] -extraParams 不存在，注入不可用");
        }
    } else {
        L(@"[FATAL] AWECommentPublishParameterModel 不存在");
    }

    /* 二、extraInfo 写入时 dump 结构（原生路径模板） */
    Class icm = objc_getClass("AWECommentInputContentModel");
    if (icm) {
        SEL sel = sel_registerName("setExtraInfo:");
        Method m = class_getInstanceMethod(icm, sel);
        if (m) {
            __block IMP orig = method_getImplementation(m);
            SEL origSel = sel;
            id block = ^(id self_, id arg) {
                @try { if (orig) ((void (*)(id, SEL, id))orig)(self_, origSel, arg); } @catch (...) {}
                @try {
                    if (!arg || ![arg isKindOfClass:[NSArray class]]) return;
                    NSArray *a = (NSArray *)arg;
                    if (a.count == 0) return;
                    if (g_extraN >= 3) return;
                    g_extraN++;
                    L(@"\n===== [EI #%d] extraInfo 被写入 %lu 个元素 =====", g_extraN, (unsigned long)a.count);
                    NSUInteger lim = a.count > 4 ? 4 : a.count;
                    for (NSUInteger i = 0; i < lim; i++) {
                        DYDumpObjectFields(a[i], [NSString stringWithFormat:@"#%d-%lu", g_extraN, (unsigned long)i]);
                    }
                } @catch (...) {}
            };
            IMP newImp = imp_implementationWithBlock(block);
            method_setImplementation(m, newImp);
            L(@"[HOOK] -setExtraInfo: 已接管（非空时 dump 元素结构）");
        }
    }

    /* 三、显式 hook NSMutableURLRequest */
    Class req = objc_getClass("NSMutableURLRequest");
    if (req) {
        Method m1 = class_getInstanceMethod(req, sel_registerName("setHTTPBody:"));
        if (m1) {
            g_origSetHTTPBody = method_setImplementation(m1, (IMP)dy_setHTTPBody);
            L(@"[HOOK] NSMutableURLRequest -setHTTPBody:");
        }
        Method m2 = class_getInstanceMethod(req, sel_registerName("setURL:"));
        if (m2) {
            g_origSetURL = method_setImplementation(m2, (IMP)dy_setURL);
            L(@"[HOOK] NSMutableURLRequest -setURL:");
        }
    }

    /* 四、扫描网络类的 body setter */
    DYScanAndHook();

    L(@"[DONE] v24 安装完成");
}

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    DYBeacon("dylib 已加载");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v24] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v24] 安装异常，已忽略"); }
            L(@"[v24] 请发一条带话题的评论：#测试 你好   （这条必然生成 text_extra）");
            L(@"[v24] 再发一条纯文本 tt21，然后杀进程导出 Documents/dyprobe_v24.txt");
        }
    });

    /* 心跳 */
    for (int i = 1; i <= 6; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 15.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
            @autoreleasepool {
                L(@"[心跳 %ds] 已写 %d 行 / body 见过 %d 次 / 命中 %d 次",
                  i * 15, g_writes, g_bodySeen, g_bodyHit);
            }
        });
    }
}
