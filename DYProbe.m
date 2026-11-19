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
 * DYProbe v25 —— 查服务端到底有没有收下 text_extra
 *
 * v24 已证实（铁证，不是推测）：
 *   comment/publish 请求体 = extraParams 直通，实测发出去的是：
 *   text=%23ai%20666&text_extra=[{"start":0,"end":7,"type":21}]
 *   字段名 / JSON 字符串 / UTF-8 字节偏移 / type=21 全部与网页端一致
 *   → 客户端这一侧没有任何问题，问题在服务端是否接受
 *
 * 剩下两种可能，必须用「服务端响应」区分：
 *   A. 服务端收了并回传了 text_extra → 任务其实已成，只是网页端不渲染 type=21
 *   B. 服务端剥离了 text_extra → 需要补字段（自己的 user_id/sec_uid）或换路径
 *
 * 本版做三件事：
 *   1. 抓响应体（类名含 Response 的 setBody/setData 等），命中 text_extra 就把
 *      它前后文整段打出来 —— 一眼看出服务端存没存
 *   2. 找自己的 uid / sec_uid（NSUserDefaults 里的登录信息），下一版给 span 补上
 *   3. 关掉注入的开关改成实时读盘（放/删 Documents/dyprobe_off.txt 立即生效，
 *      不用重装）—— 方便你发一条「原生话题评论」看原始 text_extra 长什么样
 *
 * 噪音比 v24 大幅降低：只留含 publish_scene / text_extra / comment / aweme_id
 * 且长度不大的 body，同一 unique_key 只打一次。
 */

#define DY_MAXLEN   6000
#define DY_MAXLINE  500
#define DY_BEACON   "[v25]"
#define DY_MAXHOOK  300

static int g_writes = 0;
static int g_injectN = 0;
static int g_bodySeen = 0;
static int g_bodyHit = 0;
static int g_respHit = 0;
static int g_rawN = 0;
static int g_extraN = 0;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static IMP g_origExtraParams = NULL;
static NSString *g_myUid = nil;
static NSString *g_mySecUid = nil;
static NSString *g_lastBody = nil;

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
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v25.txt", home);
        paths[n++] = p1; paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v25.txt", tmpd);
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
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v25.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v25.txt"]];
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

/* ===================== 调试开关（实时读盘，不缓存） ===================== */
static NSString *DYDocPath(NSString *name) {
    NSString *d = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return d ? [d stringByAppendingPathComponent:name] : nil;
}

static BOOL DYSwitchOff(void) {
    NSString *p = DYDocPath(@"dyprobe_off.txt");
    return (p && [[NSFileManager defaultManager] fileExistsAtPath:p]) ? YES : NO;
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

/* ===================== 找自己的 uid / sec_uid ===================== */
static void DYFindMyUser(void) {
    @try {
        NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        NSMutableArray *hits = [NSMutableArray array];
        NSMutableArray *keys = [NSMutableArray arrayWithArray:[all allKeys]];
        for (NSString *k in keys) {
            if (![k isKindOfClass:[NSString class]]) continue;
            NSString *lk = [k lowercaseString];
            BOOL want = ([lk containsString:@"sec_uid"] || [lk containsString:@"secuid"]
                         || [lk containsString:@"user_id"] || [lk containsString:@"userid"]
                         || [lk isEqualToString:@"uid"]);
            if (!want) continue;
            id v = all[k];
            if (!([v isKindOfClass:[NSString class]] || [v isKindOfClass:[NSNumber class]])) continue;
            NSString *sv = [v description];
            if (sv.length == 0 || sv.length > 200) continue;
            [hits addObject:[NSString stringWithFormat:@"%@=%@", k, sv]];
            NSString *lk2 = lk;
            if ([lk2 containsString:@"sec"]) { if (!g_mySecUid) g_mySecUid = [sv copy]; }
            else if (!g_myUid) g_myUid = [sv copy];
        }
        if (hits.count) {
            NSUInteger lim = hits.count > 30 ? 30 : hits.count;
            L(@"[MYUSER] NSUserDefaults 里找到 %lu 条 uid 相关项：", (unsigned long)hits.count);
            for (NSUInteger i = 0; i < lim; i++) L(@"[MYUSER]   %@", hits[i]);
        } else {
            L(@"[MYUSER] NSUserDefaults 里没有 uid 相关项，下一版改用账号服务取");
        }
    } @catch (...) { L(@"[MYUSER] 读取异常"); }
    L(@"[MYUSER] 采用值：uid=%@ sec_uid=%@", g_myUid ?: @"(空)", g_mySecUid ?: @"(空)");
}

/* ===================== 抓 body / response ===================== */
static BOOL DYInteresting(NSString *s) {
    if (s.length < 8) return NO;
    if ([s containsString:@"publish_scene"]) return YES;      /* 评论发布请求 */
    if ([s containsString:@"text_extra"]) return YES;         /* 任何带 text_extra 的 */
    if ([s containsString:@"comment"] && s.length < 8000) return YES;
    if ([s containsString:@"aweme_id"] && s.length < 8000) return YES;
    return NO;
}

static NSString *DYBodyRepr(id arg) {
    if (!arg) return nil;
    @try {
        if ([arg isKindOfClass:[NSString class]]) return (NSString *)arg;
        if ([arg isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)arg;
            if (d.length == 0 || d.length > 400000) return nil;
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s.length) return s;
            const unsigned char *b = (const unsigned char *)d.bytes;
            if (d.length >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd) {
                return @"<zstd 压缩体>";
            }
            return nil;
        }
        if ([arg isKindOfClass:[NSDictionary class]] || [arg isKindOfClass:[NSArray class]]) {
            NSData *d = [NSJSONSerialization dataWithJSONObject:arg options:0 error:NULL];
            if (d) return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            return [arg description];
        }
    } @catch (...) { return @"(取值异常)"; }
    return nil;
}

/* 把 needle 前后文整段打出来 —— 响应体很长时也能定位 text_extra */
static void DYEmitAround(NSString *s, NSString *needle, int idx, NSString *label) {
    NSRange r = [s rangeOfString:needle];
    if (r.location == NSNotFound) return;
    NSUInteger start = r.location > 300 ? r.location - 300 : 0;
    NSUInteger end = NSMaxRange(r) + 500;
    if (end > s.length) end = s.length;
    NSString *seg = [s substringWithRange:NSMakeRange(start, end - start)];
    LFast([NSString stringWithFormat:@"[%@ #%d] 命中「%@」上下文：%@", label, idx, needle, seg]);
}

static void DYOnBody(id arg, const char *clsName, const char *selName, BOOL isResp) {
    if (isResp) {
        NSString *repr = DYBodyRepr(arg);
        if (!repr.length) return;
        if (![repr containsString:@"text_extra"] && ![repr containsString:@"publish_scene"]) return;
        g_respHit++;
        if (g_respHit > 20) return;
        LFast([NSString stringWithFormat:@"\n===== [RESP #%d] %s -%s （长度 %lu）=====", g_respHit, clsName, selName, (unsigned long)repr.length]);
        DYEmitAround(repr, @"text_extra", g_respHit, @"RESP");
        if (![repr containsString:@"text_extra"]) {
            NSString *shown = repr.length > 1500 ? [repr substringToIndex:1500] : repr;
            LFast([NSString stringWithFormat:@"[RESP #%d] 无 text_extra，前段：%@", g_respHit, shown]);
        }
        return;
    }

    g_bodySeen++;
    if (g_bodySeen > 40000) return;
    NSString *repr = DYBodyRepr(arg);
    if (!repr.length) return;
    if (!DYInteresting(repr)) return;

    /* 同一份 body 只打一次（同一请求常被 setBody 调用两次） */
    NSString *head = repr.length > 300 ? [repr substringToIndex:300] : repr;
    if (g_lastBody && [g_lastBody isEqualToString:head]) return;
    g_lastBody = [head copy];

    g_bodyHit++;
    if (g_bodyHit > 30) return;

    NSString *shown = repr.length > DY_MAXLEN ? [[repr substringToIndex:DY_MAXLEN] stringByAppendingString:@"…<截断>"] : repr;
    LFast([NSString stringWithFormat:@"\n===== [BODY #%d] %s -%s =====", g_bodyHit, clsName, selName]);
    LFast([NSString stringWithFormat:@"[BODY #%d] 长度 %lu：%@", g_bodyHit, (unsigned long)repr.length, shown]);
    if ([repr containsString:@"text_extra"]) DYEmitAround(repr, @"text_extra", g_bodyHit, @"BODY");
}

/* ===================== 显式 hook NSMutableURLRequest ===================== */
static IMP g_origSetHTTPBody = NULL;
static void dy_setHTTPBody(id self, SEL _cmd, id arg) {
    @try { if (g_origSetHTTPBody) ((void (*)(id, SEL, id))g_origSetHTTPBody)(self, _cmd, arg); } @catch (...) {}
    @try { DYOnBody(arg, "NSMutableURLRequest", "setHTTPBody:", NO); } @catch (...) {}
}

/* ===================== 运行时扫描 ===================== */
static const char *kSetters[] = {
    "setBody:", "setPostData:", "setBodyData:", "setHttpBody:",
    "setRequestBody:", "setPostBody:", "setRequestData:",
    "setPostBodyData:", "setHttpBodyData:", "setFormData:",
    "setPostParams:", "setParameters:", "setRequestParams:",
    "setResponseBody:", "setRawData:", "setResponseData:"
};
static const int kSetterCount = sizeof(kSetters) / sizeof(kSetters[0]);

static const char *kStrongKeys[] = { "Net", "Network", "Http", "Channel" };
static const int kStrongCount = sizeof(kStrongKeys) / sizeof(kStrongKeys[0]);
static const char *kWeakKeys[] = { "Request", "Task", "Api", "Session", "Client" };
static const int kWeakCount = sizeof(kWeakKeys) / sizeof(kWeakKeys[0]);

static BOOL DYHasKey(const char *name, const char **keys, int n) {
    if (!name) return NO;
    for (int i = 0; i < n; i++) if (strstr(name, keys[i])) return YES;
    return NO;
}

static int g_hookN = 0;

/* pass 0 = 强网络类 / 1 = 弱匹配类 / 2 = Response 类 */
static int DYScanPass(int pass) {
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) return 0;
    Class *list = (Class *)malloc(sizeof(Class) * total);
    if (!list) return 0;
    total = objc_getClassList(list, total);
    int hooked = 0;

    for (int i = 0; i < total && g_hookN < DY_MAXHOOK; i++) {
        Class c = list[i];
        if (!c) continue;
        const char *cn = class_getName(c);
        BOOL strong = DYHasKey(cn, kStrongKeys, kStrongCount);
        BOOL weak = DYHasKey(cn, kWeakKeys, kWeakCount);
        BOOL isResp = (strstr(cn, "Response") != NULL);
        BOOL want = NO;
        if (pass == 0 && strong) want = YES;
        if (pass == 1 && weak && !strong) want = YES;
        if (pass == 2 && isResp) want = YES;
        if (!want) continue;

        const char *mod = class_getImageName(c);
        if (mod && strstr(mod, "/System/Library/")) continue;

        unsigned int mcount = 0;
        Method *mlist = class_copyMethodList(c, &mcount);
        if (!mlist) continue;

        for (unsigned int mi = 0; mi < mcount && g_hookN < DY_MAXHOOK; mi++) {
            const char *sn = sel_getName(method_getName(mlist[mi]));
            if (!sn) continue;
            BOOL matched = NO;
            for (int k = 0; k < kSetterCount; k++) {
                if (strcmp(sn, kSetters[k]) == 0) { matched = YES; break; }
            }
            if (!matched) continue;

            Method m = mlist[mi];
            if (method_getNumberOfArguments(m) != 3) continue;
            char tbuf[8] = {0};
            method_getArgumentType(m, 2, tbuf, sizeof(tbuf));
            if (tbuf[0] != '@') continue;
            char rbuf[8] = {0};
            method_getReturnType(m, rbuf, sizeof(rbuf));
            if (rbuf[0] != 'v') continue;

            char *dumpCls = strdup(cn);
            char *dumpSel = strdup(sn);
            if (!dumpCls || !dumpSel) { if (dumpCls) free(dumpCls); if (dumpSel) free(dumpSel); continue; }

            IMP orig = method_getImplementation(m);
            SEL origSel = method_getName(m);
            BOOL resp = isResp;
            id block = ^(id self_, id arg) {
                @try { if (orig) ((void (*)(id, SEL, id))orig)(self_, origSel, arg); } @catch (...) {}
                @try { DYOnBody(arg, dumpCls, dumpSel, resp); } @catch (...) {}
            };
            method_setImplementation(m, imp_implementationWithBlock(block));
            g_hookN++;
            hooked++;
        }
        free(mlist);
    }
    free(list);
    return hooked;
}

/* ===================== extraInfo 结构 ===================== */
static void DYDumpObjectFields(id o, NSString *tag) {
    if (!o) return;
    Class c = object_getClass(o);
    if (!c) return;
    L(@"[EI] %@ 元素类 = %s", tag, class_getName(c));

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
}

/* ===================== 注入 ===================== */
static NSString *DYBuildTextExtra(NSString *text, int type) {
    if (![text isKindOfClass:[NSString class]] || text.length == 0) return nil;
    NSUInteger bytes = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (bytes == 0) return nil;

    NSMutableDictionary *span = [NSMutableDictionary dictionary];
    span[@"start"] = @0;
    span[@"end"] = @(bytes);
    span[@"type"] = @(type);
    if (g_myUid.length) span[@"user_id"] = g_myUid;
    if (g_mySecUid.length) span[@"sec_uid"] = g_mySecUid;

    NSData *d = [NSJSONSerialization dataWithJSONObject:@[ span ] options:0 error:NULL];
    if (!d) return nil;
    return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
}

static id dy_extraParams(id self, SEL _cmd) {
    id r = nil;
    @try { if (g_origExtraParams) r = ((id (*)(id, SEL))g_origExtraParams)(self, _cmd); } @catch (...) {}

    if (![r isKindOfClass:[NSDictionary class]]) return r;

    /* 原生已有 text_extra 时（带话题/艾特的评论）打出来 —— iOS 端真实格式 */
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
        if (g_injectN < 2) { g_injectN++; L(@"[INJECT] dyprobe_off.txt 存在 → 不注入（观察原生）"); }
        return r;
    }

    NSString *text = nil;
    @try { text = [self valueForKeyPath:@"contentModel.content"]; } @catch (...) {}
    if (![text isKindOfClass:[NSString class]] || text.length == 0) return r;

    int type = DYTypeValue();
    NSString *js = DYBuildTextExtra(text, type);
    if (!js) return r;

    NSMutableDictionary *m = [r mutableCopy];
    m[@"text_extra"] = js;

    if (g_injectN < 6) {
        g_injectN++;
        L(@"[INJECT #%d] type=%d 正文=「%@」(%lu 字节) → text_extra=%@",
          g_injectN, type, text,
          (unsigned long)[text lengthOfBytesUsingEncoding:NSUTF8StringEncoding], js);
    }
    return m;
}

/* ===================== 安装 ===================== */
static void DYInstall(void) {
    DYFindMyUser();

    Class pm = objc_getClass("AWECommentPublishParameterModel");
    if (pm) {
        Method m = class_getInstanceMethod(pm, sel_registerName("extraParams"));
        if (m) {
            g_origExtraParams = method_setImplementation(m, (IMP)dy_extraParams);
            L(@"[HOOK] -extraParams 已接管，默认 type=%d", DYTypeValue());
        }
    }

    Class icm = objc_getClass("AWECommentInputContentModel");
    if (icm) {
        Method m = class_getInstanceMethod(icm, sel_registerName("setExtraInfo:"));
        if (m) {
            IMP orig = method_getImplementation(m);
            SEL origSel = sel_registerName("setExtraInfo:");
            id block = ^(id self_, id arg) {
                @try { if (orig) ((void (*)(id, SEL, id))orig)(self_, origSel, arg); } @catch (...) {}
                @try {
                    if (!arg || ![arg isKindOfClass:[NSArray class]]) return;
                    NSArray *a = (NSArray *)arg;
                    if (a.count == 0 || g_extraN >= 2) return;
                    g_extraN++;
                    L(@"\n===== [EI #%d] extraInfo 写入 %lu 个元素 =====", g_extraN, (unsigned long)a.count);
                    NSUInteger lim = a.count > 4 ? 4 : a.count;
                    for (NSUInteger i = 0; i < lim; i++) {
                        DYDumpObjectFields(a[i], [NSString stringWithFormat:@"#%d-%lu", g_extraN, (unsigned long)i]);
                    }
                } @catch (...) {}
            };
            method_setImplementation(m, imp_implementationWithBlock(block));
            L(@"[HOOK] -setExtraInfo:");
        }
    }

    Class req = objc_getClass("NSMutableURLRequest");
    if (req) {
        Method m1 = class_getInstanceMethod(req, sel_registerName("setHTTPBody:"));
        if (m1) g_origSetHTTPBody = method_setImplementation(m1, (IMP)dy_setHTTPBody);
    }

    int a = DYScanPass(0), b = DYScanPass(1), c = DYScanPass(2);
    L(@"[SCAN] 强网络 %d / 其它 %d / 响应 %d，合计 %d 个 hook", a, b, c, g_hookN);
    L(@"[DONE] v25 安装完成");
}

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    DYBeacon("dylib 已加载");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v25] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v25] 安装异常，已忽略"); }
            L(@"[v25] 发一条 tt21。重点看日志里 [RESP #n] 有没有 text_extra");
        }
    });

    for (int i = 1; i <= 8; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 15.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
            @autoreleasepool {
                L(@"[心跳 %ds] 行 %d / body %d / 命中 %d / 响应命中 %d",
                  i * 15, g_writes, g_bodySeen, g_bodyHit, g_respHit);
            }
        });
    }
}
