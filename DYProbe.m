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
 * DYProbe v26 —— 补上 span 的 user_id / sec_uid
 *
 * 已确证（v24 铁证 + 网页端脚本逐行比对）：
 *   1. comment/publish 请求体里 text_extra 已经发出去了：
 *      [{"start":0,"end":4,"type":21}]   —— 格式/偏移/type 全对
 *   2. 但网页端脚本发的是：
 *      [{"start":0,"end":4,"type":21,"user_id":"...","sec_uid":"MS4wLjABAAAA..."}]
 *      脚本注释原话：「自己账号的 uid / sec_uid（span 里带上，服务器更认）」
 *      而且 type=0 时拿不到账号信息会直接拦下不发 → 服务端对 span 归属有校验
 *   3. v24 发出去的 span 没有这两个字段 → 服务端无法确认 span 属于评论者本人
 *
 * v26 做三件事：
 *   A. 三路取自己的 uid/sec_uid（v25 只扫 key 名，扫不到）：
 *      ① 缓存文件 Documents/dyprobe_uid.txt（可手写 uid|sec_uid 强制指定）
 *      ② NSUserDefaults 深扫值内容（递归，认 MS4wLjABAAAA 前缀 + 就近配对 uid）
 *      ③ 反射账号服务类（AWEUserModel / TTAccount / IESAccountManager 等）
 *   B. 注入时带上 user_id / sec_uid（拿不到就裸发，不崩）
 *   C. 发布响应里回捞 uid —— 第一次发完自动缓存，第二条起自动带
 *
 * 另外：响应体一旦出现 text_extra 就整段打出来，直接看服务端存没存。
 */

#define DY_MAXLEN   6000
#define DY_MAXLINE  700
#define DY_BEACON   "[v26]"
#define DY_MAXHOOK  300

static int g_writes = 0;
static int g_injectN = 0;
static int g_bodySeen = 0;
static int g_bodyHit = 0;
static int g_respHit = 0;
static int g_rawN = 0;
static int g_extraN = 0;
static int g_userN = 0;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static IMP g_origExtraParams = NULL;
static NSString *g_myUid = nil;
static NSString *g_mySecUid = nil;
static NSString *g_lastBody = nil;
static NSString *g_uidSource = @"无";

/* ===================== 信标（纯 C，构造即写） ===================== */
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
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v26.txt", home);
        paths[n++] = p1; paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v26.txt", tmpd);
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
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v26.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v26.txt"]];
    for (NSString *p in targets) {
        FILE *f = fopen(p.fileSystemRepresentation, "a");
        if (!f) continue;
        fwrite(d.bytes, 1, d.length, f);
        fflush(f); fclose(f);
    }
}

static void LFast(NSString *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mtx);
    if (g_writes < DY_MAXLINE) { g_writes++; @try { LRawLocked(s); } @catch (...) {} }
    pthread_mutex_unlock(&g_mtx);
}

static void L(NSString *fmt, ...) {
    if (!fmt) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    LFast(s);
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

/* ===================== 路径 / 开关 ===================== */
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

/* ===================== 正则工具 ===================== */
static NSString *DYFirstMatch(NSString *s, NSString *pat) {
    if (![s isKindOfClass:[NSString class]] || s.length < 8) return nil;
    @try {
        NSError *e = nil;
        NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pat options:0 error:&e];
        if (!re || e) return nil;
        NSTextCheckingResult *m = [re firstMatchInString:s options:0 range:NSMakeRange(0, s.length)];
        if (!m || m.numberOfRanges < 2) return nil;
        NSRange r = [m rangeAtIndex:1];
        if (r.location == NSNotFound || r.length == 0) return nil;
        return [s substringWithRange:r];
    } @catch (...) { return nil; }
}

/* ===================== uid 缓存 ===================== */
static void DYLoadUidCache(void) {
    NSString *p = DYDocPath(@"dyprobe_uid.txt");
    if (!p) return;
    NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:NULL];
    if (!s) return;
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!s.length) return;
    NSArray *parts = [s componentsSeparatedByString:@"|"];
    if (parts.count < 2) return;
    NSString *u = [parts[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *su = [parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (u.length >= 5 && su.length >= 10) {
        g_myUid = [u copy];
        g_mySecUid = [su copy];
        g_uidSource = @"缓存文件";
    }
}

static void DYSaveUidCache(void) {
    if (g_myUid.length < 5 || g_mySecUid.length < 10) return;
    NSString *p = DYDocPath(@"dyprobe_uid.txt");
    if (!p) return;
    NSString *s = [NSString stringWithFormat:@"%@|%@\n", g_myUid, g_mySecUid];
    [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

/* ===================== NSUserDefaults 深扫 ===================== */
/* 抖音把登录信息藏在值里（JSON 字符串 / NSData），不是藏在 key 名上 */
static long g_scanNodes = 0;

static void DYScanStringValue(NSString *s, NSMutableArray *pairs) {
    if (![s isKindOfClass:[NSString class]]) return;
    if (s.length < 40 || s.length > 300000) return;
    if (![s containsString:@"MS4wLjABAAAA"]) return;

    NSString *su = DYFirstMatch(s, @"(MS4wLjABAAAA[A-Za-z0-9_\\-]{10,})");
    if (!su) return;
    NSString *u = DYFirstMatch(s, @"\"uid\"\\s*:\\s*\"?([0-9]{5,})");
    if (!u) u = DYFirstMatch(s, @"\"user_id\"\\s*:\\s*\"?([0-9]{5,})");
    if (!u) u = DYFirstMatch(s, @"\"userId\"\\s*:\\s*\"?([0-9]{5,})");
    if (!u) u = DYFirstMatch(s, @"(?:^|[^0-9])uid=(\\d{5,})");
    if (u && su) [pairs addObject:@[u, su]];
}

static void DYScanObject(id o, int depth, NSMutableArray *pairs) {
    if (!o || depth > 4) return;
    if (++g_scanNodes > 30000) return;
    @try {
        if ([o isKindOfClass:[NSString class]]) {
            DYScanStringValue((NSString *)o, pairs);
        } else if ([o isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)o;
            if (d.length > 0 && d.length < 300000) {
                NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (s) DYScanStringValue(s, pairs);
            }
        } else if ([o isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)o;
            for (id k in dict) {
                if ([k isKindOfClass:[NSString class]]) DYScanStringValue((NSString *)k, pairs);
                DYScanObject(dict[k], depth + 1, pairs);
            }
        } else if ([o isKindOfClass:[NSArray class]]) {
            for (id v in (NSArray *)o) DYScanObject(v, depth + 1, pairs);
        }
    } @catch (...) {}
}

static void DYScanDefaults(void) {
    @try {
        NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        if (!all) { L(@"[MYUSER] defaults 为空"); return; }
        NSMutableArray *pairs = [NSMutableArray array];
        g_scanNodes = 0;
        NSInteger scanned = 0;
        for (id k in all) {
            if (++scanned > 5000) break;
            DYScanObject(all[k], 0, pairs);
        }
        L(@"[MYUSER] defaults 深扫：遍历 %ld 个 key，配对成功 %lu 组",
          (long)scanned, (unsigned long)pairs.count);
        if (pairs.count) {
            NSUInteger lim = pairs.count > 8 ? 8 : pairs.count;
            for (NSUInteger i = 0; i < lim; i++) {
                NSArray *p = pairs[i];
                L(@"[MYUSER]   候选 #%lu uid=%@ sec_uid=%@", (unsigned long)(i + 1), p[0], p[1]);
            }
            if (!g_myUid.length) {
                NSArray *p = pairs.firstObject;
                g_myUid = [p[0] copy];
                g_mySecUid = [p[1] copy];
                g_uidSource = @"defaults 深扫";
            }
        }
    } @catch (...) { L(@"[MYUSER] defaults 读取异常"); }
}

/* ===================== 反射账号服务 ===================== */
static id DYCallClassMethod(Class c, SEL s) {
    if (!c || !s) return nil;
    @try {
        if (![c respondsToSelector:s]) return nil;
        Class meta = object_getClass((id)c);
        IMP imp = class_getMethodImplementation(meta, s);
        if (!imp) return nil;
        id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
        return fn((id)c, s);
    } @catch (...) { return nil; }
}

/* 从任意对象上取 uid / sec_uid，成功返回 YES */
static BOOL DYPickFromObject(id obj, const char **fromWhat) {
    if (!obj) return NO;
    NSArray *uidSels = @[@"uid", @"userID", @"userId", @"user_id", @"UID"];
    NSArray *secSels = @[@"secUid", @"sec_uid", @"secUserID", @"sec_user_id", @"secUidString"];
    NSString *u = nil, *su = nil;
    @try {
        for (NSString *n in uidSels) {
            SEL s = NSSelectorFromString(n);
            if (![obj respondsToSelector:s]) continue;
            NSMethodSignature *sig = [obj methodSignatureForSelector:s];
            if (!sig) continue;
            const char *rt = sig.methodReturnType;
            if (!rt) continue;
            IMP imp = [obj methodForSelector:s];
            if (!imp) continue;
            if (rt[0] == '@') {
                id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
                id v = fn(obj, s);
                if (v) u = [v isKindOfClass:[NSString class]] ? (NSString *)v : [v description];
            } else if (rt[0] == 'q' || rt[0] == 'Q') {
                long long (*fn)(id, SEL) = (long long (*)(id, SEL))imp;
                long long v = fn(obj, s);
                if (v > 0) u = [NSString stringWithFormat:@"%lld", v];
            } else if (rt[0] == 'i' || rt[0] == 'I') {
                int (*fn)(id, SEL) = (int (*)(id, SEL))imp;
                int v = fn(obj, s);
                if (v > 0) u = [NSString stringWithFormat:@"%d", v];
            }
            if (u.length >= 5) break;
            u = nil;
        }
        for (NSString *n in secSels) {
            SEL s = NSSelectorFromString(n);
            if (![obj respondsToSelector:s]) continue;
            IMP imp = [obj methodForSelector:s];
            if (!imp) continue;
            NSMethodSignature *sig = [obj methodSignatureForSelector:s];
            if (!sig || !sig.methodReturnType || sig.methodReturnType[0] != '@') continue;
            id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
            id v = fn(obj, s);
            if (v && [v isKindOfClass:[NSString class]] && [(NSString *)v length] >= 10) {
                su = (NSString *)v;
                break;
            }
        }
    } @catch (...) { return NO; }
    if (u.length >= 5 && su.length >= 10) {
        if (!g_myUid.length) {
            g_myUid = [u copy];
            g_mySecUid = [su copy];
            g_uidSource = [NSString stringWithUTF8String:fromWhat ? *fromWhat : "反射"];
        }
        return YES;
    }
    return NO;
}

static void DYReflectAccounts(void) {
    if (g_myUid.length && g_mySecUid.length) return;

    NSArray *clsNames = @[
        @"AWEUserModel", @"TTAccount", @"TTAccountManager", @"TTAcountManager",
        @"IESAccountManager", @"AWEAccountManager", @"AWEUserService",
        @"BDADAccount", @"BDADAccountManager", @"AWECurrentUser",
        @"AWELoginUserModel", @"AWEProfileUser", @"ACCOUNT_TTAccountManager"
    ];
    NSArray *accessors = @[
        @"currentUser", @"currentAccount", @"sharedInstance", @"sharedManager",
        @"sharedAccount", @"currentLoginUser", @"currentUserModel", @"defaultAccount",
        @"current", @"shared"
    ];

    int tried = 0, hit = 0;
    for (NSString *cn in clsNames) {
        Class c = objc_getClass(cn.UTF8String);
        if (!c) continue;
        tried++;
        for (NSString *an in accessors) {
            SEL as = NSSelectorFromString(an);
            id obj = DYCallClassMethod(c, as);
            if (!obj) continue;
            const char *tag = [cn UTF8String];
            if (DYPickFromObject(obj, &tag)) { hit++; break; }
        }
        if (g_myUid.length && g_mySecUid.length) break;
    }
    L(@"[MYUSER] 账号类反射：命中类 %d / 拿到用户 %d", tried, hit);
}

/* ===================== 从响应里回捞 uid ===================== */
static void DYHarvestUser(NSString *s) {
    if (g_myUid.length && g_mySecUid.length) return;
    if (![s isKindOfClass:[NSString class]]) return;
    if (s.length < 40 || s.length > 400000) return;
    if (![s containsString:@"MS4wLjABAAAA"]) return;

    /* 只认发布/本人资料类响应，避免把别人的 uid 当自己 */
    BOOL isPublish = [s containsString:@"\"cid\""] || [s containsString:@"\"comment_id\""];
    BOOL isSelf = [s containsString:@"user/profile/self"] || [s containsString:@"\"is_self\":true"];
    if (!isPublish && !isSelf) return;

    NSString *su = DYFirstMatch(s, @"(MS4wLjABAAAA[A-Za-z0-9_\\-]{10,})");
    NSString *u = DYFirstMatch(s, @"\"uid\"\\s*:\\s*\"?([0-9]{5,})");
    if (!u || !su) return;

    g_myUid = [u copy];
    g_mySecUid = [su copy];
    g_uidSource = @"发布响应回捞";
    DYSaveUidCache();
    L(@"[MYUSER] ★ 从响应捞到 uid=%@ sec_uid=%@，已写入 dyprobe_uid.txt，下一条评论自动带上", u, su);
}

/* ===================== 统一取用户 ===================== */
static void DYFindMyUser(BOOL quiet) {
    if (!quiet) L(@"[MYUSER] ---- 开始取自己的账号 ----");
    DYLoadUidCache();
    if (!(g_myUid.length && g_mySecUid.length)) DYScanDefaults();
    if (!(g_myUid.length && g_mySecUid.length)) DYReflectAccounts();
    if (g_myUid.length && g_mySecUid.length) DYSaveUidCache();
    L(@"[MYUSER] 最终：uid=%@ sec_uid=%@ 来源=%@",
      g_myUid.length ? g_myUid : @"(空)",
      g_mySecUid.length ? g_mySecUid : @"(空)",
      g_uidSource);
    if (!g_myUid.length) {
        L(@"[MYUSER] 没取到。逃生门：往 Documents/dyprobe_uid.txt 写一行  uid|sec_uid  后杀进程重开");
    }
}

/* ===================== 抓 body / response ===================== */
static BOOL DYInteresting(NSString *s) {
    if (s.length < 8) return NO;
    if ([s containsString:@"publish_scene"]) return YES;
    if ([s containsString:@"text_extra"]) return YES;
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

static void DYEmitAround(NSString *s, NSString *needle, int idx, NSString *label) {
    NSRange r = [s rangeOfString:needle];
    if (r.location == NSNotFound) return;
    NSUInteger start = r.location > 400 ? r.location - 400 : 0;
    NSUInteger end = NSMaxRange(r) + 600;
    if (end > s.length) end = s.length;
    NSString *seg = [s substringWithRange:NSMakeRange(start, end - start)];
    LFast([NSString stringWithFormat:@"[%@ #%d] 命中「%@」上下文：%@", label, idx, needle, seg]);
}

static void DYOnBody(id arg, const char *clsName, const char *selName, BOOL isResp) {
    if (isResp) {
        NSString *repr = DYBodyRepr(arg);
        if (!repr.length) return;
        @try { DYHarvestUser(repr); } @catch (...) {}
        if (![repr containsString:@"text_extra"] && ![repr containsString:@"publish_scene"]) return;
        g_respHit++;
        if (g_respHit > 20) return;
        LFast([NSString stringWithFormat:@"\n===== [RESP #%d] %s -%s （长度 %lu）=====",
               g_respHit, clsName, selName, (unsigned long)repr.length]);
        if ([repr containsString:@"text_extra"]) {
            DYEmitAround(repr, @"text_extra", g_respHit, @"RESP");
            LFast([NSString stringWithFormat:@"[RESP #%d] ★★★ 服务端回传里带 text_extra，说明存了 ★★★", g_respHit]);
        } else {
            NSString *shown = repr.length > 1200 ? [repr substringToIndex:1200] : repr;
            LFast([NSString stringWithFormat:@"[RESP #%d] 无 text_extra，前段：%@", g_respHit, shown]);
        }
        return;
    }

    g_bodySeen++;
    if (g_bodySeen > 40000) return;
    NSString *repr = DYBodyRepr(arg);
    if (!repr.length) return;
    if (!DYInteresting(repr)) return;

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

/* ===================== 网络 hook ===================== */
static IMP g_origSetHTTPBody = NULL;
static void dy_setHTTPBody(id self, SEL _cmd, id arg) {
    @try { if (g_origSetHTTPBody) ((void (*)(id, SEL, id))g_origSetHTTPBody)(self, _cmd, arg); } @catch (...) {}
    @try { DYOnBody(arg, "NSMutableURLRequest", "setHTTPBody:", NO); } @catch (...) {}
}

static const char *kSetters[] = {
    "setBody:", "setPostData:", "setBodyData:", "setHttpBody:",
    "setRequestBody:", "setPostBody:", "setRequestData:",
    "setPostBodyData:", "setHttpBodyData:", "setFormData:",
    "setPostParams:", "setParameters:", "setRequestParams:",
    "setResponseBody:", "setRawData:", "setResponseData:",
    "setJSONResponse:", "setResponseString:", "setJsonData:",
    "setResponseJSON:", "setResponseInfo:", "setResponseModel:"
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
        if (!cn) continue;
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

/* ===================== 注入 ===================== */
static NSString *DYBuildTextExtra(NSString *text, int type) {
    if (![text isKindOfClass:[NSString class]] || text.length == 0) return nil;
    NSUInteger bytes = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (bytes == 0) return nil;

    NSMutableDictionary *span = [NSMutableDictionary dictionary];
    span[@"start"] = @0;
    span[@"end"] = @(bytes);
    span[@"type"] = @(type);
    if (g_myUid.length >= 5) span[@"user_id"] = g_myUid;
    if (g_mySecUid.length >= 10) span[@"sec_uid"] = g_mySecUid;

    NSData *d = [NSJSONSerialization dataWithJSONObject:@[ span ] options:0 error:NULL];
    if (!d) return nil;
    return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
}

static id dy_extraParams(id self, SEL _cmd) {
    id r = nil;
    @try { if (g_origExtraParams) r = ((id (*)(id, SEL))g_origExtraParams)(self, _cmd); } @catch (...) {}

    if (![r isKindOfClass:[NSDictionary class]]) return r;

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
        BOOL hasUid = (g_myUid.length >= 5 && g_mySecUid.length >= 10);
        L(@"[INJECT #%d] type=%d 正文=「%@」(%lu 字节) uid=%@ → text_extra=%@",
          g_injectN, type, text,
          (unsigned long)[text lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
          hasUid ? g_myUid : @"缺失!",
          js);
    }
    return m;
}

/* ===================== 安装 ===================== */
static void DYInstall(void) {
    DYFindMyUser(NO);

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
    L(@"[DONE] v26 安装完成");
}

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    DYBeacon("dylib 已加载");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v26] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v26] 安装异常，已忽略"); }
            L(@"[v26] 发一条 tt21。看 [INJECT] 里 uid= 是不是「缺失!」");
        }
    });

    /* 15s / 30s 再补扫两次——登录态可能比 dylib 加载晚 */
    for (int i = 1; i <= 2; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 15.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
            @autoreleasepool {
                if (!(g_myUid.length && g_mySecUid.length)) {
                    @try { DYFindMyUser(YES); } @catch (...) {}
                }
                L(@"[心跳 %ds] 行 %d / body %d / 命中 %d / 响应 %d / uid=%@",
                  i * 15, g_writes, g_bodySeen, g_bodyHit, g_respHit,
                  g_myUid.length ? g_myUid : @"(空)");
            }
        });
    }
}
