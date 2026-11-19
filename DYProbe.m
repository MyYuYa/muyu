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
 * DYProbe v27 —— 用 label_text:"我" 精准锁定自己的 uid
 *
 * v26 已证实的铁证（日志 BODY #4 / #6 是发布接口的服务端回包）：
 *
 *   "status_msg":"评论成功"
 *   "text_extra":[{"start":0,"end":4,"user_id":"","type":21,
 *                  "hashtag_name":"","hashtag_id":""}]
 *
 *   → 服务端不但没剥离 type=21，还把它原样存下并回传了。
 *   → 唯一缺口是 user_id 为空字符串（客户端没传）。
 *
 * 对照网页脚本 douyin-comment-color.user.js：
 *   line 175  if (me) { span.user_id = me.uid; span.sec_uid = me.sec_uid; }
 *   line 321  if (j.comment && j.comment.user) saveMyUser(j.comment.user.uid, ...)
 *   → 网页端发的 span 几乎必定带真实 uid；App 端响应里的 comment 没有 user 对象，
 *     所以 App 从来没带上过。
 *
 * v26 为什么取不到 uid：
 *   NSUserDefaults 里根本没有（抖音 iOS 的登录态不放这里）
 *   类名靠猜（AWEUserModel / TTAccount …）全空
 *   发布响应里没有 user 对象
 *
 * v27 换一条完全不靠猜的路 —— 服务端自己会给"我的评论"打标记：
 *   发布响应里就有  "label_text":"我"
 *   评论列表响应里，我的那条评论也带 label_text:"我"
 *   而列表里的 comment 对象一定带 user:{uid, sec_uid}
 *
 * 所以：hook +[NSJSONSerialization JSONObjectWithData:options:error:]，在已经解析好的
 * 对象树里递归找 label_text == "我" 的字典，把它 user 里的 uid / sec_uid 取出来。
 * 这条路绕开了"类名猜不准"和"响应 hook 没挂上"两个坑，因为所有 JSON 解析都经过它。
 *
 * 另外保留字符串正则兜底（有些响应可能没走 NSJSONSerialization）。
 *
 * 拿到之后立刻写盘 + 立刻生效：下一条评论的 text_extra 就会带上 user_id。
 *
 * 怎么用：
 *   1. 装上，进任意视频的评论区（让评论列表加载一次）
 *   2. 看日志有没有 [MYUSER] ★★★ 拿到自己的 uid=数字
 *   3. 有的话直接发一条 tt21，[INJECT] 里应该显示 uid=数字 而不是「缺失!」
 */

#define DY_MAXLEN   6000
#define DY_MAXLINE  900
#define DY_BEACON   "[v27]"
#define DY_MAXHOOK  400

static int g_writes = 0;
static int g_injectN = 0;
static int g_bodySeen = 0;
static int g_bodyHit = 0;
static int g_respHit = 0;
static int g_rawN = 0;
static int g_extraN = 0;
static int g_jsonSeen = 0;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_userMtx = PTHREAD_MUTEX_INITIALIZER;
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
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v27.txt", home);
        paths[n++] = p1; paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v27.txt", tmpd);
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
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v27.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v27.txt"]];
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

static int DYCountOccur(NSString *s, NSString *needle) {
    if (![s isKindOfClass:[NSString class]] || !s.length || !needle.length) return 0;
    int n = 0;
    NSUInteger loc = 0;
    while (loc < s.length && n < 60) {
        NSRange r = [s rangeOfString:needle options:0 range:NSMakeRange(loc, s.length - loc)];
        if (r.location == NSNotFound) break;
        n++;
        loc = NSMaxRange(r);
    }
    return n;
}

/* ===================== uid 缓存 ===================== */
static void DYSaveUidCache(void) {
    if (g_myUid.length < 5) return;
    NSString *p = DYDocPath(@"dyprobe_uid.txt");
    if (!p) return;
    NSString *s = [NSString stringWithFormat:@"%@|%@\n", g_myUid, g_mySecUid ?: @""];
    [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

static BOOL DYIsDigits(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length < 5 || s.length > 24) return NO;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < '0' || c > '9') return NO;
    }
    return YES;
}

/* 统一的"采用这个 uid"入口：只认第一次，拿到就写盘 + 打日志 */
static BOOL DYAdoptUser(NSString *u, NSString *su, NSString *src) {
    if (!DYIsDigits(u)) return NO;
    if (su && ![su isKindOfClass:[NSString class]]) su = nil;
    if (su.length && ![su hasPrefix:@"MS4w"]) su = nil;

    pthread_mutex_lock(&g_userMtx);
    BOOL already = (g_myUid.length >= 5);
    if (!already) {
        g_myUid = [u copy];
        if (su.length >= 10) g_mySecUid = [su copy];
        g_uidSource = [src copy] ?: @"未知";
    }
    NSString *uidC = g_myUid, *secC = g_mySecUid, *srcC = g_uidSource;
    pthread_mutex_unlock(&g_userMtx);

    if (already) return YES;

    DYSaveUidCache();
    L(@"\n[MYUSER] ★★★ 拿到自己的 uid=%@ sec_uid=%@", uidC, secC.length ? secC : @"(空)");
    L(@"[MYUSER] ★★★ 来源：%@，已写入 dyprobe_uid.txt", srcC);
    L(@"[MYUSER] ★★★ 现在再发一条评论，[INJECT] 里 uid= 就应该显示这个数字了");
    return YES;
}

static void DYLoadUidCache(void) {
    NSString *p = DYDocPath(@"dyprobe_uid.txt");
    if (!p) return;
    NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:NULL];
    if (!s) return;
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!s.length) return;
    NSArray *parts = [s componentsSeparatedByString:@"|"];
    if (!parts.count) return;
    NSString *u = [parts[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *su = parts.count >= 2 ? [parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] : @"";
    if (DYIsDigits(u)) {
        g_myUid = [u copy];
        if (su.length >= 10) g_mySecUid = [su copy];
        g_uidSource = @"缓存文件";
    }
}

/* ===================== 核心：在已解析的 JSON 对象树里找「我」 ===================== */
/*
 * 抖音评论对象长这样（列表接口）：
 *   {"cid":"...","text":"tt21","label_text":"我","label_type":24,
 *    "user":{"uid":"123456","sec_uid":"MS4wLjABAAAA...","nickname":"..."}}
 *
 * 发布接口回包里 label_text 也有，但 comment 里没 user —— 所以只解列表。
 */
static void DYScanJSONForMe(id o, int depth, int *nodes, BOOL *found) {
    if (!o || *found || depth > 12) return;
    if (++(*nodes) > 4000) return;
    if (g_myUid.length >= 5) { *found = YES; return; }

    @try {
        if ([o isKindOfClass:[NSDictionary class]]) {
            NSDictionary *d = (NSDictionary *)o;

            id lt = d[@"label_text"];
            BOOL isMe = ([lt isKindOfClass:[NSString class]] && [(NSString *)lt isEqualToString:@"我"]);
            if (!isMe) {
                id b = d[@"is_self"];
                if (b && [b respondsToSelector:@selector(boolValue)] && [b boolValue]) isMe = YES;
            }

            if (isMe) {
                NSString *u = nil, *su = nil;

                /* comment 自己身上直接有 uid 的情况 */
                id uv = d[@"uid"];
                if (!uv) uv = d[@"user_id"];
                if ([uv isKindOfClass:[NSString class]]) u = (NSString *)uv;
                else if ([uv isKindOfClass:[NSNumber class]]) u = [(NSNumber *)uv stringValue];

                id sv = d[@"sec_uid"];
                if (sv == nil) sv = d[@"sec_user_id"];
                if ([sv isKindOfClass:[NSString class]]) su = (NSString *)sv;

                /* 主要路径：comment.user 里取 */
                id user = d[@"user"];
                if ([user isKindOfClass:[NSDictionary class]]) {
                    NSDictionary *ud = (NSDictionary *)user;
                    if (u.length < 5) {
                        id uu = ud[@"uid"];
                        if (!uu) uu = ud[@"user_id"];
                        if ([uu isKindOfClass:[NSString class]]) u = (NSString *)uu;
                        else if ([uu isKindOfClass:[NSNumber class]]) u = [(NSNumber *)uu stringValue];
                    }
                    if (su.length < 10) {
                        id ss = ud[@"sec_uid"];
                        if (!ss) ss = ud[@"sec_user_id"];
                        if ([ss isKindOfClass:[NSString class]]) su = (NSString *)ss;
                    }
                }

                if (DYIsDigits(u)) {
                    NSString *nick = nil;
                    id nv = d[@"nickname"];
                    if ([nv isKindOfClass:[NSString class]]) nick = (NSString *)nv;
                    *found = YES;
                    L(@"[MYUSER] JSON 命中 label_text=我 的评论（昵称 %@ 文本 %@），uid=%@ sec_uid=%@",
                      nick.length ? nick : @"?", DYStr(d[@"text"]), u, su.length ? su : @"(空)");
                    DYAdoptUser(u, su, @"JSON label_text=我");
                    return;
                }
            }

            for (id k in d) DYScanJSONForMe(d[k], depth + 1, nodes, found);
        } else if ([o isKindOfClass:[NSArray class]]) {
            for (id v in (NSArray *)o) DYScanJSONForMe(v, depth + 1, nodes, found);
        }
    } @catch (...) {}
}

/* ===================== 字符串兜底（响应不是走 NSJSONSerialization 的） ===================== */
static void DYHarvestUserFromString(NSString *s) {
    if (g_myUid.length >= 5) return;
    if (![s isKindOfClass:[NSString class]] || s.length < 40 || s.length > 800000) return;
    if (![s containsString:@"MS4wLjABAAAA"]) return;

    NSUInteger win = 2500;

    /* ① 最精准：label_text 是「我」的那条评论 */
    NSRange r = [s rangeOfString:@"\"label_text\":\"我\""];
    if (r.location == NSNotFound) r = [s rangeOfString:@"\"label_text\" : \"我\""];
    if (r.location != NSNotFound) {
        NSUInteger lo = r.location > win ? r.location - win : 0;
        NSUInteger hi = NSMaxRange(r) + win;
        if (hi > s.length) hi = s.length;
        NSString *seg = [s substringWithRange:NSMakeRange(lo, hi - lo)];
        NSString *su = DYFirstMatch(seg, @"\"sec_uid\"\\s*:\\s*\"(MS4wLjABAAAA[A-Za-z0-9_\\-]{10,})\"");
        NSString *u = DYFirstMatch(seg, @"\"uid\"\\s*:\\s*\"?([0-9]{5,24})");
        if (!u) u = DYFirstMatch(seg, @"\"user_id\"\\s*:\\s*\"([0-9]{5,24})\"");
        if (DYIsDigits(u)) {
            L(@"[MYUSER] 字符串命中 label_text=我，uid=%@ sec_uid=%@", u, su.length ? su : @"(空)");
            DYAdoptUser(u, su, @"字符串 label_text=我");
            return;
        } else {
            /* 诊断：找到了「我」的标记但附近没有 uid —— 说明这条评论对象不带 user */
            L(@"[MYUSER] 见到 label_text=我 但附近取不到 uid（窗口 %lus 内），片段：%@",
              (unsigned long)seg.length, seg.length > 600 ? [seg substringToIndex:600] : seg);
        }
    }

    /* ② is_self:true 的自我资料 */
    NSRange r2 = [s rangeOfString:@"\"is_self\":true"];
    if (r2.location == NSNotFound) r2 = [s rangeOfString:@"\"is_self\" : true"];
    if (r2.location != NSNotFound) {
        NSUInteger lo = r2.location > win ? r2.location - win : 0;
        NSUInteger hi = NSMaxRange(r2) + win;
        if (hi > s.length) hi = s.length;
        NSString *seg = [s substringWithRange:NSMakeRange(lo, hi - lo)];
        NSString *su = DYFirstMatch(seg, @"\"sec_uid\"\\s*:\\s*\"(MS4wLjABAAAA[A-Za-z0-9_\\-]{10,})\"");
        NSString *u = DYFirstMatch(seg, @"\"uid\"\\s*:\\s*\"?([0-9]{5,24})");
        if (DYIsDigits(u)) {
            DYAdoptUser(u, su, @"字符串 is_self");
            return;
        }
    }

    /* ③ 兜底：整段响应里只有一个用户（profile/self 这类接口）才敢用 */
    int secN = DYCountOccur(s, @"MS4wLjABAAAA");
    int uidN = DYCountOccur(s, @"\"uid\":");
    if (secN == 1 && uidN == 1) {
        NSString *su = DYFirstMatch(s, @"(MS4wLjABAAAA[A-Za-z0-9_\\-]{10,})");
        NSString *u = DYFirstMatch(s, @"\"uid\"\\s*:\\s*\"?([0-9]{5,24})");
        if (DYIsDigits(u)) {
            L(@"[MYUSER] 单用户响应（sec_uid 1 个 / uid 1 个），uid=%@", u);
            DYAdoptUser(u, su, @"单用户响应");
        }
    }
}

/* ===================== NSJSONSerialization hook ===================== */
static IMP g_origJSONObj = NULL;
static __thread int g_inJSONHook = 0;

static id dy_JSONObjectWithData(id self, SEL _cmd, NSData *data, NSJSONReadingOptions opt, NSError **err) {
    id r = nil;
    @try {
        if (g_origJSONObj) {
            r = ((id (*)(id, SEL, id, NSUInteger, NSError **))g_origJSONObj)(self, _cmd, data, (NSUInteger)opt, err);
        }
    } @catch (...) {}

    if (r && g_inJSONHook == 0 && g_myUid.length < 5) {
        g_inJSONHook = 1;
        @try {
            g_jsonSeen++;
            int nodes = 0;
            BOOL found = NO;
            DYScanJSONForMe(r, 0, &nodes, &found);
        } @catch (...) {}
        g_inJSONHook = 0;
    }
    return r;
}

/* ===================== NSUserDefaults 深扫（保留） ===================== */
static long g_scanNodes = 0;
static NSMutableArray *g_pairs = nil;

static void DYScanStringValue(NSString *s) {
    if (![s isKindOfClass:[NSString class]]) return;
    if (s.length < 40 || s.length > 300000) return;
    if (![s containsString:@"MS4wLjABAAAA"]) return;
    NSString *su = DYFirstMatch(s, @"(MS4wLjABAAAA[A-Za-z0-9_\\-]{10,})");
    if (!su) return;
    NSString *u = DYFirstMatch(s, @"\"uid\"\\s*:\\s*\"?([0-9]{5,24})");
    if (!u) u = DYFirstMatch(s, @"\"user_id\"\\s*:\\s*\"?([0-9]{5,24})");
    if (!u) u = DYFirstMatch(s, @"(?:^|[^0-9])uid=(\\d{5,24})");
    if (DYIsDigits(u)) [g_pairs addObject:@[u, su]];
}

static void DYScanObject(id o, int depth) {
    if (!o || depth > 4) return;
    if (++g_scanNodes > 30000) return;
    @try {
        if ([o isKindOfClass:[NSString class]]) {
            DYScanStringValue((NSString *)o);
        } else if ([o isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)o;
            if (d.length > 0 && d.length < 300000) {
                NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (s) DYScanStringValue(s);
            }
        } else if ([o isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)o;
            for (id k in dict) {
                if ([k isKindOfClass:[NSString class]]) DYScanStringValue((NSString *)k);
                DYScanObject(dict[k], depth + 1);
            }
        } else if ([o isKindOfClass:[NSArray class]]) {
            for (id v in (NSArray *)o) DYScanObject(v, depth + 1);
        }
    } @catch (...) {}
}

static void DYScanDefaults(void) {
    if (g_myUid.length >= 5) return;
    @try {
        NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        if (!all) { L(@"[MYUSER] defaults 为空"); return; }
        g_pairs = [NSMutableArray array];
        g_scanNodes = 0;
        NSInteger scanned = 0;
        for (id k in all) {
            if (++scanned > 5000) break;
            DYScanObject(all[k], 0);
        }
        L(@"[MYUSER] defaults 深扫：遍历 %ld 个 key，候选 %lu 组",
          (long)scanned, (unsigned long)g_pairs.count);
        if (g_pairs.count) {
            NSArray *p = g_pairs.firstObject;
            DYAdoptUser(p[0], p[1], @"defaults 深扫");
        }
    } @catch (...) { L(@"[MYUSER] defaults 读取异常"); }
}

/* ===================== 反射账号服务（保留，但不再作为主力） ===================== */
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

static BOOL DYPickFromObject(id obj, const char *fromWhat) {
    if (!obj) return NO;
    NSArray *uidSels = @[@"uid", @"userID", @"userId", @"user_id", @"UID"];
    NSArray *secSels = @[@"secUid", @"sec_uid", @"secUserID", @"sec_user_id"];
    NSString *u = nil, *su = nil;
    @try {
        for (NSString *n in uidSels) {
            SEL s = NSSelectorFromString(n);
            if (![obj respondsToSelector:s]) continue;
            NSMethodSignature *sig = [obj methodSignatureForSelector:s];
            if (!sig || !sig.methodReturnType) continue;
            const char *rt = sig.methodReturnType;
            IMP imp = [obj methodForSelector:s];
            if (!imp) continue;
            if (rt[0] == '@') {
                id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
                id v = fn(obj, s);
                if (v && [v isKindOfClass:[NSString class]]) u = (NSString *)v;
                else if (v) u = [v description];
            } else if (rt[0] == 'q' || rt[0] == 'Q') {
                long long (*fn)(id, SEL) = (long long (*)(id, SEL))imp;
                long long v = fn(obj, s);
                if (v > 0) u = [NSString stringWithFormat:@"%lld", v];
            } else if (rt[0] == 'i' || rt[0] == 'I') {
                int (*fn)(id, SEL) = (int (*)(id, SEL))imp;
                int v = fn(obj, s);
                if (v > 0) u = [NSString stringWithFormat:@"%d", v];
            }
            if (DYIsDigits(u)) break;
            u = nil;
        }
        for (NSString *n in secSels) {
            SEL s = NSSelectorFromString(n);
            if (![obj respondsToSelector:s]) continue;
            NSMethodSignature *sig = [obj methodSignatureForSelector:s];
            if (!sig || !sig.methodReturnType || sig.methodReturnType[0] != '@') continue;
            IMP imp = [obj methodForSelector:s];
            if (!imp) continue;
            id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
            id v = fn(obj, s);
            if (v && [v isKindOfClass:[NSString class]] && [(NSString *)v length] >= 10) {
                su = (NSString *)v;
                break;
            }
        }
    } @catch (...) { return NO; }
    if (DYIsDigits(u)) {
        DYAdoptUser(u, su, [NSString stringWithUTF8String:fromWhat ? fromWhat : "反射"]);
        return YES;
    }
    return NO;
}

static void DYReflectAccounts(void) {
    if (g_myUid.length >= 5) return;

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
            if (DYPickFromObject(obj, tag)) { hit++; break; }
        }
        if (g_myUid.length >= 5) break;
    }
    L(@"[MYUSER] 账号类反射：命中类 %d / 拿到用户 %d", tried, hit);
}

/* ===================== 统一取用户 ===================== */
static void DYFindMyUser(BOOL quiet) {
    if (!quiet) L(@"[MYUSER] ---- 开始取自己的账号 ----");
    DYLoadUidCache();
    if (g_myUid.length < 5) DYScanDefaults();
    if (g_myUid.length < 5) DYReflectAccounts();
    L(@"[MYUSER] 当前：uid=%@ sec_uid=%@ 来源=%@",
      g_myUid.length ? g_myUid : @"(空)",
      g_mySecUid.length ? g_mySecUid : @"(空)",
      g_uidSource);
    if (g_myUid.length < 5) {
        L(@"[MYUSER] 还没拿到。等评论列表加载一次就会从 label_text=我 里捞到。");
        L(@"[MYUSER] 手动逃生门：往 Documents/dyprobe_uid.txt 写一行  uid|sec_uid  后杀进程重开");
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

        /* 字符串兜底（部分响应不走 NSJSONSerialization，靠正则也能认 label_text） */
        @try { DYHarvestUserFromString(repr); } @catch (...) {}

        BOOL hasTE = [repr containsString:@"text_extra"];
        BOOL hasLt = [repr containsString:@"label_text"];
        BOOL hasComments = [repr containsString:@"\"comments\""];
        if (!hasTE && !hasLt && !hasComments) return;

        g_respHit++;
        if (g_respHit > 24) return;
        LFast([NSString stringWithFormat:@"\n===== [RESP #%d] %s -%s （长度 %lu）hasTE=%d hasLabelText=%d hasComments=%d =====",
               g_respHit, clsName, selName, (unsigned long)repr.length, hasTE, hasLt, hasComments]);

        if (hasTE) {
            DYEmitAround(repr, @"text_extra", g_respHit, @"RESP");
            LFast([NSString stringWithFormat:@"[RESP #%d] ★★ 服务端回传里带 text_extra", g_respHit]);
        } else if (hasLt) {
            DYEmitAround(repr, @"label_text", g_respHit, @"RESP");
        } else {
            NSString *shown = repr.length > 1500 ? [repr substringToIndex:1500] : repr;
            LFast([NSString stringWithFormat:@"[RESP #%d] 前段：%@", g_respHit, shown]);
        }
        return;
    }

    g_bodySeen++;
    if (g_bodySeen > 60000) return;
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
    "setResponseJSON:", "setResponseInfo:", "setResponseModel:",
    "setResponseObject:", "setResultData:", "setResponseBodyData:"
};
static const int kSetterCount = sizeof(kSetters) / sizeof(kSetters[0]);

static const char *kStrongKeys[] = { "Net", "Network", "Http", "Channel" };
static const int kStrongCount = sizeof(kStrongKeys) / sizeof(kStrongKeys[0]);
static const char *kWeakKeys[] = { "Request", "Task", "Api", "Session", "Client" };
static const int kWeakCount = sizeof(kWeakKeys) / sizeof(kWeakKeys[0]);
static const char *kRespKeys[] = { "Response", "Context", "Parser", "JSON", "Resp" };
static const int kRespCount = sizeof(kRespKeys) / sizeof(kRespKeys[0]);

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
        BOOL isResp = DYHasKey(cn, kRespKeys, kRespCount);
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

    if (g_injectN < 8) {
        g_injectN++;
        BOOL hasUid = (g_myUid.length >= 5);
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

    /* 核心：所有 JSON 解析都从这里过，靠它拿到 label_text=我 的那条评论 */
    Class jc = objc_getClass("NSJSONSerialization");
    if (jc) {
        SEL js = NSSelectorFromString(@"JSONObjectWithData:options:error:");
        Method jm = class_getClassMethod(jc, js);
        if (jm) {
            g_origJSONObj = method_setImplementation(jm, (IMP)dy_JSONObjectWithData);
            L(@"[HOOK] +[NSJSONSerialization JSONObjectWithData:options:error:] 已接管");
        } else {
            L(@"[HOOK] NSJSONSerialization 方法没找到，只走字符串兜底");
        }
    }

    int a = DYScanPass(0), b = DYScanPass(1), c = DYScanPass(2);
    L(@"[SCAN] 强网络 %d / 其它 %d / 响应 %d，合计 %d 个 hook", a, b, c, g_hookN);
    L(@"[DONE] v27 安装完成");
}

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    DYBeacon("dylib 已加载");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v27] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v27] 安装异常，已忽略"); }
            L(@"[v27] 下一步：进任意视频评论区（让评论列表加载一次），看有没有 [MYUSER] ★★★");
        }
    });

    /* 5s/20s/45s 补扫：登录态和评论列表都比 dylib 加载晚 */
    static const double ticks[3] = { 5.0, 20.0, 45.0 };
    for (int i = 0; i < 3; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(ticks[i] * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
            @autoreleasepool {
                if (g_myUid.length < 5) @try { DYFindMyUser(YES); } @catch (...) {}
                L(@"[心跳 %.0fs] 行 %d / body %d / 响应 %d / JSON %d / uid=%@",
                  ticks[i], g_writes, g_bodySeen, g_respHit, g_jsonSeen,
                  g_myUid.length ? g_myUid : @"(空)");
            }
        });
    }
}
