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
 * DYProbe v23 —— 第一个会真正改数据的版本
 *
 * v21/v22 实测链条（全部为日志实证，不是推测）：
 *   AWECommentPublishParameterModel.extraParams（NSDictionary）
 *     → 22 个 key 全是 comment/publish 接口的顶层请求参数：
 *        publish_scene / paste_edit_method / one_level_comment_rank / time_from_input_to_send
 *        / author_secuid / common_flags / unique_key ...
 *     → 说明这个字典 = 请求体顶层参数直通车
 *   AWECommentPublishParameterModel.contentModel.content（NSString）= 正文
 *   AWECommentInputContentModel.extraInfo（NSArray）纯文本时为空 []
 *   → 结论：iOS 原生纯文本评论根本不带 text_extra，必须我们自己塞
 *
 * 网页端（douyin-comment-color.user.js 实测可用）的写法：
 *   text_extra = JSON.stringify([{ start: 0, end: <UTF-8 字节长度>, type: 21, user_id, sec_uid }])
 *   - start/end 是 UTF-8 字节偏移，不是字符数
 *   - type 21 = 红色（2026-11-18 批量实测）
 *   - 作为 form 字段发送，值是 JSON 字符串
 *
 * 本版做法：hook extraParams 的 getter，原样取出 → 加一个 text_extra 键 → 返回新字典。
 *   - 不改原对象、不碰网络层、不碰 KMP，最坏情况就是无效，不会崩
 *   - 每次 getter 被调用都会重新算，正文改了也不会错
 *
 * 免重装的调试开关（放 Documents 里，改完杀进程重开即生效）：
 *   dyprobe_off.txt  存在 → 不注入（对照组）
 *   dyprobe_type.txt 内容写数字 → 用这个 type（默认 21）
 */

#define DY_MAXLEN   8000
#define DY_MAXLINE  300
#define DY_BEACON   "[v23]"

static int g_writes = 0;
static int g_injectN = 0;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static IMP g_origExtraParams = NULL;

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
        snprintf(p2, sizeof(p2), "%s/Documents/dyprobe_v23.txt", home);
        paths[n++] = p1; paths[n++] = p2;
    }
    if (tmpd) {
        snprintf(p3, sizeof(p3), "%s/dyprobe_v23.txt", tmpd);
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
        [targets addObject:[docs stringByAppendingPathComponent:@"dyprobe_v23.txt"]];
    }
    NSString *td = NSTemporaryDirectory();
    if (td) [targets addObject:[td stringByAppendingPathComponent:@"dyprobe_v23.txt"]];
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
    static int cache = -1;                 /* 缓存，避免 getter 被高频调用时反复读盘 */
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

/* ===================== 注入：extraParams 的 getter ===================== */
static NSString *DYBuildTextExtra(NSString *text, int type, NSString *uid) {
    if (![text isKindOfClass:[NSString class]] || text.length == 0) return nil;
    /* 网页端用的是 UTF-8 字节偏移，不是字符数 */
    NSUInteger bytes = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (bytes == 0) return nil;

    NSMutableDictionary *span = [NSMutableDictionary dictionary];
    span[@"start"] = @0;
    span[@"end"] = @(bytes);
    span[@"type"] = @(type);
    if (uid.length) span[@"user_id"] = uid;

    NSData *d = [NSJSONSerialization dataWithJSONObject:@[ span ] options:0 error:NULL];
    if (!d) return nil;
    return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
}

static id dy_extraParams(id self, SEL _cmd) {
    id r = nil;
    @try { if (g_origExtraParams) r = ((id (*)(id, SEL))g_origExtraParams)(self, _cmd); } @catch (...) {}

    if (![r isKindOfClass:[NSDictionary class]]) {
        if (g_injectN < 3) { g_injectN++; L(@"[INJECT] extraParams 不是字典（%@），跳过", r ? NSStringFromClass([r class]) : @"nil"); }
        return r;
    }
    if (DYSwitchOff()) {
        if (g_injectN < 3) { g_injectN++; L(@"[INJECT] 检测到 dyprobe_off.txt，本版不注入（对照组）"); }
        return r;
    }

    NSString *text = nil;
    @try { text = [self valueForKeyPath:@"contentModel.content"]; } @catch (...) {}

    int type = DYTypeValue();
    NSString *js = DYBuildTextExtra(text, type, nil);
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
        L(@"[INJECT #%d] 返回字典键数 %lu → %lu，新键 text_extra 已就位",
          g_injectN, (unsigned long)[(NSDictionary *)r count], (unsigned long)m.count);
    }
    return m;
}

/* ===================== 结构情报（失败时用，不发评论也写） ===================== */
static void DYDumpIvars(Class c, const char *tag) {
    if (!c) { L(@"[%s] 类不存在", tag); return; }
    int lvl = 0;
    Class cur = c;
    while (cur && cur != [NSObject class] && lvl < 3) {
        unsigned int n = 0;
        Ivar *iv = class_copyIvarList(cur, &n);
        NSMutableArray *a = [NSMutableArray array];
        for (unsigned int i = 0; i < n && i < 40; i++) {
            const char *nm = ivar_getName(iv[i]);
            const char *tp = ivar_getTypeEncoding(iv[i]);
            if (nm) [a addObject:[NSString stringWithFormat:@"%s:%s", nm, tp ? tp : "?"]];
        }
        if (iv) free(iv);
        if (n) L(@"[IVAR %s] %s 的 %u 个: %@", tag, class_getName(cur), n, [a componentsJoinedByString:@", "]);
        cur = class_getSuperclass(cur);
        lvl++;
    }
}

static void DYInstall(void) {
    /* 一、注入 */
    Class pm = objc_getClass("AWECommentPublishParameterModel");
    if (!pm) {
        L(@"[FATAL] AWECommentPublishParameterModel 不存在，本版无法工作");
        return;
    }
    SEL sel = sel_registerName("extraParams");
    Method m = class_getInstanceMethod(pm, sel);
    if (!m) {
        L(@"[FATAL] -extraParams 不存在");
        return;
    }
    g_origExtraParams = method_setImplementation(m, (IMP)dy_extraParams);
    L(@"[HOOK] -extraParams 已接管（返回时注入 text_extra），默认 type=%d", DYTypeValue());
    if (DYSwitchOff()) L(@"[WARN] 当前存在 dyprobe_off.txt → 不注入，只做对照");

    /* 二、情报：如果注入无效，这些类的 ivar 就是下一步要用的 */
    DYDumpIvars(objc_getClass("AWECommentPanelListSwiftImpl.CommentContentTextExtra"), "ContentTextExtra");
    DYDumpIvars(objc_getClass("TextExtraStructV2"), "TextExtraStructV2");
    DYDumpIvars(objc_getClass("AWEKMPCreateAwemeTextExtraKMP"), "KMPCreateTextExtra");

    L(@"[DONE] v23 安装完成");
}

/* ===================== 入口 ===================== */
__attribute__((constructor)) static void DYInit(void) {
    DYBeacon("dylib 已加载");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"\n========== [v23] 安装开始 %@ ==========", [NSDate date]);
            @try { DYInstall(); } @catch (...) { L(@"[v23] 安装异常，已忽略"); }
            L(@"[v23] 用法：发一条 plain text 评论，然后去网页版（或用别的号）看是不是红字");
            L(@"[v23] 日志 Documents/dyprobe_v23.txt；想换颜色改 Documents/dyprobe_type.txt");
        }
    });
}
