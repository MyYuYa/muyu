#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

/*
 * DYProbe v17 —— 全量调用索引 + 命中单独成档（仍然只读，不改一个字节）
 * ============================================================================
 * v16 实测结论（用户日志，2026-11-20 00:13，53 次 SSL_write）：
 *   hook 完全正常：安装 7 处，写入了 53 段，没有一次崩溃。
 *   但整段日志里 **没有一条 POST、没有 tt21、没有 text/text_extra/comment**。
 *   能读出来的请求全是这一类：
 *       GET /.../video/tos/...  Host: v5-whe.douyinvod.com
 *       Range: bytes=0-511999   X-ReqType: preload
 *       User-Agent: AVDML_...,homepage_hot,MDLTaskPreload,MDLGroup(Aweme)
 *   也就是说：这一次启动抖音只做了「首页信息流视频/音频预加载」，
 *   评论的发布请求根本没有发出去（评论没点发送，或点了但没发成功）。
 *   → 观测层已经通了，缺的是「那条请求」本身。
 *
 * v17 只做三件事，都是为了下一次能稳稳接住那条请求：
 *   1) 每一次 SSL_write 都写一行索引（序号 / 相对毫秒 / 字节数 / 类型 / ASCII 预览），
 *      小包另附 24 字节十六进制 → 能看出 HTTP/2 帧头、能一眼看出有没有 POST。
 *   2) 命中关键词的段落单独写进 dyprobe_hit.txt（最多 32KB 全文），
 *      用户只需要把这一份发出来，不用再贴几万字。
 *   3) 日志改成「跨会话追加」：文件 < 3MB 就接着写，不覆盖。
 *      抖音被系统重启也不会把已经抓到的东西冲掉。
 *
 * 安装逻辑与 v15/v16 **逐字相同**（已实测不崩）：
 *   - 延迟 4 秒装；只改 __DATA 段的 la_symbol_ptr 指针
 *   - 不 vm_protect、不扫 ObjC 类、不碰业务对象、不改 buffer、不改返回值
 */

/* ============================ 类型别名 ============================ */
/* Apple SDK 里这些只是 struct 标签，没有同名 typedef，直接当类型名用会编译报错 */
typedef struct mach_header_64      dy_mach_header_t;
typedef struct segment_command_64  dy_segment_command_t;
typedef struct section_64          dy_section_t;
typedef struct nlist_64            dy_nlist_t;

/* ============================ 日志基础设施 ============================ */
static NSLock       *g_lock     = nil;
static NSFileHandle *g_fh       = nil;    /* Documents/dyprobe_dump.txt  全量索引 */
static NSFileHandle *g_hit      = nil;    /* Documents/dyprobe_hit.txt   只放命中 */
static CFAbsoluteTime g_t0      = 0;
static long long     g_dumpBytes = 0;
static long long     g_hitBytes  = 0;
static long long     g_bodyBytes = 0;     /* 正文抄写配额，防止日志写爆 */
static int           g_bodyCount = 0;
static BOOL          g_dumpFull  = NO;
static BOOL          g_hitFull   = NO;

static const long long kDumpFileCap = 3LL * 1024 * 1024;   /* 超过就重开一个空文件 */
static const long long kHitFileCap  = 512LL * 1024;
static const long long kBodyByteCap = 2LL * 1024 * 1024;   /* 本次会话正文最多抄 2MB */
static const int       kBodyCountCap = 600;
static const int       kBodyPerWrite = 8192;               /* 单段正文最多 8KB */
static const int       kHitBodyMax   = 32768;              /* 命中段落最多 32KB */
static const int       kSummaryCap   = 20000;              /* 索引最多记 2 万条 */

static NSString *DYDoc(NSString *name) {
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!doc) return nil;
    return [doc stringByAppendingPathComponent:name];
}

static long long DYFileSize(NSString *p) {
    if (!p) return 0;
    NSDictionary *a = [[NSFileManager defaultManager] attributesOfItemAtPath:p error:NULL];
    if (!a) return 0;
    NSNumber *n = [a objectForKey:NSFileSize];
    return n ? (long long)[n longLongValue] : 0;
}

static void DYLockInit(void) {
    if (!g_lock) g_lock = [[NSLock alloc] init];
}

/*
 * 跨会话追加：文件小于上限就接着写（抖音被重启也不会冲掉已抓到的内容），
 * 超过上限才截断重来。
 */
static void DYSetup(void) {
    DYLockInit();
    [g_lock lock];
    @try {
        NSString *pd = DYDoc(@"dyprobe_dump.txt");
        NSString *ph = DYDoc(@"dyprobe_hit.txt");

        if (pd) {
            if (DYFileSize(pd) > kDumpFileCap) [[NSData data] writeToFile:pd atomically:YES];
            if (![[NSFileManager defaultManager] fileExistsAtPath:pd]) [[NSData data] writeToFile:pd atomically:YES];
            g_fh = [NSFileHandle fileHandleForWritingAtPath:pd];
            @try { [g_fh seekToEndOfFile]; } @catch (...) {}
            g_dumpBytes = DYFileSize(pd);
        }
        if (ph) {
            if (DYFileSize(ph) > kHitFileCap) [[NSData data] writeToFile:ph atomically:YES];
            if (![[NSFileManager defaultManager] fileExistsAtPath:ph]) [[NSData data] writeToFile:ph atomically:YES];
            g_hit = [NSFileHandle fileHandleForWritingAtPath:ph];
            @try { [g_hit seekToEndOfFile]; } @catch (...) {}
            g_hitBytes = DYFileSize(ph);
        }
    } @catch (...) {
    } @finally {
        [g_lock unlock];
    }
}

/* 内部：调用者已持锁。sync=YES 时强制落盘（只在命中时用，见下方说明） */
static void DYAppendLocked(NSFileHandle *fh, NSString *s, BOOL toHit, BOOL sync) {
    if (!fh || !s) return;
    NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (!d) return;
    @try {
        [fh writeData:d];
        /* 只在命中时 fsync。writeData 本身已经 write() 到内核，进程被杀（用户上滑杀进程）
         * 数据不会丢；fsync 只防「掉电」。而 RTCLive 推流时 SSL_write 可能每秒几十次，
         * 每次都 fsync 会把网络线程拖死、还会把日志瞬间写满 —— 所以默认不同步。 */
        if (sync) [fh synchronizeFile];
    } @catch (...) {}
    if (toHit) g_hitBytes += (long long)d.length;
    else       g_dumpBytes += (long long)d.length;
}

static void DYAppend(NSString *s) {
    if (!s) return;
    DYLockInit();
    [g_lock lock];
    @try {
        if (!g_dumpFull && g_dumpBytes + (long long)[s length] > kDumpFileCap + (512 * 1024)) {
            g_dumpFull = YES;
            DYAppendLocked(g_fh, @"[v17] 索引已达上限，后续不再写索引", NO, YES);
        }
        if (!g_dumpFull) DYAppendLocked(g_fh, s, NO, NO);
    } @catch (...) {
    } @finally {
        [g_lock unlock];
    }
}

static void DYAppendHit(NSString *s) {
    if (!s) return;
    DYLockInit();
    [g_lock lock];
    @try {
        if (!g_hitFull && g_hitBytes > kHitFileCap) {
            g_hitFull = YES;
            DYAppendLocked(g_hit, @"[v17] 命中档已达上限，后续不再写", YES, YES);
        }
        if (!g_hitFull) DYAppendLocked(g_hit, s, YES, YES);
    } @catch (...) {
    } @finally {
        [g_lock unlock];
    }
}

/* ============================ 小工具 ============================ */
static const void *dy_memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (!h || !n || nl == 0 || hl < nl) return NULL;
    const unsigned char *p = (const unsigned char *)h;
    const unsigned char *last = p + (hl - nl);
    unsigned char first = *(const unsigned char *)n;
    while (p <= last) {
        if (*p == first && memcmp(p, n, nl) == 0) return p;
        p++;
    }
    return NULL;
}

static BOOL dy_has(const unsigned char *p, int n, const char *kw) {
    if (!p || n <= 0 || !kw) return NO;
    size_t kl = strlen(kw);
    if (kl == 0 || (size_t)n < kl) return NO;
    return dy_memmem(p, (size_t)n, kw, kl) != NULL;
}

/* 可打印占比（0~100），换行/回车/制表算可打印（HTTP 头都是这种） */
static int dy_ratio(const unsigned char *p, int n) {
    if (!p || n <= 0) return 0;
    int good = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t') good++;
    }
    return good * 100 / n;
}

/* 单行 ASCII 预览：换行压成空格，不可打印转 '.' */
static NSString *dy_line(const unsigned char *p, int n, int maxLen) {
    if (!p || n <= 0) return @"";
    int lim = (n < maxLen) ? n : maxLen;
    NSMutableString *ms = [NSMutableString stringWithCapacity:(NSUInteger)lim + 8];
    for (int i = 0; i < lim; i++) {
        unsigned char c = p[i];
        if (c == '\n' || c == '\r' || c == '\t') [ms appendString:@" "];
        else if (c >= 32 && c < 127) [ms appendFormat:@"%c", c];
        else [ms appendString:@"."];
    }
    return ms;
}

/* 十六进制前缀：用来读 HTTP/2 帧头 9 字节（len3 + type + flags + streamid4） */
static NSString *dy_hex(const unsigned char *p, int n, int maxBytes) {
    if (!p || n <= 0) return @"";
    int lim = (n < maxBytes) ? n : maxBytes;
    NSMutableString *ms = [NSMutableString stringWithCapacity:(NSUInteger)lim * 3 + 4];
    for (int i = 0; i < lim; i++) {
        if (i) [ms appendString:@" "];
        [ms appendFormat:@"%02x", p[i]];
    }
    return ms;
}

/* 多行正文：可打印保留，\r 写成 \\r，其余转 '.'（与 v16 一致，便于肉眼比对） */
static NSString *dy_text(const unsigned char *p, int n) {
    if (!p || n <= 0) return @"";
    NSMutableString *ms = [NSMutableString stringWithCapacity:(NSUInteger)n + 32];
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c == '\n')      [ms appendString:@"\n"];
        else if (c == '\r') [ms appendString:@"\\r"];
        else if (c == '\t') [ms appendString:@"\\t"];
        else if (c >= 32 && c < 127) [ms appendFormat:@"%c", c];
        else                [ms appendString:@"."];
    }
    return ms;
}

/* ============================ 分类与命中判定 ============================ */
static void dy_classify(const unsigned char *p, int n, const char **tagOut, BOOL *isGetOut) {
    BOOL isGet = NO;
    const char *tag = "BIN";

    if (n >= 4 && memcmp(p, "GET ", 4) == 0)        { isGet = YES; tag = "GET"; }
    else if (n >= 5 && memcmp(p, "POST ", 5) == 0)  { tag = "POST"; }
    else if (n >= 4 && memcmp(p, "PUT ", 4) == 0)   { tag = "PUT"; }
    else if (n >= 14 && memcmp(p, "PRI * HTTP/2.0", 14) == 0) { tag = "H2PRE"; }
    else {
        int r = dy_ratio(p, n);
        if (r >= 92) tag = "TXT";
        else if (r >= 55) tag = "MIX";
        else tag = "BIN";
    }
    *tagOut = tag;
    *isGetOut = isGet;
}

/* 命中 = 出现下面任何一条。命中段会整段抄进 dyprobe_hit.txt */
static BOOL dy_isHit(const unsigned char *p, int n) {
    if (!p || n <= 0) return NO;
    static const char *kws[] = {
        "POST ",                  /* 任何 POST 都记：评论发布一定是 POST */
        "text_extra",             /* 目标字段 */
        "comment/publish",        /* 评论发布路径 */
        "aweme/v1/comment",
        "\"text\"",
        "reply_id",
        "tt21",                   /* 用户测试串 */
        "multipart/form-data",
        "x-www-form-urlencoded",
        "X-SS-STUB",              /* TTNet 签名头 */
        "X-Gorgon",
    };
    for (size_t i = 0; i < sizeof(kws) / sizeof(kws[0]); i++) {
        if (dy_has(p, n, kws[i])) return YES;
    }
    return NO;
}

/* ============================ 核心：SSL_write ============================ */
typedef int (*dy_ssl_write_t)(void *ssl, const void *buf, int num);
static dy_ssl_write_t orig_SSL_write = NULL;

static volatile int       g_calls = 0;
static volatile long long g_bytes = 0;
static volatile int       g_hits  = 0;
static volatile int       g_posts = 0;

static void dy_record(int idx, const void *buf, int len) {
    const unsigned char *p = (const unsigned char *)buf;

    const char *tag = "BIN";
    BOOL isGet = NO;
    dy_classify(p, len, &tag, &isGet);

    BOOL hit = dy_isHit(p, len);
    if (hit) __sync_add_and_fetch(&g_hits, 1);
    /* 计数用 dy_has：HTTP/2 下请求行被 HPACK 压掉了，不能只看开头是不是 "POST " */
    if (strcmp(tag, "POST") == 0 || dy_has(p, len, "POST ")) __sync_add_and_fetch(&g_posts, 1);

    long long ms = (long long)((CFAbsoluteTimeGetCurrent() - g_t0) * 1000.0);
    if (ms < 0) ms = 0;

    /* 硬闸：超过 20000 次调用后只留命中段，防止推流类流量把索引刷爆 */
    if (!hit && idx > kSummaryCap) return;

    /* 每一行索引：序号 / 相对毫秒 / 长度 / 类型 / ASCII 预览 */
    NSMutableString *s = [NSMutableString stringWithCapacity:256];
    [s appendFormat:@"#%d +%lldms %dB %s%@", idx, ms, len, tag, hit ? @"  ★HIT" : @""];
    [s appendFormat:@"\n    a=\"%@\"", dy_line(p, len, 150)];
    if (strcmp(tag, "BIN") == 0 || strcmp(tag, "H2PRE") == 0) {
        [s appendFormat:@"\n    h=\"%@\"", dy_hex(p, len, 24)];
    }
    DYAppend(s);

    /* 正文：命中段落一定抄；非 GET 的小包也抄（评论 body 就在这个量级） */
    BOOL wantBody = hit || (!isGet && len <= kBodyPerWrite);
    BOOL bodyRoom = (g_bodyCount < kBodyCountCap && g_bodyBytes < kBodyByteCap);

    if (wantBody && bodyRoom) {
        int lim = len;
        if (lim > kBodyPerWrite) lim = kBodyPerWrite;
        NSString *body = dy_text(p, lim);

        NSMutableString *blk = [NSMutableString stringWithCapacity:(NSUInteger)lim + 256];
        [blk appendFormat:@"----- BODY #%d (%dB, %s)%@ -----\n", idx, len, tag, hit ? @" ★HIT" : @""];
        [blk appendString:body];
        if (len > lim) [blk appendFormat:@"\n...[正文截断，原长 %d 字节]...", len];
        [blk appendString:@"\n----- END BODY -----"];
        DYAppend(blk);

        g_bodyCount++;
        g_bodyBytes += lim;
    }

    /* 命中档不参与上面的配额：它是唯一要拿出去看的东西，必须写进去 */
    if (hit) {
        int hlim = (len < kHitBodyMax) ? len : kHitBodyMax;
        NSMutableString *hb = [NSMutableString stringWithCapacity:(NSUInteger)hlim + 320];
        [hb appendFormat:@"\n@@@@@ HIT #%d +%lldms %dB %s @@@@@\n", idx, ms, len, tag];
        [hb appendString:@"hex: "];
        [hb appendString:dy_hex(p, hlim, 32)];
        [hb appendString:@"\n--- text ---\n"];
        [hb appendString:dy_text(p, hlim)];
        if (len > hlim) [hb appendFormat:@"\n...[截断，原长 %d 字节]...", len];
        [hb appendString:@"\n@@@@@ END HIT @@@@@"];
        DYAppendHit(hb);
    }
}

static int dy_SSL_write(void *ssl, const void *buf, int num) {
    int c = __sync_add_and_fetch(&g_calls, 1);

    if (c == 1 || (c % 200) == 0) {
        DYAppend([NSString stringWithFormat:
                  @"[v17] 心跳：调用 %d 次 / 累计 %lld 字节 / 命中 %d / POST %d",
                  c, (long long)g_bytes, g_hits, g_posts]);
    }

    if (buf && num > 0) {
        g_bytes += num;
        @try { dy_record(c, buf, num); } @catch (...) {}
    }

    if (orig_SSL_write) return orig_SSL_write(ssl, buf, num);
    return -1;
}

/* ============================ fishhook（自实现，逻辑与 v15/v16 一致） ============================ */
struct dy_rebinding { const char *name; void *replacement; };

static struct dy_rebinding g_rb[] = {
    { "SSL_write", (void *)dy_SSL_write },
};
static const size_t g_rb_n = sizeof(g_rb) / sizeof(g_rb[0]);
static int g_replaced = 0;

static BOOL dy_name_match(const char *symname) {
    if (!symname || !symname[0] || !symname[1]) return NO;
    const char *shortname = symname + 1;   /* 跳过前导 '_' */
    for (size_t i = 0; i < g_rb_n; i++) {
        if (strcmp(shortname, g_rb[i].name) == 0) return YES;
    }
    return NO;
}

static void dy_rebind_section(dy_section_t *sect, intptr_t slide,
                              dy_nlist_t *symtab, char *strtab, uint32_t *indirect) {
    if ((sect->flags & SECTION_TYPE) != S_NON_LAZY_SYMBOL_POINTERS &&
        (sect->flags & SECTION_TYPE) != S_LAZY_SYMBOL_POINTERS) return;

    size_t cnt = sect->size / sizeof(void *);
    if (cnt == 0) return;
    void **bindings = (void **)((uintptr_t)slide + sect->addr);
    uint32_t *indices = indirect + sect->reserved1;

    /* 先探一遍：这段里有没有目标符号。没有就完全不动内存 */
    BOOL hit = NO;
    for (size_t k = 0; k < cnt; k++) {
        uint32_t si = indices[k];
        if (si == INDIRECT_SYMBOL_ABS || si == INDIRECT_SYMBOL_LOCAL ||
            si == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        if (dy_name_match(strtab + symtab[si].n_un.n_strx)) { hit = YES; break; }
    }
    if (!hit) return;

    /* 目标符号位于 __DATA,__la_symbol_ptr，该段本身可写，直接改指针即可 */
    for (size_t k = 0; k < cnt; k++) {
        uint32_t si = indices[k];
        if (si == INDIRECT_SYMBOL_ABS || si == INDIRECT_SYMBOL_LOCAL ||
            si == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        if (!dy_name_match(strtab + symtab[si].n_un.n_strx)) continue;
        for (size_t r = 0; r < g_rb_n; r++) {
            if (strcmp(strtab + symtab[si].n_un.n_strx + 1, g_rb[r].name) == 0) {
                if (bindings[k] != g_rb[r].replacement) {
                    bindings[k] = g_rb[r].replacement;
                    g_replaced++;
                }
            }
        }
    }
}

static void dy_rebind_image(const struct mach_header *header, intptr_t slide) {
    const dy_mach_header_t *mh = (const dy_mach_header_t *)header;
    if (!mh || mh->magic != MH_MAGIC_64) return;

    dy_segment_command_t *linkedit = NULL;
    struct symtab_command *stcmd = NULL;
    struct dysymtab_command *dstcmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(dy_mach_header_t);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        dy_segment_command_t *seg = (dy_segment_command_t *)cur;
        if (seg->cmdsize == 0) break;
        if (seg->cmd == LC_SEGMENT_64 && strcmp(seg->segname, SEG_LINKEDIT) == 0) linkedit = seg;
        else if (seg->cmd == LC_SYMTAB)   stcmd  = (struct symtab_command *)seg;
        else if (seg->cmd == LC_DYSYMTAB) dstcmd = (struct dysymtab_command *)seg;
        cur += seg->cmdsize;
    }
    if (!linkedit || !stcmd || !dstcmd || dstcmd->nindirectsyms == 0) return;

    uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    dy_nlist_t *symtab = (dy_nlist_t *)(base + stcmd->symoff);
    char *strtab = (char *)(base + stcmd->stroff);
    uint32_t *indirect = (uint32_t *)(base + dstcmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(dy_mach_header_t);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        dy_segment_command_t *seg = (dy_segment_command_t *)cur;
        if (seg->cmdsize == 0) break;
        cur += seg->cmdsize;
        if (seg->cmd != LC_SEGMENT_64) continue;
        /* 只处理 __DATA（RW 可写段）。实测 AwemeCore 无 __DATA_CONST */
        if (strcmp(seg->segname, SEG_DATA) != 0) continue;
        dy_section_t *sect = (dy_section_t *)((uintptr_t)seg + sizeof(dy_segment_command_t));
        for (uint32_t j = 0; j < seg->nsects; j++, sect++) {
            dy_rebind_section(sect, slide, symtab, strtab, indirect);
        }
    }
}

/* ============================ 安装（延迟执行） ============================ */
static void dy_install(void) {
    g_t0 = CFAbsoluteTimeGetCurrent();
    DYSetup();

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    NSString *ts = [df stringFromDate:[NSDate date]] ?: @"?";

    DYAppend([NSString stringWithFormat:
              @"\n\n========== [v17] 会话开始 %@ ==========", ts]);
    DYAppendHit([NSString stringWithFormat:
                 @"\n\n========== [v17] 会话开始 %@ ==========", ts]);

    void *p = dlsym(RTLD_DEFAULT, "SSL_write");
    if (!p) {
        DYAppend(@"[v17] dlsym SSL_write = NULL（boringssl 未加载），放弃安装");
        return;
    }
    orig_SSL_write = (dy_ssl_write_t)p;
    DYAppend([NSString stringWithFormat:@"[v17] dlsym SSL_write = %p", p]);

    uint32_t total = _dyld_image_count();
    uint32_t scanned = 0;
    for (uint32_t i = 0; i < total; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        /* 跳过系统库：只关心 App 自己的 image，减少无关内存操作 */
        if (strncmp(nm, "/usr/lib/", 9) == 0) continue;
        if (strncmp(nm, "/System/Library/", 16) == 0) continue;
        if (strncmp(nm, "/System/Cryptexes/", 18) == 0) continue;
        int before = g_replaced;
        dy_rebind_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        if (g_replaced != before) {
            DYAppend([NSString stringWithFormat:@"[v17] 命中 image: %s（改写 %d 处）", nm, g_replaced - before]);
        }
        scanned++;
    }
    DYAppend([NSString stringWithFormat:@"[v17] 安装完成：扫描 %u/%u 个非系统 image，改写 GOT %d 处",
              scanned, total, g_replaced]);

    if (g_replaced == 0) {
        DYAppend(@"[v17] 注意：改写 0 处 → hook 未生效，抓不到数据但不影响 App");
    } else {
        DYAppend(@"[v17] 请进入任意视频评论区，发一条内容为 tt21 的评论，看到“评论成功”后退出抖音");
        DYAppend(@"[v17] 索引在 Documents/dyprobe_dump.txt，命中段在 Documents/dyprobe_hit.txt");
    }
}

__attribute__((constructor)) static void DYInit(void) {
    /* 不在 constructor 里立刻动手：那一刻各 image 仍在加载，
     * 遍历它们做符号解析容易读到未就绪的数据（v14 崩在这个阶段）。
     * 延后 4 秒，等 App 启动稳定、各 image 的 __DATA 已就绪后再改。 */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            @try { dy_install(); } @catch (...) {
                DYAppend(@"[v17] 安装异常，已忽略");
            }
        }
    });
}
