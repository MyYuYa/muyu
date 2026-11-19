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
 * DYProbe v16 — 在 SSL_write 抄明文（只读，不改一个字节）
 * ============================================================================
 * v15 实测结论（用户日志，2026-11-20 00:04）：
 *   启动正常、不闪退；dlsym SSL_write = 0x105e0c244；
 *   AwemeCore / ByteRtsEngineKit / OmniStream / RTCLive / StreamCore / TTFFmpeg / libvcn
 *   共 7 个 image、7 处 GOT 改写成功。
 *   但是一条数据都没抄到。
 *
 * 为什么抄不到（这是本版唯一改动的原因）：
 *   v15 的触发条件是 buffer 里能搜到 "comment/publish"。而抖音 API 走 HTTP/2，
 *   请求路径在 HEADERS 帧里被 HPACK 压缩，明文字节流中不存在 "comment/publish"；
 *   备选条件 "text=" + "aweme_id" 也不成立（body 多为 params=<urlencoded JSON>）。
 *   → hook 是活的，是筛选条件太窄，把目标全滤掉了。
 *
 * v16 的做法：不再猜特征，改成「有界全量记录 + 心跳计数」。
 *   1) 每次 SSL_write 都计数，第 1/100/200... 次打心跳 → 一眼看出 hook 有没有被调用
 *   2) 长度 <= 8192 的写入全部抄下来（API 请求都在这个量级；媒体分片通常几十 KB~MB，自然被排除）
 *   3) 命中 "text"/"aweme_id"/"params" 的，头部打 ★HIT 便于检索
 *   4) 每次启动清空日志，避免新旧版本混在一个文件里
 *   5) 抄写有上限（400 段 / 900KB），到顶即停，不会把文件写爆
 *
 * 与 v15 相同的安全约束（这部分一行没动，是已经验证不崩的版本）：
 *   - 延迟 4 秒安装（不在 constructor 里动手）
 *   - 只改 GOT 指针，只处理 __DATA 段里 S_LAZY/ NON_LAZY_SYMBOL_POINTERS
 *   - 不 vm_protect、不扫 ObjC 类、不碰业务对象、不改 buffer、不改返回值
 *
 * 实测结构（AwemeCore，Python 直接解析 Mach-O 得到，非推测）：
 *   - 无 LC_DYLD_CHAINED_FIXUPS（走老的 LC_DYLD_INFO_ONLY）
 *   - 无 __DATA_CONST 段；目标符号全在 __DATA,__la_symbol_ptr（RW，可直接写）
 *       _SSL_write 0x31e0e610 / _SSL_read 0x31e0e4a0 / _X509_verify_cert 0x31e0ea20
 */

/* ============================ 类型别名 ============================ */
/* Apple SDK 里这些只是 struct 标签，没有同名 typedef，直接当类型名用会编译报错 */
typedef struct mach_header_64     dy_mach_header_t;
typedef struct segment_command_64 dy_segment_command_t;
typedef struct section_64         dy_section_t;
typedef struct nlist_64           dy_nlist_t;

/* ============================ 日志（单句柄 + 加锁 + 落盘） ============================ */
static NSLock       *g_lock = nil;
static NSFileHandle *g_fh   = nil;

static NSString *DYLogPath(void) {
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!doc) return nil;
    return [doc stringByAppendingPathComponent:@"dyprobe_dump.txt"];
}

static void DYLockInit(void) {
    if (!g_lock) g_lock = [[NSLock alloc] init];
}

/* 每次启动清空日志：旧版本（v12/v13/v14/v15）的内容混在一起没法看 */
static void DYLogReset(void) {
    DYLockInit();
    [g_lock lock];
    @try {
        @try { if (g_fh) { [g_fh closeFile]; g_fh = nil; } } @catch (...) {}
        NSString *p = DYLogPath();
        if (!p) return;
        [[NSData data] writeToFile:p atomically:YES];   /* 截断成空文件 */
        g_fh = [NSFileHandle fileHandleForWritingAtPath:p];
        @try { [g_fh seekToEndOfFile]; } @catch (...) {}
    } @catch (...) {
    } @finally {
        [g_lock unlock];
    }
}

static void DYWrite(NSString *s) {
    if (!s) return;
    NSLog(@"[DYSW16] %@", s);
    DYLockInit();
    [g_lock lock];
    @try {
        if (!g_fh) {   /* 还没 reset 过（例如极早调用），退化成追加 */
            NSString *p = DYLogPath();
            if (!p) return;
            if (![[NSFileManager defaultManager] fileExistsAtPath:p]) {
                [[NSData data] writeToFile:p atomically:YES];
            }
            g_fh = [NSFileHandle fileHandleForWritingAtPath:p];
            @try { [g_fh seekToEndOfFile]; } @catch (...) {}
        }
        NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        if (g_fh && d) {
            [g_fh writeData:d];
            @try { [g_fh synchronizeFile]; } @catch (...) {}   /* 立即落盘，防崩溃丢数据 */
        }
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

/* 把字节转成可读文本：可打印字符保留，换行保留，其余转 '.' */
static NSString *DYSanitize(const unsigned char *p, int n) {
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

/* 是否像我们要找的东西（只用于打标记，不再作为过滤条件） */
static BOOL dy_looksInteresting(const unsigned char *p, int n) {
    if (!p || n <= 0) return NO;
    size_t len = (size_t)n;
    if (dy_memmem(p, len, "aweme_id", 8)) return YES;
    if (dy_memmem(p, len, "text", 4)) return YES;
    if (dy_memmem(p, len, "params", 6)) return YES;
    if (dy_memmem(p, len, "comment", 7)) return YES;
    if (dy_memmem(p, len, "reply", 5)) return YES;
    return NO;
}

/* ============================ 核心：SSL_write ============================ */
typedef int (*dy_ssl_write_t)(void *ssl, const void *buf, int num);
static dy_ssl_write_t orig_SSL_write = NULL;

static volatile int       g_calls       = 0;
static volatile long long g_bytes       = 0;
static int                g_dumpCount   = 0;
static long long          g_dumpedBytes = 0;

static const int       kSmallLimit   = 8192;          /* 只抄 <=8KB 的写入（API 请求量级） */
static const int       kDumpMaxCount = 400;           /* 最多 400 段 */
static const long long kDumpMaxBytes = 900 * 1024;    /* 或者 900KB，先到为准 */
static const int       kHeadBytes    = 3072;
static const int       kTailBytes    = 512;

static void DYDumpWrite(int idx, const void *buf, int len) {
    const unsigned char *p = (const unsigned char *)buf;
    int head = (len > kHeadBytes) ? kHeadBytes : len;
    BOOL hit = dy_looksInteresting(p, len);

    NSMutableString *s = [NSMutableString stringWithCapacity:(NSUInteger)head + 256];
    [s appendFormat:@"\n===== SSL_write#%d len=%d %@=====\n", idx, len, hit ? @"★HIT " : @""];
    [s appendString:DYSanitize(p, head)];
    if (len > head) {
        int tail = (len < kTailBytes) ? len : kTailBytes;
        [s appendString:@"\n...[TAIL]...\n"];
        [s appendString:DYSanitize(p + (len - tail), tail)];
    }
    [s appendString:@"\n===== END ====="];
    DYWrite(s);
}

static int dy_SSL_write(void *ssl, const void *buf, int num) {
    int c = __sync_add_and_fetch(&g_calls, 1);

    if (c == 1 || (c % 100) == 0) {
        DYWrite([NSString stringWithFormat:@"[v16] 心跳：SSL_write 已调用 %d 次，累计 %lld 字节",
                 c, (long long)g_bytes]);
    }

    if (buf && num > 0) {
        g_bytes += num;
        /* 只抄小包：媒体分片通常几十 KB~MB，自然排除；API 请求都在 8KB 以内 */
        if (num <= kSmallLimit && g_dumpCount < kDumpMaxCount && g_dumpedBytes < kDumpMaxBytes) {
            g_dumpCount++;
            g_dumpedBytes += (num > kHeadBytes ? kHeadBytes : num);
            @try { DYDumpWrite(g_dumpCount, buf, num); } @catch (...) {}
            if (g_dumpCount == kDumpMaxCount || g_dumpedBytes >= kDumpMaxBytes) {
                DYWrite([NSString stringWithFormat:
                         @"[v16] 已达记录上限（%d 段 / %lld 字节），后续只计数不再抄写",
                         g_dumpCount, (long long)g_dumpedBytes]);
            }
        }
    }

    if (orig_SSL_write) return orig_SSL_write(ssl, buf, num);
    return -1;
}

/* ============================ fishhook（与 v15 完全一致，已验证不崩） ============================ */
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
    DYLogReset();
    DYWrite(@"[v16] ===== 本次启动开始（本文件已清空，只含本次记录）=====");

    void *p = dlsym(RTLD_DEFAULT, "SSL_write");
    if (!p) {
        DYWrite(@"[v16] dlsym SSL_write = NULL（boringssl 未加载），放弃安装");
        return;
    }
    orig_SSL_write = (dy_ssl_write_t)p;
    DYWrite([NSString stringWithFormat:@"[v16] dlsym SSL_write = %p", p]);

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
            DYWrite([NSString stringWithFormat:@"[v16] 命中 image: %s（改写 %d 处）", nm, g_replaced - before]);
        }
        scanned++;
    }
    DYWrite([NSString stringWithFormat:@"[v16] 安装完成：扫描 %u/%u 个非系统 image，改写 GOT %d 处",
             scanned, total, g_replaced]);
    if (g_replaced == 0) {
        DYWrite(@"[v16] 注意：改写 0 处 → hook 未生效（SSL_write 可能不在指针段），抓不到数据但不影响 App");
    } else {
        DYWrite(@"[v16] 请发一条评论（内容随意，例如 tt21），然后退出抖音导出本文件");
    }
}

__attribute__((constructor)) static void DYInit(void) {
    /* 不在 constructor 里立刻动手：那一刻各 image 仍在加载，
     * 遍历它们做符号解析容易读到未就绪的数据（v14 崩在这个阶段）。
     * 延后 4 秒，等 App 启动稳定、各 image 的 __DATA 已就绪后再改。 */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            @try { dy_install(); } @catch (...) { DYWrite(@"[v16] 安装异常，已忽略"); }
        }
    });
}
