#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_prot.h>
#import <mach/vm_param.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

/*
 * DYProbe v15 — 在 SSL_write 抄明文（只读，不改一个字节）
 * ============================================================================
 * 为什么是这里（静态分析已确认）：
 *   - boringssl.framework 只导出 SSL_write / SSL_read，没有 _ex 版本
 *   - AwemeCore 只导入 SSL_write，没有 SSL_write_ex
 *   - 不存在独立 QUIC 库 → 抖音 TLS 流量必经 SSL_write
 *   - Charles 抓不到 amemv.com（TTNet 不走系统代理），Pinning 也挡；
 *     但 SSL_write 是加密前明文，两者都绕过了
 *
 * 与 v13/v14 的区别（针对两次启动闪退的教训）：
 *   - v13 崩：全类扫描 hook 几百个方法，ABI 靠猜
 *   - v14 崩：constructor 里立刻动手，且遍历了所有 image（含 dyld 共享缓存里的系统库）。
 *             对缓存镜像，linkedit->vmaddr - linkedit->fileoff + slide 算出的基址不成立，
 *             读到的 symtab/strtab 是垃圾 → indirect 索引越界 → 崩。这是最可能的真实崩因。
 *   - v15：延迟 4 秒（App 启动完成后再动手）；只改 1 个符号；跳过系统库；
 *          只读 buffer，绝不改内容、绝不改返回值、绝不 hook 业务对象
 *
 * 实测结构（AwemeCore，Python 直接解析 Mach-O 得到，非推测）：
 *   - 无 LC_DYLD_CHAINED_FIXUPS（走老的 LC_DYLD_INFO_ONLY）
 *   - 无 __DATA_CONST 段；段只有 __TEXT / __DATA / Data / __LYNX__DATA / __LINKEDIT
 *   - 目标符号全在 __DATA,__la_symbol_ptr（lazy，RW 可写段）：
 *       _SSL_write                 0x31e0e610
 *       _SSL_read                  0x31e0e4a0
 *       _X509_verify_cert          0x31e0ea20
 *       _SSL_CTX_set_custom_verify 0x31e0e160
 *   - 因此：写 GOT 不需要 vm_protect 提权，直接改指针即可。本版不再做任何 mprotect。
 *
 * 只做三件事：
 *   1) dlsym 先拿到 boringssl 里 SSL_write 的真实地址（orig）
 *   2) 把各 image 里的 SSL_write GOT 指针指向本文件的 dy_SSL_write
 *   3) dy_SSL_write 里检查 buffer，命中评论关键词就抄到 dyprobe_dump.txt，然后原样调用 orig
 *
 * 失败模式：hook 不上 = 什么都不发生，App 照常跑。日志里会有明确状态行。
 */

/* ============================ 类型别名 ============================ */
/* Apple SDK 里这些只是 struct 标签，没有同名 typedef，直接当类型名用会编译报错 */
typedef struct mach_header_64     dy_mach_header_t;
typedef struct segment_command_64 dy_segment_command_t;
typedef struct section_64         dy_section_t;
typedef struct nlist_64           dy_nlist_t;

/* ============================ 日志 ============================ */
static NSString *DYLogPath(void) {
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!doc) return nil;
    return [doc stringByAppendingPathComponent:@"dyprobe_dump.txt"];
}

static void DYWrite(NSString *s) {
    if (!s) return;
    NSLog(@"[DYSW15] %@", s);
    @try {
        NSString *p = DYLogPath();
        if (!p) return;
        NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        if (!d) return;
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
        if (!fh) {
            [d writeToFile:p atomically:YES];
        } else {
            @try { [fh seekToEndOfFile]; [fh writeData:d]; }
            @finally { [fh closeFile]; }
        }
    } @catch (...) {}
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

/* 把 buffer 转成可读文本：可打印字符保留，换行保留，其余转 '.'
 * 参数全用 C 类型，tag 在函数内部生成 NSString —— 避免 Objective-C 与 C 类型混用。 */
static void DYDumpBuf(const char *kind, int index, const void *buf, int len) {
    if (!kind || !buf || len <= 0) return;
    int n = len > 4096 ? 4096 : len;   /* 单次最多抄 4KB，防止文件爆掉 */
    const unsigned char *p = (const unsigned char *)buf;
    NSMutableString *ms = [NSMutableString stringWithCapacity:(NSUInteger)n + 128];
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c == '\n')      [ms appendString:@"\n"];
        else if (c == '\r') [ms appendString:@"\\r"];
        else if (c == '\t') [ms appendString:@"\\t"];
        else if (c >= 32 && c < 127) [ms appendFormat:@"%c", c];
        else                [ms appendString:@"."];
    }
    NSString *tag    = [NSString stringWithFormat:@"%s#%d", kind, index];
    NSString *suffix = (len > n) ? @" (截断到4096)" : @"";
    NSString *head   = [NSString stringWithFormat:@"\n===== %@ len=%d%@ =====\n", tag, len, suffix];
    NSString *body   = [NSString stringWithFormat:@"%@\n===== END %@ =====", ms, tag];
    DYWrite([head stringByAppendingString:body]);
}

/* ============================ 核心：SSL_write ============================ */
typedef int (*dy_ssl_write_t)(void *ssl, const void *buf, int num);
static dy_ssl_write_t orig_SSL_write = NULL;

static int g_dumpCount = 0;
static const int kDumpLimit = 40;      /* 总共最多抄 40 段，够定位了 */

/* 命中判定：评论发布请求的特征 */
static BOOL dy_isCommentPublish(const void *buf, int len) {
    if (!buf || len <= 0) return NO;
    size_t n = (size_t)len;
    if (dy_memmem(buf, n, "comment/publish", 15)) return YES;   /* HTTP/1.1 请求行 */
    if (dy_memmem(buf, n, "/aweme/v1/comment", 17)) return YES; /* 路径片段 */
    /* HTTP/2 下请求行被 HPACK 压缩搜不到，但 body 里 text= 是明文 */
    if (dy_memmem(buf, n, "text=", 5) && dy_memmem(buf, n, "aweme_id", 8)) return YES;
    return NO;
}

static int dy_SSL_write(void *ssl, const void *buf, int num) {
    @autoreleasepool {
        if (buf && num > 0 && g_dumpCount < kDumpLimit) {
            @try {
                if (dy_isCommentPublish(buf, num)) {
                    g_dumpCount++;
                    DYDumpBuf("SSL_write", g_dumpCount, buf, num);
                }
            } @catch (...) {}
        }
    }
    if (orig_SSL_write) return orig_SSL_write(ssl, buf, num);
    return -1;
}

/* ============================ fishhook（精简：只改指定符号的 GOT） ============================ */
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

    /* 先探一遍：这段里到底有没有我们的目标符号。没有就不碰权限，尽量少动内存 */
    BOOL hit = NO;
    for (size_t k = 0; k < cnt; k++) {
        uint32_t si = indices[k];
        if (si == INDIRECT_SYMBOL_ABS || si == INDIRECT_SYMBOL_LOCAL ||
            si == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        if (dy_name_match(strtab + symtab[si].n_un.n_strx)) { hit = YES; break; }
    }
    if (!hit) return;

    /* 实测：目标符号位于 __DATA,__la_symbol_ptr，该段本身可写，
     * 直接改指针即可。v14 里那套 vm_protect 提权是多余的，本版全部去掉。 */

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
        /* 只处理 __DATA（RW 可写段）。实测 AwemeCore 无 __DATA_CONST；
         * 限定 __DATA 也顺带避免误碰其他 image 的只读段。 */
        if (strcmp(seg->segname, SEG_DATA) != 0) continue;
        dy_section_t *sect = (dy_section_t *)((uintptr_t)seg + sizeof(dy_segment_command_t));
        for (uint32_t j = 0; j < seg->nsects; j++, sect++) {
            dy_rebind_section(sect, slide, symtab, strtab, indirect);
        }
    }
}

/* ============================ 安装（延迟执行） ============================ */
static void dy_install(void) {
    void *p = dlsym(RTLD_DEFAULT, "SSL_write");
    if (!p) {
        DYWrite(@"[v15] dlsym SSL_write = NULL（boringssl 未加载），放弃安装");
        return;
    }
    orig_SSL_write = (dy_ssl_write_t)p;
    DYWrite([NSString stringWithFormat:@"[v15] dlsym SSL_write = %p", p]);

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
            DYWrite([NSString stringWithFormat:@"[v15] 命中 image: %s（改写 %d 处）", nm, g_replaced - before]);
        }
        scanned++;
    }
    DYWrite([NSString stringWithFormat:@"[v15] 安装完成：扫描 %u/%u 个非系统 image，改写 GOT %d 处",
             scanned, total, g_replaced]);
    if (g_replaced == 0) {
        DYWrite(@"[v15] 注意：改写 0 处 → hook 未生效（SSL_write 可能不在 LDYNSYM 指针段），抓不到数据但不影响 App");
    }
}

__attribute__((constructor)) static void DYInit(void) {
    /* 不在 constructor 里立刻动手：那一刻所有 image 仍在加载与初始化，
     * 遍历它们做符号解析容易读到未就绪的数据（v14 崩在这个阶段）。
     * 延后 4 秒，等 App 启动稳定、各 image 的 `__DATA` 已就绪后再改。 */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            DYWrite(@"[v15] 启动完成，开始安装 SSL_write 探针");
            @try { dy_install(); } @catch (...) { DYWrite(@"[v15] 安装异常，已忽略"); }
        }
    });
}
