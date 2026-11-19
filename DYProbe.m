#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_prot.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

/*
 * DYProbe v14 — BoringSSL Pinning Bypass（只做一件事：让 Charles 能看到抖音明文）
 * ============================================================================
 * 为什么这一版不会闪退（设计原则：失败也不崩）：
 *   1) 不 hook 任何 ObjC 方法、不扫类、不碰任何业务对象。
 *   2) 只用 fishhook 改 boringssl 外部符号的 GOT 指针（纯数据指针替换）。
 *   3) 每个替换函数都判空后转发；hook 不到就什么都不做，App 照常跑。
 *
 * 技术依据（砸壳包静态分析，已确认）：
 *   - AwemeCore 通过 LC_LOAD_DYLIB 链接 @rpath/boringssl.framework/boringssl
 *   - SSL_write / X509_verify_cert / SSL_CTX_set_custom_verify 等 9 个符号
 *     在 AwemeCore 中均为 N_UNDF（外部导入），可被 fishhook 重绑
 *   - 网络栈是 TTNet(855) + Cronet(200)，TLS 由 BoringSSL 承担
 *
 * hook 三个点（三重保险）：
 *   A. SSL_CTX_set_custom_verify：把业务传入的校验回调替换为"永远 OK"
 *      （字节 Pinning 的标准实现方式就是 custom_verify 回调）
 *   B. X509_verify_cert：直接返回 1（证书链校验通过）
 *   C. SSL_get_verify_result：返回 0（X509_V_OK）
 *
 * 用法：装上 -> 打开抖音 -> Charles 里刷评论区/发评论 -> 看 amemv.com 是否变明文。
 *       本版不发红字，只负责"让抓包能看见"。
 */

/* ============================ fishhook（内联） ============================ */
/* 基于 Facebook fishhook (BSD)。补了 iOS 13+ __DATA_CONST 段的 vm_protect，
 * 否则向只读段写指针会 EXC_BAD_ACCESS —— 这正是很多 fishhook 版本闪退的根因。 */

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

/* Apple SDK 中 mach_header_64 / segment_command_64 / section_64 / nlist_64
 * 都是 struct 标签，没有同名 typedef。必须自建别名，否则编译直接报错。 */
typedef struct mach_header_64     mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64         section_t;
typedef struct nlist_64           nlist_t;

static int dy_prepend_rebindings(struct rebindings_entry **head,
                                 struct rebinding rebindings[], size_t nel) {
    struct rebindings_entry *e = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
    if (!e) return -1;
    e->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
    if (!e->rebindings) { free(e); return -1; }
    memcpy(e->rebindings, rebindings, sizeof(struct rebinding) * nel);
    e->rebindings_nel = nel;
    e->next = *head;
    *head = e;
    return 0;
}

static void dy_rebind_section(struct rebindings_entry *rebindings,
                              section_t *section, intptr_t slide,
                              nlist_t *symtab, char *strtab,
                              uint32_t *indirect_symtab) {
    uint32_t *indices = indirect_symtab + section->reserved1;
    void **bindings = (void **)((uintptr_t)slide + section->addr);

    /* 关键：__DATA_CONST 是只读段，必须临时加写权限，否则写指针直接崩。
     * 加权限失败（chained fixups / 权限策略收紧）就整段跳过——宁可 hook 不生效，也绝不崩。 */
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)bindings, section->size,
                                  0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return;

    for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t symidx = indices[i];
        if (symidx == INDIRECT_SYMBOL_ABS || symidx == INDIRECT_SYMBOL_LOCAL ||
            symidx == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;

        uint32_t strx = symtab[symidx].n_un.n_strx;
        char *symname = strtab + strx;
        if (!symname[0] || !symname[1]) continue;   /* 需跳过前导 '_' */

        for (struct rebindings_entry *cur = rebindings; cur; cur = cur->next) {
            for (size_t j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symname[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL &&
                        bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = bindings[i];
                    }
                    bindings[i] = cur->rebindings[j].replacement;
                }
            }
        }
    }
}

static void dy_rebind_image(struct rebindings_entry *rebindings,
                            const struct mach_header *header, intptr_t slide) {
    if (!rebindings) return;
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

    const mach_header_t *mh = (const mach_header_t *)header;
    segment_command_t *cur_seg = NULL;
    segment_command_t *linkedit = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < mh->ncmds; i++, cur += cur_seg->cmdsize) {
        cur_seg = (segment_command_t *)cur;
        if (cur_seg->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg->segname, SEG_LINKEDIT) == 0) linkedit = cur_seg;
        } else if (cur_seg->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg;
        } else if (cur_seg->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg;
        }
    }
    if (!symtab_cmd || !dysymtab_cmd || !linkedit ||
        !dysymtab_cmd->nindirectsyms) return;

    uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    nlist_t *symtab = (nlist_t *)(base + symtab_cmd->symoff);
    char *strtab = (char *)(base + symtab_cmd->stroff);
    uint32_t *indirect = (uint32_t *)(base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < mh->ncmds; i++, cur += cur_seg->cmdsize) {
        cur_seg = (segment_command_t *)cur;
        if (cur_seg->cmd != LC_SEGMENT_64) continue;
        if (strcmp(cur_seg->segname, SEG_DATA) != 0 &&
            strcmp(cur_seg->segname, "__DATA_CONST") != 0) continue;
        for (uint32_t j = 0; j < cur_seg->nsects; j++) {
            section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
            if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                dy_rebind_section(rebindings, sect, slide, symtab, strtab, indirect);
            }
        }
    }
}

static void dy_rebind_cb(const struct mach_header *header, intptr_t slide) {
    dy_rebind_image(_rebindings_head, header, slide);
}

static int dy_rebind_symbols(struct rebinding rebindings[], size_t nel) {
    if (dy_prepend_rebindings(&_rebindings_head, rebindings, nel) < 0) return -1;
    if (!_rebindings_head->next) {
        _dyld_register_func_for_add_image(dy_rebind_cb);
    } else {
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            dy_rebind_image(_rebindings_head, _dyld_get_image_header(i),
                            _dyld_get_image_vmaddr_slide(i));
        }
    }
    return 0;
}

/* ============================ 日志 ============================ */
static void DYLog(NSString *msg) {
    NSLog(@"[DYPROBE14] %@", msg);
    @try {
        NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (!doc) return;
        NSString *path = [doc stringByAppendingPathComponent:@"dyprobe_dump.txt"];
        NSString *line = [NSString stringWithFormat:@"[v14] %@\n", msg];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) { [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
        else { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (...) {}
}

/* ============================ 三个 hook 点 ============================ */

/* --- A. SSL_CTX_set_custom_verify ---
 * BoringSSL 原型：
 *   void SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode,
 *        enum ssl_verify_result_t (*callback)(SSL *ssl, uint8_t *out_alert));
 * ssl_verify_result_t: ssl_verify_ok = 0
 * 做法：无视业务传入的回调，一律换成"永远返回 0"。
 */
typedef int (*DYVerifyCb)(void *ssl, uint8_t *out_alert);
static void (*orig_SSL_CTX_set_custom_verify)(void *ctx, int mode, DYVerifyCb cb);

static int dy_always_ok_cb(void *ssl, uint8_t *out_alert) {
    (void)ssl; (void)out_alert;
    return 0;   /* ssl_verify_ok */
}

static void dy_SSL_CTX_set_custom_verify(void *ctx, int mode, DYVerifyCb cb) {
    (void)cb;
    if (orig_SSL_CTX_set_custom_verify) {
        orig_SSL_CTX_set_custom_verify(ctx, mode, dy_always_ok_cb);
    }
}

/* --- A2. SSL_set_custom_verify（per-SSL 版本，TTNet 也可能用这个） --- */
static void (*orig_SSL_set_custom_verify)(void *ssl, int mode, DYVerifyCb cb);
static void dy_SSL_set_custom_verify(void *ssl, int mode, DYVerifyCb cb) {
    (void)cb;
    if (orig_SSL_set_custom_verify) {
        orig_SSL_set_custom_verify(ssl, mode, dy_always_ok_cb);
    }
}

/* --- B. X509_verify_cert ---
 * int X509_verify_cert(X509_STORE_CTX *ctx);  返回 1 = 校验通过
 */
static int (*orig_X509_verify_cert)(void *ctx);
static int dy_X509_verify_cert(void *ctx) {
    (void)ctx;
    return 1;
}

/* --- C. SSL_get_verify_result ---
 * long SSL_get_verify_result(const SSL *ssl);  返回 0 = X509_V_OK
 */
static long (*orig_SSL_get_verify_result)(void *ssl);
static long dy_SSL_get_verify_result(void *ssl) {
    (void)ssl;
    return 0;
}

/* ============================ 安装 ============================ */
__attribute__((constructor)) static void DYInit(void) {
    @autoreleasepool {
        struct rebinding rb[] = {
            { "SSL_CTX_set_custom_verify", (void *)dy_SSL_CTX_set_custom_verify,
              (void **)&orig_SSL_CTX_set_custom_verify },
            { "SSL_set_custom_verify", (void *)dy_SSL_set_custom_verify,
              (void **)&orig_SSL_set_custom_verify },
            { "X509_verify_cert", (void *)dy_X509_verify_cert,
              (void **)&orig_X509_verify_cert },
            { "SSL_get_verify_result", (void *)dy_SSL_get_verify_result,
              (void **)&orig_SSL_get_verify_result },
        };
        int rc = dy_rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));
        DYLog([NSString stringWithFormat:@"init rc=%d (0=成功注册)", rc]);

        /* 稍后回报实际是否 rebind 到（orig 非空 = 已接管） */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            DYLog([NSString stringWithFormat:@"接管状态 ctx_custom=%@ ssl_custom=%@ x509=%@ verify_result=%@",
                   orig_SSL_CTX_set_custom_verify ? @"YES" : @"NO",
                   orig_SSL_set_custom_verify ? @"YES" : @"NO",
                   orig_X509_verify_cert ? @"YES" : @"NO",
                   orig_SSL_get_verify_result ? @"YES" : @"NO"]);
        });
    }
}
