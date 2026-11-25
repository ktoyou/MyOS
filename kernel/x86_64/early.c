#include "paging.h"
#include "framebuffer.h"
#include "segments.h"
#ifdef X64_TEST_LINUX
#include "linux_fb.h"
#include "linux.h"
#endif

#define COM1              0x3f8
#define UEFI_ENTRY_MAGIC  0x55454649u
#define BOOT_ARENA_SIZE   (32u * 4096)
#define BOOT_MAP_OFFSET   (2u * 4096)
#define BOOT_MAP_MAX      128u
#define EXCEPTION_COUNT   32

#ifndef X64_TEST_EXCEPTION
#define X64_TEST_EXCEPTION 0
#endif

#ifdef X64_TEST_PMM
extern bool pmm64_check(const struct boot_info *boot, const struct gop64_framebuffer *fb);
#endif
#if defined(X64_TEST_RING3) || defined(X64_TEST_GOP)
extern bool ring3_check(unsigned mode);
#endif
#ifdef X64_TEST_GOP
extern bool gop64_check(const struct boot_info *boot, const struct gop64_framebuffer *fb);
#endif
#ifdef X64_TEST_ETHERNET
extern bool e1000_check(void);
#endif
#ifdef X64_TEST_IPV4
extern bool net64_check(void);
#endif

struct idt_gate {
    u16 offset_low, selector;
    u8 ist, flags;
    u16 offset_mid;
    u32 offset_high, reserved;
} __attribute__((packed));

struct idt_pointer {
    u16 limit;
    u64 base;
} __attribute__((packed));

_Static_assert(sizeof(struct boot_info) == 100, "UEFI boot-info v5");
_Static_assert(sizeof(struct boot_region) == 24, "UEFI memory map entry");
_Static_assert(sizeof(struct idt_gate) == 16, "x86-64 IDT gate");
_Static_assert(sizeof(struct idt_pointer) == 10, "x86-64 IDTR");

extern const uptr kernel64_vectors[EXCEPTION_COUNT];
static struct idt_gate idt[EXCEPTION_COUNT];

static void serial_init(void) {
    outb(COM1 + 1, 0);
    outb(COM1 + 3, 0x80);
    outb(COM1, 1);
    outb(COM1 + 1, 0);
    outb(COM1 + 3, 3);
    outb(COM1 + 2, 0xc7);
    outb(COM1 + 4, 0x0b);
}

void kernel64_serial_char(char ch) {
    for (unsigned spin = 0; spin < 100000; ++spin) {
        if (inb(COM1 + 5) & 0x20) {
            outb(COM1, (u8)ch);
            return;
        }
    }
}

static void serial_puts(const char *text) {
    while (*text) {
        if (*text == '\n') kernel64_serial_char('\r');
        kernel64_serial_char(*text++);
    }
}

static void serial_hex(u64 value) {
    static const char digits[] = "0123456789abcdef";
    serial_puts("0x");
    for (int shift = 60; shift >= 0; shift -= 4)
        kernel64_serial_char(digits[(value >> shift) & 15u]);
}

static __attribute__((noreturn)) void halt(void) {
    for (;;) __asm__ volatile("cli; hlt");
}

#ifdef X64_TEST_LINUX
struct linux_test_files {
    const u8 *cursor, *end;
    uptr count;
    const char *exec_path;
    struct linux64_file executable;
    bool aligned;
};

struct linux_test_entry {
    u64 path_size, file_size;
} __attribute__((packed));

static struct linux_test_files test_files;
enum { LINUX_TEST_MAX_FILES = 1024 };
static const char *test_paths[LINUX_TEST_MAX_FILES + 1];

static const char *linux_test_entry_path(const void *context, uptr index) {
    const struct linux_test_files *files = context;
    return index <= files->count ? test_paths[index] : NULL;
}

static bool valid_test_path(const char *path, uptr size) {
    if (size < 2 || size > LINUX64_PATH_LIMIT || path[0] != '/' || path[size - 1]) return false;
    for (uptr i = 1; i < size - 1; ++i)
        if (!path[i]) return false;
    return true;
}

static bool test_path_equal(const char *path, const char *expected) {
    while (*path && *path == *expected) {
        ++path;
        ++expected;
    }
    return *path == *expected;
}

static const u8 *test_payload(const u8 *start, const u8 *end, uptr size, bool aligned) {
    uptr available = (uptr)(end - start);
    uptr padding = aligned ? -(uptr)start & (PMM_PAGE_SIZE - 1) : 0;
    if (padding > available || size > available - padding) return NULL;
    return start + padding;
}

static bool linux_test_next(struct linux_test_files *files, const char **path,
                            struct linux64_file *file) {
    uptr remaining = (uptr)(files->end - files->cursor);
    if (remaining < sizeof(struct linux_test_entry)) return false;
    const struct linux_test_entry *entry = (const void *)files->cursor;
    remaining -= sizeof(*entry);
    if (entry->path_size < 2 || entry->path_size > remaining) return false;
    *path = (const char *)(entry + 1);
    if (!valid_test_path(*path, entry->path_size)) return false;
    const u8 *bytes = test_payload((const u8 *)*path + entry->path_size, files->end,
                                   entry->file_size, files->aligned);
    if (!bytes) return false;
    *file = (struct linux64_file){.bytes = bytes, .size = entry->file_size, .live_pages = files->aligned};
    files->cursor = file->bytes + file->size;
    return true;
}

static bool linux_test_lookup(const void *context, const char *path, struct linux64_file *file) {
    struct linux_test_files files = *(const struct linux_test_files *)context;
    if (test_path_equal(path, files.exec_path)) {
        *file = files.executable;
        return true;
    }
    for (uptr i = 0; i < files.count; ++i) {
        const char *expected;
        if (!linux_test_next(&files, &expected, file)) return false;
        if (test_path_equal(path, expected)) {
            file->inode = i + 2;
            return true;
        }
    }
    return false;
}

static bool test_has_child(const char *entry, const char *path) {
    while (*path && *entry == *path) { ++entry; ++path; }
    return !*path && *entry == '/' && entry[1];
}

static u64 linux_test_directory(const void *context, const char *path) {
    struct linux_test_files files = *(const struct linux_test_files *)context;
    uptr length = 0;
    while (path[length]) ++length;
    if (test_has_child(files.exec_path, path)) return 3 + length;
    for (uptr i = 0; i < files.count; ++i) {
        const char *entry;
        struct linux64_file file;
        if (!linux_test_next(&files, &entry, &file)) return 0;
        /* Один файл и длина префикса однозначно задают каталог. */
        if (test_has_child(entry, path)) return 3 + (i + 1) * LINUX64_PATH_LIMIT + length;
    }
    return 0;
}

static void linux_test_boot(uptr root_phys, uptr root_bytes) {
    /* Заголовок, путь запуска, основной ELF и записи дополнительных файлов. */
    if (!root_phys || root_bytes < 32) return;
    const u64 *header = pmm64_pointer(root_phys);
    bool aligned = header[0] == 0x3636584c534f594dull; /* MYOSLX66 */
    if ((!aligned && header[0] != 0x3536584c534f594dull) || header[3] > root_bytes - 32 ||
        header[2] > LINUX_TEST_MAX_FILES)
        return;
    const char *path = (const void *)(header + 4);
    if (!valid_test_path(path, header[3])) return;
    const u8 *end = (const u8 *)header + root_bytes;
    const u8 *image = test_payload((const u8 *)path + header[3], end, header[1], aligned);
    if (!image) return;
    test_files = (struct linux_test_files){
        .cursor = image + header[1], .end = end, .aligned = aligned,
        .count = header[2], .exec_path = path,
        .executable = {.bytes = image, .size = header[1], .inode = 1, .live_pages = aligned},
    };
    struct linux_test_files scan = test_files;
    test_paths[0] = path;
    for (uptr i = 0; i < scan.count; ++i) {
        const char *entry_path;
        struct linux64_file file;
        if (!linux_test_next(&scan, &entry_path, &file)) return;
        test_paths[i + 1] = entry_path;
    }
    const struct linux64_file_source source = {
        .lookup = linux_test_lookup, .context = &test_files, .directory = linux_test_directory,
        .entry_path = linux_test_entry_path,
    };
    linux64_run(&test_files.executable, path, header[3] - 1, &source);
}
#endif

#ifdef X64_TEST_PAGING
static void check_paging(unsigned mode, const struct boot_info *boot) {
    static const u8 readonly = 0x5a;
    uptr physical = pmm64_alloc();
    if (!physical) {
        serial_puts("x86-64 paging check FAIL\n");
        halt();
    }
    volatile u8 *page = pmm64_pointer(physical);
    page[PMM_PAGE_SIZE - 1] = 0x5a;
    if ((uptr)page != X64_DIRECT_BASE + physical ||
        page[PMM_PAGE_SIZE - 1] != 0x5a || !pmm64_free(physical) ||
        pmm64_alloc() != physical || page[PMM_PAGE_SIZE - 1]) {
        serial_puts("x86-64 paging check FAIL\n");
        halt();
    }
    if (boot->root_bytes) {
        const volatile u8 *root = pmm64_pointer(boot->root_phys);
        const char expected[] = "MYOSPG!";
        for (u32 i = 0; i < sizeof(expected) - 1; ++i) {
            if (root[i] != (u8)expected[i]) {
                serial_puts("x86-64 paging check FAIL\n");
                halt();
            }
        }
        serial_puts("x86-64 paging live root PASS\n");
    }
    serial_puts("x86-64 paging access PASS\n");
    if (!mode) return;

    uptr address = mode == 1 ? X64_DIRECT_BASE + (uptr)&readonly :
                   mode == 2 ? (uptr)page : physical;
    serial_puts("x86-64 expected fault address=");
    serial_hex(address);
    serial_puts("\n");
    if (mode == 1) {
        __asm__ volatile("movb $0,(%0)" : : "r"(address) : "memory");
    } else if (mode == 2) {
        page[0] = 0xc3;   /* ret, если право исполнения задано ошибочно */
        __asm__ volatile("call *%0" : : "r"(address) : "memory");
    } else {
        __asm__ volatile("movb (%0),%%al" : : "r"(address) : "al", "memory");
    }
    serial_puts("x86-64 paging check FAIL\n");
}
#endif

static void install_idt(void) {
    u16 cs;
    __asm__ volatile("mov %%cs,%0" : "=r"(cs));
    for (unsigned vector = 0; vector < EXCEPTION_COUNT; ++vector) {
        uptr offset = kernel64_vectors[vector];
        idt[vector] = (struct idt_gate){
            .offset_low = (u16)offset,
            .selector = cs,
            .flags = 0x8e,
            .offset_mid = (u16)(offset >> 16),
            .offset_high = (u32)(offset >> 32),
        };
#ifdef X64_TEST_LINUX
        if (vector == 3) idt[vector].flags |= 0x60; /* INT3 разрешён из ring 3. */
#endif
    }
    const struct idt_pointer pointer = {sizeof(idt) - 1, (uptr)idt};
    __asm__ volatile("lidt %0" : : "m"(pointer) : "memory");
}

static bool valid_boot_map(const struct boot_info *boot, u32 entry_magic) {
    uptr address = (uptr)boot;
    if (entry_magic != UEFI_ENTRY_MAGIC || address < 0x100000 ||
        (address & 4095u) || address > BOOT_MEMORY_LIMIT - BOOT_ARENA_SIZE)
        return false;
    if (boot->magic != BOOT_INFO_MAGIC || boot->version != 5 || boot->firmware != 1 ||
        boot->arena_phys != address || boot->arena_bytes != BOOT_ARENA_SIZE ||
        boot->map_phys != address + BOOT_MAP_OFFSET ||
        !boot->map_count || boot->map_count > BOOT_MAP_MAX || !boot_root_valid(boot))
        return false;

    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    for (u32 i = 0; i < boot->map_count; ++i) {
        if (map[i].base >= BOOT_MEMORY_LIMIT || !map[i].length ||
            map[i].length > BOOT_MEMORY_LIMIT - map[i].base ||
            ((map[i].base | map[i].length) & 4095u))
            return false;
        u64 end = map[i].base + map[i].length;
        for (u32 j = 0; j < i; ++j) {
            if (map[i].base < map[j].base + map[j].length && map[j].base < end)
                return false;
        }
    }
    return true;
}

void kernel64_exception(u64 vector, u64 error, u64 rip, u64 cs, uptr frame, uptr interrupted_sp) {
    uptr cr2 = 0;
    if (vector == 14) __asm__ volatile("mov %%cr2,%0" : "=r"(cr2));
#ifdef X64_TEST_LINUX
    if ((cs & 3u) == 3) {
        if (vector == 14 && paging64_zero_fault(cr2, error)) return;
        linux64_task_exception(vector);
    }
#endif
    serial_puts("x86-64 exception vector=");
    serial_hex(vector);
    serial_puts(" error=");
    serial_hex(error);
    serial_puts(" rip=");
    serial_hex(rip);
    if (vector == 14) {
        serial_puts(" cr2=");
        serial_hex(cr2);
    }
    serial_puts(" cpl=");
    kernel64_serial_char((char)('0' + (cs & 3u)));
    if ((cs & 3u) == 3) {
        serial_puts(" user_rsp=");
        serial_hex(interrupted_sp);
        if (cs == 0x23 && segments64_on_entry_stack(frame) && ((const u64 *)frame)[6] == 0x1b)
            serial_puts("\nx86-64 TSS entry stack active");
    }
    serial_puts("\nx86-64 exception halted\n");
    halt();
}

__attribute__((noreturn)) void kernel64_main(const struct boot_info *boot, u32 entry_magic) {
    serial_init();
    install_idt();
    if (!valid_boot_map(boot, entry_magic)) {
        serial_puts("MyOS x86-64: invalid UEFI boot information\n");
        halt();
    }
    serial_puts("MyOS x86-64: UEFI memory map verified, IDT active\n");
    struct gop64_framebuffer fb;
    if (!gop64_from_boot(boot, &fb)) {
        serial_puts("MyOS x86-64: invalid GOP framebuffer\n");
        halt();
    }
    if (!pmm64_init(boot, &fb)) {
        serial_puts("MyOS x86-64: no free physical pages\n");
        halt();
    }
    serial_puts("MyOS x86-64: physical pages ready\n");
#ifdef X64_TEST_PMM
    if (!pmm64_check(boot, &fb)) serial_puts("x86-64 PMM FAIL\n");
    else if (boot->root_bytes) serial_puts("x86-64 PMM live PASS\n");
    else serial_puts("x86-64 PMM disk PASS\n");
#else
    if (!paging64_init(boot, &fb)) {
        serial_puts("MyOS x86-64: cannot activate kernel page tables\n");
        halt();
    }
    serial_puts("MyOS x86-64: kernel CR3 active\n");
    segments64_init();
#ifdef X64_TEST_GOP
    if (!gop64_check(boot, &fb)) {
        serial_puts("x86-64 GOP frame FAIL\n");
        halt();
    }
    serial_puts("x86-64 GOP frame PASS\n");
    if (!ring3_check(4)) serial_puts("x86-64 ring3 FAIL\n");
#endif
#if X64_TEST_EXCEPTION == 6
    __asm__ volatile("ud2");
#elif X64_TEST_EXCEPTION == 13
    /* Системный дескриптор TSS недопустим в DS и даёт #GP с его селектором. */
    __asm__ volatile("mov $0x28, %%ax; mov %%ax, %%ds" : : : "ax", "memory");
#endif
#ifdef X64_TEST_PAGING
    check_paging(X64_TEST_PAGING, boot);
#endif
#ifdef X64_TEST_RING3
    if (!ring3_check(X64_TEST_RING3)) serial_puts("x86-64 ring3 FAIL\n");
#endif
#ifdef X64_TEST_ETHERNET
    serial_puts(e1000_check() ? "x86-64 e1000 ARP PASS\n" : "x86-64 e1000 ARP FAIL\n");
#endif
#ifdef X64_TEST_IPV4
    serial_puts(net64_check() ? "x86-64 IPv4 PASS\n" : "x86-64 IPv4 FAIL\n");
#endif
#ifdef X64_TEST_LINUX
    if (linux64_net_init()) serial_puts("MyOS x86-64: e1000 Ethernet ready\n");
    linux64_fb_init(&fb.surface);
    linux_test_boot(boot->root_phys, boot->root_bytes);
    serial_puts("Linux x86-64 ELF rejected\n");
#endif
#endif
    halt();
}
