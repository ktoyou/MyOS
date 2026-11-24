#include "paging.h"

#define PRESENT       (1ull << 0)
#define WRITE         (1ull << 1)
#define NO_EXECUTE    (1ull << 63)
#define ADDRESS_MASK  0x000ffffffffff000ull
#define CR0_WP        (1ul << 16)
#define EFER_MSR      0xc0000080u
#define EFER_NXE      (1u << 11)

extern const u8 _start[], __text_end[], __rodata_end[], __kernel_end[];

static bool nx_supported(void) {
    u32 eax = 0x80000000u, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (eax < 0x80000001u) return false;
    eax = 0x80000001u;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return (edx & (1u << 20)) != 0;
}

static bool map_page(uptr root, uptr virtual, uptr physical, u64 flags) {
    u64 *table = pmm64_pointer(root);
    for (int shift = 39; shift > 12; shift -= 9) {
        u64 *entry = &table[(virtual >> shift) & 511u];
        if (!(*entry & PRESENT)) {
            uptr child = pmm64_alloc();
            if (!child) return false;
            *entry = child | WRITE | PRESENT;
        }
        table = pmm64_pointer(*entry & ADDRESS_MASK);
    }
    u64 *leaf = &table[(virtual >> 12) & 511u];
    if (*leaf & PRESENT) return false;
    *leaf = physical | flags | PRESENT;
    return true;
}

static bool map_identity(uptr root, uptr start, uptr end, u64 flags) {
    for (uptr page = start; page < end; page += PMM_PAGE_SIZE)
        if (!map_page(root, page, page, flags)) return false;
    return true;
}

static bool map_ram(uptr root, const struct boot_info *boot) {
    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    u64 fb_start = boot->fb_phys;
    u64 fb_end = fb_start + (u64)boot->pitch * boot->height;
    for (u32 i = 0; i < boot->map_count; ++i) {
        if (map[i].type != 1 || !(map[i].attributes & 1u)) continue;
        u64 end = map[i].base + map[i].length;
        for (uptr page = (uptr)map[i].base; page < end; page += PMM_PAGE_SIZE) {
            if (page < 0x100000u ||
                (fb_start < fb_end && page < fb_end && fb_start < page + PMM_PAGE_SIZE))
                continue;
            /* Прямое отображение не должно давать запись в код и rodata. */
            bool readonly = page >= (uptr)_start && page < (uptr)__rodata_end;
            if (!map_page(root, X64_DIRECT_BASE + page, page,
                          NO_EXECUTE | (readonly ? 0 : WRITE))) return false;
        }
    }
    return true;
}

bool paging64_init(const struct boot_info *boot) {
    uptr previous;
    __asm__ volatile("mov %%cr3,%0" : "=r"(previous));
    if (!nx_supported()) return false;
    uptr root = pmm64_alloc();
    if (!root ||
        !map_identity(root, (uptr)_start, (uptr)__text_end, 0) ||
        !map_identity(root, (uptr)__text_end, (uptr)__rodata_end, NO_EXECUTE) ||
        !map_identity(root, (uptr)__rodata_end, (uptr)__kernel_end, WRITE | NO_EXECUTE) ||
        !map_identity(root, boot->arena_phys, (uptr)boot->arena_phys + boot->arena_bytes,
                      WRITE | NO_EXECUTE) ||
        !map_ram(root, boot))
        return false;

    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(EFER_MSR));
    __asm__ volatile("wrmsr" : : "a"(low | EFER_NXE), "d"(high), "c"(EFER_MSR) : "memory");
    uptr cr0, active;
    __asm__ volatile("mov %%cr0,%0" : "=r"(cr0));
    __asm__ volatile("mov %0,%%cr0" : : "r"(cr0 | CR0_WP) : "memory");
    __asm__ volatile("mov %0,%%cr3" : : "r"(root) : "memory");
    pmm64_use_direct_map();
    __asm__ volatile("mov %%cr3,%0" : "=r"(active));
    return active == root && active != previous;
}
