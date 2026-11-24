#include "../kernel/x86_64/framebuffer.h"
#include "../kernel/x86_64/paging.h"
#include "../user/lib/video_mode.h"

#define ADDRESS_MASK 0x000ffffffffff000ull

static u64 leaf(uptr root, uptr address) {
    for (unsigned shift = 39;; shift -= 9) {
        const u64 *table = pmm64_pointer(root);
        u64 entry = table[(address >> shift) & 511];
        if (!(entry & 1)) return 0;
        if (shift == 12) return entry;
        root = entry & ADDRESS_MASK;
    }
}

static bool is_uc(u64 entry) {
    u32 eax = 1, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (!(edx & (1u << 16))) return (entry & 0x18) == 0x18;
    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0x277u));
    unsigned index = ((entry >> 3) & 3) | ((entry >> 5) & 4);
    return !(((((u64)high << 32) | low) >> (8 * index)) & 0xff);
}

static bool check_pages(uptr root, const struct gop64_framebuffer *fb) {
    const u64 cache_mask = 0x98;
    u64 first = leaf(root, X64_FRAMEBUFFER_BASE);
    for (uptr offset = 0; offset < fb->page_bytes; offset += PMM_PAGE_SIZE) {
        u64 entry = leaf(root, X64_FRAMEBUFFER_BASE + offset);
        if ((entry & (7ull | (1ull << 63))) != (3ull | (1ull << 63)) ||
            (entry & cache_mask) != (first & cache_mask) ||
            (entry & ADDRESS_MASK) != fb->physical + offset ||
            leaf(root, X64_DIRECT_BASE + fb->physical + offset) ||
            leaf(root, fb->physical + offset)) return false;
    }
    return is_uc(first) && !leaf(root, X64_FRAMEBUFFER_BASE + fb->page_bytes);
}

static bool check_geometry(const struct boot_info *boot) {
    struct boot_info bad = *boot;
    struct gop64_framebuffer fb;
    bad.pitch = 4;
    if (gop64_from_boot(&bad, &fb)) return false;
    bad = *boot;
    bad.fb_phys = boot->arena_phys;
    if (gop64_from_boot(&bad, &fb)) return false;
    bad = *boot;
    bad.fb_phys = 0xfffff000;
    if (gop64_from_boot(&bad, &fb)) return false;
    bad = *boot;
    bad.pixel_order = 2;
    return !gop64_from_boot(&bad, &fb);
}

static bool check_blit(void) {
    const u32 source[6] = {0x123456, 0xf0b021, 0, 0x3c0405, 0x7e8f90, 0};
    const u32 expected[2][4] = {
        {0x123456, 0xf0b021, 0x3c0405, 0x7e8f90},
        {0x563412, 0x21b0f0, 0x05043c, 0x908f7e},
    };
    for (unsigned order = 0; order < 2; ++order) {
        u32 buffer[8];
        for (unsigned i = 0; i < 8; ++i) buffer[i] = 0xffffffff;
        struct gop64_surface surface = {(volatile u8 *)buffer, 3, 2, 16, order};
        if (gop64_blit(&surface, 2, 0, 2, 2, source, 3) ||
            !gop64_blit(&surface, 1, 0, 2, 2, source, 3)) return false;
        for (unsigned y = 0; y < 2; ++y) {
            const u32 *row = buffer + 4 * y;
            if (row[0] != 0xffffffff || row[1] != expected[order][2 * y] ||
                row[2] != expected[order][2 * y + 1] || row[3] != 0xffffffff)
                return false;
        }
    }
    return true;
}

static bool draw(const struct gop64_surface *surface, uptr root, u32 begin, u32 end, u32 left, u32 right) {
    static u32 line[VIDEO_MAX_WIDTH];
    for (u32 x = 0; x < surface->width; ++x) line[x] = x < surface->width / 2 ? left : right;
    uptr old = paging64_active_root();
    paging64_switch_root(root);
    bool result = true;
    for (u32 y = begin; y < end && result; ++y)
        result = gop64_blit(surface, 0, y, surface->width, 1, line, surface->width);
    paging64_switch_root(old);
    return result;
}

bool gop64_check(const struct boot_info *boot, const struct gop64_framebuffer *fb) {
    if (!check_geometry(boot) || !check_blit() || !check_pages(paging64_active_root(), fb) ||
        pmm64_retain(fb->physical)) return false;
    uptr fork = paging64_fork_root(), exec = paging64_exec_root();
    if (!fork || !exec) return false;
    const struct gop64_surface *surface = &fb->surface;
    u32 middle = surface->height / 2;
    bool result = check_pages(fork, fb) && check_pages(exec, fb) &&
                  draw(surface, fork, 0, middle, 0xde292f, 0x23b471) &&
                  draw(surface, exec, middle, surface->height, 0x365ed6, 0xefd487);
    paging64_drop_root(exec);
    paging64_drop_root(fork);
    return result && check_pages(paging64_active_root(), fb);
}
