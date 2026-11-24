#include "../kernel/x86_64/pmm.h"

extern const u8 _start[], __kernel_end[];

static bool overlaps(uptr page, u64 start, u64 size) {
    return size && page < start + size && start < page + PMM_PAGE_SIZE;
}

static bool usable(const struct boot_info *boot, uptr page) {
    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    for (u32 i = 0; i < boot->map_count; ++i)
        if (map[i].type == 1 && (map[i].attributes & 1u) &&
            page >= map[i].base && page + PMM_PAGE_SIZE <= map[i].base + map[i].length)
            return true;
    return false;
}

static bool reserved(const struct boot_info *boot, uptr page) {
    return page < 0x100000 ||
           overlaps(page, (uptr)_start, (uptr)__kernel_end - (uptr)_start) ||
           overlaps(page, boot->arena_phys, boot->arena_bytes) ||
           overlaps(page, boot->root_phys, boot->root_bytes) ||
           overlaps(page, boot->fb_phys, (u64)boot->pitch * boot->height);
}

static u32 expected_pages(const struct boot_info *boot) {
    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    u32 count = 0;
    for (u32 i = 0; i < boot->map_count; ++i) {
        if (map[i].type != 1 || !(map[i].attributes & 1u)) continue;
        u64 end = map[i].base + map[i].length;
        for (u64 page = map[i].base; page < end; page += PMM_PAGE_SIZE)
            if (!reserved(boot, (uptr)page)) ++count;
    }
    return count;
}

bool pmm64_check(const struct boot_info *boot) {
    uptr first = pmm64_alloc();
    if (!first) return false;
    /* GOP обычно выше управляемой памяти QEMU. Проверяем также частичное пересечение. */
    struct boot_info low_gop = *boot;
    low_gop.fb_phys = (u32)first + 16;
    low_gop.pitch = PMM_PAGE_SIZE;
    low_gop.height = 1;
    if (!pmm64_init(&low_gop)) return false;
    uptr without_gop = pmm64_alloc();
    if (!without_gop || overlaps(without_gop, low_gop.fb_phys, PMM_PAGE_SIZE) ||
        pmm64_free(first) || !pmm64_init(boot))
        return false;

    first = pmm64_alloc();
    uptr second = pmm64_alloc();
    if (!first || !second || first == second) return false;
    volatile u64 *words = (void *)first;
    words[0] = 0x123456789abcdef0ull;
    words[PMM_PAGE_SIZE / sizeof(*words) - 1] = words[0];
    if (pmm64_free(0) || pmm64_free(first + 1) || pmm64_free((uptr)_start) ||
        pmm64_free(boot->arena_phys) || !pmm64_free(first) || pmm64_free(first) ||
        pmm64_alloc() != first || words[0] || words[PMM_PAGE_SIZE / sizeof(*words) - 1])
        return false;

    if (!pmm64_free(first) || !pmm64_free(second)) return false;
    uptr previous = 0;
    u32 count = 0;
    for (uptr page; (page = pmm64_alloc()) != 0;) {
        if (page <= previous || (page & (PMM_PAGE_SIZE - 1)) ||
            !usable(boot, page) || reserved(boot, page))
            return false;
        previous = page;
        ++count;
    }
    if (boot->root_bytes) {
        const volatile char *root = (const void *)(uptr)boot->root_phys;
        const char expected[] = "MYOSPMM!";
        for (u32 i = 0; i < sizeof(expected) - 1; ++i)
            if (root[i] != expected[i]) return false;
    }
    return count && count == expected_pages(boot);
}
