#include "pmm.h"

#define PAGE_COUNT    (BOOT_MEMORY_LIMIT / PMM_PAGE_SIZE)
#define BITMAP_WORDS  (PAGE_COUNT / 64)
#define LOW_MEMORY    0x100000u

extern const u8 _start[], __kernel_end[];
static u64 available[BITMAP_WORDS];
static u64 allocated[BITMAP_WORDS];
static u32 next_page = PAGE_COUNT;
static uptr physical_base;

void *pmm64_pointer(uptr physical) {
    return (void *)(physical_base + physical);
}

void pmm64_use_direct_map(void) {
    physical_base = X64_DIRECT_BASE;
}

static u64 page_bit(u32 page) {
    return 1ull << (page % 64);
}

static u32 find_available(u32 start) {
    for (u32 page = start; page < PAGE_COUNT; ++page)
        if (available[page / 64] & page_bit(page)) return page;
    return PAGE_COUNT;
}

static void reserve(u64 start, u64 end) {
    if (start >= end || start >= BOOT_MEMORY_LIMIT) return;
    if (end > BOOT_MEMORY_LIMIT) end = BOOT_MEMORY_LIMIT;
    u32 limit = (u32)((end + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE);
    for (u32 page = (u32)(start / PMM_PAGE_SIZE); page < limit; ++page)
        available[page / 64] &= ~page_bit(page);
}

bool pmm64_init(const struct boot_info *boot) {
    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    for (u32 i = 0; i < BITMAP_WORDS; ++i) {
        available[i] = 0;
        allocated[i] = 0;
    }
    for (u32 i = 0; i < boot->map_count; ++i) {
        if (map[i].type != 1 || !(map[i].attributes & 1u)) continue;
        u32 first = (u32)(map[i].base / PMM_PAGE_SIZE);
        u32 end = (u32)((map[i].base + map[i].length) / PMM_PAGE_SIZE);
        for (u32 page = first; page < end; ++page)
            available[page / 64] |= page_bit(page);
    }
    reserve(0, LOW_MEMORY);
    reserve((uptr)_start, (uptr)__kernel_end);
    /* В арене работают стек, GDT и текущие таблицы страниц. */
    reserve(boot->arena_phys, (u64)boot->arena_phys + boot->arena_bytes);
    reserve(boot->root_phys, (u64)boot->root_phys + boot->root_bytes);
    reserve(boot->fb_phys, (u64)boot->fb_phys + (u64)boot->pitch * boot->height);
    next_page = find_available(0);
    return next_page < PAGE_COUNT;
}

uptr pmm64_alloc(void) {
    u32 page = next_page;
    if (page == PAGE_COUNT) return 0;
    u64 bit = page_bit(page);
    available[page / 64] &= ~bit;
    allocated[page / 64] |= bit;
    next_page = find_available(page + 1);

    uptr physical = (uptr)page * PMM_PAGE_SIZE;
    u64 *words = pmm64_pointer(physical);
    for (u32 i = 0; i < PMM_PAGE_SIZE / sizeof(*words); ++i) words[i] = 0;
    return physical;
}

bool pmm64_free(uptr physical) {
    if (physical >= BOOT_MEMORY_LIMIT || (physical & (PMM_PAGE_SIZE - 1))) return false;
    u32 page = (u32)(physical / PMM_PAGE_SIZE);
    u64 bit = page_bit(page);
    if (!(allocated[page / 64] & bit)) return false;
    allocated[page / 64] &= ~bit;
    available[page / 64] |= bit;
    if (page < next_page) next_page = page;
    return true;
}
