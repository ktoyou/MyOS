#include "pmm.h"
#include "framebuffer.h"

#define PAGE_COUNT    (X64_RAM_LIMIT / PMM_PAGE_SIZE)
#define BITMAP_WORDS  (PAGE_COUNT / 64)
#define LOW_MEMORY    0x100000u

extern const u8 _start[], __kernel_end[];
static u64 available[BITMAP_WORDS];
static uptr references_phys;
static u32 reference_count;
static u32 next_page = PAGE_COUNT;
static u32 total_pages, free_pages;
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
    if (start >= end || start >= X64_RAM_LIMIT) return;
    if (end > X64_RAM_LIMIT) end = X64_RAM_LIMIT;
    u32 limit = (u32)((end + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE);
    for (u32 page = (u32)(start / PMM_PAGE_SIZE); page < limit; ++page)
        available[page / 64] &= ~page_bit(page);
}

static uptr allocate_run(u32 count) {
    if (!count || count > free_pages) return 0;
    u32 first = next_page, run = 1;
    while (run < count) {
        u32 page = first + run;
        if (page == PAGE_COUNT) return 0;
        if (available[page / 64] & page_bit(page)) {
            ++run;
        } else {
            first = find_available(page + 1);
            if (first == PAGE_COUNT) return 0;
            run = 1;
        }
    }
    for (u32 page = first; page < first + count; ++page)
        available[page / 64] &= ~page_bit(page);
    free_pages -= count;
    if (first == next_page) next_page = find_available(first + count);
    return (uptr)first * PMM_PAGE_SIZE;
}

bool pmm64_init(const struct boot_info *boot, const struct gop64_framebuffer *fb) {
    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    for (u32 i = 0; i < BITMAP_WORDS; ++i) available[i] = 0;
    reference_count = 0;
    for (u32 i = 0; i < boot->map_count; ++i) {
        if (map[i].type != 1 || !(map[i].attributes & 1u)) continue;
        u32 first = (u32)(map[i].base / PMM_PAGE_SIZE);
        u32 end = (u32)((map[i].base + map[i].length) / PMM_PAGE_SIZE);
        if (end > reference_count) reference_count = end;
        for (u32 page = first; page < end; ++page)
            available[page / 64] |= page_bit(page);
    }
    reserve(0, LOW_MEMORY);
    reserve((uptr)_start, (uptr)__kernel_end);
    /* В арене работают стек, GDT и текущие таблицы страниц. */
    reserve(boot->arena_phys, (u64)boot->arena_phys + boot->arena_bytes);
    reserve(boot->root_phys, (u64)boot->root_phys + boot->root_bytes);
    reserve(fb->physical, fb->physical + fb->page_bytes);
    free_pages = 0;
    for (u32 i = 0; i < BITMAP_WORDS; ++i)
        for (u64 bits = available[i]; bits; bits &= bits - 1) ++free_pages;
    next_page = find_available(0);
    /* Таблица счётчиков не должна расширять BSS ядра до начала пользовательского ELF. */
    u32 bytes = reference_count * sizeof(u16);
    references_phys = allocate_run((bytes + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE);
    if (!references_phys) return false;
    u16 *references = pmm64_pointer(references_phys);
    for (u32 i = 0; i < reference_count; ++i) references[i] = 0;
    total_pages = free_pages;
    return next_page < PAGE_COUNT;
}

uptr pmm64_alloc(void) {
    return pmm64_alloc_contiguous(1);
}

uptr pmm64_alloc_contiguous(u32 count) {
    uptr physical = allocate_run(count);
    if (!physical) return 0;
    u16 *references = pmm64_pointer(references_phys);
    u32 first = (u32)(physical / PMM_PAGE_SIZE);
    for (u32 page = first; page < first + count; ++page) references[page] = 1;
    u64 *words = pmm64_pointer(physical);
    for (u32 i = 0; i < count * (PMM_PAGE_SIZE / sizeof(*words)); ++i) words[i] = 0;
    return physical;
}

static u16 *page_references(uptr physical) {
    if ((physical & (PMM_PAGE_SIZE - 1)) || physical / PMM_PAGE_SIZE >= reference_count) return NULL;
    u16 *references = pmm64_pointer(references_phys);
    return &references[physical / PMM_PAGE_SIZE];
}

bool pmm64_retain(uptr physical) {
    u16 *count = page_references(physical);
    if (!count || !*count || *count == 0xffffu) return false;
    ++*count;
    return true;
}

bool pmm64_has_aliases(uptr physical) {
    const u16 *count = page_references(physical);
    return count && *count > 1;
}

bool pmm64_free(uptr physical) {
    u16 *count = page_references(physical);
    if (!count || !*count) return false;
    if (--*count) return true;
    u32 page = (u32)(physical / PMM_PAGE_SIZE);
    available[page / 64] |= page_bit(page);
    ++free_pages;
    if (page < next_page) next_page = page;
    return true;
}

void pmm64_page_counts(u32 *total, u32 *free) {
    *total = total_pages;
    *free = free_pages;
}
