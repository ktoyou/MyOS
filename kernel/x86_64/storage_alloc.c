#include "storage_alloc.h"
#include "pmm.h"

struct storage_allocation {
    u32 pages;
} __attribute__((aligned(16)));

void *storage64_alloc(uptr bytes) {
    if (!bytes || bytes > BOOT_MEMORY_LIMIT - sizeof(struct storage_allocation)) return NULL;
    u32 pages = (u32)((bytes + sizeof(struct storage_allocation) + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE);
    uptr physical = pmm64_alloc_contiguous(pages);
    if (!physical) return NULL;
    struct storage_allocation *allocation = pmm64_pointer(physical);
    allocation->pages = pages;
    return allocation + 1;
}

void storage64_free(void *data) {
    if (!data) return;
    struct storage_allocation *allocation = (struct storage_allocation *)data - 1;
    uptr physical = (uptr)allocation - X64_DIRECT_BASE;
    /* Освобождение первой страницы может уничтожить заголовок. */
    u32 pages = allocation->pages;
    for (u32 i = 0; i < pages; ++i) pmm64_free(physical + (uptr)i * PMM_PAGE_SIZE);
}
