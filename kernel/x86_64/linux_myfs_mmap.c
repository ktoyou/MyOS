#include "linux_myfs.h"
#include "paging.h"

enum { BUCKETS = 128, SLAB_PAGES = 100 };

struct mapped_page {
    struct mapped_page *by_file, *by_frame;
    uptr physical;
    u32 ino, offset;
};

struct page_slab {
    struct page_slab *next;
    struct mapped_page *free;
    unsigned used;
    struct mapped_page pages[SLAB_PAGES];
};

_Static_assert(sizeof(struct page_slab) <= PMM_PAGE_SIZE, "MyFS mmap slab");

static struct page_slab *slabs;
static struct mapped_page *file_pages[BUCKETS], *frames[BUCKETS];

static struct mapped_page *page_alloc(void) {
    if (!slabs) {
        uptr physical = pmm64_alloc();
        if (!physical) return NULL;
        slabs = pmm64_pointer(physical);
        for (unsigned i = 0; i < SLAB_PAGES; ++i) {
            slabs->pages[i].by_file = slabs->free;
            slabs->free = &slabs->pages[i];
        }
    }
    struct page_slab *slab = slabs;
    struct mapped_page *page = slab->free;
    slab->free = page->by_file;
    ++slab->used;
    if (!slab->free) slabs = slab->next;
    return page;
}

static void page_free(struct mapped_page *page) {
    struct page_slab *slab = (void *)((uptr)page & ~(PMM_PAGE_SIZE - 1ul));
    if (!slab->free) {
        slab->next = slabs;
        slabs = slab;
    }
    page->by_file = slab->free;
    slab->free = page;
    if (!--slab->used) {
        struct page_slab **slot = &slabs;
        while (*slot != slab) slot = &(*slot)->next;
        *slot = slab->next;
        pmm64_free((uptr)slab - X64_DIRECT_BASE);
    }
}

static struct mapped_page **file_bucket(u32 ino, u32 offset) {
    return &file_pages[(ino * 31u + offset / PMM_PAGE_SIZE) % BUCKETS];
}

static struct mapped_page **frame_bucket(uptr physical) {
    return &frames[(physical / PMM_PAGE_SIZE) % BUCKETS];
}

static struct mapped_page *find_page(u32 ino, u32 offset) {
    struct mapped_page *page = *file_bucket(ino, offset);
    while (page && (page->ino != ino || page->offset != offset)) page = page->by_file;
    return page;
}

/* Кэш владеет одной ссылкой. Отображения и подготовка mmap удерживают остальные. */
static void release_frame(uptr physical) {
    if (pmm64_has_aliases(physical)) return;
    struct mapped_page **frame = frame_bucket(physical);
    while (*frame && (*frame)->physical != physical) frame = &(*frame)->by_frame;
    struct mapped_page *page = *frame;
    if (!page) return;
    *frame = page->by_frame;
    struct mapped_page **file = file_bucket(page->ino, page->offset);
    while (*file != page) file = &(*file)->by_file;
    *file = page->by_file;
    linux64_myfs_release(page->ino);
    pmm64_free(physical);
    page_free(page);
}

static long cache_page(u32 ino, u32 offset, uptr expected, struct mapped_page **cached) {
    *cached = find_page(ino, offset);
    if (*cached) return 0;
    struct mapped_page *page = page_alloc();
    if (!page) return -12;
    uptr physical = pmm64_alloc();
    if (!physical) {
        page_free(page);
        return -12;
    }

    long result = linux64_myfs_read(ino, offset, pmm64_pointer(physical), PMM_PAGE_SIZE);
    if (result >= 0)
        result = (uptr)result == expected ? linux64_myfs_retain(ino) : -5;
    if (result) {
        pmm64_free(physical);
        page_free(page);
        return result;
    }
    struct mapped_page **file = file_bucket(ino, offset);
    struct mapped_page **frame = frame_bucket(physical);
    *page = (struct mapped_page){ .by_file = *file, .by_frame = *frame, .physical = physical,
                                  .ino = ino, .offset = offset };
    *file = *frame = page;
    *cached = page;
    return 0;
}

void linux64_myfs_map_finish(u32 ino, uptr offset, uptr length) {
    for (uptr done = 0; done < length; done += PMM_PAGE_SIZE) {
        struct mapped_page *page = find_page(ino, (u32)(offset + done));
        uptr physical = page->physical;
        pmm64_free(physical);
        release_frame(physical);
    }
}

long linux64_myfs_map_prepare(u32 ino, uptr offset, uptr length) {
    paging64_set_cached_file_release(release_frame);
    for (uptr done = 0; done < length; done += PMM_PAGE_SIZE) {
        struct mapped_page *page;
        uptr expected = length - done;
        if (expected > PMM_PAGE_SIZE) expected = PMM_PAGE_SIZE;
        long result = cache_page(ino, (u32)(offset + done), expected, &page);
        if (!result && !pmm64_retain(page->physical)) {
            release_frame(page->physical);
            result = -12;
        }
        if (result) {
            linux64_myfs_map_finish(ino, offset, done);
            return result;
        }
    }
    return 0;
}

uptr linux64_myfs_map_frame(const void *object, uptr offset) {
    struct mapped_page *page = find_page((u32)(uptr)object, (u32)offset);
    return page ? page->physical : 0;
}

void linux64_myfs_map_update(u32 ino, uptr offset, const void *data, uptr length) {
    const u8 *source = data;
    while (length) {
        u32 start = (u32)(offset & ~(PMM_PAGE_SIZE - 1ul));
        uptr within = offset - start;
        uptr count = PMM_PAGE_SIZE - within;
        if (count > length) count = length;
        struct mapped_page *page = find_page(ino, start);
        if (page) {
            u8 *target = pmm64_pointer(page->physical);
            for (uptr i = 0; i < count; ++i) target[within + i] = source[i];
        }
        source += count;
        offset += count;
        length -= count;
    }
}

bool linux64_myfs_has_mapping(u32 ino) {
    for (unsigned i = 0; i < BUCKETS; ++i)
        for (struct mapped_page *page = file_pages[i]; page; page = page->by_file)
            if (page->ino == ino) return true;
    return false;
}
