#include "linux.h"
#include "paging.h"

/* MAP_FIXED меняет только страницы отдельной области mmap. */
#define MAP_START 0x1000000000ul
#define MAP_END   0x00007fff00000000ul
#define PAGE_MASK (PMM_PAGE_SIZE - 1ul)
#define RESERVE_COUNT 256u

enum {
    PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4,
    MAP_SHARED = 1, MAP_PRIVATE = 2, MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20, MAP_DENYWRITE = 0x800,
    MAP_EXECUTABLE = 0x1000, MAP_NORESERVE = 0x4000, MAP_FIXED_NOREPLACE = 0x100000,
    EBADF = 9, ENOMEM = 12, EACCES = 13, EEXIST = 17, EINVAL = 22, EOVERFLOW = 75,
};

struct reserve_range {
    uptr start, end;
};

/* BSP держит подготовленный список отдельно, пока изменение PTE может завершиться ошибкой. */
static struct reserve_range reserves[RESERVE_COUNT], staged[RESERVE_COUNT];
static unsigned reserve_count, staged_count;

static bool append_range(uptr start, uptr end) {
    if (staged_count && staged[staged_count - 1].end == start) {
        staged[staged_count - 1].end = end;
        return true;
    }
    if (staged_count == RESERVE_COUNT) return false;
    staged[staged_count++] = (struct reserve_range){start, end};
    return true;
}

static bool stage_range(uptr start, uptr end, bool reserve) {
    staged_count = 0;
    for (unsigned i = 0; i < reserve_count && reserves[i].start < start; ++i) {
        uptr limit = reserves[i].end < start ? reserves[i].end : start;
        if (!append_range(reserves[i].start, limit)) return false;
    }
    if (reserve && !append_range(start, end)) return false;
    for (unsigned i = 0; i < reserve_count; ++i) {
        if (reserves[i].end <= end) continue;
        uptr first = reserves[i].start > end ? reserves[i].start : end;
        if (!append_range(first, reserves[i].end)) return false;
    }
    return true;
}

static void commit_ranges(void) {
    for (unsigned i = 0; i < staged_count; ++i) reserves[i] = staged[i];
    reserve_count = staged_count;
}

static uptr reserved_end(uptr address) {
    for (unsigned i = 0; i < reserve_count && reserves[i].start <= address; ++i)
        if (address < reserves[i].end) return reserves[i].end;
    return 0;
}

static uptr overlap_end(uptr start, uptr end) {
    for (unsigned i = 0; i < reserve_count && reserves[i].start < end; ++i)
        if (start < reserves[i].end) return reserves[i].end;
    return 0;
}

static bool in_arena(uptr address, uptr size) {
    return address >= MAP_START && address < MAP_END && size <= MAP_END - address;
}

static uptr find_free(uptr length) {
    uptr address = MAP_START;
    while (in_arena(address, length)) {
        uptr end = address + length;
        uptr overlap = overlap_end(address, end);
        if (overlap) {
            address = overlap;
            continue;
        }
        uptr occupied = paging64_first_mapped(address, end);
        if (occupied == end) return address;
        address = occupied + PMM_PAGE_SIZE;
    }
    return 0;
}

long linux64_mprotect(uptr address, uptr length, uptr protection) {
    if (address & PAGE_MASK) return -EINVAL;
    if (!length) return 0;
    if (address >= X64_USER_TOP || length > X64_USER_TOP - address) return -ENOMEM;
    if (protection & ~(uptr)(PROT_READ | PROT_WRITE | PROT_EXEC)) return -EINVAL;
    bool writable = (protection & PROT_WRITE) != 0;
    bool executable = (protection & PROT_EXEC) != 0;
    if (writable && executable) return -EACCES;
    uptr end = address + ((length + PAGE_MASK) & ~PAGE_MASK);
    bool materialize = protection && overlap_end(address, end);
    if (materialize && !stage_range(address, end, false)) return -ENOMEM;
    enum paging64_protect_result result =
        paging64_protect(address, end, protection != 0, writable, executable, reserved_end);
    if (result != PAGING64_PROTECT_OK)
        return result == PAGING64_PROTECT_DENIED ? -EACCES : -ENOMEM;
    if (materialize) commit_ranges();
    return 0;
}

long linux64_munmap(uptr address, uptr length) {
    if (!length || (address & PAGE_MASK) ||
        address >= X64_USER_TOP || length > X64_USER_TOP - address) return -EINVAL;
    length = (length + PAGE_MASK) & ~PAGE_MASK;
    if (!in_arena(address, length)) return -EINVAL;
    uptr end = address + length;
    if (!stage_range(address, end, false)) return -ENOMEM;
    if (!paging64_remove_mmap(address, end)) return -EINVAL;
    commit_ranges();
    return 0;
}

long linux64_mmap(uptr address, uptr length, u32 protection, u32 flags, i32 fd, uptr offset) {
    u32 type = flags & (MAP_SHARED | MAP_PRIVATE);
    if (!length || (offset & PAGE_MASK) || (long)offset < 0 ||
        (protection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) ||
        (type != MAP_SHARED && type != MAP_PRIVATE) ||
        (flags & ~(MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE |
                   MAP_EXECUTABLE | MAP_NORESERVE | MAP_FIXED_NOREPLACE))) return -EINVAL;
    bool writable = (protection & PROT_WRITE) != 0;
    bool executable = (protection & PROT_EXEC) != 0;
    if (writable && executable) return -EACCES;
    if (length > MAP_END - MAP_START) return -ENOMEM;
    length = (length + PAGE_MASK) & ~PAGE_MASK;
    bool anonymous = (flags & MAP_ANONYMOUS) != 0;
    bool shared = type == MAP_SHARED;
    if (shared && anonymous) return -EINVAL;
    bool reserve = anonymous && !protection;
    if (!reserve && length > BOOT_MEMORY_LIMIT) return -ENOMEM;
    struct linux64_fd_view view;
    struct paging64_mmap_file mapping = {0};
    bool no_write = false;
    if (!anonymous) {
        if (!linux64_get_file(fd, &view)) return -EBADF;
        if (offset > 0x7ffffffffffffffful - length) return -EOVERFLOW;
        no_write = shared && !view.writable;
        if (offset < view.file.size) {
            if (view.file.bytes) mapping.bytes = view.file.bytes + offset;
            mapping.length = view.file.size - offset;
            if (mapping.length > length) mapping.length = length;
        }
        mapping.offset = offset;
        mapping.frame = view.frame;
        mapping.object = view.object;
    }

    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        if (address & PAGE_MASK) return -EINVAL;
        if (!in_arena(address, length)) return -ENOMEM;
        if ((flags & MAP_FIXED_NOREPLACE) &&
            (overlap_end(address, address + length) || !paging64_range_free(address, address + length)))
            return -EEXIST;
    } else {
        address &= ~PAGE_MASK;
        if (!in_arena(address, length) || overlap_end(address, address + length) ||
            !paging64_range_free(address, address + length)) address = find_free(length);
        if (!address) return -ENOMEM;
    }
    if ((no_write && writable) || (shared && mapping.frame && executable)) return -EACCES;
    /* При росте объекта страницы за старым EOF потребовали бы новых PTE. */
    if (shared && mapping.frame && view.may_grow &&
        ((mapping.length + PAGE_MASK) & ~PAGE_MASK) < length) return -EINVAL;
    uptr end = address + length;
    if (!stage_range(address, end, reserve)) return -ENOMEM;
    if (reserve ? !paging64_remove_mmap(address, end)
                : !paging64_map_mmap(address, end, anonymous ? NULL : &mapping,
                                     protection != 0, writable, executable, shared, no_write))
        return -ENOMEM;
    commit_ranges();
    return (long)address;
}
