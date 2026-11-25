#include "linux_task.h"
#include "paging.h"
#include "linux_myfs.h"

/* MAP_FIXED меняет только страницы отдельной области mmap. */
#define MAP_START 0x1000000000ul
#define MAP_END   0x00007fff00000000ul
_Static_assert(MAP_END <= LINUX64_STACK_FLOOR - PMM_PAGE_SIZE, "Linux mmap and stack overlap");
#define PAGE_MASK (PMM_PAGE_SIZE - 1ul)

enum {
    PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4,
    MAP_SHARED = 1, MAP_PRIVATE = 2, MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20, MAP_DENYWRITE = 0x800,
    MAP_EXECUTABLE = 0x1000, MAP_NORESERVE = 0x4000, MAP_STACK = 0x20000,
    MAP_FIXED_NOREPLACE = 0x100000,
    MADV_DONTNEED = 4,
    EBADF = 9, ENOMEM = 12, EACCES = 13, EEXIST = 17, EINVAL = 22, ENOSYS = 38, EOVERFLOW = 75,
};

/* BSP держит подготовленный список отдельно, пока изменение PTE может завершиться ошибкой. */
static struct linux64_reserve_range staged[LINUX64_RESERVE_COUNT];
static unsigned staged_count;

static bool append_range(uptr start, uptr end) {
    if (staged_count && staged[staged_count - 1].end == start) {
        staged[staged_count - 1].end = end;
        return true;
    }
    if (staged_count == LINUX64_RESERVE_COUNT) return false;
    staged[staged_count++] = (struct linux64_reserve_range){start, end};
    return true;
}

static bool stage_range(uptr start, uptr end, bool reserve) {
    const struct linux64_address_space *memory = linux64_current->memory;
    const struct linux64_reserve_range *reserves = memory->reserves;
    unsigned reserve_count = memory->reserve_count;
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
    struct linux64_address_space *memory = linux64_current->memory;
    for (unsigned i = 0; i < staged_count; ++i) memory->reserves[i] = staged[i];
    memory->reserve_count = staged_count;
}

static uptr reserved_end(uptr address) {
    const struct linux64_address_space *memory = linux64_current->memory;
    const struct linux64_reserve_range *reserves = memory->reserves;
    for (unsigned i = 0; i < memory->reserve_count && reserves[i].start <= address; ++i)
        if (address < reserves[i].end) return reserves[i].end;
    return 0;
}

static uptr overlap_end(uptr start, uptr end) {
    const struct linux64_address_space *memory = linux64_current->memory;
    const struct linux64_reserve_range *reserves = memory->reserves;
    for (unsigned i = 0; i < memory->reserve_count && reserves[i].start < end; ++i)
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
    struct linux64_address_space *memory = linux64_current->memory;
    enum paging64_protect_result result =
        paging64_protect(address, end, protection != 0, writable, executable, reserved_end,
                         &memory->data_bytes, linux64_current->process->data_limit.soft);
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
    uptr released = paging64_data_bytes(address, end);
    if (!paging64_remove_mmap(address, end)) return -EINVAL;
    linux64_current->memory->data_bytes -= released;
    commit_ranges();
    return 0;
}

long linux64_madvise(uptr address, uptr length, i32 advice) {
    if (advice != MADV_DONTNEED) return -ENOSYS;
    if ((address & PAGE_MASK) || length > (uptr)-1 - PAGE_MASK) return -EINVAL;
    length = (length + PAGE_MASK) & ~PAGE_MASK;
    if (!length) return 0;
    if (length > (uptr)-1 - address) return -EINVAL;
    if (address >= X64_USER_TOP || length > X64_USER_TOP - address) return -ENOMEM;
    switch (paging64_discard_anon(address, address + length, reserved_end)) {
    case PAGING64_DISCARD_OK: return 0;
    case PAGING64_DISCARD_HOLE: return -ENOMEM;
    case PAGING64_DISCARD_UNSUPPORTED: return -ENOSYS;
    }
    return -EINVAL;
}

long linux64_mmap(uptr address, uptr length, u32 protection, u32 flags, i32 fd, uptr offset) {
    u32 type = flags & (MAP_SHARED | MAP_PRIVATE);
    if (!length || (offset & PAGE_MASK) || (long)offset < 0 ||
        (protection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) ||
        (type != MAP_SHARED && type != MAP_PRIVATE) ||
        (flags & ~(MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE |
                   MAP_EXECUTABLE | MAP_NORESERVE | MAP_STACK | MAP_FIXED_NOREPLACE))) return -EINVAL;
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
    u32 myfs_ino = 0;
    if (!anonymous) {
        long result = linux64_get_file(fd, &view);
        if (result) return result;
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
        myfs_ino = view.file.myfs_ino;
        if (myfs_ino) {
            if (((mapping.length + PAGE_MASK) & ~PAGE_MASK) < length) return -EINVAL;
            no_write = shared;
            mapping.frame = linux64_myfs_map_frame;
            mapping.object = (const void *)(uptr)myfs_ino;
            mapping.cached = true;
        }
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
    struct linux64_address_space *memory = linux64_current->memory;
    uptr released = flags & MAP_FIXED ? paging64_data_bytes(address, end) : 0;
    uptr data_bytes = memory->data_bytes - released + (writable && !shared ? length : 0);
    if (data_bytes > memory->data_bytes && data_bytes > linux64_current->process->data_limit.soft)
        return -ENOMEM;
    if (!stage_range(address, end, reserve)) return -ENOMEM;
    if (myfs_ino) {
        long result = linux64_myfs_map_prepare(myfs_ino, offset, mapping.length);
        if (result) return result;
    }
    bool mapped = reserve ? paging64_remove_mmap(address, end)
                          : paging64_map_mmap(address, end, anonymous ? NULL : &mapping,
                                              protection != 0, writable, executable, shared, no_write);
    if (myfs_ino) linux64_myfs_map_finish(myfs_ino, offset, mapping.length);
    if (!mapped) return -ENOMEM;
    memory->data_bytes = data_bytes;
    commit_ranges();
    return (long)address;
}
