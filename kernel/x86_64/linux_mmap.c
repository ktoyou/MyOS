#include "linux.h"
#include "paging.h"

/* MAP_FIXED меняет только страницы отдельной области mmap. */
#define MAP_START 0x1000000000ul
#define MAP_END   (MAP_START + BOOT_MEMORY_LIMIT)
#define PAGE_MASK (PMM_PAGE_SIZE - 1ul)

enum {
    PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4,
    MAP_PRIVATE = 2, MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20, MAP_DENYWRITE = 0x800,
    MAP_EXECUTABLE = 0x1000, MAP_FIXED_NOREPLACE = 0x100000,
    EBADF = 9, ENOMEM = 12, EACCES = 13, EEXIST = 17, EINVAL = 22, EOVERFLOW = 75,
};

static bool in_arena(uptr address, uptr size) {
    return address >= MAP_START && address < MAP_END && size <= MAP_END - address;
}

long linux64_mmap(uptr address, uptr length, u32 protection, u32 flags, i32 fd, uptr offset) {
    if (!length || (offset & PAGE_MASK) || (long)offset < 0 ||
        (protection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) ||
        !(flags & MAP_PRIVATE) ||
        (flags & ~(MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE |
                   MAP_EXECUTABLE | MAP_FIXED_NOREPLACE))) return -EINVAL;
    bool writable = (protection & PROT_WRITE) != 0;
    bool executable = (protection & PROT_EXEC) != 0;
    if (writable && executable) return -EACCES;
    if (length > MAP_END - MAP_START) return -ENOMEM;
    length = (length + PAGE_MASK) & ~PAGE_MASK;
    bool anonymous = (flags & MAP_ANONYMOUS) != 0;
    const u8 *source = NULL;
    uptr file_bytes = 0;
    if (!anonymous) {
        const struct linux64_file *file = linux64_get_file(fd);
        if (!file) return -EBADF;
        if (offset > 0x7ffffffffffffffful - length) return -EOVERFLOW;
        if (offset < file->size) {
            source = file->bytes + offset;
            file_bytes = file->size - offset;
            if (file_bytes > length) file_bytes = length;
        }
    }

    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        if (address & PAGE_MASK) return -EINVAL;
        if (!in_arena(address, length)) return -ENOMEM;
        if ((flags & MAP_FIXED_NOREPLACE) && !paging64_range_free(address, address + length))
            return -EEXIST;
    } else {
        address &= ~PAGE_MASK;
        if (!in_arena(address, length) || !paging64_range_free(address, address + length))
            address = paging64_find_free(MAP_START, MAP_END, length);
        if (!address) return -ENOMEM;
    }
    return paging64_map_private(address, address + length, source, file_bytes,
                                anonymous, protection != 0, writable, executable)
           ? (long)address : -ENOMEM;
}
