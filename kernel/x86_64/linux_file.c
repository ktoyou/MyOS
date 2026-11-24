#include "linux.h"
#include "paging.h"

enum {
    EBADF = 9, ENOENT = 2, EACCES = 13, EFAULT = 14, ENOTDIR = 20,
    EINVAL = 22, EMFILE = 24, EROFS = 30, ENAMETOOLONG = 36, ENOSYS = 38,
    AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100, AT_NO_AUTOMOUNT = 0x800,
    AT_EMPTY_PATH = 0x1000, PATH_LIMIT = 4096,
    O_ACCMODE = 3, O_CREAT = 0x40, O_TRUNC = 0x200, O_NONBLOCK = 0x800,
    O_LARGEFILE = 0x8000, O_DIRECTORY = 0x10000, O_NOFOLLOW = 0x20000,
    O_CLOEXEC = 0x80000,
    STDIO_COUNT = 3, FD_COUNT = 32,
};

/* Linux x86-64 передаёт 144 байта; у i386 другая раскладка stat. */
struct linux_stat {
    u64 dev, ino, nlink;
    u32 mode, uid, gid, padding;
    u64 rdev, size, blksize, blocks;
    u64 times[6], reserved[3];
};

_Static_assert(sizeof(struct linux_stat) == 144, "Linux x86-64 stat size");
_Static_assert(__builtin_offsetof(struct linux_stat, size) == 48, "Linux x86-64 st_size");

static struct linux64_file_source files;
static struct {
    struct linux64_file file;
    uptr offset;
    bool used;
} handles[FD_COUNT];

void linux64_use_files(const struct linux64_file_source *source) {
    files = source ? *source : (struct linux64_file_source){0};
    for (unsigned i = STDIO_COUNT; i < FD_COUNT; ++i)
        handles[i].used = false;
}

static bool open_file(i32 fd) {
    return fd >= STDIO_COUNT && fd < FD_COUNT && handles[fd].used;
}

const struct linux64_file *linux64_get_file(i32 fd) {
    return open_file(fd) ? &handles[fd].file : NULL;
}

static uptr user_store(uptr address, const void *data, uptr size) {
    const u8 *source = data;
    uptr copied = 0;
    while (copied < size) {
        u8 *target = paging64_user_write(address + copied);
        if (!target) break;
        uptr chunk = PMM_PAGE_SIZE - ((address + copied) & (PMM_PAGE_SIZE - 1));
        if (chunk > size - copied) chunk = size - copied;
        for (uptr i = 0; i < chunk; ++i) target[i] = source[copied + i];
        copied += chunk;
    }
    return copied;
}

static long user_path(uptr address, char path[PATH_LIMIT]) {
    for (uptr copied = 0; copied < PATH_LIMIT;) {
        const u8 *source = paging64_user_read(address + copied);
        if (!source) return -EFAULT;
        uptr chunk = PMM_PAGE_SIZE - ((address + copied) & (PMM_PAGE_SIZE - 1));
        if (chunk > PATH_LIMIT - copied) chunk = PATH_LIMIT - copied;
        for (uptr i = 0; i < chunk; ++i) {
            path[copied + i] = (char)source[i];
            if (!source[i]) return 0;
        }
        copied += chunk;
    }
    return -ENAMETOOLONG;
}

static long lookup(i32 dirfd, uptr address, bool empty_path, struct linux64_file *file) {
    char path[PATH_LIMIT + 1];
    path[1] = 0;
    if (address || !empty_path) {
        long result = user_path(address, path + 1);
        if (result) return result;
    }
    if (!path[1]) {
        if (!empty_path || dirfd == AT_FDCWD) return -ENOENT;
        if (!open_file(dirfd)) return -EBADF;
        *file = handles[dirfd].file;
        return 0;
    }
    const char *absolute = path + 1;
    if (*absolute != '/') {
        if (dirfd != AT_FDCWD)
            return (dirfd >= 0 && dirfd < STDIO_COUNT) || open_file(dirfd) ? -ENOTDIR : -EBADF;
        path[0] = '/';
        absolute = path;
    }
    return files.lookup && files.lookup(files.context, absolute, file) ? 0 : -ENOENT;
}

static long linux_open(i32 dirfd, uptr path, u32 flags) {
    if ((flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    if (flags & (O_ACCMODE | O_CREAT | O_TRUNC)) return -EROFS;
    if (flags & ~(O_NONBLOCK | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
        return -EINVAL;
    struct linux64_file file;
    long result = lookup(dirfd, path, false, &file);
    if (result) return result;
    if (flags & O_DIRECTORY) return -ENOTDIR;
    for (unsigned i = STDIO_COUNT; i < FD_COUNT; ++i) {
        if (handles[i].used) continue;
        handles[i].file = file;
        handles[i].offset = 0;
        handles[i].used = true;
        return i;
    }
    return -EMFILE;
}

static long linux_read(i32 fd, uptr buffer, uptr count, uptr offset, bool positioned) {
    if (!open_file(fd)) return -EBADF;
    if (!positioned) offset = handles[fd].offset;
    if ((long)offset < 0) return -EINVAL;
    if (buffer >= X64_USER_TOP || count > X64_USER_TOP - buffer) return -EFAULT;
    const struct linux64_file *file = &handles[fd].file;
    if (!count || offset >= file->size) return 0;
    if (count > 0x7ffff000u) count = 0x7ffff000u;
    if (count > file->size - offset) count = file->size - offset;
    uptr copied = user_store(buffer, file->bytes + offset, count);
    if (!copied) return -EFAULT;
    if (!positioned) handles[fd].offset += copied;
    return (long)copied;
}

static long file_stat(const struct linux64_file *file, uptr stat_address) {
    const struct linux_stat stat = {
        .dev = 1, .ino = file->inode, .nlink = 1, .mode = 0100444,
        .size = file->size, .blksize = PMM_PAGE_SIZE, .blocks = (file->size + 511) / 512,
    };
    return user_store(stat_address, &stat, sizeof(stat)) == sizeof(stat) ? 0 : -EFAULT;
}

long linux64_file_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2, uptr arg3) {
    const i32 fd = (i32)arg0;
    struct linux64_file file;
    long result;
    switch (number) {
    case 0: /* read */
        return linux_read(fd, arg1, arg2, 0, false);
    case 2: /* open */
        return linux_open(AT_FDCWD, arg0, (u32)arg1);
    case 3: /* close */
        if (!open_file(fd)) return -EBADF;
        handles[fd].used = false;
        return 0;
    case 5: /* fstat */
        if (!open_file(fd)) return -EBADF;
        return file_stat(&handles[fd].file, arg1);
    case 17: /* pread64 */
        return linux_read(fd, arg1, arg2, arg3, true);
    case 21: /* access */
        if ((u32)arg1 & ~7u) return -EINVAL;
        result = lookup(AT_FDCWD, arg0, false, &file);
        if (result) return result;
        return (arg1 & 3u) ? -EACCES : 0;
    case 257: /* openat */
        return linux_open(fd, arg1, (u32)arg2);
    case 262: /* newfstatat */
        if ((u32)arg3 & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW))
            return -EINVAL;
        result = lookup(fd, arg1, (arg3 & AT_EMPTY_PATH) != 0, &file);
        return result ? result : file_stat(&file, arg2);
    default:
        return -ENOSYS;
    }
}
