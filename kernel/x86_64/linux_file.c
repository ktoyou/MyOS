#include "linux_task.h"
#include "paging.h"

enum {
    EPERM = 1, ENOENT = 2, EBADF = 9, ENOMEM = 12, EACCES = 13, EFAULT = 14,
    EBUSY = 16, ENOTDIR = 20, EINVAL = 22, EMFILE = 24, EFBIG = 27, EROFS = 30,
    ENODEV = 19, ESPIPE = 29, ENAMETOOLONG = 36, ENOSYS = 38, ELOOP = 40, ENOTSOCK = 88,
    AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100, AT_NO_AUTOMOUNT = 0x800,
    AT_EMPTY_PATH = 0x1000,
    O_ACCMODE = 3, O_RDWR = 2, O_CREAT = 0x40, O_TRUNC = 0x200, O_NONBLOCK = 0x800,
    O_LARGEFILE = 0x8000, O_DIRECTORY = 0x10000, O_NOFOLLOW = 0x20000,
    O_CLOEXEC = 0x80000,
    F_GETFD = 1, F_SETFD = 2, F_GETFL = 3, F_ADD_SEALS = 1033, F_GET_SEALS = 1034,
    F_SEAL_SEAL = 1, F_SEAL_SHRINK = 2, F_SEAL_GROW = 4, F_SEAL_EXEC = 0x20,
    MFD_CLOEXEC = 1, MFD_ALLOW_SEALING = 2, MFD_NOEXEC_SEAL = 8,
    MEMFD_NAME_LIMIT = 249, MEMFD_CHUNKS = 128,
    FRAMES_PER_CHUNK = PMM_PAGE_SIZE / sizeof(uptr),
    STDIO_COUNT = 3, FD_COUNT = LINUX64_FD_COUNT,
    OPEN_FILE_COUNT = LINUX64_TASK_COUNT * (FD_COUNT - STDIO_COUNT),
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
static struct memfd {
    uptr *chunks[MEMFD_CHUNKS];
    uptr size;
    u64 inode;
    u32 seals;
    unsigned handles;
} memfds[OPEN_FILE_COUNT];
static u64 next_memfd_inode = 1;
static u64 next_socket_inode = 1;

static struct file_handle {
    struct linux64_file file;
    struct memfd *memfd;
    struct linux64_socket *socket;
    uptr offset;
    u32 flags;
    unsigned references;
} open_files[OPEN_FILE_COUNT];

static struct file_handle *file_at(i32 fd) {
    return linux64_current->fds[fd].file;
}

static uptr memfd_frame(const void *object, uptr offset) {
    const struct memfd *memfd = object;
    uptr page = offset / PMM_PAGE_SIZE;
    return memfd->chunks[page / FRAMES_PER_CHUNK][page % FRAMES_PER_CHUNK];
}

static uptr memfd_page_count(uptr size) {
    return (size + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE;
}

static void memfd_trim(struct memfd *memfd, uptr first, uptr end) {
    while (end > first) {
        uptr page = --end;
        uptr slot = page % FRAMES_PER_CHUNK;
        uptr **chunk = &memfd->chunks[page / FRAMES_PER_CHUNK];
        pmm64_free((*chunk)[slot]);
        if (!slot) {
            pmm64_free((uptr)*chunk - (uptr)pmm64_pointer(0));
            *chunk = NULL;
        }
    }
}

static void close_slot(struct linux64_fd_slot *slot) {
    struct file_handle *file = slot->file;
    *slot = (struct linux64_fd_slot){0};
    if (!file || --file->references) return;
    if (file->socket) linux64_socket_close(file->socket);
    struct memfd *memfd = file->memfd;
    if (memfd && !--memfd->handles) {
        memfd_trim(memfd, 0, memfd_page_count(memfd->size));
        memfd->size = 0;
    }
    *file = (struct file_handle){0};
}

static void close_file(i32 fd) {
    close_slot(&linux64_current->fds[fd]);
}

void linux64_close_files(struct linux64_task *task) {
    for (unsigned fd = STDIO_COUNT; fd < FD_COUNT; ++fd) close_slot(&task->fds[fd]);
}

void linux64_close_on_exec(struct linux64_task *task) {
    for (unsigned fd = STDIO_COUNT; fd < FD_COUNT; ++fd)
        if (task->fds[fd].cloexec) close_slot(&task->fds[fd]);
}

void linux64_retain_files(struct linux64_task *task) {
    for (unsigned fd = STDIO_COUNT; fd < FD_COUNT; ++fd)
        if (task->fds[fd].file) ++task->fds[fd].file->references;
}

void linux64_use_files(const struct linux64_file_source *source, const char *path, uptr path_length) {
    files = source ? *source : (struct linux64_file_source){0};
    linux64_current->executable_path_length = path_length;
    for (uptr i = 0; i <= path_length; ++i) linux64_current->executable_path[i] = path[i];
    linux64_close_files(linux64_current);
}

const struct linux64_file_source *linux64_file_source(void) {
    return &files;
}

static bool open_file(i32 fd) {
    return fd >= STDIO_COUNT && fd < FD_COUNT && file_at(fd);
}

long linux64_get_file(i32 fd, struct linux64_fd_view *view) {
    if (!open_file(fd)) return -EBADF;
    if (file_at(fd)->socket) return -ENODEV;
    const struct memfd *memfd = file_at(fd)->memfd;
    *view = (struct linux64_fd_view){.file = file_at(fd)->file};
    if (memfd) {
        view->file.size = memfd->size;
        view->file.inode = memfd->inode;
        view->object = memfd;
        view->frame = memfd_frame;
        view->writable = (file_at(fd)->flags & O_ACCMODE) == O_RDWR;
        view->may_grow = !(memfd->seals & F_SEAL_GROW);
    }
    return 0;
}

long linux64_user_string(uptr address, char *string, uptr limit) {
    for (uptr copied = 0; copied < limit;) {
        const u8 *source = paging64_user_read(address + copied);
        if (!source) return -EFAULT;
        uptr chunk = PMM_PAGE_SIZE - ((address + copied) & (PMM_PAGE_SIZE - 1));
        if (chunk > limit - copied) chunk = limit - copied;
        for (uptr i = 0; i < chunk; ++i) {
            string[copied + i] = (char)source[i];
            if (!source[i]) return (long)(copied + i);
        }
        copied += chunk;
    }
    return -ENAMETOOLONG;
}

static long user_path(uptr address, char *path) {
    long result = linux64_user_string(address, path, LINUX64_PATH_LIMIT);
    return result < 0 ? result : 0;
}

static const char *root_path(char *path) {
    path[0] = '/';
    return path[1] == '/' ? path + 1 : path;
}

static long memfd_proc_path(const char *path, i32 *fd) {
    const char *prefix = "/proc/self/fd/";
    while (*prefix && *path == *prefix) {
        ++path;
        ++prefix;
    }
    if (*prefix) return 0;
    if (*path < '1' || *path > '9') return -ENOENT;
    unsigned number = 0;
    while (*path >= '0' && *path <= '9') {
        number = number * 10 + (unsigned)(*path++ - '0');
        if (number >= FD_COUNT) return -ENOENT;
    }
    if (*path == '/' && !path[1] && open_file(number) && file_at(number)->memfd) return -ENOTDIR;
    if (*path || !open_file(number) || !file_at(number)->memfd) return -ENOENT;
    *fd = (i32)number;
    return 1;
}

static long absolute_path(i32 dirfd, char *path, const char **absolute) {
    *absolute = path + 1;
    if (**absolute == '/') return 0;
    if (dirfd != AT_FDCWD)
        return (dirfd >= 0 && dirfd < STDIO_COUNT) || open_file(dirfd) ? -ENOTDIR : -EBADF;
    *absolute = root_path(path);
    return 0;
}

static long new_handle(const struct linux64_file *file, struct memfd *memfd, u32 flags) {
    unsigned fd = STDIO_COUNT;
    while (fd < FD_COUNT && file_at(fd)) ++fd;
    if (fd == FD_COUNT) return -EMFILE;
    for (unsigned i = 0; i < OPEN_FILE_COUNT; ++i) {
        struct file_handle *description = &open_files[i];
        if (description->references) continue;
        *description = (struct file_handle){.memfd = memfd, .flags = flags & ~O_CLOEXEC,
                                            .references = 1};
        if (file) description->file = *file;
        if (memfd) ++memfd->handles;
        linux64_current->fds[fd] = (struct linux64_fd_slot){description, (flags & O_CLOEXEC) != 0};
        return fd;
    }
    return -EMFILE;
}

static long linux_socketpair(i32 domain, u32 type, i32 protocol, uptr address) {
    struct linux64_socket *ends[2];
    long error = linux64_socket_pair(domain, type, protocol, ends);
    if (error) return error;
    i32 fds[2];
    for (unsigned i = 0; i < 2; ++i) {
        long fd = new_handle(NULL, NULL, O_RDWR | (type & (O_CLOEXEC | O_NONBLOCK)));
        if (fd < 0) {
            if (i) close_file(fds[0]);
            else linux64_socket_close(ends[0]);
            linux64_socket_close(ends[1]);
            return fd;
        }
        fds[i] = (i32)fd;
        file_at(fd)->socket = ends[i];
        file_at(fd)->file.inode = next_socket_inode++;
    }
    u64 pair = (u32)fds[0] | ((u64)(u32)fds[1] << 32);
    if (paging64_put_user_u64(address, pair)) return 0;
    close_file(fds[0]);
    close_file(fds[1]);
    return -EFAULT;
}

long linux64_sockopt(bool get, i32 fd, i32 level, i32 option, uptr value, uptr length) {
    if (!open_file(fd)) return fd >= 0 && fd < STDIO_COUNT ? -ENOTSOCK : -EBADF;
    if (!file_at(fd)->socket) return -ENOTSOCK;
    return linux64_socket_option(file_at(fd)->socket, get, level, option, value, length);
}

static long memfd_create(uptr name_address, u32 flags) {
    if (flags & ~(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)) return -EINVAL;
    char name[MEMFD_NAME_LIMIT + 1];
    long result = linux64_user_string(name_address, name, sizeof(name));
    if (result < 0) return result == -ENAMETOOLONG ? -EINVAL : result;
    for (unsigned i = 0; i < OPEN_FILE_COUNT; ++i) {
        struct memfd *memfd = &memfds[i];
        if (memfd->handles) continue;
        result = new_handle(NULL, memfd, O_RDWR | O_LARGEFILE |
                             (flags & MFD_CLOEXEC ? O_CLOEXEC : 0));
        if (result < 0) return result;
        memfd->inode = next_memfd_inode++;
        memfd->seals = flags & MFD_NOEXEC_SEAL ? F_SEAL_EXEC :
                       flags & MFD_ALLOW_SEALING ? 0 : F_SEAL_SEAL;
        return result;
    }
    return -EMFILE;
}

static bool memfd_grow(struct memfd *memfd, uptr first, uptr end) {
    uptr page = first;
    for (; page < end; ++page) {
        uptr slot = page % FRAMES_PER_CHUNK;
        uptr **chunk = &memfd->chunks[page / FRAMES_PER_CHUNK];
        uptr frame = pmm64_alloc();
        if (!frame) break;
        if (!slot) {
            uptr table = pmm64_alloc();
            if (!table) {
                pmm64_free(frame);
                break;
            }
            *chunk = pmm64_pointer(table);
        }
        (*chunk)[slot] = frame;
    }
    if (page == end) return true;
    memfd_trim(memfd, first, page);
    return false;
}

static long linux_ftruncate(i32 fd, uptr size) {
    if ((long)size < 0) return -EINVAL;
    if (!open_file(fd)) return -EBADF;
    struct memfd *memfd = file_at(fd)->memfd;
    if (!memfd || (file_at(fd)->flags & O_ACCMODE) != O_RDWR) return -EINVAL;
    uptr old_size = memfd->size;
    if (size == old_size) return 0;
    if (memfd->seals & (size < old_size ? F_SEAL_SHRINK : F_SEAL_GROW)) return -EPERM;
    if (size > (uptr)MEMFD_CHUNKS * FRAMES_PER_CHUNK * PMM_PAGE_SIZE) return -EFBIG;
    uptr old_pages = memfd_page_count(old_size), pages = memfd_page_count(size);
    for (uptr i = 0; i < old_pages; ++i)
        if (pmm64_has_aliases(memfd_frame(memfd, i * PMM_PAGE_SIZE))) return -EBUSY;
    if (pages > old_pages && !memfd_grow(memfd, old_pages, pages)) return -ENOMEM;
    memfd_trim(memfd, pages, old_pages);
    /* Общий алиас мог записать в хвост последней страницы за старым EOF. */
    uptr boundary = size < old_size ? size : old_size;
    uptr tail = boundary % PMM_PAGE_SIZE;
    if (tail) {
        u8 *bytes = pmm64_pointer(memfd_frame(memfd, boundary));
        for (uptr i = tail; i < PMM_PAGE_SIZE; ++i) bytes[i] = 0;
    }
    memfd->size = size;
    return 0;
}

static long linux_fcntl(i32 fd, i32 command, u32 value) {
    if (!open_file(fd)) return -EBADF;
    struct memfd *memfd = file_at(fd)->memfd;
    if (command == F_GETFD) return linux64_current->fds[fd].cloexec;
    if (command == F_SETFD) {
        linux64_current->fds[fd].cloexec = (value & 1) != 0;
        return 0;
    }
    if (command == F_GETFL) return file_at(fd)->flags;
    if (!memfd) return -EINVAL;
    if (command == F_GET_SEALS) return memfd->seals;
    if (command != F_ADD_SEALS) return -EINVAL;
    if ((file_at(fd)->flags & O_ACCMODE) != O_RDWR) return -EPERM;
    if (value & ~(F_SEAL_SEAL | F_SEAL_GROW | F_SEAL_SHRINK | (memfd->seals & F_SEAL_EXEC)))
        return -EINVAL;
    if (memfd->seals & F_SEAL_SEAL) return -EPERM;
    memfd->seals |= value;
    return 0;
}

static void handle_stat(i32 fd, struct linux64_file *file, const struct memfd **memfd) {
    *memfd = file_at(fd)->memfd;
    *file = file_at(fd)->file;
    if (*memfd) {
        file->size = (*memfd)->size;
        file->inode = (*memfd)->inode;
    }
}

static long lookup(i32 dirfd, uptr address, bool empty_path, struct linux64_file *file,
                   const struct memfd **memfd, bool *socket) {
    char path[LINUX64_PATH_LIMIT + 1];
    path[1] = 0;
    if (address || !empty_path) {
        long result = user_path(address, path + 1);
        if (result) return result;
    }
    if (!path[1]) {
        if (!empty_path || dirfd == AT_FDCWD) return -ENOENT;
        if (!open_file(dirfd)) return -EBADF;
        handle_stat(dirfd, file, memfd);
        *socket = file_at(dirfd)->socket != NULL;
        return 0;
    }
    const char *absolute;
    long result = absolute_path(dirfd, path, &absolute);
    if (result) return result;
    *memfd = NULL;
    *socket = false;
    return files.lookup && files.lookup(files.context, absolute, file) ? 0 : -ENOENT;
}

static long linux_readlink(uptr path_address, uptr destination, i32 size) {
    if (size <= 0) return -EINVAL;
    char path[LINUX64_PATH_LIMIT + 1];
    long result = user_path(path_address, path + 1);
    if (result) return result;
    if (!path[1]) return -ENOENT;
    const char *absolute = root_path(path);
    const char *actual = absolute, *expected = "/proc/self/exe";
    while (*actual && *actual == *expected) {
        ++actual;
        ++expected;
    }
    if (*actual != *expected) {
        struct linux64_file file;
        return files.lookup && files.lookup(files.context, absolute, &file) ? -EINVAL : -ENOENT;
    }
    uptr length = linux64_current->executable_path_length;
    if (!length) return -ENOENT;
    if (length > (uptr)size) length = (uptr)size;
    return paging64_copy_to_user(destination, linux64_current->executable_path, length) == length
        ? (long)length : -EFAULT;
}

static long linux_open(i32 dirfd, uptr address, u32 flags) {
    if ((flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    char path[LINUX64_PATH_LIMIT + 1];
    long result = user_path(address, path + 1);
    if (result) return result;
    if (!path[1]) return -ENOENT;
    const char *absolute;
    result = absolute_path(dirfd, path, &absolute);
    if (result) return result;
    i32 target;
    result = memfd_proc_path(absolute, &target);
    if (result < 0) return result;
    if (result) {
        if (flags & O_NOFOLLOW) return -ELOOP;
        if (flags & O_DIRECTORY) return -ENOTDIR;
        if (flags & ~(O_CLOEXEC | O_LARGEFILE | O_NONBLOCK)) return -EINVAL;
        return new_handle(NULL, file_at(target)->memfd, flags | O_LARGEFILE);
    }
    if (flags & (O_ACCMODE | O_CREAT | O_TRUNC)) return -EROFS;
    if (flags & ~(O_NONBLOCK | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
        return -EINVAL;
    struct linux64_file file;
    if (!files.lookup || !files.lookup(files.context, absolute, &file)) return -ENOENT;
    if (flags & O_DIRECTORY) return -ENOTDIR;
    return new_handle(&file, NULL, flags | O_LARGEFILE);
}

static long linux_read(i32 fd, uptr buffer, uptr count, uptr offset, bool positioned) {
    if (!open_file(fd)) return -EBADF;
    if (file_at(fd)->socket)
        return positioned ? -ESPIPE : linux64_socket_io(file_at(fd)->socket, true, buffer, count);
    if (!positioned) offset = file_at(fd)->offset;
    if ((long)offset < 0) return -EINVAL;
    if (buffer >= X64_USER_TOP || count > X64_USER_TOP - buffer) return -EFAULT;
    struct linux64_fd_view view;
    linux64_get_file(fd, &view);
    if (!count || offset >= view.file.size) return 0;
    if (count > 0x7ffff000u) count = 0x7ffff000u;
    if (count > view.file.size - offset) count = view.file.size - offset;
    uptr copied = 0;
    if (view.frame) {
        while (copied < count) {
            uptr current = offset + copied, page_offset = current % PMM_PAGE_SIZE;
            uptr chunk = PMM_PAGE_SIZE - page_offset;
            if (chunk > count - copied) chunk = count - copied;
            const u8 *page = pmm64_pointer(view.frame(view.object, current));
            uptr done = paging64_copy_to_user(buffer + copied, page + page_offset, chunk);
            copied += done;
            if (done < chunk) break;
        }
    } else {
        copied = paging64_copy_to_user(buffer, view.file.bytes + offset, count);
    }
    if (!copied) return -EFAULT;
    if (!positioned) file_at(fd)->offset += copied;
    return (long)copied;
}

static long file_stat(const struct linux64_file *file, const struct memfd *memfd, bool socket,
                      uptr stat_address) {
    u32 mode = socket ? 0140777 : memfd ? (memfd->seals & F_SEAL_EXEC ? 0100666 : 0100777) : 0100444;
    const struct linux_stat stat = {
        .dev = socket ? 3 : memfd ? 2 : 1, .ino = file->inode, .nlink = !memfd, .mode = mode,
        .uid = socket || memfd ? LINUX64_UID : 0, .gid = socket || memfd ? LINUX64_GID : 0,
        .size = file->size, .blksize = PMM_PAGE_SIZE, .blocks = (file->size + 511) / 512,
    };
    return paging64_copy_to_user(stat_address, &stat, sizeof(stat)) == sizeof(stat) ? 0 : -EFAULT;
}

long linux64_file_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2, uptr arg3) {
    const i32 fd = (i32)arg0;
    struct linux64_file file;
    const struct memfd *memfd;
    bool socket;
    long result;
    switch (number) {
    case 0: /* read */
        return linux_read(fd, arg1, arg2, 0, false);
    case 1: /* write */
        if (!open_file(fd) || !file_at(fd)->socket) return -EBADF;
        return linux64_socket_io(file_at(fd)->socket, false, arg1, arg2);
    case 2: /* open */
        return linux_open(AT_FDCWD, arg0, (u32)arg1);
    case 3: /* close */
        if (!open_file(fd)) return -EBADF;
        close_file(fd);
        return 0;
    case 5: /* fstat */
        if (!open_file(fd)) return -EBADF;
        handle_stat(fd, &file, &memfd);
        return file_stat(&file, memfd, file_at(fd)->socket != NULL, arg1);
    case 17: /* pread64 */
        return linux_read(fd, arg1, arg2, arg3, true);
    case 21: /* access */
        if ((u32)arg1 & ~7u) return -EINVAL;
        result = lookup(AT_FDCWD, arg0, false, &file, &memfd, &socket);
        if (result) return result;
        return (arg1 & 3u) ? -EACCES : 0;
    case 46: /* sendmsg */
    case 47: /* recvmsg */
        if (!open_file(fd)) return fd >= 0 && fd < STDIO_COUNT ? -ENOTSOCK : -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        return linux64_socket_message(file_at(fd)->socket, number == 47, arg1, (u32)arg2);
    case 48: /* shutdown */
        if (!open_file(fd)) return fd >= 0 && fd < STDIO_COUNT ? -ENOTSOCK : -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        return linux64_socket_shutdown(file_at(fd)->socket, (i32)arg1);
    case 53: /* socketpair */
        return linux_socketpair(fd, (u32)arg1, (i32)arg2, arg3);
    case 72: /* fcntl */
        return linux_fcntl(fd, (i32)arg1, (u32)arg2);
    case 77: /* ftruncate */
        return linux_ftruncate(fd, arg1);
    case 89: /* readlink */
        return linux_readlink(arg0, arg1, (i32)arg2);
    case 257: /* openat */
        return linux_open(fd, arg1, (u32)arg2);
    case 262: /* newfstatat */
        if ((u32)arg3 & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW))
            return -EINVAL;
        result = lookup(fd, arg1, (arg3 & AT_EMPTY_PATH) != 0, &file, &memfd, &socket);
        return result ? result : file_stat(&file, memfd, socket, arg2);
    case 319: /* memfd_create */
        return memfd_create(arg0, (u32)arg1);
    default:
        return -ENOSYS;
    }
}
