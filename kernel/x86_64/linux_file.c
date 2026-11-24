#include "linux_task.h"
#include "paging.h"

#define NS_PER_SECOND 1000000000ul

enum {
    EPERM = 1, ENOENT = 2, EIO = 5, EBADF = 9, EAGAIN = 11, ENOMEM = 12, EACCES = 13, EFAULT = 14,
    EBUSY = 16, EEXIST = 17, ENOTDIR = 20, EISDIR = 21, EINVAL = 22, EMFILE = 24, EFBIG = 27, EROFS = 30,
    ENODEV = 19, ENXIO = 6, ESPIPE = 29, ENAMETOOLONG = 36, ENOSYS = 38, ELOOP = 40, ENOTSOCK = 88,
    EOPNOTSUPP = 95, EADDRINUSE = 98, ECONNREFUSED = 111, AF_UNIX = 1, MSG_DONTWAIT = 0x40,
    AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100, AT_REMOVEDIR = 0x200, AT_NO_AUTOMOUNT = 0x800,
    AT_EMPTY_PATH = 0x1000,
    O_ACCMODE = 3, O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0x40, O_EXCL = 0x80,
    O_NOCTTY = 0x100, O_TRUNC = 0x200, O_APPEND = 0x400, O_NONBLOCK = 0x800,
    O_DIRECT = 0x4000, O_LARGEFILE = 0x8000, O_DIRECTORY = 0x10000, O_NOFOLLOW = 0x20000,
    O_CLOEXEC = 0x80000,
    F_DUPFD = 0, F_GETFD = 1, F_SETFD = 2, F_GETFL = 3, F_SETFL = 4,
    F_DUPFD_CLOEXEC = 1030, F_ADD_SEALS = 1033, F_GET_SEALS = 1034,
    F_SEAL_SEAL = 1, F_SEAL_SHRINK = 2, F_SEAL_GROW = 4, F_SEAL_EXEC = 0x20,
    MFD_CLOEXEC = 1, MFD_ALLOW_SEALING = 2, MFD_NOEXEC_SEAL = 8,
    EFD_SEMAPHORE = 1,
    EPOLL_ADD = 1, EPOLL_DEL = 2, EPOLL_MOD = 3,
    EPOLL_EXCLUSIVE = 1u << 28, EPOLL_WAKEUP = 1u << 29,
    EPOLL_ONESHOT = 1u << 30, EPOLL_ET = 1u << 31,
    MEMFD_NAME_LIMIT = 249, MEMFD_CHUNKS = 128,
    FRAMES_PER_CHUNK = PMM_PAGE_SIZE / sizeof(uptr),
    FD_COUNT = LINUX64_FD_COUNT, OPEN_FILE_COUNT = LINUX64_PROCESS_COUNT * FD_COUNT,
};

enum file_kind {
    FILE_REGULAR, FILE_SOCKET, FILE_PIPE, FILE_PROC_DIR, FILE_PROC_MAP, FILE_NULL, FILE_SERIAL,
    FILE_NAMESPACE, FILE_PROC_LINK, FILE_DIRECTORY, FILE_SYMLINK, FILE_NAMED_SOCKET, FILE_URANDOM,
    FILE_EVENTFD, FILE_EPOLL,
};
#define EVENTFD_MAX ((u64)-2)
static const struct linux64_file null_file = {.inode = 1};
static const struct linux64_file urandom_file = {.inode = 2};

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
static u64 next_special_inode = 1;
static u64 next_pid_ns_link_inode = 1ull << 33;
static u64 next_fdinfo_inode = 1ull << 34;
static u64 next_proc_fd_inode = 1ull << 35;

struct epoll_event {
    u32 events;
    u64 data;
} __attribute__((packed));

_Static_assert(sizeof(struct epoll_event) == 12 && __builtin_offsetof(struct epoll_event, data) == 4,
               "Linux x86-64 epoll_event");

struct epoll_watch {
    struct epoll_watch *next;
    struct file_handle *target;
    struct epoll_event event;
    i32 fd;
    bool armed;
};

static struct file_handle {
    struct linux64_file file;
    struct memfd *memfd;
    struct linux64_socket *socket;
    struct linux64_pipe *pipe;
    struct linux64_userns *proc_ns;
    struct linux64_pidns *proc_pid_ns;
    enum linux64_proc_node proc_node;
    bool proc_admin;
    enum file_kind device;
    bool serial;
    uptr directory_path;
    uptr offset;
    struct epoll_watch *watches, *epoll_next;
    u64 event_count;
    u32 flags;
    unsigned references, watched_by;
    bool event_semaphore;
} open_files[OPEN_FILE_COUNT];

static struct file_handle *file_at(i32 fd) {
    return linux64_current->process->fds[fd].file;
}

_Static_assert(sizeof(struct linux64_pollfd) == 8, "Linux x86-64 pollfd size");
_Static_assert(__builtin_offsetof(struct linux64_pollfd, revents) == 6, "Linux x86-64 revents");

static bool epoll_ready(const struct file_handle *file);

static u16 file_ready(const struct file_handle *file) {
    if (file->serial) return LINUX64_POLL_WRITE;
    if (file->pipe) return linux64_pipe_poll(file->pipe, (file->flags & O_ACCMODE) == O_WRONLY);
    if (file->socket) return linux64_socket_poll(file->socket);
    if (file->device == FILE_EVENTFD)
        return (file->event_count ? LINUX64_POLLIN : 0) |
               (file->event_count < EVENTFD_MAX ? LINUX64_POLLOUT : 0);
    if (file->device == FILE_EPOLL)
        return epoll_ready(file) ? LINUX64_POLLIN | LINUX64_POLLRDNORM : 0;
    return LINUX64_POLL_READ | LINUX64_POLL_WRITE;
}

static u16 epoll_watch_ready(const struct epoll_watch *watch) {
    if (!watch->armed) return 0;
    return file_ready(watch->target) & (watch->event.events | LINUX64_POLLERR | LINUX64_POLLHUP);
}

static bool epoll_ready(const struct file_handle *file) {
    for (const struct epoll_watch *watch = file->watches; watch; watch = watch->next)
        if (epoll_watch_ready(watch)) return true;
    return false;
}

static u16 poll_fd(const struct linux64_process *process, i32 fd, u16 events) {
    if (fd < 0) return 0;
    if (fd >= FD_COUNT) return LINUX64_POLLNVAL;
    const struct file_handle *file = process->fds[fd].file;
    if (!file) return LINUX64_POLLNVAL;
    return file_ready(file) & (events | LINUX64_POLLERR | LINUX64_POLLHUP);
}

bool linux64_poll_ready(struct linux64_task *task) {
    struct linux64_poll_wait *poll = &task->poll;
    poll->ready = 0;
    /* Сохраняем номера, чтобы заново искать файлы после close в соседнем потоке. */
    for (unsigned i = 0; i < poll->count; ++i) {
        struct linux64_pollfd *entry = &poll->entries[i];
        entry->revents = poll_fd(task->process, entry->fd, entry->events);
        if (entry->revents) ++poll->ready;
    }
    if (poll->ready) return true;
    u64 nanos;
    return poll->deadline && linux64_monotonic_ns(&nanos) && nanos >= poll->deadline;
}

static void poll_remaining(const struct linux64_poll_timeout *end) {
    u64 nanos;
    if (!end || !end->address || !linux64_monotonic_ns(&nanos)) return;
    u64 seconds = nanos / NS_PER_SECOND;
    u64 fraction = nanos % NS_PER_SECOND;
    u64 time[2] = {0};
    if (end->seconds > seconds || (end->seconds == seconds && end->nanoseconds >= fraction)) {
        time[0] = end->seconds - seconds;
        if (end->nanoseconds < fraction) {
            --time[0];
            time[1] = NS_PER_SECOND - fraction + end->nanoseconds;
        } else {
            time[1] = end->nanoseconds - fraction;
        }
    }
    /* Linux сохраняет результат ppoll, даже если остаток нельзя записать. */
    paging64_copy_to_user(end->address, time, sizeof(time));
}

long linux64_poll_resume(struct linux64_task *task) {
    const struct linux64_poll_wait *poll = &task->poll;
    long result = poll->ready;
    for (unsigned i = 0; i < poll->count; ++i) {
        uptr field = poll->address + i * sizeof(poll->entries[0]) +
                     __builtin_offsetof(struct linux64_pollfd, revents);
        if (!paging64_put_user_u16(field, poll->entries[i].revents)) {
            result = -EFAULT;
            break;
        }
    }
    task->signal_mask = poll->saved_mask;
    poll_remaining(&poll->timeout);
    return result;
}

static long poll_wait(uptr address, u32 count, u64 deadline, bool immediate,
                      const struct linux64_poll_timeout *timeout, const u64 *mask) {
    struct linux64_task *task = linux64_current;
    struct linux64_poll_wait *poll = &task->poll;
    if (count > FD_COUNT) {
        poll_remaining(timeout);
        return -EINVAL;
    }
    uptr bytes = count * sizeof(poll->entries[0]);
    if (address > X64_USER_TOP || bytes > X64_USER_TOP - address ||
        paging64_copy_from_user(poll->entries, address, bytes) != bytes) {
        poll_remaining(timeout);
        return -EFAULT;
    }
    poll->address = address;
    poll->count = count;
    poll->deadline = deadline;
    poll->timeout = timeout ? *timeout : (struct linux64_poll_timeout){0};
    poll->saved_mask = task->signal_mask;
    if (mask) task->signal_mask = *mask;
    if (linux64_poll_ready(task) || immediate) return linux64_poll_resume(task);
    task->state = TASK_POLL_WAIT;
    return 0;
}

long linux64_poll(uptr address, u32 count, i32 timeout) {
    if (count > FD_COUNT) return -EINVAL;
    u64 deadline = 0;
    if (timeout > 0) {
        if (!linux64_monotonic_ns(&deadline)) return -EIO;
        deadline += (u64)timeout * 1000000ul;
    }
    return poll_wait(address, count, deadline, timeout == 0, NULL, NULL);
}

long linux64_ppoll(uptr address, u32 count, uptr timeout, uptr sigmask, uptr sigset_size) {
    u64 deadline = 0;
    bool immediate = false;
    struct linux64_poll_timeout end = {0};
    if (timeout) {
        long time[2];
        if (paging64_copy_from_user(time, timeout, sizeof(time)) != sizeof(time)) return -EFAULT;
        if (time[0] < 0 || (u64)time[1] >= NS_PER_SECOND) return -EINVAL;
        immediate = !time[0] && !time[1];
        if (!immediate) {
            u64 nanos;
            if (!linux64_monotonic_ns(&nanos)) return -EIO;
            const u64 limit = 0x7fffffffffffffffULL;
            u64 fraction = nanos % NS_PER_SECOND + (u64)time[1];
            end.address = timeout;
            end.seconds = (u64)time[0] + nanos / NS_PER_SECOND + fraction / NS_PER_SECOND;
            end.nanoseconds = fraction % NS_PER_SECOND;
            if (end.seconds > limit) {
                end.seconds = limit;
                end.nanoseconds = 0;
            }
            /* Планировщик ограничен 64-битными наносекундами, ABI timespec шире. */
            deadline = end.seconds > (limit - end.nanoseconds) / NS_PER_SECOND
                           ? limit : end.seconds * NS_PER_SECOND + end.nanoseconds;
        }
    }
    u64 mask;
    if (sigmask) {
        long result = linux64_read_signal_mask(sigmask, sigset_size, &mask);
        if (result) return result;
    }
    return poll_wait(address, count, deadline, immediate, &end, sigmask ? &mask : NULL);
}

static bool namespace_node(enum linux64_proc_node proc) {
    return proc == PROC_USER_NS || proc == PROC_PID_NS;
}

static enum file_kind kind_of(const struct file_handle *file) {
    if (file->directory_path) return FILE_DIRECTORY;
    if (file->device) return file->device;
    if (file->serial) return FILE_SERIAL;
    if (namespace_node(file->proc_node)) return FILE_NAMESPACE;
    if (file->proc_node >= PROC_ROOT) return FILE_PROC_DIR;
    if (file->proc_node) return FILE_PROC_MAP;
    if (file->pipe) return FILE_PIPE;
    return file->socket ? FILE_SOCKET : FILE_REGULAR;
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

static void epoll_remove(struct file_handle *epoll, struct epoll_watch **link) {
    struct epoll_watch *watch = *link;
    *link = watch->next;
    if (epoll->epoll_next == watch) epoll->epoll_next = watch->next;
    --watch->target->watched_by;
    pmm64_free((uptr)watch - (uptr)pmm64_pointer(0));
}

static void epoll_remove_target(struct file_handle *target) {
    /* Регистрация не удерживает файл. Убираем все ссылки до повторного использования слота. */
    for (unsigned i = 0; i < OPEN_FILE_COUNT && target->watched_by; ++i) {
        struct file_handle *epoll = &open_files[i];
        for (struct epoll_watch **link = &epoll->watches; *link;) {
            if ((*link)->target == target) epoll_remove(epoll, link);
            else link = &(*link)->next;
        }
    }
}

static void release_file(struct file_handle *file) {
    if (!file || --file->references) return;
    epoll_remove_target(file);
    while (file->watches) epoll_remove(file, &file->watches);
    if (file->socket) linux64_socket_close(file->socket);
    if (file->pipe) linux64_pipe_close(file->pipe, (file->flags & O_ACCMODE) == O_WRONLY);
    linux64_userns_release(file->proc_ns);
    linux64_pidns_release(file->proc_pid_ns);
    if (file->directory_path) pmm64_free(file->directory_path);
    struct memfd *memfd = file->memfd;
    if (memfd && !--memfd->handles) {
        memfd_trim(memfd, 0, memfd_page_count(memfd->size));
        memfd->size = 0;
    }
    *file = (struct file_handle){0};
}

static void close_slot(struct linux64_fd_slot *slot) {
    release_file(slot->file);
    *slot = (struct linux64_fd_slot){0};
}

void linux64_pipe_finish(struct linux64_task *task) {
    release_file(task->pipe_io.file);
    task->pipe_io.file = NULL;
}

void linux64_socket_wait_finish(struct linux64_task *task) {
    release_file(task->socket_wait.file);
    task->socket_wait.file = NULL;
}

void linux64_eventfd_wait_finish(struct linux64_task *task) {
    release_file(task->eventfd_wait.file);
    task->eventfd_wait.file = NULL;
}

void linux64_epoll_wait_finish(struct linux64_task *task) {
    release_file(task->epoll_wait.file);
    task->epoll_wait.file = NULL;
}

static bool epoll_expired(const struct linux64_epoll_wait *wait) {
    u64 now;
    return wait->deadline && linux64_monotonic_ns(&now) && now >= wait->deadline;
}

bool linux64_epoll_wait_ready(const struct linux64_epoll_wait *wait) {
    return epoll_ready(wait->file) || epoll_expired(wait);
}

static long epoll_deliver(const struct linux64_epoll_wait *wait) {
    struct file_handle *epoll = wait->file;
    struct epoll_watch *first = epoll->epoll_next ? epoll->epoll_next : epoll->watches;
    if (!first) return 0;
    struct epoll_watch *watch = first;
    unsigned copied = 0;
    do {
        u16 ready = epoll_watch_ready(watch);
        if (ready) {
            const struct epoll_event event = {.events = ready, .data = watch->event.data};
            if (paging64_copy_to_user(wait->address + copied * sizeof(event), &event, sizeof(event)) !=
                sizeof(event)) return copied ? (long)copied : -EFAULT;
            epoll->epoll_next = watch->next ? watch->next : epoll->watches;
            if (watch->event.events & EPOLL_ONESHOT) watch->armed = false;
            if (++copied == wait->maxevents) break;
        }
        watch = watch->next ? watch->next : epoll->watches;
    } while (watch != first);
    return copied;
}

long linux64_epoll_resume(void) {
    const struct linux64_epoll_wait *wait = &linux64_current->epoll_wait;
    long result = epoll_deliver(wait);
    if (!result && !epoll_expired(wait)) linux64_current->state = TASK_EPOLL_WAIT;
    return result;
}

bool linux64_eventfd_ready(const struct linux64_eventfd_wait *wait) {
    u64 count = wait->file->event_count;
    return wait->write ? wait->value <= EVENTFD_MAX - count : count != 0;
}

static long eventfd_attempt(const struct linux64_eventfd_wait *wait) {
    if (!linux64_eventfd_ready(wait)) return -EAGAIN;
    struct file_handle *file = wait->file;
    if (wait->write) {
        file->event_count += wait->value;
    } else {
        u64 value = file->event_semaphore ? 1 : file->event_count;
        file->event_count -= value;
        /* Linux уменьшает счётчик до копирования в буфер пользователя. */
        if (paging64_copy_to_user(wait->address, &value, sizeof(value)) != sizeof(value))
            return -EFAULT;
    }
    return sizeof(u64);
}

long linux64_eventfd_resume(void) {
    long result = eventfd_attempt(&linux64_current->eventfd_wait);
    if (result == -EAGAIN) linux64_current->state = TASK_EVENTFD_WAIT;
    return result;
}

static long eventfd_io(struct file_handle *file, bool write, uptr address, uptr length) {
    if (length < sizeof(u64) || (write && length != sizeof(u64))) return -EINVAL;
    struct linux64_eventfd_wait wait = {.file = file, .address = address, .write = write};
    if (write) {
        if (paging64_copy_from_user(&wait.value, address, sizeof(wait.value)) != sizeof(wait.value))
            return -EFAULT;
        if (wait.value > EVENTFD_MAX) return -EINVAL;
    }
    long result = eventfd_attempt(&wait);
    if (result == -EAGAIN && !(file->flags & O_NONBLOCK)) {
        ++file->references;
        linux64_current->eventfd_wait = wait;
        linux64_current->state = TASK_EVENTFD_WAIT;
    }
    return result;
}

static long pipe_io(struct file_handle *file, bool write, uptr address, uptr length) {
    long result = linux64_pipe_io(file->pipe, write, (file->flags & O_NONBLOCK) != 0,
                                  address, length);
    if (linux64_current->state == TASK_PIPE_WAIT) {
        ++file->references;
        linux64_current->pipe_io.file = file;
    }
    return result;
}

static void close_file(i32 fd) {
    close_slot(&linux64_current->process->fds[fd]);
}

void linux64_close_files(struct linux64_process *process) {
    for (unsigned fd = 0; fd < FD_COUNT; ++fd) close_slot(&process->fds[fd]);
}

void linux64_close_on_exec(struct linux64_process *process) {
    for (unsigned fd = 0; fd < FD_COUNT; ++fd)
        if (process->fds[fd].cloexec) close_slot(&process->fds[fd]);
}

void linux64_retain_files(struct linux64_process *process) {
    for (unsigned fd = 0; fd < FD_COUNT; ++fd)
        if (process->fds[fd].file) ++process->fds[fd].file->references;
}

void linux64_use_files(const struct linux64_file_source *source, const char *path, uptr path_length) {
    files = source ? *source : (struct linux64_file_source){0};
    struct linux64_process *process = linux64_current->process;
    process->executable_path_length = path_length;
    for (uptr i = 0; i <= path_length; ++i) process->executable_path[i] = path[i];
    /* При первой загрузке таблица и пул открытых файлов ещё пусты. */
    open_files[0] = (struct file_handle){.file = null_file, .device = FILE_NULL, .references = 1};
    for (unsigned fd = 1; fd <= 2; ++fd)
        open_files[fd] = (struct file_handle){
            .file.inode = 1, .serial = true, .flags = O_WRONLY, .references = 1,
        };
    for (unsigned fd = 0; fd <= 2; ++fd) process->fds[fd].file = &open_files[fd];
}

const struct linux64_file_source *linux64_file_source(void) {
    return &files;
}

static bool open_file(i32 fd) {
    return fd >= 0 && fd < FD_COUNT && file_at(fd);
}

long linux64_get_file(i32 fd, struct linux64_fd_view *view) {
    if (!open_file(fd)) return -EBADF;
    if (kind_of(file_at(fd)) != FILE_REGULAR) return -ENODEV;
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

static long proc_fd_table(i32 owner, const struct linux64_process **process) {
    const struct linux64_process *target = linux64_process_by_pid(owner);
    if (!target || !target->threads) return -ENOENT;
    if (target->userns != linux64_current->process->userns) return -EACCES;
    *process = target;
    return 0;
}

long linux64_proc_fd_entry(i32 owner, const char *name, uptr length, struct linux64_file *file) {
    if (!length || (length > 1 && name[0] == '0')) return -ENOENT;
    unsigned number = 0;
    for (uptr i = 0; i < length; ++i) {
        if (name[i] < '0' || name[i] > '9') return -ENOENT;
        number = number * 10 + (unsigned)(name[i] - '0');
        if (number >= FD_COUNT) return -ENOENT;
    }
    const struct linux64_process *process;
    long result = proc_fd_table(owner, &process);
    if (result) return result;
    const struct file_handle *target = process->fds[number].file;
    if (!target) return -ENOENT;
    enum file_kind kind = kind_of(target);
    *file = (struct linux64_file){
        .mode = LINUX64_S_IFLNK | 0777, .inode = process->proc_fd_inode + 1 + number,
        .proc_fd_owner = owner, .proc_fd_number = (i32)number,
        .proc_fd_directory = kind == FILE_DIRECTORY || kind == FILE_PROC_DIR,
    };
    return 0;
}

static long directory_base(i32 dirfd, const char *path, struct linux64_directory *base) {
    *base = linux64_current->process->fs->cwd;
    if (*path == '/' || dirfd == AT_FDCWD) return 0;
    if (!open_file(dirfd)) return -EBADF;
    const struct file_handle *handle = file_at(dirfd);
    if (handle->proc_node == PROC_ROOT) {
        *base = (struct linux64_directory){
            .path = "/proc", .file = {.mode = LINUX64_S_IFDIR | 0555, .inode = PROC_ROOT},
        };
        return 0;
    }
    if (handle->proc_node == PROC_FDS) {
        *base = (struct linux64_directory){.path = "/proc/self/fd", .file = handle->file};
        return 0;
    }
    if (!handle->directory_path) return -ENOTDIR;
    *base = (struct linux64_directory){
        .path = pmm64_pointer(handle->directory_path), .file = handle->file,
    };
    return 0;
}

static const char *path_tail(const char *actual, const char *expected) {
    while (*expected && *actual == *expected) { ++actual; ++expected; }
    return *expected ? NULL : actual;
}

static bool path_equal(const char *actual, const char *expected, bool directory) {
    actual = path_tail(actual, expected);
    if (!actual) return false;
    if (directory) while (*actual == '/') ++actual;
    return !*actual;
}

static enum file_kind device_node(const char *path, struct linux64_file *file) {
    if (path_equal(path, "/dev/null", false)) {
        *file = null_file;
        return FILE_NULL;
    }
    if (path_equal(path, "/dev/urandom", false)) {
        *file = urandom_file;
        return FILE_URANDOM;
    }
    return FILE_REGULAR;
}

static enum linux64_proc_node proc_path(const char *path) {
    if (*path == '/') {
        if (path_equal(path, "/proc", true)) return PROC_ROOT;
        const char *prefix = "/proc/";
        while (*prefix && *path == *prefix) { ++path; ++prefix; }
        if (*prefix) return USERNS_NONE;
    }
    if (path_equal(path, "self/task", true)) return PROC_TASKS;
    if (path_equal(path, "self/fd", true)) return PROC_FDS;
    if (path_equal(path, "self/uid_map", false)) return USERNS_UID_MAP;
    if (path_equal(path, "self/gid_map", false)) return USERNS_GID_MAP;
    if (path_equal(path, "self/setgroups", false)) return USERNS_SETGROUPS;
    if (path_equal(path, "self/ns/user", false)) return PROC_USER_NS;
    if (path_equal(path, "self/ns/pid", false)) return PROC_PID_NS;
    if (path_equal(path, "self/exe", false)) return PROC_EXE;
    return USERNS_NONE;
}

bool linux64_special_node(const char *path, struct linux64_file *file) {
    if (device_node(path, file)) return true;
    if (path_equal(path, "/proc/self/fdinfo", false)) {
        struct linux64_process *process = linux64_current->process;
        if (!process->fdinfo_inode) process->fdinfo_inode = next_fdinfo_inode++;
        *file = (struct linux64_file){
            .mode = LINUX64_S_IFDIR | 0555, .inode = process->fdinfo_inode, .private_directory = true,
        };
        return true;
    }
    enum linux64_proc_node proc = proc_path(path);
    if (proc == PROC_EXE) {
        const char *exe = linux64_current->process->executable_path;
        return files.lookup && files.lookup(files.context, exe, file);
    }
    if (proc == PROC_FDS) {
        struct linux64_process *process = linux64_current->process;
        if (!process->proc_fd_inode) {
            process->proc_fd_inode = next_proc_fd_inode;
            next_proc_fd_inode += FD_COUNT + 1;
        }
        *file = (struct linux64_file){
            .mode = LINUX64_S_IFDIR | 0555, .inode = process->proc_fd_inode,
            .proc_fd_owner = process->pid, .proc_fd_number = -1,
        };
        return true;
    }
    if (proc) {
        *file = (struct linux64_file){
            .mode = proc >= PROC_ROOT ? LINUX64_S_IFDIR | 0555 : 0, .inode = proc,
        };
        return true;
    }
    static const char *const dirs[] = {"/dev", "/proc/self", "/proc/self/ns"};
    for (unsigned i = 0; i < sizeof(dirs) / sizeof(*dirs); ++i) {
        if (!path_equal(path, dirs[i], false)) continue;
        *file = (struct linux64_file){.mode = LINUX64_S_IFDIR | 0555, .inode = (1ull << 31) + i};
        return true;
    }
    return false;
}

static unsigned free_fd(unsigned fd) {
    while (fd < FD_COUNT && file_at(fd)) ++fd;
    return fd;
}

static long copy_fd(i32 source, unsigned target, bool cloexec) {
    struct file_handle *file = file_at(source);
    struct linux64_fd_slot *slot = &linux64_current->process->fds[target];
    ++file->references;
    close_slot(slot);
    *slot = (struct linux64_fd_slot){file, cloexec};
    return target;
}

static long dup_fd(i32 source, u32 minimum, bool cloexec) {
    if (!open_file(source)) return -EBADF;
    if (minimum >= FD_COUNT) return -EINVAL;
    unsigned target = free_fd(minimum);
    return target == FD_COUNT ? -EMFILE : copy_fd(source, target, cloexec);
}

static long dup_to(i32 source, i32 target, bool cloexec) {
    if (!open_file(source) || target < 0 || target >= FD_COUNT) return -EBADF;
    return source == target ? target : copy_fd(source, (unsigned)target, cloexec);
}

static long new_handle(const struct linux64_file *file, struct memfd *memfd, u32 flags) {
    unsigned fd = free_fd(0);
    if (fd == FD_COUNT) return -EMFILE;
    for (unsigned i = 0; i < OPEN_FILE_COUNT; ++i) {
        struct file_handle *description = &open_files[i];
        if (description->references) continue;
        *description = (struct file_handle){.memfd = memfd, .flags = flags & ~O_CLOEXEC,
                                            .references = 1};
        if (file) description->file = *file;
        if (memfd) ++memfd->handles;
        linux64_current->process->fds[fd] = (struct linux64_fd_slot){description, (flags & O_CLOEXEC) != 0};
        return fd;
    }
    return -EMFILE;
}

static bool copy_fd_pair(uptr address, i32 left, i32 right) {
    return paging64_put_user_u64(address, (u32)left | ((u64)(u32)right << 32));
}

static long linux_eventfd(u32 initial, u32 flags) {
    if (flags & ~(EFD_SEMAPHORE | O_NONBLOCK | O_CLOEXEC)) return -EINVAL;
    long fd = new_handle(NULL, NULL, (flags & (O_NONBLOCK | O_CLOEXEC)) | O_RDWR);
    if (fd < 0) return fd;
    struct file_handle *file = file_at((i32)fd);
    file->device = FILE_EVENTFD;
    file->event_count = initial;
    file->event_semaphore = (flags & EFD_SEMAPHORE) != 0;
    file->file.inode = next_special_inode++;
    return fd;
}

static long linux_epoll_create(u32 flags) {
    if (flags & ~O_CLOEXEC) return -EINVAL;
    long fd = new_handle(NULL, NULL, O_RDWR | flags);
    if (fd < 0) return fd;
    struct file_handle *file = file_at((i32)fd);
    file->device = FILE_EPOLL;
    file->file.inode = next_special_inode++;
    return fd;
}

static long linux_epoll_ctl(i32 fd, i32 operation, i32 target_fd, uptr address) {
    struct epoll_event event;
    if ((operation == EPOLL_ADD || operation == EPOLL_MOD) &&
        paging64_copy_from_user(&event, address, sizeof(event)) != sizeof(event)) return -EFAULT;
    if (!open_file(fd) || !open_file(target_fd)) return -EBADF;
    struct file_handle *epoll = file_at(fd), *target = file_at(target_fd);
    if (!target->pipe && !target->socket && !target->serial &&
        target->device != FILE_EVENTFD && target->device != FILE_EPOLL)
        return -EPERM;
    if (epoll->device != FILE_EPOLL || epoll == target) return -EINVAL;
    if (target->device == FILE_EPOLL) return -EOPNOTSUPP;
    if (operation != EPOLL_ADD && operation != EPOLL_MOD && operation != EPOLL_DEL) return -EINVAL;
    if (operation != EPOLL_DEL && (event.events & (EPOLL_ET | EPOLL_EXCLUSIVE))) return -EOPNOTSUPP;
    struct epoll_watch **link = &epoll->watches;
    while (*link && ((*link)->fd != target_fd || (*link)->target != target)) link = &(*link)->next;
    if (operation == EPOLL_ADD) {
        if (*link) return -EEXIST;
        uptr page = pmm64_alloc();
        if (!page) return -ENOMEM;
        *link = pmm64_pointer(page);
        **link = (struct epoll_watch){.target = target, .fd = target_fd};
        ++target->watched_by;
    } else if (!*link) return -ENOENT;
    if (operation == EPOLL_DEL) epoll_remove(epoll, link);
    else {
        (*link)->event = event;
        (*link)->event.events &= ~EPOLL_WAKEUP;
        (*link)->armed = true;
    }
    return 0;
}

static long linux_epoll_wait(i32 fd, uptr address, i32 maxevents, i32 timeout) {
    if (maxevents <= 0 || (unsigned)maxevents > ((1u << 31) - 1) / sizeof(struct epoll_event))
        return -EINVAL;
    if (address >= X64_USER_TOP || (uptr)maxevents * sizeof(struct epoll_event) > X64_USER_TOP - address)
        return -EFAULT;
    if (!open_file(fd)) return -EBADF;
    struct file_handle *file = file_at(fd);
    if (file->device != FILE_EPOLL) return -EINVAL;
    struct linux64_epoll_wait wait = {.file = file, .address = address, .maxevents = (u32)maxevents};
    if (timeout > 0) {
        u64 now;
        if (!linux64_monotonic_ns(&now)) return -EIO;
        wait.deadline = now + (u64)timeout * 1000000;
    }
    long result = epoll_deliver(&wait);
    if (result || !timeout || epoll_expired(&wait)) return result;
    ++file->references;
    linux64_current->epoll_wait = wait;
    linux64_current->state = TASK_EPOLL_WAIT;
    return 0;
}

static long linux_pipe2(uptr address, u32 flags) {
    if (flags & ~(O_CLOEXEC | O_NONBLOCK)) return -EINVAL;
    long read_fd = new_handle(NULL, NULL, flags);
    if (read_fd < 0) return read_fd;
    long write_fd = new_handle(NULL, NULL, flags | O_WRONLY);
    if (write_fd < 0) {
        close_file((i32)read_fd);
        return write_fd;
    }
    struct linux64_pipe *pipe = linux64_pipe_create();
    if (pipe) {
        struct file_handle *reader = file_at((i32)read_fd), *writer = file_at((i32)write_fd);
        reader->pipe = writer->pipe = pipe;
        reader->file.inode = writer->file.inode = next_special_inode++;
        if (copy_fd_pair(address, (i32)read_fd, (i32)write_fd)) return 0;
    }
    close_file((i32)read_fd);
    close_file((i32)write_fd);
    return pipe ? -EFAULT : -ENOMEM;
}

static long new_socket_handle(struct linux64_socket *socket, u32 type) {
    long fd = new_handle(NULL, NULL, O_RDWR | (type & (O_CLOEXEC | O_NONBLOCK)));
    if (fd < 0) return fd;
    file_at(fd)->socket = socket;
    file_at(fd)->file.inode = next_special_inode++;
    return fd;
}

static long linux_socket(i32 domain, u32 type, i32 protocol) {
    struct linux64_socket *socket;
    long error = linux64_socket_create(domain, type, protocol, &socket);
    if (error) return error;
    long fd = new_socket_handle(socket, type);
    if (fd < 0) linux64_socket_close(socket);
    return fd;
}

static long linux_socketpair(i32 domain, u32 type, i32 protocol, uptr address) {
    struct linux64_socket *ends[2];
    long error = linux64_socket_pair(domain, type, protocol, ends);
    if (error) return error;
    i32 fds[2];
    for (unsigned i = 0; i < 2; ++i) {
        long fd = new_socket_handle(ends[i], type);
        if (fd < 0) {
            if (i) close_file(fds[0]);
            else linux64_socket_close(ends[0]);
            linux64_socket_close(ends[1]);
            return fd;
        }
        fds[i] = (i32)fd;
    }
    if (copy_fd_pair(address, fds[0], fds[1])) return 0;
    close_file(fds[0]);
    close_file(fds[1]);
    return -EFAULT;
}

static long socket_write(struct linux64_socket_wait *wait) {
    if (!linux64_socket_is_stream(wait->file->socket))
        return linux64_socket_io(wait->file->socket, false, wait->address, wait->length);
    while (wait->blocking) {
        long result = linux64_socket_io(wait->file->socket, false,
                                       wait->address + wait->transferred, wait->length - wait->transferred);
        if (result == -EAGAIN) return result;
        if (result <= 0) return wait->transferred ? (long)wait->transferred : result;
        wait->transferred += (uptr)result;
        if (wait->transferred == wait->length) return (long)wait->transferred;
    }
    return linux64_socket_io(wait->file->socket, false, wait->address, wait->length);
}

static long socket_attempt(struct linux64_socket_wait *wait) {
    struct linux64_socket *socket = wait->file->socket;
    switch (wait->operation) {
    case SOCKET_CONNECT: {
        struct linux64_file node;
        long result = linux64_vfs_walk(NULL, wait->path, &node, NULL, true);
        if (result) return result;
        if ((node.mode & LINUX64_S_IFMT) != LINUX64_S_IFSOCK) return -ECONNREFUSED;
        if (!(linux64_file_permissions(&node) & 2u)) return -EACCES;
        wait->inode = node.inode;
        return linux64_socket_connect(socket, wait->inode);
    }
    case SOCKET_ACCEPT: {
        if (free_fd(0) == FD_COUNT) return -EMFILE;
        struct linux64_socket *accepted;
        long result = linux64_socket_pending(socket, wait->blocking, &accepted);
        if (result) return result;
        long fd = new_socket_handle(accepted, wait->flags);
        if (fd < 0) return fd;
        linux64_socket_dequeue(socket);
        if (wait->address) {
            result = linux64_socket_name(accepted, true, wait->address, wait->length);
            if (result) {
                close_file((i32)fd);
                return result;
            }
        }
        return fd;
    }
    case SOCKET_READ:
        return linux64_socket_io(socket, true, wait->address, wait->length);
    case SOCKET_WRITE:
        return socket_write(wait);
    case SOCKET_SENDMSG:
    case SOCKET_RECVMSG:
        return linux64_socket_message(socket, wait->operation == SOCKET_RECVMSG, wait->address, wait->flags);
    }
    return -EINVAL;
}

static long socket_run(struct linux64_socket_wait wait) {
    bool per_call = wait.operation == SOCKET_WRITE || wait.operation == SOCKET_SENDMSG ||
                    wait.operation == SOCKET_RECVMSG;
    wait.blocking = !(wait.file->flags & O_NONBLOCK) && !(per_call && (wait.flags & MSG_DONTWAIT));
    long result = socket_attempt(&wait);
    if (result == -EAGAIN && wait.blocking) {
        ++wait.file->references;
        linux64_current->socket_wait = wait;
        linux64_current->state = TASK_SOCKET_WAIT;
    }
    return result;
}

long linux64_sendto(i32 fd, uptr buffer, uptr length, u32 flags, uptr address, i32 address_length) {
    if (buffer >= X64_USER_TOP || length > X64_USER_TOP - buffer) return -EFAULT;
    if (!open_file(fd)) return -EBADF;
    struct file_handle *file = file_at(fd);
    if (!file->socket) return -ENOTSOCK;
    long result = linux64_socket_check_sendto(file->socket, flags, address, address_length);
    if (result) return result;
    return socket_run((struct linux64_socket_wait){.file = file, .operation = SOCKET_WRITE,
                                                   .address = buffer, .length = length, .flags = flags});
}

bool linux64_socket_wait_ready(const struct linux64_task *task) {
    const struct linux64_socket_wait *wait = &task->socket_wait;
    const struct linux64_socket *socket = wait->file->socket;
    if (wait->operation == SOCKET_CONNECT) return linux64_socket_connect_ready(socket, wait->inode);
    if (wait->operation == SOCKET_ACCEPT) return linux64_socket_accept_ready(socket);
    return linux64_socket_io_ready(socket, wait->operation == SOCKET_READ || wait->operation == SOCKET_RECVMSG);
}

long linux64_socket_wait_resume(void) {
    long result = socket_attempt(&linux64_current->socket_wait);
    if (result == -EAGAIN) linux64_current->state = TASK_SOCKET_WAIT;
    return result;
}

static long socket_path(struct file_handle *file, bool bind, uptr address, u32 length) {
    struct linux64_sockaddr name = {0};
    if (length <= 2 || length > 2 + sizeof(name.path) - 1) return -EINVAL;
    if (paging64_copy_from_user(&name, address, length) != length) return -EFAULT;
    if (name.family != AF_UNIX) return -EINVAL;
    if (!name.path[0]) return -EOPNOTSUPP;
    if (bind) {
        if (!linux64_socket_can_bind(file->socket)) return -EINVAL;
        u64 inode;
        u32 mode = 0777u & ~linux64_current->process->fs->umask;
        long result = linux64_vfs_socket(NULL, name.path, mode, &inode);
        if (result) return result == -EEXIST ? -EADDRINUSE : result;
        linux64_socket_bind(file->socket, inode, name.path);
        return 0;
    }
    struct linux64_socket_wait wait = {.file = file, .operation = SOCKET_CONNECT};
    for (unsigned i = 0; (wait.path[i] = name.path[i]); ++i) {}
    return socket_run(wait);
}

long linux64_sockopt(bool get, i32 fd, i32 level, i32 option, uptr value, uptr length) {
    if (!open_file(fd)) return -EBADF;
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
    if (command == F_DUPFD || command == F_DUPFD_CLOEXEC)
        return dup_fd(fd, value, command == F_DUPFD_CLOEXEC);
    struct memfd *memfd = file_at(fd)->memfd;
    if (command == F_GETFD) return linux64_current->process->fds[fd].cloexec;
    if (command == F_SETFD) {
        linux64_current->process->fds[fd].cloexec = (value & 1) != 0;
        return 0;
    }
    if (command == F_GETFL) return file_at(fd)->flags;
    if (command == F_SETFL && (file_at(fd)->socket || file_at(fd)->device == FILE_EVENTFD)) {
        if (value & O_DIRECT) return -EINVAL;
        const u32 mask = O_APPEND | O_NONBLOCK;
        file_at(fd)->flags = (file_at(fd)->flags & ~mask) | (value & mask);
        return 0;
    }
    if (command == F_SETFL && file_at(fd)->pipe) {
        if (value & O_DIRECT) return -EINVAL;
        file_at(fd)->flags = (file_at(fd)->flags & ~O_NONBLOCK) | (value & O_NONBLOCK);
        return 0;
    }
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

static void handle_stat(const struct file_handle *handle, struct linux64_file *file,
                        const struct memfd **memfd) {
    *memfd = handle->memfd;
    *file = handle->file;
    if (*memfd) {
        file->size = (*memfd)->size;
        file->inode = (*memfd)->inode;
    }
}

static long lookup(i32 dirfd, uptr address, u32 flags, struct linux64_file *file,
                   const struct memfd **memfd, enum file_kind *kind) {
    char path[LINUX64_PATH_LIMIT];
    path[0] = 0;
    if (address || !(flags & AT_EMPTY_PATH)) {
        long result = user_path(address, path);
        if (result) return result;
    }
    if (!path[0]) {
        if (!(flags & AT_EMPTY_PATH) || dirfd == AT_FDCWD) return -ENOENT;
        if (!open_file(dirfd)) return -EBADF;
        handle_stat(file_at(dirfd), file, memfd);
        *kind = kind_of(file_at(dirfd));
        return 0;
    }
    struct linux64_directory base;
    long result = directory_base(dirfd, path, &base);
    if (result) return result;
    result = linux64_vfs_walk(&base, path, file, path, !(flags & AT_SYMLINK_NOFOLLOW));
    if (result) return result;
    const char *absolute = path;
    *memfd = NULL;
    if (file->proc_fd_owner && file->proc_fd_number >= 0) {
        if ((flags & AT_SYMLINK_NOFOLLOW) && (file->mode & LINUX64_S_IFMT) == LINUX64_S_IFLNK) {
            *kind = FILE_PROC_LINK;
            return 0;
        }
        const struct linux64_process *process;
        result = proc_fd_table(file->proc_fd_owner, &process);
        if (result) return result;
        const struct file_handle *target = process->fds[file->proc_fd_number].file;
        if (!target) return -ENOENT;
        handle_stat(target, file, memfd);
        *kind = kind_of(target);
        return 0;
    }
    *kind = device_node(absolute, file);
    if (*kind) return 0;
    enum linux64_proc_node proc = proc_path(absolute);
    if ((namespace_node(proc) || proc == PROC_EXE) && (flags & AT_SYMLINK_NOFOLLOW)) {
        struct linux64_process *process = linux64_current->process;
        u64 inode = 2 * (u64)(u32)process->pid + (proc == PROC_EXE);
        if (proc == PROC_PID_NS) {
            if (!process->pid_ns_link_inode) process->pid_ns_link_inode = next_pid_ns_link_inode++;
            inode = process->pid_ns_link_inode;
        }
        *file = (struct linux64_file){.inode = inode};
        *kind = FILE_PROC_LINK;
        return 0;
    }
    if (namespace_node(proc)) {
        const struct linux64_process *process = linux64_current->process;
        *file = (struct linux64_file){
            .inode = proc == PROC_PID_NS ? linux64_pidns_inode(process->pid_ns) :
                                         linux64_userns_inode(process->userns),
        };
        *kind = FILE_NAMESPACE;
        return 0;
    }
    if (proc == PROC_EXE) {
        *kind = FILE_REGULAR;
        return 0;
    }
    if (proc) {
        if (proc != PROC_FDS) *file = (struct linux64_file){.inode = proc};
        *kind = proc >= PROC_ROOT ? FILE_PROC_DIR : FILE_PROC_MAP;
        return 0;
    }
    u32 type = file->mode & LINUX64_S_IFMT;
    *kind = type == LINUX64_S_IFDIR ? FILE_DIRECTORY :
            type == LINUX64_S_IFSOCK ? FILE_NAMED_SOCKET :
            type == LINUX64_S_IFLNK ? FILE_SYMLINK : FILE_REGULAR;
    return 0;
}

static long linux_readlink(i32 dirfd, uptr path_address, uptr destination, i32 size) {
    if (size <= 0) return -EINVAL;
    char path[LINUX64_PATH_LIMIT];
    long result = user_path(path_address, path);
    if (result) return result;
    if (!path[0]) return dirfd != AT_FDCWD && !open_file(dirfd) ? -EBADF : -ENOENT;
    struct linux64_directory base;
    result = directory_base(dirfd, path, &base);
    if (result) return result;
    struct linux64_file file;
    result = linux64_vfs_walk(&base, path, &file, path, false);
    if (result) return result;
    if (file.proc_fd_owner && file.proc_fd_number >= 0) return -EOPNOTSUPP;
    enum linux64_proc_node proc = proc_path(path);
    if (proc == PROC_USER_NS)
        return linux64_userns_readlink(linux64_current->process->userns, destination, (uptr)size);
    if (proc == PROC_PID_NS)
        return linux64_pidns_readlink(linux64_current->process->pid_ns, destination, (uptr)size);
    const u8 *target = file.bytes;
    uptr length = file.size;
    if (proc == PROC_EXE) {
        target = (const u8 *)linux64_current->process->executable_path;
        length = linux64_current->process->executable_path_length;
    } else if ((file.mode & LINUX64_S_IFMT) != LINUX64_S_IFLNK) return -EINVAL;
    if (!length) return -ENOENT;
    if (length > (uptr)size) length = (uptr)size;
    return paging64_copy_to_user(destination, target, length) == length ? (long)length : -EFAULT;
}

static long linux_open(i32 dirfd, uptr address, u32 flags) {
    if ((flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    char path[LINUX64_PATH_LIMIT];
    long result = user_path(address, path);
    if (result) return result;
    if (!path[0]) return -ENOENT;
    struct linux64_directory base;
    result = directory_base(dirfd, path, &base);
    if (result) return result;
    struct linux64_file file;
    bool exclusive = (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
    result = linux64_vfs_walk(&base, path, &file, path, !(flags & O_NOFOLLOW) && !exclusive);
    if (result) {
        if (result == -ENOENT && (flags & (O_ACCMODE | O_CREAT | O_TRUNC))) return -EROFS;
        return result;
    }
    const char *absolute = path;
    u32 type = file.mode & LINUX64_S_IFMT;
    if (file.proc_fd_owner && file.proc_fd_number >= 0) {
        if (exclusive) return -EEXIST;
        if (flags & O_NOFOLLOW) return -ELOOP;
        if (file.proc_fd_owner != linux64_current->process->pid) return -EACCES;
        const struct file_handle *target = file_at(file.proc_fd_number);
        if ((flags & O_DIRECTORY) && !file.proc_fd_directory) return -ENOTDIR;
        if (!target->memfd) return -ENOSYS;
        if (flags & ~(O_CLOEXEC | O_LARGEFILE | O_NONBLOCK)) return -EINVAL;
        return new_handle(NULL, target->memfd, flags | O_LARGEFILE);
    }
    if (type == LINUX64_S_IFLNK) {
        if (flags & O_DIRECTORY) return -ENOTDIR;
        return exclusive ? -EEXIST : -ELOOP;
    }
    if (type == LINUX64_S_IFSOCK) {
        if (flags & O_DIRECTORY) return -ENOTDIR;
        return exclusive ? -EEXIST : -ENXIO;
    }
    enum file_kind device = device_node(absolute, &file);
    if (device) {
        if (flags & O_DIRECTORY) return -ENOTDIR;
        if (exclusive) return -EEXIST;
        if (flags & ~(O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND |
                      O_NONBLOCK | O_LARGEFILE | O_NOFOLLOW | O_CLOEXEC)) return -EINVAL;
        u32 status = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
        result = new_handle(&file, NULL, status | O_LARGEFILE);
        if (result >= 0) file_at((i32)result)->device = device;
        return result;
    }
    enum linux64_proc_node proc = proc_path(absolute);
    if (proc == PROC_EXE && (flags & O_NOFOLLOW)) return -ELOOP;
    if (namespace_node(proc)) {
        if (flags & O_DIRECTORY) return -ENOTDIR;
        if (flags & O_NOFOLLOW) return -ELOOP;
        if (flags & (O_ACCMODE | O_TRUNC)) return -EPERM;
        if (flags & ~(O_CLOEXEC | O_LARGEFILE | O_NONBLOCK | O_NOCTTY)) return -EINVAL;
        struct linux64_process *process = linux64_current->process;
        const struct linux64_file file = {
            .inode = proc == PROC_PID_NS ? linux64_pidns_inode(process->pid_ns) :
                                         linux64_userns_inode(process->userns),
        };
        result = new_handle(&file, NULL, (flags & ~O_NOCTTY) | O_LARGEFILE);
        if (result < 0) return result;
        struct file_handle *handle = file_at((i32)result);
        handle->proc_node = proc;
        if (proc == PROC_PID_NS) {
            handle->proc_pid_ns = process->pid_ns;
            linux64_pidns_retain(handle->proc_pid_ns);
        } else {
            handle->proc_ns = process->userns;
            linux64_userns_retain(handle->proc_ns);
        }
        return result;
    }
    if (proc && proc != PROC_EXE) {
        if (flags & ~(O_ACCMODE | O_DIRECTORY | O_CLOEXEC | O_LARGEFILE | O_NONBLOCK |
                      O_NOFOLLOW | O_TRUNC)) return -EINVAL;
        bool directory = proc >= PROC_ROOT;
        if (proc == PROC_TASKS) return -ENOSYS;
        if (directory && (flags & O_ACCMODE)) return -EISDIR;
        if (!directory && (flags & O_DIRECTORY)) return -ENOTDIR;
        struct linux64_userns *ns = directory ? NULL : linux64_current->process->userns;
        bool admin = (linux64_current->caps.effective & LINUX64_CAP_SYS_ADMIN) != 0;
        if (proc == USERNS_SETGROUPS && (flags & O_ACCMODE) && !admin) return -EACCES;
        if (!directory && !ns && (flags & O_ACCMODE)) return -EPERM;
        if (proc == PROC_FDS && (flags & (O_CREAT | O_TRUNC))) return -EISDIR;
        if (proc == PROC_FDS) {
            const struct linux64_process *owner;
            result = proc_fd_table(file.proc_fd_owner, &owner);
            if (result) return result;
        }
        result = new_handle(proc == PROC_FDS ? &file : NULL, NULL,
                            proc == PROC_FDS ? flags | O_LARGEFILE : flags);
        if (result < 0) return result;
        struct file_handle *handle = file_at((i32)result);
        if (proc != PROC_FDS) handle->file.inode = proc;
        handle->proc_node = proc;
        handle->proc_ns = ns;
        handle->proc_admin = admin;
        linux64_userns_retain(ns);
        return result;
    }
    if (type == LINUX64_S_IFDIR) {
        if (flags & (O_ACCMODE | O_TRUNC)) return -EISDIR;
        if (flags & O_CREAT) return flags & O_EXCL ? -EEXIST : -EISDIR;
        if (flags & ~(O_NONBLOCK | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
            return -EINVAL;
        if (!(linux64_file_permissions(&file) & 4u)) return -EACCES;
        uptr physical = pmm64_alloc();
        if (!physical) return -ENOMEM;
        result = new_handle(&file, NULL, flags | O_LARGEFILE);
        if (result < 0) {
            pmm64_free(physical);
            return result;
        }
        char *directory = pmm64_pointer(physical);
        const char *cursor = path;
        while ((*directory++ = *cursor++)) {}
        file_at((i32)result)->directory_path = physical;
        return result;
    }
    if (flags & (O_ACCMODE | O_CREAT | O_TRUNC)) return -EROFS;
    if (flags & ~(O_NONBLOCK | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
        return -EINVAL;
    if (flags & O_DIRECTORY) return -ENOTDIR;
    return new_handle(&file, NULL, flags | O_LARGEFILE);
}

static long change_directory(uptr address, bool chroot) {
    char path[LINUX64_PATH_LIMIT];
    long result = user_path(address, path);
    if (result) return result;
    if (!path[0]) return -ENOENT;
    struct linux64_file file;
    result = linux64_vfs_walk(NULL, path, &file, path, true);
    if (result) return result;
    if (file.proc_fd_owner && file.proc_fd_number >= 0) return -EOPNOTSUPP;
    if ((file.mode & LINUX64_S_IFMT) != LINUX64_S_IFDIR) return -ENOTDIR;
    if (!(linux64_file_permissions(&file) & 1u)) return -EACCES;
    if (chroot && !(linux64_current->caps.effective & LINUX64_CAP_SYS_CHROOT)) return -EPERM;
    uptr page = pmm64_alloc();
    if (!page) return -ENOMEM;
    char *name = pmm64_pointer(page);
    for (uptr i = 0; (name[i] = path[i]); ++i) {}
    struct linux64_fs *fs = linux64_current->process->fs;
    struct linux64_directory *anchor = chroot ? &fs->root : &fs->cwd;
    if (anchor->page) pmm64_free(anchor->page);
    *anchor = (struct linux64_directory){.path = name, .page = page, .file = file};
    return 0;
}

static long linux_mkdir(i32 dirfd, uptr address, u32 mode) {
    char path[LINUX64_PATH_LIMIT];
    long result = user_path(address, path);
    if (result) return result;
    if (!path[0]) return -ENOENT;
    struct linux64_directory base;
    result = directory_base(dirfd, path, &base);
    if (result) return result;
    u32 mask = linux64_current->process->fs->umask;
    return linux64_vfs_mkdir(&base, path, LINUX64_S_IFDIR | (mode & 01777u & ~mask));
}

static long linux_symlink(i32 dirfd, uptr address, uptr target_address) {
    /* Строка сохраняется в узле только после разрешения родительского пути. */
    static char target[LINUX64_PATH_LIMIT];
    long length = linux64_user_string(target_address, target, sizeof(target));
    if (length <= 0) return length ? length : -ENOENT;
    char path[LINUX64_PATH_LIMIT];
    long result = user_path(address, path);
    if (result) return result;
    if (!path[0]) return -ENOENT;
    struct linux64_directory base;
    result = directory_base(dirfd, path, &base);
    return result ? result : linux64_vfs_symlink(&base, path, target, (uptr)length);
}

static long linux_unlink(i32 dirfd, uptr address, u32 flags) {
    if (flags & ~AT_REMOVEDIR) return -EINVAL;
    if (flags & AT_REMOVEDIR) return -ENOSYS;
    char path[LINUX64_PATH_LIMIT];
    long result = user_path(address, path);
    if (result) return result;
    if (!path[0]) return -ENOENT;
    struct linux64_directory base;
    result = directory_base(dirfd, path, &base);
    return result ? result : linux64_vfs_unlink(&base, path);
}

static long device_io(struct file_handle *file, bool write, uptr buffer, uptr count) {
    if ((file->flags & O_ACCMODE) == (write ? 0u : O_WRONLY)) return -EBADF;
    /* VFS проверяет диапазон даже у устройства, которое не обращается к буферу. */
    if (buffer >= X64_USER_TOP || count > X64_USER_TOP - buffer) return -EFAULT;
    if (file->device == FILE_EVENTFD) return eventfd_io(file, write, buffer, count);
    if (file->device == FILE_EPOLL) return -EINVAL;
    if (file->device == FILE_URANDOM) {
        /* Запись требует пула энтропии, которого у источника RDRAND нет. */
        return write ? -ENOSYS : linux64_getrandom(buffer, count, 0);
    }
    if (count > 0x7ffff000u) count = 0x7ffff000u;
    return write ? (long)count : 0;
}

static long serial_write(uptr address, uptr size) {
    if (size > 0x7ffff000u) size = 0x7ffff000u;
    uptr written = 0;
    while (written < size) {
        const u8 *bytes = paging64_user_read(address);
        if (!bytes) return written ? (long)written : -EFAULT;
        uptr chunk = PMM_PAGE_SIZE - (address & (PMM_PAGE_SIZE - 1));
        if (chunk > size - written) chunk = size - written;
        for (uptr i = 0; i < chunk; ++i) kernel64_serial_char((char)bytes[i]);
        written += chunk;
        address += chunk;
    }
    return (long)written;
}

static long linux_read(i32 fd, uptr buffer, uptr count, uptr offset, bool positioned) {
    if (!open_file(fd)) return -EBADF;
    struct file_handle *handle = file_at(fd);
    if (handle->directory_path) return -EISDIR;
    if (positioned && (handle->device == FILE_EVENTFD || handle->device == FILE_EPOLL)) return -ESPIPE;
    if (handle->device) return device_io(handle, false, buffer, count);
    if (handle->serial) return positioned ? -ESPIPE : -EBADF;
    if (handle->pipe) {
        if (positioned) return -ESPIPE;
        if ((handle->flags & O_ACCMODE) == O_WRONLY) return -EBADF;
        return pipe_io(handle, false, buffer, count);
    }
    if (handle->socket) {
        if (positioned) return -ESPIPE;
        return socket_run((struct linux64_socket_wait){.file = handle, .operation = SOCKET_READ,
                                                       .address = buffer, .length = count});
    }
    if (!positioned) offset = file_at(fd)->offset;
    if (handle->proc_node) {
        if (namespace_node(handle->proc_node)) return positioned ? -ESPIPE : -EINVAL;
        if (handle->proc_node >= PROC_ROOT) return -EISDIR;
        if ((handle->flags & O_ACCMODE) == O_WRONLY) return -EBADF;
        long copied = linux64_userns_read(handle->proc_ns, handle->proc_node, buffer, count, offset);
        if (!positioned && copied > 0) handle->offset += (uptr)copied;
        return copied;
    }
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

static long file_stat(const struct linux64_file *file, const struct memfd *memfd, enum file_kind kind,
                      uptr stat_address) {
    if (kind == FILE_PROC_DIR && file->proc_fd_owner) {
        const struct linux64_process *owner;
        long result = proc_fd_table(file->proc_fd_owner, &owner);
        if (result) return result;
    }
    u32 mode = 0100444, device = 1, links = !memfd;
    u64 rdev = 0;
    if (kind == FILE_SOCKET) {
        mode = 0140777;
        device = 3;
    } else if (kind == FILE_PIPE) {
        mode = 0010600;
        device = 4;
    } else if (kind == FILE_EVENTFD || kind == FILE_EPOLL) {
        mode = 0600;
        device = 10;
    } else if (kind == FILE_PROC_DIR) {
        mode = 0040555;
        links = 2 + (file->inode == PROC_TASKS ? linux64_current->process->threads : 0);
    } else if (kind == FILE_PROC_MAP) {
        mode = 0100644;
    } else if (kind == FILE_NULL || kind == FILE_URANDOM) {
        mode = 0020666;
        device = 5;
        rdev = kind == FILE_NULL ? 0x103 : 0x109;
    } else if (kind == FILE_SERIAL) {
        mode = 0020600;
        device = 6;
        rdev = 0x501;
    } else if (kind == FILE_NAMESPACE) {
        device = 7;
    } else if (kind == FILE_PROC_LINK) {
        mode = 0120777;
        device = 8;
    } else if (kind == FILE_DIRECTORY) {
        mode = file->mode;
        device = 9;
        links = 2;
    } else if (kind == FILE_SYMLINK || kind == FILE_NAMED_SOCKET) {
        mode = file->mode;
        device = 9;
    } else if (memfd) {
        mode = memfd->seals & F_SEAL_EXEC ? 0100666 : 0100777;
        device = 2;
    }
    const struct linux64_userns *ns = linux64_current->process->userns;
    bool owned = kind == FILE_SOCKET || kind == FILE_PIPE || kind == FILE_PROC_MAP ||
                 kind == FILE_PROC_LINK || memfd;
    bool named = kind == FILE_DIRECTORY || kind == FILE_SYMLINK || kind == FILE_NAMED_SOCKET;
    const struct linux_stat stat = {
        .dev = device, .ino = file->inode, .nlink = links, .mode = mode,
        .uid = linux64_visible_id(ns, false, named ? file->uid : owned ? LINUX64_UID : 0),
        .gid = linux64_visible_id(ns, true, named ? file->gid : owned ? LINUX64_GID : 0),
        .rdev = rdev, .size = file->size, .blksize = PMM_PAGE_SIZE,
        .blocks = kind == FILE_SYMLINK ? 0 : (file->size + 511) / 512,
    };
    return paging64_copy_to_user(stat_address, &stat, sizeof(stat)) == sizeof(stat) ? 0 : -EFAULT;
}

/* Имена до четырёх цифр занимают один 24-байтовый linux_dirent64. */
struct linux_dirent64 {
    u64 inode, next;
    u16 length;
    u8 type;
    char name[5];
};

_Static_assert(FD_COUNT <= 10000 && sizeof(struct linux_dirent64) == 24 &&
               __builtin_offsetof(struct linux_dirent64, name) == 19, "Linux x86-64 proc dirent");

static long linux_getdents64(i32 fd, uptr address, u32 capacity) {
    if (!open_file(fd)) return -EBADF;
    struct file_handle *dir = file_at(fd);
    if (dir->proc_node != PROC_FDS) {
        enum file_kind kind = kind_of(dir);
        return kind == FILE_DIRECTORY || kind == FILE_PROC_DIR ? -ENOSYS : -ENOTDIR;
    }
    const struct linux64_process *process;
    long result = proc_fd_table(dir->file.proc_fd_owner, &process);
    if (result) return result;
    uptr copied = 0;
    while (dir->offset < FD_COUNT + 2) {
        uptr position = dir->offset;
        if (position >= 2 && !process->fds[position - 2].file) {
            ++dir->offset;
            continue;
        }
        if (capacity - copied < sizeof(struct linux_dirent64)) return copied ? (long)copied : -EINVAL;
        uptr next = position + 1;
        while (next >= 2 && next < FD_COUNT + 2 && !process->fds[next - 2].file) ++next;
        struct linux_dirent64 entry = {.next = next, .length = sizeof(entry)};
        if (position < 2) {
            entry.inode = position ? (1ull << 31) + 1 : dir->file.inode;
            entry.type = 4; /* DT_DIR */
            entry.name[0] = '.';
            if (position) entry.name[1] = '.';
        } else {
            unsigned number = (unsigned)(position - 2);
            entry.inode = dir->file.inode + 1 + number;
            entry.type = 10; /* DT_LNK */
            char digits[4];
            unsigned count = 0;
            do {
                digits[count++] = (char)('0' + number % 10);
                number /= 10;
            } while (number);
            for (unsigned i = 0; i < count; ++i) entry.name[i] = digits[count - i - 1];
        }
        if (address >= X64_USER_TOP || copied > X64_USER_TOP - address ||
            paging64_copy_to_user(address + copied, &entry, sizeof(entry)) != sizeof(entry))
            return copied ? (long)copied : -EFAULT;
        dir->offset = entry.next;
        copied += sizeof(entry);
    }
    return (long)copied;
}

long linux64_file_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2, uptr arg3) {
    const i32 fd = (i32)arg0;
    struct linux64_file file;
    const struct memfd *memfd;
    enum file_kind kind;
    long result;
    switch (number) {
    case 0: /* read */
        return linux_read(fd, arg1, arg2, 0, false);
    case 1: /* write */
        if (!open_file(fd)) return -EBADF;
        if (file_at(fd)->serial) return serial_write(arg1, arg2);
        if (file_at(fd)->device) return device_io(file_at(fd), true, arg1, arg2);
        if (file_at(fd)->proc_node) {
            struct file_handle *handle = file_at(fd);
            if (!(handle->flags & O_ACCMODE)) return -EBADF;
            if (!handle->proc_admin) return -EPERM;
            long copied = linux64_userns_write(handle->proc_ns, handle->proc_node, arg1, arg2,
                                              handle->offset);
            if (copied > 0) handle->offset += (uptr)copied;
            return copied;
        }
        if (file_at(fd)->socket)
            return socket_run((struct linux64_socket_wait){.file = file_at(fd), .operation = SOCKET_WRITE,
                                                           .address = arg1, .length = arg2});
        if (!file_at(fd)->pipe || (file_at(fd)->flags & O_ACCMODE) != O_WRONLY) return -EBADF;
        return pipe_io(file_at(fd), true, arg1, arg2);
    case 2: /* open */
        return linux_open(AT_FDCWD, arg0, (u32)arg1);
    case 3: /* close */
        if (!open_file(fd)) return -EBADF;
        close_file(fd);
        return 0;
    case 4: /* stat */
    case 6: /* lstat */
        result = lookup(AT_FDCWD, arg0, number == 6 ? AT_SYMLINK_NOFOLLOW : 0, &file, &memfd, &kind);
        return result ? result : file_stat(&file, memfd, kind, arg1);
    case 5: /* fstat */
        if (!open_file(fd)) return -EBADF;
        handle_stat(file_at(fd), &file, &memfd);
        return file_stat(&file, memfd, kind_of(file_at(fd)), arg1);
    case 8: /* lseek */
        if (!open_file(fd)) return -EBADF;
        if (file_at(fd)->device == FILE_EPOLL) return -ESPIPE;
        if (file_at(fd)->device) return (u32)arg2 <= 4 ? 0 : -EINVAL;
        if (file_at(fd)->proc_node == PROC_FDS) {
            long offset = (long)arg1;
            u32 whence = (u32)arg2;
            if (whence > 1 ||
                (whence && __builtin_add_overflow((long)file_at(fd)->offset, offset, &offset)) ||
                offset < 0) return -EINVAL;
            file_at(fd)->offset = (uptr)offset;
            return offset;
        }
        return kind_of(file_at(fd)) != FILE_REGULAR ? -ESPIPE : -ENOSYS;
    case 17: /* pread64 */
        if ((long)arg3 < 0) return -EINVAL;
        return linux_read(fd, arg1, arg2, arg3, true);
    case 18: /* pwrite64 */
        if ((long)arg3 < 0) return -EINVAL;
        if (!open_file(fd)) return -EBADF;
        if (file_at(fd)->serial || file_at(fd)->socket ||
            file_at(fd)->device == FILE_EVENTFD || file_at(fd)->device == FILE_EPOLL) return -ESPIPE;
        return file_at(fd)->device ? device_io(file_at(fd), true, arg1, arg2) : -ENOSYS;
    case 21: /* access */
        if ((u32)arg1 & ~7u) return -EINVAL;
        result = lookup(AT_FDCWD, arg0, 0, &file, &memfd, &kind);
        if (result) return result;
        if (kind == FILE_NULL || kind == FILE_URANDOM) return (arg1 & 1u) ? -EACCES : 0;
        if (kind == FILE_NAMESPACE) {
            if (arg1 & 1u) return -EACCES;
            return (arg1 & 2u) ? -EPERM : 0;
        }
        if (kind == FILE_DIRECTORY || kind == FILE_NAMED_SOCKET) {
            if (kind == FILE_DIRECTORY && (arg1 & 2u) && !file.writable_directory) return -EROFS;
            return (arg1 & ~linux64_file_permissions(&file)) ? -EACCES : 0;
        }
        return (arg1 & 3u) ? -EACCES : 0;
    case 22: /* pipe */
        return linux_pipe2(arg0, 0);
    case 32: /* dup */
        return dup_fd(fd, 0, false);
    case 33: /* dup2 */
        return dup_to(fd, (i32)arg1, false);
    case 41: /* socket */
        return linux_socket(fd, (u32)arg1, (i32)arg2);
    case 42: /* connect */
    case 49: /* bind */
        if (!open_file(fd)) return -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        return socket_path(file_at(fd), number == 49, arg1, (u32)arg2);
    case 43: /* accept */
    case 288: /* accept4 */ {
        if (!open_file(fd)) return -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        u32 flags = number == 288 ? (u32)arg3 : 0;
        if (flags & ~(O_NONBLOCK | O_CLOEXEC)) return -EINVAL;
        return socket_run((struct linux64_socket_wait){.file = file_at(fd), .operation = SOCKET_ACCEPT,
                                                       .address = arg1, .length = arg2, .flags = flags});
    }
    case 46: /* sendmsg */
    case 47: /* recvmsg */
        if (!open_file(fd)) return -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        return socket_run((struct linux64_socket_wait){.file = file_at(fd), .address = arg1, .flags = (u32)arg2,
                                                       .operation = number == 47 ? SOCKET_RECVMSG : SOCKET_SENDMSG});
    case 48: /* shutdown */
        if (!open_file(fd)) return -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        return linux64_socket_shutdown(file_at(fd)->socket, (i32)arg1);
    case 50: /* listen */
        if (!open_file(fd)) return -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        return linux64_socket_listen(file_at(fd)->socket, (u32)arg1);
    case 51: /* getsockname */
    case 52: /* getpeername */
        if (!open_file(fd)) return -EBADF;
        if (!file_at(fd)->socket) return -ENOTSOCK;
        return linux64_socket_name(file_at(fd)->socket, number == 52, arg1, arg2);
    case 53: /* socketpair */
        return linux_socketpair(fd, (u32)arg1, (i32)arg2, arg3);
    case 72: /* fcntl */
        return linux_fcntl(fd, (i32)arg1, (u32)arg2);
    case 77: /* ftruncate */
        return linux_ftruncate(fd, arg1);
    case 80: /* chdir */
    case 161: /* chroot */
        return change_directory(arg0, number == 161);
    case 83: /* mkdir */
        return linux_mkdir(AT_FDCWD, arg0, (u32)arg1);
    case 87: /* unlink */
        return linux_unlink(AT_FDCWD, arg0, 0);
    case 88: /* symlink */
        return linux_symlink(AT_FDCWD, arg1, arg0);
    case 89: /* readlink */
        return linux_readlink(AT_FDCWD, arg0, arg1, (i32)arg2);
    case 217: /* getdents64 */
        return linux_getdents64(fd, arg1, (u32)arg2);
    case 257: /* openat */
        return linux_open(fd, arg1, (u32)arg2);
    case 258: /* mkdirat */
        return linux_mkdir(fd, arg1, (u32)arg2);
    case 262: /* newfstatat */
        if ((u32)arg3 & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW))
            return -EINVAL;
        result = lookup(fd, arg1, (u32)arg3, &file, &memfd, &kind);
        return result ? result : file_stat(&file, memfd, kind, arg2);
    case 263: /* unlinkat */
        return linux_unlink(fd, arg1, (u32)arg2);
    case 266: /* symlinkat */
        return linux_symlink((i32)arg1, arg2, arg0);
    case 267: /* readlinkat */
        return linux_readlink(fd, arg1, arg2, (i32)arg3);
    case 213: /* epoll_create */
        return fd > 0 ? linux_epoll_create(0) : -EINVAL;
    case 232: /* epoll_wait */
        return linux_epoll_wait(fd, arg1, (i32)arg2, (i32)arg3);
    case 233: /* epoll_ctl */
        return linux_epoll_ctl(fd, (i32)arg1, (i32)arg2, arg3);
    case 284: /* eventfd */
    case 290: /* eventfd2 */
        return linux_eventfd((u32)arg0, number == 290 ? (u32)arg1 : 0);
    case 291: /* epoll_create1 */
        return linux_epoll_create((u32)arg0);
    case 292: /* dup3 */
        if (((u32)arg2 & ~O_CLOEXEC) || fd == (i32)arg1) return -EINVAL;
        return dup_to(fd, (i32)arg1, (arg2 & O_CLOEXEC) != 0);
    case 293: /* pipe2 */
        return linux_pipe2(arg0, (u32)arg1);
    case 319: /* memfd_create */
        return memfd_create(arg0, (u32)arg1);
    default:
        return -ENOSYS;
    }
}
