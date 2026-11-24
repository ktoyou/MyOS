#ifndef X86_64_LINUX_H
#define X86_64_LINUX_H

#include "../types.h"

#define LINUX64_PATH_LIMIT 4096u
#define LINUX64_FD_COUNT 32u
#define LINUX64_PID 1
#define LINUX64_UID 1000
#define LINUX64_GID 1000
#define LINUX64_STACK_TOP 0x00007ffffff00000ul
#define LINUX64_STACK_FLOOR (LINUX64_STACK_TOP - 8 * 1024 * 1024ul)
#define LINUX64_S_IFDIR 0040000u
#define LINUX64_S_IFLNK 0120000u
#define LINUX64_S_IFMT  0170000u

enum linux64_poll_events {
    LINUX64_POLLIN = 0x001, LINUX64_POLLOUT = 0x004, LINUX64_POLLERR = 0x008,
    LINUX64_POLLHUP = 0x010, LINUX64_POLLNVAL = 0x020, LINUX64_POLLRDNORM = 0x040,
    LINUX64_POLLWRNORM = 0x100, LINUX64_POLLWRBAND = 0x200, LINUX64_POLLRDHUP = 0x2000,
    LINUX64_POLL_READ = LINUX64_POLLIN | LINUX64_POLLRDNORM,
    LINUX64_POLL_WRITE = LINUX64_POLLOUT | LINUX64_POLLWRNORM,
};

struct linux64_file {
    const u8 *bytes;
    uptr size;
    u64 inode;
    u32 mode, uid, gid;
    bool writable_directory;
};

struct linux64_file_source {
    bool (*lookup)(const void *context, const char *path, struct linux64_file *file);
    const void *context;
    u64 (*directory)(const void *context, const char *path);
};

bool linux64_run(const void *image, uptr size, const char *path, uptr path_length,
                 const struct linux64_file_source *source);
void linux64_use_files(const struct linux64_file_source *source, const char *path, uptr path_length);
struct linux64_fd_view {
    struct linux64_file file;
    const void *object;
    uptr (*frame)(const void *object, uptr offset);
    bool writable, may_grow;
};
long linux64_get_file(i32 fd, struct linux64_fd_view *view);
long linux64_file_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2, uptr arg3);
long linux64_sockopt(bool get, i32 fd, i32 level, i32 option, uptr value, uptr length);
struct linux64_socket;
long linux64_socket_create(i32 domain, u32 type, i32 protocol, struct linux64_socket **socket);
long linux64_socket_pair(i32 domain, u32 type, i32 protocol, struct linux64_socket *ends[2]);
void linux64_socket_close(struct linux64_socket *socket);
long linux64_socket_shutdown(struct linux64_socket *socket, i32 how);
long linux64_socket_option(struct linux64_socket *socket, bool get, i32 level, i32 option,
                           uptr value, uptr length);
long linux64_socket_message(struct linux64_socket *socket, bool receive, uptr message, u32 flags);
long linux64_socket_io(struct linux64_socket *socket, bool receive, uptr buffer, uptr length);
u16 linux64_socket_poll(const struct linux64_socket *socket);
long linux64_mmap(uptr address, uptr length, u32 protection, u32 flags, i32 fd, uptr offset);
long linux64_mprotect(uptr address, uptr length, uptr protection);
long linux64_munmap(uptr address, uptr length);
uptr linux64_random_bytes(void *buffer, uptr length);
long linux64_getrandom(uptr address, uptr length, u32 flags);
void linux64_clock_init(void);
bool linux64_monotonic_ns(u64 *nanos);
long linux64_clock_gettime(i32 clock, uptr address);
long linux64_gettimeofday(uptr timeval, uptr timezone);
void linux64_reset_signals(void);
long linux64_rt_sigaction(i32 signal, uptr action, uptr previous, uptr sigset_size);
long linux64_rt_sigprocmask(i32 how, uptr set, uptr previous, uptr sigset_size);
bool linux64_enable_syscall(void);
void linux64_task_exception(u64 vector);
void kernel64_serial_char(char ch);

#endif
