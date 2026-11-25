#ifndef X86_64_LINUX_H
#define X86_64_LINUX_H

#include "../types.h"

#define LINUX64_PATH_LIMIT 4096u
#define LINUX64_FD_COUNT 256u
/* Глобальные пулы не растут вместе с таблицей отдельного процесса. */
#define LINUX64_OPEN_FILE_COUNT 512u
#define LINUX64_PID 1
#define LINUX64_UID 1000
#define LINUX64_GID 1000
#define LINUX64_STACK_TOP 0x00007ffffff00000ul
#define LINUX64_STACK_FLOOR (LINUX64_STACK_TOP - 8 * 1024 * 1024ul)
#define LINUX64_S_IFDIR 0040000u
#define LINUX64_S_IFREG 0100000u
#define LINUX64_S_IFLNK 0120000u
#define LINUX64_S_IFSOCK 0140000u
#define LINUX64_S_IFMT  0170000u

enum linux64_poll_events {
    LINUX64_POLLIN = 0x001, LINUX64_POLLOUT = 0x004, LINUX64_POLLERR = 0x008,
    LINUX64_POLLHUP = 0x010, LINUX64_POLLNVAL = 0x020, LINUX64_POLLRDNORM = 0x040,
    LINUX64_POLLWRNORM = 0x100, LINUX64_POLLWRBAND = 0x200, LINUX64_POLLRDHUP = 0x2000,
    LINUX64_POLL_READ = LINUX64_POLLIN | LINUX64_POLLRDNORM,
    LINUX64_POLL_WRITE = LINUX64_POLLOUT | LINUX64_POLLWRNORM,
};

struct memfd;

struct linux64_file {
    const u8 *bytes;
    struct memfd *backing;
    uptr size;
    u64 inode;
    u32 mode, uid, gid;
    i32 proc_fd_owner, proc_fd_number;
    bool writable_directory, live_pages, private_directory;
    bool proc_fd_directory, proc_exe;
};

struct linux64_file_source {
    bool (*lookup)(const void *context, const char *path, struct linux64_file *file);
    const void *context;
    u64 (*directory)(const void *context, const char *path);
    const char *(*entry_path)(const void *context, uptr index);
};

bool linux64_run(const struct linux64_file *file, const char *path, uptr path_length,
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
long linux64_sendto(i32 fd, uptr buffer, uptr length, u32 flags, uptr address, i32 address_length);
long linux64_recvfrom(i32 fd, uptr buffer, uptr length, u32 flags, uptr address, uptr address_length);
long linux64_sockopt(bool get, i32 fd, i32 level, i32 option, uptr value, uptr length);
struct linux64_socket;
struct linux64_udp_address { u32 ip; u16 port; };
bool linux64_socket_is_udp(const struct linux64_socket *socket);
long linux64_udp_address(uptr address, u32 length, struct linux64_udp_address *result, bool disconnect);
long linux64_udp_path(struct linux64_socket *socket, bool bind, uptr address, u32 length);
void linux64_udp_receive(void *context, u32 source, u32 destination, u8 protocol, const u8 *data, u32 length);
bool linux64_udp_flush(u64 now);
#define LINUX64_UNIX_PATH_LIMIT 108u
struct linux64_sockaddr { u16 family; char path[LINUX64_UNIX_PATH_LIMIT + 1]; };
long linux64_socket_create(i32 domain, u32 type, i32 protocol, struct linux64_socket **socket);
long linux64_socket_pair(i32 domain, u32 type, i32 protocol, struct linux64_socket *ends[2]);
bool linux64_socket_can_bind(const struct linux64_socket *socket);
void linux64_socket_bind(struct linux64_socket *socket, u64 inode, const char *name);
long linux64_socket_listen(struct linux64_socket *socket, u32 backlog);
long linux64_socket_connect(struct linux64_socket *socket, u64 inode);
bool linux64_socket_connect_ready(const struct linux64_socket *socket, u64 inode);
bool linux64_socket_io_ready(const struct linux64_socket *socket, bool receive);
bool linux64_socket_accept_ready(const struct linux64_socket *socket);
long linux64_socket_pending(struct linux64_socket *socket, bool blocking, struct linux64_socket **accepted);
void linux64_socket_dequeue(struct linux64_socket *socket);
long linux64_socket_name(const struct linux64_socket *socket, bool peer, uptr address, uptr length);
long linux64_socket_check_sendto(const struct linux64_socket *socket, u32 flags, uptr address, i32 length);
bool linux64_socket_is_stream(const struct linux64_socket *socket);
void linux64_socket_close(struct linux64_socket *socket);
long linux64_socket_shutdown(struct linux64_socket *socket, i32 how);
long linux64_socket_option(struct linux64_socket *socket, bool get, i32 level, i32 option,
                           uptr value, uptr length);
long linux64_socket_io(struct linux64_socket *socket, bool receive, uptr buffer, uptr length);
u16 linux64_socket_poll(const struct linux64_socket *socket);
long linux64_mmap(uptr address, uptr length, u32 protection, u32 flags, i32 fd, uptr offset);
long linux64_mprotect(uptr address, uptr length, uptr protection);
long linux64_munmap(uptr address, uptr length);
long linux64_madvise(uptr address, uptr length, i32 advice);
uptr linux64_random_bytes(void *buffer, uptr length);
bool linux64_net_init(void);
bool linux64_net_poll(void);
long linux64_getrandom(uptr address, uptr length, u32 flags);
void linux64_clock_init(void);
bool linux64_monotonic_ns(u64 *nanos);
bool linux64_clock_sample(bool realtime, long *seconds, u64 *nanoseconds);
long linux64_clock_gettime(i32 clock, uptr address);
long linux64_gettimeofday(uptr timeval, uptr timezone);
void linux64_reset_signals(void);
long linux64_rt_sigaction(i32 signal, uptr action, uptr previous, uptr sigset_size);
long linux64_rt_sigprocmask(i32 how, uptr set, uptr previous, uptr sigset_size);
bool linux64_enable_syscall(void);
void linux64_task_exception(u64 vector);
void kernel64_serial_char(char ch);

#endif
