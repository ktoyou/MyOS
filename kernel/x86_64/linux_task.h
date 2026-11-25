#ifndef X86_64_LINUX_TASK_H
#define X86_64_LINUX_TASK_H

#include "linux.h"

#define LINUX64_TASK_COUNT 256u
#define LINUX64_PROCESS_COUNT 16u
#define LINUX64_RESERVE_COUNT 256u
#define LINUX64_SIGNAL_COUNT 64u
#define LINUX64_XSTATE_SIZE 16384u
#define LINUX64_FS_BASE 0xc0000100u
#define LINUX64_GS_BASE 0xc0000101u

/* Порядок полей совпадает с сохранёнными регистрами в linux_syscall.asm. */
struct linux64_frame {
    u64 rcx, r11, rax, r9, r8, r10, rdx, rsi, rdi, r15, r14, r13, r12, rbp, rbx;
    u64 rip, cs, rflags, rsp, ss;
};

struct linux64_reserve_range {
    uptr start, end;
};

struct linux64_address_space {
    struct linux64_reserve_range reserves[LINUX64_RESERVE_COUNT];
    uptr root, data_bytes;
    unsigned reserve_count, references;
};

struct linux64_rlimit {
    u64 soft, hard;
};

struct linux64_sigaction {
    u64 handler, flags, restorer, mask;
};

struct linux64_fd_slot {
    struct file_handle *file;
    bool cloexec;
};

struct linux64_userns;
struct linux64_pidns;
struct linux64_pid;

enum linux64_proc_node {
    USERNS_NONE, USERNS_UID_MAP, USERNS_GID_MAP, USERNS_SETGROUPS,
    PROC_USER_NS, PROC_PID_NS, PROC_EXE, PROC_ROOT, PROC_TASKS, PROC_FDS,
};

struct linux64_caps {
    u64 effective, permitted, inheritable;
};

#define LINUX64_CAP_SYS_ADMIN (1ull << 21)
#define LINUX64_CAP_SYS_CHROOT (1ull << 18)
#define LINUX64_CAP_SETFCAP (1ull << 31)

enum linux64_task_state {
    TASK_FREE, TASK_RUNNABLE, TASK_WAITING, TASK_VFORK_WAIT, TASK_PIPE_WAIT, TASK_FUTEX_WAIT,
    TASK_POLL_WAIT, TASK_SOCKET_WAIT, TASK_EVENTFD_WAIT, TASK_EPOLL_WAIT, TASK_FLOCK_WAIT,
    TASK_KEYBOARD_WAIT, TASK_DEAD,
};

struct linux64_pipe_io {
    struct linux64_pipe *pipe;
    struct file_handle *file;
    uptr address, length, transferred;
    bool write, nonblock;
};

enum linux64_socket_operation { SOCKET_CONNECT, SOCKET_ACCEPT, SOCKET_READ, SOCKET_WRITE,
                                SOCKET_SENDMSG, SOCKET_RECVMSG };
struct linux64_scm_rights;

struct linux64_socket_wait {
    struct file_handle *file;
    struct linux64_scm_rights *rights;
    uptr address, length, transferred;
    u64 inode;
    u32 flags;
    enum linux64_socket_operation operation;
    bool blocking;
    char path[LINUX64_UNIX_PATH_LIMIT + 1];
};

struct linux64_eventfd_wait {
    struct file_handle *file;
    u64 value;
    uptr address;
    bool write;
};

struct linux64_epoll_wait {
    struct file_handle *file;
    uptr address;
    u64 deadline;
    u32 maxevents;
};

struct linux64_flock_wait {
    struct file_handle *file;
    u32 mode;
};

struct linux64_keyboard_wait {
    struct file_handle *file;
    uptr address, count;
};

struct linux64_wait {
    uptr address;
    i32 kind;
    i32 filter;
    u32 options;
    bool signal_info, current_group;
};

struct linux64_directory {
    const char *path;
    struct linux64_file file;
    uptr page;
};

struct linux64_fs {
    struct linux64_directory root, cwd;
    uptr page;
    unsigned references;
    u32 umask;
};

struct linux64_process {
    struct linux64_fd_slot fds[LINUX64_FD_COUNT];
    struct linux64_sigaction actions[LINUX64_SIGNAL_COUNT];
    struct linux64_rlimit data_limit;
    char executable_path[LINUX64_PATH_LIMIT];
    uptr executable_path_length;
    u64 pid_ns_link_inode, fdinfo_inode, proc_fd_inode;
    i32 pid, ppid, sid, pgid, exit_status;
    unsigned threads;
    struct linux64_fs *fs;
    struct linux64_userns *userns;
    struct linux64_pidns *pid_ns;
    struct linux64_pid *pid_identity, *group_identity;
};

struct linux64_futex_wait {
    const struct linux64_address_space *memory;
    uptr address;
    long deadline;
    u32 bits;
    bool private, timed, realtime;
};

struct linux64_pollfd {
    i32 fd;
    u16 events, revents;
};

struct linux64_poll_timeout {
    uptr address;
    u64 seconds, nanoseconds;
};

struct linux64_poll_wait {
    struct linux64_pollfd entries[LINUX64_FD_COUNT];
    struct linux64_poll_timeout timeout;
    uptr address;
    u64 deadline, saved_mask;
    unsigned count, ready;
    bool keyboard;
};

struct linux64_task {
    struct linux64_frame frame;
    u64 cpu_ns;
    struct linux64_address_space *memory;
    struct linux64_process *process;
    struct linux64_caps caps;
    u64 signal_mask, fs, gs;
    struct linux64_wait wait;
    struct linux64_pipe_io pipe_io;
    struct linux64_socket_wait socket_wait;
    struct linux64_eventfd_wait eventfd_wait;
    struct linux64_epoll_wait epoll_wait;
    struct linux64_flock_wait flock_wait;
    struct linux64_keyboard_wait keyboard_wait;
    struct linux64_futex_wait futex;
    struct linux64_poll_wait poll;
    uptr child_tid, clear_child_tid;
    i32 tid, visible_tid, vfork_child;
    u16 ds_selector, es_selector, fs_selector, gs_selector;
    enum linux64_task_state state;
    bool finish_wait, no_new_privs;
    uptr xstate_physical;
};

extern struct linux64_task *linux64_current;

struct linux64_pidns *linux64_pidns_init(void);
long linux64_pidns_create(struct linux64_pidns *parent, struct linux64_userns *owner,
                         struct linux64_pidns **result);
void linux64_pidns_retain(struct linux64_pidns *ns);
void linux64_pidns_release(struct linux64_pidns *ns);
u64 linux64_pidns_inode(const struct linux64_pidns *ns);
long linux64_pidns_readlink(const struct linux64_pidns *ns, uptr destination, uptr size);
i32 linux64_pidns_reaper(const struct linux64_pidns *ns);
void linux64_pidns_set_reaper(struct linux64_pidns *ns, i32 pid);
bool linux64_pidns_contains(const struct linux64_pidns *ns, const struct linux64_pidns *member);
struct linux64_pid *linux64_pid_create(struct linux64_pidns *ns);
struct linux64_pid *linux64_pid_init(void);
void linux64_pid_retain(struct linux64_pid *pid);
void linux64_pid_release(struct linux64_pid *pid);
i32 linux64_pid_number(const struct linux64_pid *pid, const struct linux64_pidns *ns);
long linux64_pid_allocate(struct linux64_pidns *ns, i32 global, struct linux64_pid *pid);
long linux64_userns_create(struct linux64_userns *parent, struct linux64_userns **result);
void linux64_userns_retain(struct linux64_userns *ns);
void linux64_userns_release(struct linux64_userns *ns);
u64 linux64_userns_inode(const struct linux64_userns *ns);
long linux64_userns_readlink(const struct linux64_userns *ns, uptr buffer, uptr size);
u32 linux64_visible_id(const struct linux64_userns *ns, bool group, u32 id);
void linux64_userns_caps(struct linux64_task *task);
long linux64_capabilities(bool set, uptr header, uptr data);
long linux64_userns_read(const struct linux64_userns *ns, enum linux64_proc_node file,
                         uptr buffer, uptr count, uptr offset);
long linux64_userns_write(struct linux64_userns *ns, enum linux64_proc_node file,
                          uptr buffer, uptr count, uptr offset);
bool linux64_task_init(uptr data_bytes);
void linux64_task_clock_resume(void);
bool linux64_task_cpu_ns(u64 *nanos);
const struct linux64_process *linux64_process_by_pid(i32 pid);
u16 linux64_task_count(void);
void linux64_task_syscall(struct linux64_frame *frame);
void linux64_retain_files(struct linux64_process *process);
void linux64_close_files(struct linux64_process *process);
void linux64_close_on_exec(struct linux64_process *process);
void linux64_pipe_finish(struct linux64_task *task);
long linux64_futex(uptr address, u32 operation, u32 value, uptr timeout, u32 bits);
struct linux64_pipe *linux64_pipe_create(void);
void linux64_pipe_close(struct linux64_pipe *pipe, bool writer);
long linux64_pipe_io(struct linux64_pipe *pipe, bool write, bool nonblock, uptr address, uptr length);
bool linux64_pipe_ready(const struct linux64_pipe_io *io);
long linux64_pipe_resume(void);
u16 linux64_pipe_poll(const struct linux64_pipe *pipe, bool writer);
long linux64_poll(uptr address, u32 count, i32 timeout);
long linux64_ppoll(uptr address, u32 count, uptr timeout, uptr sigmask, uptr sigset_size);
bool linux64_poll_ready(struct linux64_task *task);
long linux64_poll_resume(struct linux64_task *task);
long linux64_read_signal_mask(uptr set, uptr sigset_size, u64 *mask);
bool linux64_socket_wait_ready(const struct linux64_task *task);
void linux64_socket_wait_finish(struct linux64_task *task);
long linux64_socket_wait_resume(void);
long linux64_socket_prepare_rights(uptr message, u32 flags, struct linux64_scm_rights **rights);
long linux64_socket_message(struct linux64_socket *socket, struct linux64_socket_wait *wait);
void linux64_scm_release(struct linux64_scm_rights *rights);
struct file_handle *linux64_scm_get_file(i32 fd);
void linux64_scm_put_file(struct file_handle *file);
struct linux64_socket *linux64_scm_file_socket(const struct file_handle *file);
void linux64_scm_set_inflight(struct file_handle *file, bool inflight);
long linux64_scm_install(struct file_handle *file, bool cloexec);
void linux64_scm_close(i32 fd);
void linux64_scm_collect_pending(void);
void linux64_scm_collect_sockets(void);
void linux64_scm_mark_socket(struct linux64_socket *socket);
void linux64_scm_mark_roots(void);
bool linux64_eventfd_ready(const struct linux64_eventfd_wait *wait);
long linux64_eventfd_resume(void);
void linux64_eventfd_wait_finish(struct linux64_task *task);
bool linux64_epoll_wait_ready(const struct linux64_epoll_wait *wait);
long linux64_epoll_resume(void);
void linux64_epoll_wait_finish(struct linux64_task *task);
bool linux64_flock_ready(const struct linux64_flock_wait *wait);
long linux64_flock_resume(void);
void linux64_flock_wait_finish(struct linux64_task *task);
bool linux64_keyboard_wait_ready(const struct linux64_keyboard_wait *wait);
long linux64_keyboard_wait_resume(void);
void linux64_keyboard_wait_finish(struct linux64_task *task);
bool linux64_epoll_waits_for_keyboard(const struct linux64_epoll_wait *wait);
const struct linux64_file_source *linux64_file_source(void);
struct linux64_fs *linux64_initial_fs(void);
struct linux64_fs *linux64_fs_copy(const struct linux64_fs *source);
void linux64_fs_retain(struct linux64_fs *fs);
void linux64_fs_release(struct linux64_fs *fs);
long linux64_vfs_walk(const struct linux64_directory *base, const char *path,
                      struct linux64_file *file, char *resolved, bool follow_final);
long linux64_vfs_mkdir(const struct linux64_directory *base, const char *path, u32 mode);
long linux64_vfs_symlink(const struct linux64_directory *base, const char *path,
                         const char *target, uptr length);
long linux64_vfs_socket(const struct linux64_directory *base, const char *path, u32 mode,
                        u64 *inode);
long linux64_vfs_unlink(const struct linux64_directory *base, const char *path);
long linux64_vfs_rename(const struct linux64_directory *old_base, const char *old_path,
                        const struct linux64_directory *new_base, char *new_path);
long linux64_vfs_create_file(const struct linux64_directory *base, const char *path,
                             u32 mode, bool follow_final, struct linux64_file *file);
struct memfd *linux64_tmp_alloc(void);
void linux64_tmp_unlink(struct memfd *backing);
bool linux64_vfs_next_entry(const struct linux64_directory *dir, uptr *position,
                            char name[256], struct linux64_file *file);
u32 linux64_file_permissions(const struct linux64_file *file);
bool linux64_special_node(const char *path, struct linux64_file *file);
long linux64_proc_fd_entry(i32 owner, const char *name, uptr length, struct linux64_file *file);
long linux64_user_string(uptr address, char *string, uptr limit);
long linux64_execve(struct linux64_frame *frame, uptr filename, uptr argv, uptr envp);
bool linux64_commit_exec(struct linux64_frame *frame, uptr root, uptr entry, uptr stack, uptr data_bytes,
                        const char *path, uptr path_length);
long linux64_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2,
                    uptr arg3, uptr arg4, uptr arg5);

static inline u64 linux64_rdmsr(u32 reg) {
    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(reg));
    return ((u64)high << 32) | low;
}

static inline void linux64_wrmsr(u32 reg, u64 value) {
    __asm__ volatile("wrmsr" : : "c"(reg), "a"((u32)value), "d"((u32)(value >> 32)) : "memory");
}

#endif
