#ifndef X86_64_LINUX_TASK_H
#define X86_64_LINUX_TASK_H

#include "linux.h"

#define LINUX64_TASK_COUNT 8u
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
    uptr root;
    unsigned reserve_count, references;
};

struct linux64_sigaction {
    u64 handler, flags, restorer, mask;
};

struct linux64_fd_slot {
    struct file_handle *file;
    bool cloexec;
};

struct linux64_userns;

enum linux64_proc_node {
    USERNS_NONE, USERNS_UID_MAP, USERNS_GID_MAP, USERNS_SETGROUPS,
    PROC_USER_NS, PROC_EXE, PROC_ROOT, PROC_TASKS,
};

struct linux64_caps {
    u64 effective, permitted, inheritable;
};

#define LINUX64_CAP_SYS_ADMIN (1ull << 21)
#define LINUX64_CAP_SETFCAP (1ull << 31)

enum linux64_task_state {
    TASK_FREE, TASK_RUNNABLE, TASK_WAITING, TASK_VFORK_WAIT, TASK_PIPE_WAIT, TASK_FUTEX_WAIT,
    TASK_POLL_WAIT, TASK_DEAD,
};

struct linux64_pipe_io {
    struct linux64_pipe *pipe;
    struct file_handle *file;
    uptr address, length, transferred;
    bool write, nonblock;
};

struct linux64_wait {
    uptr address;
    i32 kind;
    i32 filter;
    u32 options;
    bool signal_info;
};

struct linux64_process {
    struct linux64_fd_slot fds[LINUX64_FD_COUNT];
    struct linux64_sigaction actions[LINUX64_SIGNAL_COUNT];
    char executable_path[LINUX64_PATH_LIMIT];
    uptr executable_path_length;
    i32 pid, ppid, sid, pgid, exit_status;
    unsigned threads;
    u32 umask;
    struct linux64_userns *userns;
};

struct linux64_futex_wait {
    const struct linux64_address_space *memory;
    uptr address;
    u32 bits;
    bool private;
};

struct linux64_pollfd {
    i32 fd;
    u16 events, revents;
};

struct linux64_poll_wait {
    struct linux64_pollfd entries[LINUX64_FD_COUNT];
    uptr address;
    u64 deadline;
    unsigned count, ready;
};

struct linux64_task {
    struct linux64_frame frame;
    struct linux64_address_space *memory;
    struct linux64_process *process;
    struct linux64_caps caps;
    u64 signal_mask, fs, gs;
    struct linux64_wait wait;
    struct linux64_pipe_io pipe_io;
    struct linux64_futex_wait futex;
    struct linux64_poll_wait poll;
    uptr child_tid, clear_child_tid;
    i32 tid, vfork_child;
    u16 ds_selector, es_selector, fs_selector, gs_selector;
    enum linux64_task_state state;
    bool finish_wait;
    u8 xstate[LINUX64_XSTATE_SIZE] __attribute__((aligned(64)));
};

extern struct linux64_task *linux64_current;

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
void linux64_task_init(void);
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
bool linux64_poll_ready(struct linux64_task *task);
long linux64_poll_resume(const struct linux64_task *task);
const struct linux64_file_source *linux64_file_source(void);
long linux64_vfs_walk(const struct linux64_file_source *source, const char *absolute,
                      struct linux64_file *file, char *resolved, bool follow_final);
long linux64_vfs_mkdir(const struct linux64_file_source *source, const char *absolute, u32 mode);
long linux64_vfs_symlink(const struct linux64_file_source *source, const char *absolute,
                         const char *target, uptr length);
long linux64_vfs_unlink(const struct linux64_file_source *source, const char *absolute);
u32 linux64_directory_permissions(const struct linux64_file *file);
bool linux64_special_node(const char *path, struct linux64_file *file);
long linux64_user_string(uptr address, char *string, uptr limit);
long linux64_execve(struct linux64_frame *frame, uptr filename, uptr argv, uptr envp);
bool linux64_commit_exec(struct linux64_frame *frame, uptr root, uptr entry, uptr stack,
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
