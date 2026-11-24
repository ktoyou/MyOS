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
    u64 rax, r9, r8, r10, rdx, rsi, rdi, r15, r14, r13, r12, rbp, rbx;
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

enum linux64_task_state {
    TASK_FREE, TASK_RUNNABLE, TASK_WAITING, TASK_VFORK_WAIT, TASK_ZOMBIE, TASK_DEAD,
};

struct linux64_wait {
    uptr address;
    i32 kind;
    i32 filter;
    u32 options;
    bool signal_info;
};

struct linux64_task {
    struct linux64_frame frame;
    struct linux64_fd_slot fds[LINUX64_FD_COUNT];
    struct linux64_address_space *memory;
    struct linux64_sigaction actions[LINUX64_SIGNAL_COUNT];
    u64 signal_mask, fs, gs;
    struct linux64_wait wait;
    uptr child_tid;
    i32 pid, ppid, sid, pgid, vfork_child, exit_status;
    u16 ds_selector, es_selector, fs_selector, gs_selector;
    enum linux64_task_state state;
    bool finish_wait;
    u8 xstate[LINUX64_XSTATE_SIZE] __attribute__((aligned(64)));
};

extern struct linux64_task *linux64_current;

void linux64_task_init(void);
void linux64_task_syscall(struct linux64_frame *frame);
void linux64_retain_files(struct linux64_task *task);
void linux64_close_files(struct linux64_task *task);
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
