#include "linux_task.h"
#include "paging.h"

enum {
    EPERM = 1, ESRCH = 3, ECHILD = 10, EAGAIN = 11, ENOMEM = 12, EFAULT = 14,
    EINVAL = 22, ENOSYS = 38,
    SIGCHLD = 17, CHILD_CLEARTID = 0x200000, CHILD_SETTID = 0x1000000,
    SA_NOCLDWAIT = 2, SIG_IGN = 1,
    WNOHANG = 1, WUNTRACED = 2, WCONTINUED = 8,
};

static struct linux64_task tasks[LINUX64_TASK_COUNT];
struct linux64_task *linux64_current = &tasks[0];
static i32 next_pid = LINUX64_PID + 1;
static u64 xfeatures;
static bool xstate_supported;

extern __attribute__((noreturn)) void linux64_task_resume(struct linux64_frame *frame);

_Static_assert(sizeof(struct linux64_frame) == 18 * sizeof(u64), "Linux syscall frame size");
_Static_assert(__builtin_offsetof(struct linux64_frame, rip) == 13 * sizeof(u64), "Linux IRET frame");

void linux64_task_init(void) {
    linux64_current->pid = LINUX64_PID;
    linux64_current->sid = LINUX64_PID;
    linux64_current->pgid = LINUX64_PID;
    linux64_current->root = paging64_active_root();
    linux64_current->state = TASK_RUNNABLE;
    xstate_supported = true;
    uptr cr0, cr4;
    __asm__ volatile("mov %%cr0,%0" : "=r"(cr0));
    /* FXSAVE и SSE не должны зависеть от настроек, оставленных прошивкой. */
    cr0 = (cr0 & ~((1ul << 2) | (1ul << 3))) | (1ul << 1) | (1ul << 5);
    __asm__ volatile("mov %0,%%cr0" : : "r"(cr0) : "memory");
    __asm__ volatile("mov %%cr4,%0" : "=r"(cr4));
    cr4 |= (1ul << 9) | (1ul << 10);
    __asm__ volatile("mov %0,%%cr4" : : "r"(cr4) : "memory");
    if (!(cr4 & (1ul << 18))) return;
    u32 low, high, eax = 0xd, size, ecx = 0, edx;
    __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(0));
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(size), "+c"(ecx), "=d"(edx));
    xfeatures = ((u64)high << 32) | low;
    xstate_supported = size <= LINUX64_XSTATE_SIZE;
}

static void save_state(struct linux64_task *task) {
    task->fs = linux64_rdmsr(LINUX64_FS_BASE);
    task->gs = linux64_rdmsr(LINUX64_GS_BASE);
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1" : "=r"(task->fs_selector), "=r"(task->gs_selector));
    __asm__ volatile("mov %%ds,%0; mov %%es,%1" : "=r"(task->ds_selector), "=r"(task->es_selector));
    if (xfeatures) {
        __asm__ volatile("xsave64 %0" : "=m"(task->xstate)
                         : "a"((u32)xfeatures), "d"((u32)(xfeatures >> 32)) : "memory");
    } else {
        __asm__ volatile("fxsave64 %0" : "=m"(task->xstate) : : "memory");
    }
}

static void restore_state(const struct linux64_task *task) {
    __asm__ volatile("mov %0,%%ds; mov %1,%%es" : : "r"(task->ds_selector),
                     "r"(task->es_selector) : "memory");
    __asm__ volatile("mov %0,%%fs; mov %1,%%gs" : : "r"(task->fs_selector),
                     "r"(task->gs_selector) : "memory");
    linux64_wrmsr(LINUX64_FS_BASE, task->fs);
    linux64_wrmsr(LINUX64_GS_BASE, task->gs);
    if (xfeatures) {
        __asm__ volatile("xrstor64 %0" : : "m"(task->xstate),
                         "a"((u32)xfeatures), "d"((u32)(xfeatures >> 32)) : "memory");
    } else {
        __asm__ volatile("fxrstor64 %0" : : "m"(task->xstate) : "memory");
    }
}

static long fork_task(struct linux64_frame *frame, uptr flags, uptr stack, uptr tid) {
    if (stack || (flags & ~(CHILD_CLEARTID | CHILD_SETTID)) != SIGCHLD || !xstate_supported)
        return -ENOSYS;
    unsigned slot = 1;
    while (slot < LINUX64_TASK_COUNT && tasks[slot].state != TASK_FREE) ++slot;
    if (slot == LINUX64_TASK_COUNT || next_pid == 0x7fffffff) return -EAGAIN;
    uptr root = paging64_fork_root();
    if (!root) return -ENOMEM;

    struct linux64_task *child = &tasks[slot];
    struct linux64_task *parent = linux64_current;
    child->frame = *frame;
    child->frame.rax = 0;
    child->root = root;
    child->pid = next_pid++;
    child->ppid = parent->pid;
    child->sid = parent->sid;
    child->pgid = parent->pgid;
    child->child_tid = flags & CHILD_SETTID ? tid : 0;
    child->finish_wait = false;
    child->signal_mask = parent->signal_mask;
    child->reserve_count = parent->reserve_count;
    for (unsigned i = 0; i < parent->reserve_count; ++i) child->reserves[i] = parent->reserves[i];
    for (unsigned i = 0; i < LINUX64_SIGNAL_COUNT; ++i) child->actions[i] = parent->actions[i];
    for (unsigned i = 0; i < LINUX64_FD_COUNT; ++i) child->fds[i] = parent->fds[i];
    linux64_retain_files(child);
    save_state(child);
    child->state = TASK_RUNNABLE;
    return child->pid;
}

static bool wait_matches(const struct linux64_task *parent, const struct linux64_task *child,
                         i32 filter) {
    return child->state != TASK_FREE && child->state != TASK_DEAD && child->ppid == parent->pid &&
           (filter == -1 || child->pid == filter ||
            (filter == 0 && child->pgid == parent->pgid) ||
            (filter < -1 && child->pgid == -(long)filter));
}

static long wait_child(i32 pid, uptr address, u32 options, uptr usage) {
    if (usage || (options & ~(WNOHANG | WUNTRACED | WCONTINUED))) return -EINVAL;
    if (pid == -0x7fffffff - 1) return -ESRCH;
    struct linux64_task *parent = linux64_current;
    bool found = false;
    for (unsigned i = 1; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *child = &tasks[i];
        if (!wait_matches(parent, child, pid)) continue;
        found = true;
        if (child->state != TASK_ZOMBIE) continue;
        i32 status = child->exit_status;
        child->state = TASK_FREE;
        if (address && paging64_copy_to_user(address, &status, sizeof(status)) != sizeof(status))
            return -EFAULT;
        return child->pid;
    }
    if (!found) return -ECHILD;
    if (!(options & WNOHANG)) {
        parent->wait_pid = pid;
        parent->wait_status_address = address;
        parent->state = TASK_WAITING;
    }
    return 0;
}

static void publish_child_exit(struct linux64_task *child) {
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *parent = &tasks[i];
        if (parent->state == TASK_FREE || parent->pid != child->ppid) continue;
        const struct linux64_sigaction *action = &parent->actions[SIGCHLD - 1];
        if (action->handler == SIG_IGN || (action->flags & SA_NOCLDWAIT))
            child->state = child->root ? TASK_DEAD : TASK_FREE;
        if (parent->state != TASK_WAITING) return;
        bool live_child = false;
        for (unsigned j = 1; j < LINUX64_TASK_COUNT; ++j) {
            if (!wait_matches(parent, &tasks[j], parent->wait_pid)) continue;
            if (tasks[j].state == TASK_ZOMBIE) {
                live_child = false;
                break;
            }
            live_child = true;
        }
        if (live_child) return;
        parent->finish_wait = true;
        parent->state = TASK_RUNNABLE;
        return;
    }
}

static void finish_child(i32 wait_status) {
    struct linux64_task *task = linux64_current;
    linux64_close_files(task);
    task->exit_status = wait_status;
    task->state = TASK_ZOMBIE;
    for (unsigned i = 1; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *orphan = &tasks[i];
        if (orphan->state == TASK_FREE || orphan->ppid != task->pid) continue;
        orphan->ppid = LINUX64_PID;
        if (orphan->state == TASK_ZOMBIE) publish_child_exit(orphan);
    }
    publish_child_exit(task);
}

static void exit_task(u32 status) {
    if (linux64_current->pid != LINUX64_PID) {
        finish_child((i32)((status & 255u) << 8));
        return;
    }
    linux64_close_files(linux64_current);
    static const char message[] = "Linux x86-64 exit status=0x";
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
    kernel64_serial_char(digits[(status >> 4) & 15u]);
    kernel64_serial_char(digits[status & 15u]);
    kernel64_serial_char('\r');
    kernel64_serial_char('\n');
    for (;;) __asm__ volatile("cli; hlt");
}

static long new_session(void) {
    struct linux64_task *task = linux64_current;
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i)
        if (tasks[i].state != TASK_FREE && tasks[i].pgid == task->pid) return -EPERM;
    task->sid = task->pgid = task->pid;
    return task->sid;
}

static void schedule(struct linux64_frame *frame) {
    struct linux64_task *old = linux64_current;
    struct linux64_task *next = NULL;
    unsigned index = (unsigned)(old - tasks);
    for (unsigned i = 1; i <= LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *candidate = &tasks[(index + i) % LINUX64_TASK_COUNT];
        if (candidate->state != TASK_RUNNABLE) continue;
        next = candidate;
        break;
    }
    if (next == old) return;
    if (!next) {
        static const char message[] = "Linux x86-64 scheduler has no runnable process\n";
        for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
        for (;;) __asm__ volatile("cli; hlt");
    }
    bool exited = old->state == TASK_ZOMBIE || old->state == TASK_DEAD;
    if (!exited) {
        old->frame = *frame;
        save_state(old);
    }
    paging64_switch_root(next->root);
    linux64_current = next;
    if (exited) {
        paging64_drop_root(old->root);
        old->root = 0;
        if (old->state == TASK_DEAD) old->state = TASK_FREE;
    }
    restore_state(next);
    if (next->child_tid) {
        paging64_copy_to_user(next->child_tid, &next->pid, sizeof(next->pid));
        next->child_tid = 0;
    }
    if (next->finish_wait) {
        next->finish_wait = false;
        next->frame.rax = (u64)wait_child(next->wait_pid, next->wait_status_address, WNOHANG, 0);
    }
    *frame = next->frame;
}

void linux64_task_exception(u64 vector) {
    if (linux64_current->pid <= LINUX64_PID) return;
    i32 signal;
    switch (vector) {
    case 0: case 16: case 19: signal = 8; break; /* SIGFPE */
    case 1: case 3: signal = 5; break; /* SIGTRAP */
    case 6: signal = 4; break; /* SIGILL */
    case 13: case 14: signal = 11; break; /* SIGSEGV */
    case 12: case 17: signal = 7; break; /* SIGBUS */
    default: return;
    }
    /* Пользовательские обработчики исключений пока не доставляются. */
    u64 bit = 1ull << (signal - 1);
    if (linux64_current->actions[signal - 1].handler > SIG_IGN &&
        !(linux64_current->signal_mask & bit)) return;
    finish_child(signal);
    struct linux64_frame frame;
    schedule(&frame);
    linux64_task_resume(&frame);
}

void linux64_task_syscall(struct linux64_frame *frame) {
    uptr number = frame->rax;
    switch (number) {
    case 24: /* sched_yield */
        frame->rax = 0;
        break;
    case 56: /* clone без CLONE_VM */
        frame->rax = (u64)fork_task(frame, frame->rdi, frame->rsi, frame->r10);
        break;
    case 57: /* fork */
        frame->rax = (u64)fork_task(frame, SIGCHLD, 0, 0);
        break;
    case 60: /* exit */
    case 231: /* exit_group */
        exit_task((u32)frame->rdi);
        break;
    case 61: /* wait4 */
        frame->rax = (u64)wait_child((i32)frame->rdi, frame->rsi, (u32)frame->rdx, frame->r10);
        break;
    case 110: /* getppid */
        frame->rax = (u64)linux64_current->ppid;
        break;
    case 111: /* getpgrp */
        frame->rax = (u64)linux64_current->pgid;
        break;
    case 112: /* setsid */
        frame->rax = (u64)new_session();
        break;
    default:
        frame->rax = (u64)linux64_syscall(number, frame->rdi, frame->rsi, frame->rdx,
                                          frame->r10, frame->r8, frame->r9);
    }
    schedule(frame);
}
