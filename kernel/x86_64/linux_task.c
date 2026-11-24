#include "linux_task.h"
#include "paging.h"

enum {
    EPERM = 1, ESRCH = 3, ECHILD = 10, EAGAIN = 11, ENOMEM = 12, EFAULT = 14,
    EINVAL = 22, ENOSYS = 38,
    SIGCHLD = 17, CLONE_VM = 0x100, CLONE_VFORK = 0x4000,
    CHILD_CLEARTID = 0x200000, CHILD_SETTID = 0x1000000,
    SA_NOCLDWAIT = 2, SIG_IGN = 1,
    WNOHANG = 1, WUNTRACED = 2, WEXITED = 4, WCONTINUED = 8, WNOWAIT = 0x01000000,
    P_ALL = 0, P_PID = 1, P_PGID = 2,
    CLD_EXITED = 1, CLD_KILLED = 2,
};

static struct linux64_task tasks[LINUX64_TASK_COUNT];
static struct linux64_address_space address_spaces[LINUX64_TASK_COUNT];
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
    linux64_current->memory = &address_spaces[0];
    linux64_current->memory->root = paging64_active_root();
    linux64_current->memory->references = 1;
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

static struct linux64_address_space *fork_memory(const struct linux64_address_space *parent) {
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_address_space *child = &address_spaces[i];
        if (child->references) continue;
        uptr root = paging64_fork_root();
        if (!root) return NULL;
        child->root = root;
        child->references = 1;
        child->reserve_count = parent->reserve_count;
        for (unsigned j = 0; j < parent->reserve_count; ++j) child->reserves[j] = parent->reserves[j];
        return child;
    }
    return NULL;
}

static void release_memory(struct linux64_task *task) {
    struct linux64_address_space *memory = task->memory;
    task->memory = NULL;
    if (!--memory->references) {
        paging64_drop_root(memory->root);
        memory->root = 0;
    }
}

static long fork_task(struct linux64_frame *frame, uptr flags, uptr stack, uptr tid) {
    bool shared = flags == (CLONE_VM | CLONE_VFORK | SIGCHLD);
    if ((!shared && (stack || (flags & ~(CHILD_CLEARTID | CHILD_SETTID)) != SIGCHLD)) ||
        !xstate_supported) return -ENOSYS;
    if (stack >= X64_USER_TOP) return -EINVAL;
    unsigned slot = 1;
    while (slot < LINUX64_TASK_COUNT && tasks[slot].state != TASK_FREE) ++slot;
    if (slot == LINUX64_TASK_COUNT || next_pid == 0x7fffffff) return -EAGAIN;
    struct linux64_task *child = &tasks[slot];
    struct linux64_task *parent = linux64_current;
    struct linux64_address_space *memory = shared ? parent->memory : fork_memory(parent->memory);
    if (!memory) return -ENOMEM;
    if (shared) ++memory->references;
    child->frame = *frame;
    child->frame.rax = 0;
    if (stack) child->frame.rsp = stack;
    child->memory = memory;
    child->pid = next_pid++;
    child->ppid = parent->pid;
    child->sid = parent->sid;
    child->pgid = parent->pgid;
    child->child_tid = flags & CHILD_SETTID ? tid : 0;
    child->finish_wait = false;
    child->vfork_child = 0;
    child->signal_mask = parent->signal_mask;
    for (unsigned i = 0; i < LINUX64_SIGNAL_COUNT; ++i) child->actions[i] = parent->actions[i];
    for (unsigned i = 0; i < LINUX64_FD_COUNT; ++i) child->fds[i] = parent->fds[i];
    linux64_retain_files(child);
    save_state(child);
    child->state = TASK_RUNNABLE;
    if (shared) {
        parent->vfork_child = child->pid;
        parent->state = TASK_VFORK_WAIT;
    }
    return child->pid;
}

static bool wait_matches(const struct linux64_task *parent, const struct linux64_task *child,
                         const struct linux64_wait *wait) {
    return child->state != TASK_FREE && child->state != TASK_DEAD && child->ppid == parent->pid &&
           (wait->kind == P_ALL || (wait->kind == P_PID && child->pid == wait->filter) ||
            (wait->kind == P_PGID && child->pgid == wait->filter));
}

/* x86-64 siginfo_t: union начинается на смещении 16 и дополняется до 128 байт. */
struct wait_siginfo {
    i32 signo, error, code, padding;
    i32 pid;
    u32 uid;
    i32 status;
    u8 reserved[100];
};

_Static_assert(sizeof(struct wait_siginfo) == 128, "Linux x86-64 siginfo");

static long wait_result(const struct linux64_wait *wait, i32 pid, i32 status) {
    if (!wait->address) return wait->signal_info ? 0 : pid;
    if (wait->signal_info) {
        struct wait_siginfo info = {0};
        if (wait->address > X64_USER_TOP - sizeof(info)) return -EFAULT;
        if (pid) {
            i32 signal = status & 0x7f;
            info.signo = SIGCHLD;
            info.code = signal ? CLD_KILLED : CLD_EXITED;
            info.pid = pid;
            info.uid = LINUX64_UID;
            info.status = signal ? signal : status >> 8;
        }
        uptr header = __builtin_offsetof(struct wait_siginfo, padding);
        uptr payload = __builtin_offsetof(struct wait_siginfo, pid);
        uptr length = __builtin_offsetof(struct wait_siginfo, reserved) - payload;
        if (paging64_copy_to_user(wait->address, &info, header) != header ||
            paging64_copy_to_user(wait->address + payload, &info.pid, length) != length)
            return -EFAULT;
        return 0;
    }
    return paging64_copy_to_user(wait->address, &status, sizeof(status)) == sizeof(status) ? pid : -EFAULT;
}

static long wait_error(const struct linux64_wait *wait, i32 error) {
    if (wait->signal_info && wait_result(wait, 0, 0) < 0) return -EFAULT;
    return error;
}

static long wait_child(struct linux64_wait wait) {
    struct linux64_task *parent = linux64_current;
    bool found = false;
    for (unsigned i = 1; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *child = &tasks[i];
        if (!wait_matches(parent, child, &wait)) continue;
        found = true;
        if (child->state != TASK_ZOMBIE) continue;
        if (!(wait.options & WNOWAIT)) child->state = TASK_FREE;
        return wait_result(&wait, child->pid, child->exit_status);
    }
    if (!found) return wait_error(&wait, -ECHILD);
    if (wait.options & WNOHANG) return wait.signal_info ? wait_result(&wait, 0, 0) : 0;
    parent->wait = wait;
    parent->state = TASK_WAITING;
    return 0;
}

static long wait4(i32 pid, uptr address, u32 options, uptr usage) {
    if (usage || (options & ~(WNOHANG | WUNTRACED | WCONTINUED))) return -EINVAL;
    if (pid == -0x7fffffff - 1) return -ESRCH;
    struct linux64_wait wait = {.address = address, .options = options};
    if (pid > 0) {
        wait.kind = P_PID;
        wait.filter = pid;
    } else if (pid != -1) {
        wait.kind = P_PGID;
        wait.filter = pid ? -pid : linux64_current->pgid;
    }
    return wait_child(wait);
}

static long waitid(i32 kind, i32 id, uptr address, u32 options, uptr usage) {
    struct linux64_wait wait = {
        .address = address, .kind = kind, .filter = id, .options = options, .signal_info = true,
    };
    if (usage || !(options & WEXITED) || (options & ~(WEXITED | WNOHANG | WNOWAIT)) ||
        (kind != P_ALL && kind != P_PID && kind != P_PGID) ||
        (kind == P_PID && id <= 0) || (kind == P_PGID && id < 0))
        return wait_error(&wait, -EINVAL);
    if (kind == P_PGID && !id) wait.filter = linux64_current->pgid;
    return wait_child(wait);
}

static void publish_child_exit(struct linux64_task *child) {
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *parent = &tasks[i];
        if (parent->state == TASK_FREE || parent->pid != child->ppid) continue;
        const struct linux64_sigaction *action = &parent->actions[SIGCHLD - 1];
        if (action->handler == SIG_IGN || (action->flags & SA_NOCLDWAIT))
            child->state = child->memory ? TASK_DEAD : TASK_FREE;
        if (parent->state != TASK_WAITING) return;
        bool live_child = false;
        for (unsigned j = 1; j < LINUX64_TASK_COUNT; ++j) {
            if (!wait_matches(parent, &tasks[j], &parent->wait)) continue;
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

static void complete_vfork(const struct linux64_task *child) {
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *parent = &tasks[i];
        if (parent->state != TASK_VFORK_WAIT || parent->vfork_child != child->pid) continue;
        parent->vfork_child = 0;
        parent->state = TASK_RUNNABLE;
        return;
    }
}

static void finish_child(i32 wait_status) {
    struct linux64_task *task = linux64_current;
    linux64_close_files(task);
    task->exit_status = wait_status;
    task->state = TASK_ZOMBIE;
    complete_vfork(task);
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
    if (next->memory != old->memory) paging64_switch_root(next->memory->root);
    linux64_current = next;
    if (exited) {
        release_memory(old);
        if (old->state == TASK_DEAD) old->state = TASK_FREE;
    }
    restore_state(next);
    if (next->child_tid) {
        paging64_copy_to_user(next->child_tid, &next->pid, sizeof(next->pid));
        next->child_tid = 0;
    }
    if (next->finish_wait) {
        next->finish_wait = false;
        struct linux64_wait wait = next->wait;
        wait.options |= WNOHANG;
        next->frame.rax = (u64)wait_child(wait);
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
    case 56: /* clone */
        frame->rax = (u64)fork_task(frame, frame->rdi, frame->rsi, frame->r10);
        break;
    case 57: /* fork */
        frame->rax = (u64)fork_task(frame, SIGCHLD, 0, 0);
        break;
    case 58: /* vfork */
        frame->rax = (u64)fork_task(frame, CLONE_VM | CLONE_VFORK | SIGCHLD, 0, 0);
        break;
    case 60: /* exit */
    case 231: /* exit_group */
        exit_task((u32)frame->rdi);
        break;
    case 61: /* wait4 */
        frame->rax = (u64)wait4((i32)frame->rdi, frame->rsi, (u32)frame->rdx, frame->r10);
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
    case 247: /* waitid */
        frame->rax = (u64)waitid((i32)frame->rdi, (i32)frame->rsi, frame->rdx,
                                (u32)frame->r10, frame->r8);
        break;
    default:
        frame->rax = (u64)linux64_syscall(number, frame->rdi, frame->rsi, frame->rdx,
                                          frame->r10, frame->r8, frame->r9);
    }
    schedule(frame);
}
