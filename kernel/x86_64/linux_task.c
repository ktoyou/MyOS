#include "linux_task.h"
#include "paging.h"

enum {
    EPERM = 1, ESRCH = 3, ECHILD = 10, EAGAIN = 11, ENOMEM = 12, EFAULT = 14,
    EINVAL = 22, ENOSYS = 38,
    SIGCHLD = 17, CLONE_VM = 0x100, CLONE_FS = 0x200, CLONE_FILES = 0x400,
    CLONE_SIGHAND = 0x800, CLONE_VFORK = 0x4000, CLONE_THREAD = 0x10000,
    CLONE_SYSVSEM = 0x40000, CLONE_SETTLS = 0x80000, CLONE_PARENT_SETTID = 0x100000,
    CHILD_CLEARTID = 0x200000, CHILD_SETTID = 0x1000000,
    PTHREAD_FLAGS = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
                    CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CHILD_CLEARTID,
    FUTEX_WAIT = 0, FUTEX_WAKE = 1, FUTEX_WAIT_BITSET = 9, FUTEX_WAKE_BITSET = 10,
    FUTEX_PRIVATE_FLAG = 128, FUTEX_CLOCK_REALTIME = 256,
    SA_NOCLDWAIT = 2, SIG_IGN = 1,
    WNOHANG = 1, WUNTRACED = 2, WEXITED = 4, WCONTINUED = 8, WNOWAIT = 0x01000000,
    P_ALL = 0, P_PID = 1, P_PGID = 2,
    CLD_EXITED = 1, CLD_KILLED = 2,
};

static struct linux64_task tasks[LINUX64_TASK_COUNT];
static struct linux64_process processes[LINUX64_TASK_COUNT];
static struct linux64_address_space address_spaces[LINUX64_TASK_COUNT];
struct linux64_task *linux64_current = &tasks[0];
static i32 next_pid = LINUX64_PID + 1;
static u64 xfeatures;
static bool xstate_supported;

extern __attribute__((noreturn)) void linux64_task_resume(struct linux64_frame *frame);

_Static_assert(sizeof(struct linux64_frame) == 20 * sizeof(u64), "Linux syscall frame size");
_Static_assert(__builtin_offsetof(struct linux64_frame, rip) == 15 * sizeof(u64), "Linux IRET frame");

void linux64_task_init(void) {
    processes[0] = (struct linux64_process){
        .pid = LINUX64_PID, .sid = LINUX64_PID, .pgid = LINUX64_PID, .threads = 1,
    };
    linux64_current->tid = LINUX64_PID;
    linux64_current->process = &processes[0];
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

static struct linux64_address_space *unused_memory(void) {
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i)
        if (!address_spaces[i].references) return &address_spaces[i];
    return NULL;
}

static struct linux64_address_space *fork_memory(const struct linux64_address_space *parent) {
    struct linux64_address_space *child = unused_memory();
    if (!child) return NULL;
    uptr root = paging64_fork_root();
    if (!root) return NULL;
    child->root = root;
    child->references = 1;
    child->reserve_count = parent->reserve_count;
    for (unsigned i = 0; i < parent->reserve_count; ++i) child->reserves[i] = parent->reserves[i];
    return child;
}

static void release_memory(struct linux64_task *task) {
    struct linux64_address_space *memory = task->memory;
    task->memory = NULL;
    if (!--memory->references) {
        paging64_drop_root(memory->root);
        memory->root = 0;
    }
}

static struct linux64_process *unused_process(void) {
    for (unsigned i = 1; i < LINUX64_TASK_COUNT; ++i)
        if (!processes[i].pid) return &processes[i];
    return NULL;
}

static long clone_task(struct linux64_frame *frame, uptr flags, uptr stack, uptr parent_tid,
                       uptr child_tid, uptr tls) {
    bool thread = flags == PTHREAD_FLAGS;
    bool vfork = flags == (CLONE_VM | CLONE_VFORK | SIGCHLD);
    bool shared = thread || vfork;
    if ((!shared && (stack || (flags & ~(CHILD_CLEARTID | CHILD_SETTID)) != SIGCHLD)) ||
        !xstate_supported) return -ENOSYS;
    if (stack >= X64_USER_TOP || (thread && (!stack || tls >= X64_USER_TOP - PMM_PAGE_SIZE)))
        return -EINVAL;
    unsigned slot = 1;
    while (slot < LINUX64_TASK_COUNT && tasks[slot].state != TASK_FREE) ++slot;
    if (slot == LINUX64_TASK_COUNT || next_pid == 0x7fffffff) return -EAGAIN;
    struct linux64_task *child = &tasks[slot];
    struct linux64_task *parent = linux64_current;
    struct linux64_process *process = thread ? parent->process : unused_process();
    if (!process) return -EAGAIN;
    struct linux64_address_space *memory = shared ? parent->memory : fork_memory(parent->memory);
    if (!memory) return -ENOMEM;
    if (shared) ++memory->references;
    child->frame = *frame;
    child->frame.rax = 0;
    if (stack) child->frame.rsp = stack;
    child->memory = memory;
    child->tid = next_pid++;
    child->process = process;
    child->child_tid = flags & CHILD_SETTID ? child_tid : 0;
    child->clear_child_tid = flags & CHILD_CLEARTID ? child_tid : 0;
    child->finish_wait = false;
    child->vfork_child = 0;
    child->signal_mask = parent->signal_mask;
    if (!thread) {
        *process = *parent->process;
        process->pid = child->tid;
        process->ppid = parent->process->pid;
        process->threads = 0;
        process->exit_status = 0;
        linux64_retain_files(process);
    }
    ++process->threads;
    save_state(child);
    if (thread) {
        child->fs = tls;
        child->fs_selector = 0;
        paging64_copy_to_user(parent_tid, &child->tid, sizeof(child->tid));
    }
    child->state = TASK_RUNNABLE;
    if (vfork) {
        parent->vfork_child = process->pid;
        parent->state = TASK_VFORK_WAIT;
    }
    return child->tid;
}

static bool wait_matches(const struct linux64_process *parent, const struct linux64_process *child,
                         const struct linux64_wait *wait) {
    return child->pid && child->ppid == parent->pid &&
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
        struct linux64_process *child = &processes[i];
        if (!wait_matches(parent->process, child, &wait)) continue;
        found = true;
        if (child->threads) continue;
        i32 pid = child->pid;
        if (!(wait.options & WNOWAIT)) child->pid = 0;
        long result = wait_result(&wait, pid, child->exit_status);
        return result;
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
        wait.filter = pid ? -pid : linux64_current->process->pgid;
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
    if (kind == P_PGID && !id) wait.filter = linux64_current->process->pgid;
    return wait_child(wait);
}

static void publish_child_exit(struct linux64_process *child) {
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_process *parent = &processes[i];
        if (parent->pid != child->ppid) continue;
        const struct linux64_sigaction *action = &parent->actions[SIGCHLD - 1];
        bool auto_reap = action->handler == SIG_IGN || (action->flags & SA_NOCLDWAIT);
        for (unsigned j = 0; j < LINUX64_TASK_COUNT; ++j) {
            struct linux64_task *waiter = &tasks[j];
            if (waiter->state != TASK_WAITING || waiter->process != parent ||
                !wait_matches(parent, child, &waiter->wait)) continue;
            waiter->finish_wait = true;
            waiter->state = TASK_RUNNABLE;
        }
        if (auto_reap) child->pid = 0;
        return;
    }
}

static void complete_vfork(i32 child_pid) {
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *parent = &tasks[i];
        if (parent->state != TASK_VFORK_WAIT || parent->vfork_child != child_pid) continue;
        parent->vfork_child = 0;
        parent->state = TASK_RUNNABLE;
        return;
    }
}

/* Новый CR3 уже активен, поэтому последнее освобождение старого корня безопасно. */
bool linux64_commit_exec(struct linux64_frame *frame, uptr root, uptr entry, uptr stack,
                        const char *path, uptr path_length) {
    if (!xstate_supported) return false;
    struct linux64_task *task = linux64_current;
    struct linux64_process *process = task->process;
    struct linux64_address_space *old = task->memory;
    struct linux64_address_space *memory = old->references == 1 ? old : unused_memory();
    if (!memory) return false;
    if (memory == old) paging64_drop_root(old->root);
    else release_memory(task);
    memory->root = root;
    memory->references = 1;
    memory->reserve_count = 0;
    task->memory = memory;

    linux64_close_on_exec(process);
    for (unsigned i = 0; i < LINUX64_SIGNAL_COUNT; ++i) {
        u64 handler = process->actions[i].handler;
        process->actions[i] = (struct linux64_sigaction){.handler = handler == SIG_IGN ? handler : 0};
    }
    task->child_tid = 0;
    task->clear_child_tid = 0;
    task->tid = process->pid;
    process->executable_path_length = path_length;
    for (uptr i = 0; i <= path_length; ++i) process->executable_path[i] = path[i];
    task->fs = task->gs = 0;
    task->fs_selector = task->gs_selector = 0;
    task->ds_selector = task->es_selector = 0x1b;
    for (uptr i = 0; i < sizeof(task->xstate); ++i) task->xstate[i] = 0;
    if (!xfeatures) {
        /* FXRSTOR принимает начальные x87 control word и MXCSR явно. */
        task->xstate[0] = 0x7f;
        task->xstate[1] = 0x03;
        task->xstate[24] = 0x80;
        task->xstate[25] = 0x1f;
    }
    restore_state(task);
    *frame = (struct linux64_frame){.rip = entry, .cs = 0x23, .rflags = 2, .rsp = stack, .ss = 0x1b};
    complete_vfork(process->pid);
    return true;
}

static void halt_init(u32 status) {
    static const char message[] = "Linux x86-64 exit status=0x";
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
    kernel64_serial_char(digits[(status >> 4) & 15u]);
    kernel64_serial_char(digits[status & 15u]);
    kernel64_serial_char('\r');
    kernel64_serial_char('\n');
    for (;;) __asm__ volatile("cli; hlt");
}

long linux64_futex(uptr address, u32 operation, u32 value, uptr timeout, u32 bits) {
    bool private = (operation & FUTEX_PRIVATE_FLAG) != 0;
    u32 command = operation & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if ((operation & FUTEX_CLOCK_REALTIME) && command != FUTEX_WAIT_BITSET) return -ENOSYS;
    bool wait = command == FUTEX_WAIT || command == FUTEX_WAIT_BITSET;
    if (!wait && command != FUTEX_WAKE && command != FUTEX_WAKE_BITSET) return -ENOSYS;
    if (command == FUTEX_WAIT || command == FUTEX_WAKE) bits = (u32)-1;
    if (!bits) return -EINVAL;
    if (address & (sizeof(u32) - 1)) return -EINVAL;
    if (address > X64_USER_TOP - sizeof(u32) ||
        (!private && !paging64_shared_futex_address(address))) return -EFAULT;
    const struct linux64_address_space *memory = linux64_current->memory;
    if (wait) {
        if (timeout) return -ENOSYS;
        u32 actual;
        if (paging64_copy_from_user(&actual, address, sizeof(actual)) != sizeof(actual)) return -EFAULT;
        if (actual != value) return -EAGAIN;
        /* На одном CPU между проверкой слова и постановкой в очередь никто его не изменит. */
        linux64_current->futex = (struct linux64_futex_wait){memory, address, bits, private};
        linux64_current->state = TASK_FUTEX_WAIT;
        return 0;
    }
    i32 woken = 0;
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_task *task = &tasks[i];
        const struct linux64_futex_wait *entry = &task->futex;
        if (task->state != TASK_FUTEX_WAIT || entry->memory != memory || entry->address != address ||
            entry->private != private || !(entry->bits & bits)) continue;
        task->frame.rax = 0;
        task->state = TASK_RUNNABLE;
        if (++woken >= (i32)value) break;
    }
    return woken;
}

static void stop_task(struct linux64_task *task) {
    const u32 zero = 0;
    uptr address = task->clear_child_tid;
    if (address && task->memory->references > 1 &&
        paging64_copy_to_user(address, &zero, sizeof(zero)) == sizeof(zero))
        linux64_futex(address, FUTEX_WAKE, 1, 0, 0);
    linux64_pipe_finish(task);
    task->state = TASK_DEAD;
    --task->process->threads;
}

static void finish_task(i32 wait_status, bool group) {
    struct linux64_task *task = linux64_current;
    struct linux64_process *process = task->process;
    stop_task(task);
    if (group) {
        for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i) {
            struct linux64_task *peer = &tasks[i];
            if (peer->state == TASK_FREE || peer->state == TASK_DEAD || peer->process != process)
                continue;
            stop_task(peer);
            release_memory(peer);
            peer->state = TASK_FREE;
        }
    }
    if (process->threads) return;
    process->exit_status = wait_status;
    linux64_close_files(process);
    if (process->pid == LINUX64_PID) halt_init((u32)process->exit_status >> 8);
    complete_vfork(process->pid);
    for (unsigned i = 1; i < LINUX64_TASK_COUNT; ++i) {
        struct linux64_process *orphan = &processes[i];
        if (!orphan->pid || orphan->ppid != process->pid) continue;
        orphan->ppid = LINUX64_PID;
        if (!orphan->threads) publish_child_exit(orphan);
    }
    publish_child_exit(process);
}

static long new_session(void) {
    struct linux64_process *process = linux64_current->process;
    for (unsigned i = 0; i < LINUX64_TASK_COUNT; ++i)
        if (processes[i].pid && processes[i].pgid == process->pid) return -EPERM;
    process->sid = process->pgid = process->pid;
    return process->sid;
}

static struct linux64_task *pick_task(const struct linux64_task *current) {
    unsigned index = (unsigned)(current - tasks);
    bool timed;
    do {
        timed = false;
        for (unsigned i = 1; i <= LINUX64_TASK_COUNT; ++i) {
            struct linux64_task *candidate = &tasks[(index + i) % LINUX64_TASK_COUNT];
            if (candidate->state == TASK_RUNNABLE ||
                (candidate->state == TASK_PIPE_WAIT && linux64_pipe_ready(&candidate->pipe_io)))
                return candidate;
            if (candidate->state != TASK_POLL_WAIT) continue;
            if (linux64_poll_ready(candidate)) return candidate;
            if (candidate->poll.deadline) timed = true;
        }
        /* Таймерных прерываний в этом режиме пока нет. */
        if (timed) __asm__ volatile("pause");
    } while (timed);
    static const char message[] = "Linux x86-64 scheduler has no runnable process\n";
    for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
    for (;;) __asm__ volatile("cli; hlt");
}

static void resume_wait(struct linux64_task *task) {
    if (task->state == TASK_POLL_WAIT) {
        task->frame.rax = (u64)linux64_poll_resume(task);
        task->state = TASK_RUNNABLE;
    }
    if (task->state == TASK_PIPE_WAIT) {
        task->state = TASK_RUNNABLE;
        task->frame.rax = (u64)linux64_pipe_resume();
        if (task->state == TASK_RUNNABLE) linux64_pipe_finish(task);
    }
    if (task->finish_wait) {
        task->finish_wait = false;
        task->frame.rax = (u64)wait_child(task->wait);
    }
}

static void schedule(struct linux64_frame *frame) {
    struct linux64_task *old = linux64_current;
    struct linux64_task *next = pick_task(old);
    if (next == old) {
        if (old->state == TASK_POLL_WAIT) {
            frame->rax = (u64)linux64_poll_resume(old);
            old->state = TASK_RUNNABLE;
        }
        return;
    }
    bool exited = old->state == TASK_DEAD;
    if (!exited) {
        old->frame = *frame;
        save_state(old);
    }
    if (next->memory != old->memory) paging64_switch_root(next->memory->root);
    linux64_current = next;
    if (exited) {
        release_memory(old);
        old->state = TASK_FREE;
    }
    for (;;) {
        resume_wait(next);
        if (next->state == TASK_RUNNABLE) break;
        /* Другой поток мог забрать статус потомка, а длинная запись снова заполнить трубу. */
        struct linux64_task *ready = pick_task(next);
        if (ready->memory != next->memory) paging64_switch_root(ready->memory->root);
        linux64_current = next = ready;
    }
    restore_state(next);
    if (next->child_tid) {
        paging64_copy_to_user(next->child_tid, &next->tid, sizeof(next->tid));
        next->child_tid = 0;
    }
    *frame = next->frame;
}

void linux64_task_exception(u64 vector) {
    if (!linux64_current->process || linux64_current->process->pid == LINUX64_PID) return;
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
    if (linux64_current->process->actions[signal - 1].handler > SIG_IGN &&
        !(linux64_current->signal_mask & bit)) return;
    finish_task(signal, true);
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
        frame->rax = (u64)clone_task(frame, frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case 57: /* fork */
        frame->rax = (u64)clone_task(frame, SIGCHLD, 0, 0, 0, 0);
        break;
    case 58: /* vfork */
        frame->rax = (u64)clone_task(frame, CLONE_VM | CLONE_VFORK | SIGCHLD, 0, 0, 0, 0);
        break;
    case 59: /* execve */
        frame->rax = linux64_current->process->threads == 1 ?
            (u64)linux64_execve(frame, frame->rdi, frame->rsi, frame->rdx) : (u64)-ENOSYS;
        break;
    case 60: /* exit */
    case 231: /* exit_group */
        finish_task((i32)((frame->rdi & 255u) << 8), number == 231);
        break;
    case 61: /* wait4 */
        frame->rax = (u64)wait4((i32)frame->rdi, frame->rsi, (u32)frame->rdx, frame->r10);
        break;
    case 110: /* getppid */
        frame->rax = (u64)linux64_current->process->ppid;
        break;
    case 111: /* getpgrp */
        frame->rax = (u64)linux64_current->process->pgid;
        break;
    case 112: /* setsid */
        frame->rax = (u64)new_session();
        break;
    case 218: /* set_tid_address */
        linux64_current->clear_child_tid = frame->rdi;
        frame->rax = (u64)linux64_current->tid;
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
