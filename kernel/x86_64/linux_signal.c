#include "linux_task.h"
#include "paging.h"

#define SIGKILL 9
#define SIGSTOP 19
#define SIGSYS 31
#define UNBLOCKABLE_SIGNALS ((1ull << (SIGKILL - 1)) | (1ull << (SIGSTOP - 1)))
#define SA_USER_FLAGS 0xdc000807ull
#define SA_SIGINFO 0x00000004ull
#define SA_RESTORER 0x04000000ull
#define SA_NODEFER 0x40000000ull
#define SA_RESETHAND 0x80000000ull

#define USER_CS 0x23
#define USER_SS 0x1b
#define USER_RFLAGS 0x240dd5ull  /* Маска из linux_syscall.asm. */
#define SIGNAL_CLEAR_RFLAGS 0x10500ull  /* TF, DF, RF. */

enum {
    SIG_BLOCK = 0, SIG_UNBLOCK = 1, SIG_SETMASK = 2,
    SYS_SECCOMP = 1, SS_DISABLE = 2, UC_SIGCONTEXT_SS = 2, UC_STRICT_RESTORE_SS = 4,
    USER_RED_ZONE = 128,
};

_Static_assert(sizeof(struct linux64_sigaction) == 32, "Linux x86-64 sigaction size");

struct linux64_sigsys_info {
    i32 signal, error, code;
    u32 padding;
    u64 call_address;
    i32 syscall;
    u32 arch;
    u8 reserved[96];
};

struct linux64_sigcontext {
    u64 r8, r9, r10, r11, r12, r13, r14, r15;
    u64 rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, rflags;
    u16 cs, gs, fs, ss;
    u64 error, trap_number, old_mask, cr2, fpstate;
    u64 reserved[8];
};

struct linux64_ucontext {
    u64 flags, link;
    struct {
        u64 pointer;
        i32 flags;
        u32 padding;
        u64 size;
    } stack;
    struct linux64_sigcontext registers;
    u64 signal_mask;
};

struct linux64_rt_sigframe {
    u64 restorer;
    struct linux64_ucontext context;
    struct linux64_sigsys_info info;
};

_Static_assert(sizeof(struct linux64_sigsys_info) == 128 &&
               __builtin_offsetof(struct linux64_sigsys_info, call_address) == 16 &&
               __builtin_offsetof(struct linux64_sigsys_info, syscall) == 24 &&
               __builtin_offsetof(struct linux64_sigsys_info, arch) == 28, "Linux x86-64 SIGSYS siginfo");
_Static_assert(sizeof(struct linux64_sigcontext) == 256 &&
               __builtin_offsetof(struct linux64_sigcontext, rax) == 104 &&
               __builtin_offsetof(struct linux64_sigcontext, rip) == 128, "Linux x86-64 sigcontext");
_Static_assert(__builtin_offsetof(struct linux64_ucontext, registers) == 40 &&
               __builtin_offsetof(struct linux64_ucontext, signal_mask) == 296, "Linux x86-64 ucontext");
_Static_assert(sizeof(struct linux64_rt_sigframe) == 440 &&
               __builtin_offsetof(struct linux64_rt_sigframe, context) == 8 &&
               __builtin_offsetof(struct linux64_rt_sigframe, info) == 312, "Linux x86-64 rt_sigframe");

static bool user_register_address(u64 address) {
    return address >= 0x400000ul && address < X64_USER_TOP;
}

bool linux64_deliver_seccomp_sigsys(struct linux64_frame *frame, u16 trap, u32 arch, uptr *user_frame) {
    struct linux64_task *task = linux64_current;
    struct linux64_sigaction *slot = &task->process->actions[SIGSYS - 1];
    const struct linux64_sigaction action = *slot;
    const u64 sigsys_bit = 1ull << (SIGSYS - 1);
    if ((task->signal_mask & sigsys_bit) || !(action.flags & SA_SIGINFO) || !(action.flags & SA_RESTORER) ||
        !user_register_address(action.handler) || !user_register_address(action.restorer) ||
        !user_register_address(frame->rsp) || frame->rsp < USER_RED_ZONE + sizeof(struct linux64_rt_sigframe) + 16)
        return false;

    /* Сохраняем red zone и обеспечиваем RSP % 16 == 8 на входе в обработчик. */
    uptr address = ((frame->rsp - USER_RED_ZONE - sizeof(struct linux64_rt_sigframe)) & ~15ul) - 8;
    struct linux64_rt_sigframe user = {
        .restorer = action.restorer,
        .context = {
            .flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS,
            .stack = {.flags = SS_DISABLE},
            .registers = {
                .r8 = frame->r8, .r9 = frame->r9, .r10 = frame->r10, .r11 = frame->r11,
                .r12 = frame->r12, .r13 = frame->r13, .r14 = frame->r14, .r15 = frame->r15,
                .rdi = frame->rdi, .rsi = frame->rsi, .rbp = frame->rbp, .rbx = frame->rbx,
                .rdx = frame->rdx, .rax = frame->rax, .rcx = frame->rcx, .rsp = frame->rsp,
                .rip = frame->rip, .rflags = frame->rflags, .cs = USER_CS, .ss = USER_SS,
                .old_mask = task->signal_mask,
            },
            .signal_mask = task->signal_mask,
        },
        .info = {.signal = SIGSYS, .error = trap, .code = SYS_SECCOMP, .call_address = frame->rip,
                 .syscall = (i32)frame->rax, .arch = arch},
    };
    if (paging64_copy_to_user(address, &user, sizeof(user)) != sizeof(user)) return false;

    task->signal_mask |= action.mask;
    if (!(action.flags & SA_NODEFER)) task->signal_mask |= sigsys_bit;
    if (action.flags & SA_RESETHAND) *slot = (struct linux64_sigaction){0};
    frame->rsp = address;
    frame->rip = action.handler;
    frame->rdi = SIGSYS;
    frame->rsi = address + __builtin_offsetof(struct linux64_rt_sigframe, info);
    frame->rdx = address + __builtin_offsetof(struct linux64_rt_sigframe, context);
    frame->rax = 0;
    frame->rflags &= ~SIGNAL_CLEAR_RFLAGS;
    *user_frame = address;
    return true;
}

bool linux64_rt_sigreturn(struct linux64_frame *frame, uptr user_frame) {
    if (!user_register_address(user_frame) || user_frame > X64_USER_TOP - sizeof(struct linux64_rt_sigframe) ||
        frame->rsp != user_frame + sizeof(u64)) return false;

    struct linux64_ucontext context;
    uptr address = user_frame + __builtin_offsetof(struct linux64_rt_sigframe, context);
    if (paging64_copy_from_user(&context, address, sizeof(context)) != sizeof(context)) return false;
    const struct linux64_sigcontext *regs = &context.registers;
    if (regs->cs != USER_CS || regs->ss != USER_SS || !user_register_address(regs->rip) ||
        !user_register_address(regs->rsp) || regs->fpstate) return false;

    /* Расширенное состояние восстанавливает вызывающий код из памяти ядра. */
    *frame = (struct linux64_frame){
        .rcx = regs->rcx, .r11 = regs->r11, .rax = regs->rax, .r9 = regs->r9, .r8 = regs->r8,
        .r10 = regs->r10, .rdx = regs->rdx, .rsi = regs->rsi, .rdi = regs->rdi, .r15 = regs->r15,
        .r14 = regs->r14, .r13 = regs->r13, .r12 = regs->r12, .rbp = regs->rbp, .rbx = regs->rbx,
        .rip = regs->rip, .cs = USER_CS, .rflags = (regs->rflags & USER_RFLAGS) | 2,
        .rsp = regs->rsp, .ss = USER_SS,
    };
    linux64_current->signal_mask = context.signal_mask & ~UNBLOCKABLE_SIGNALS;
    return true;
}

void linux64_reset_signals(void) {
    for (unsigned i = 0; i < LINUX64_SIGNAL_COUNT; ++i)
        linux64_current->process->actions[i] = (struct linux64_sigaction){0};
    linux64_current->signal_mask = 0;
}

long linux64_rt_sigaction(i32 signal, uptr action, uptr previous, uptr sigset_size) {
    struct linux64_sigaction input;
    if (sigset_size != sizeof(input.mask)) return -22;
    if (action && paging64_copy_from_user(&input, action, sizeof(input)) != sizeof(input))
        return -14;
    if (signal < 1 || signal > (i32)LINUX64_SIGNAL_COUNT ||
        (action && (signal == SIGKILL || signal == SIGSTOP))) return -22;
    struct linux64_sigaction *slot = &linux64_current->process->actions[signal - 1];
    const struct linux64_sigaction old = *slot;
    if (action) {
        input.flags &= SA_USER_FLAGS;
        input.mask &= ~UNBLOCKABLE_SIGNALS;
        *slot = input;
    }
    /* Ошибка при копировании прежнего действия не отменяет установку нового. */
    if (previous && paging64_copy_to_user(previous, &old, sizeof(old)) != sizeof(old))
        return -14;
    return 0;
}

long linux64_read_signal_mask(uptr set, uptr sigset_size, u64 *mask) {
    if (sigset_size != sizeof(*mask)) return -22;
    if (paging64_copy_from_user(mask, set, sizeof(*mask)) != sizeof(*mask)) return -14;
    *mask &= ~UNBLOCKABLE_SIGNALS;
    return 0;
}

long linux64_rt_sigprocmask(i32 how, uptr set, uptr previous, uptr sigset_size) {
    if (sigset_size != sizeof(u64)) return -22;
    const u64 old = linux64_current->signal_mask;
    if (set) {
        u64 input;
        long result = linux64_read_signal_mask(set, sigset_size, &input);
        if (result) return result;
        switch (how) {
        case SIG_BLOCK:
            linux64_current->signal_mask |= input;
            break;
        case SIG_UNBLOCK:
            linux64_current->signal_mask &= ~input;
            break;
        case SIG_SETMASK:
            linux64_current->signal_mask = input;
            break;
        default:
            return -22;
        }
    }
    if (previous && paging64_copy_to_user(previous, &old, sizeof(old)) != sizeof(old))
        return -14;
    return 0;
}
