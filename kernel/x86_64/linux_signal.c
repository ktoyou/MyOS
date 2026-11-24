#include "linux_task.h"
#include "paging.h"

#define SIGKILL 9
#define SIGSTOP 19
#define UNBLOCKABLE_SIGNALS ((1ull << (SIGKILL - 1)) | (1ull << (SIGSTOP - 1)))
#define SA_USER_FLAGS 0xdc000807ull

enum { SIG_BLOCK = 0, SIG_UNBLOCK = 1, SIG_SETMASK = 2 };

_Static_assert(sizeof(struct linux64_sigaction) == 32, "Linux x86-64 sigaction size");

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
