#include "linux.h"
#include "paging.h"

#define SIGNAL_COUNT 64
#define SIGKILL 9
#define SIGSTOP 19
#define SA_USER_FLAGS 0xdc000807ull

struct linux_sigaction {
    u64 handler, flags, restorer, mask;
};

_Static_assert(sizeof(struct linux_sigaction) == 32, "Linux x86-64 sigaction size");

static struct linux_sigaction actions[SIGNAL_COUNT];

void linux64_reset_signals(void) {
    for (unsigned i = 0; i < SIGNAL_COUNT; ++i)
        actions[i] = (struct linux_sigaction){0};
}

long linux64_rt_sigaction(i32 signal, uptr action, uptr previous, uptr sigset_size) {
    struct linux_sigaction input;
    if (sigset_size != sizeof(input.mask)) return -22;
    if (action && paging64_copy_from_user(&input, action, sizeof(input)) != sizeof(input))
        return -14;
    if (signal < 1 || signal > SIGNAL_COUNT ||
        (action && (signal == SIGKILL || signal == SIGSTOP))) return -22;
    struct linux_sigaction *slot = &actions[signal - 1];
    const struct linux_sigaction old = *slot;
    if (action) {
        input.flags &= SA_USER_FLAGS;
        input.mask &= ~((1ull << (SIGKILL - 1)) | (1ull << (SIGSTOP - 1)));
        *slot = input;
    }
    /* Ошибка при копировании прежнего действия не отменяет установку нового. */
    if (previous && paging64_copy_to_user(previous, &old, sizeof(old)) != sizeof(old))
        return -14;
    return 0;
}
