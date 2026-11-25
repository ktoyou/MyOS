typedef unsigned long word;

enum {
    SYS_READ = 0, SYS_WRITE = 1, SYS_CLOSE = 3, SYS_RT_SIGACTION = 13, SYS_RT_SIGPROCMASK = 14,
    SYS_PIPE = 22, SYS_FORK = 57, SYS_EXIT = 60, SYS_WAIT4 = 61, SYS_GETUID = 102,
    SYS_GETTID = 186, SYS_FUTEX = 202, SYS_PPOLL = 271,
    SIG_SETMASK = 2, SIGCHLD = 17, SIG_IGN = 1, CLD_EXITED = 1,
    SA_NOCLDWAIT = 2, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, SA_RESTART = 0x10000000,
    EINTR = 4, ECHILD = 10, EAGAIN = 11, POLLIN = 1,
};

struct signal_action { word handler, flags; void (*restore)(void); word mask; };
struct child_info { int signal, error, code, padding, pid; unsigned uid; int status; };
struct signal_context { word header[5], before_rax[13]; long rax; word before_mask[18], mask; };
struct timespec { long seconds, nanos; };
struct pollfd { int fd; short events, revents; };

_Static_assert(__builtin_offsetof(struct child_info, status) == 24, "Linux x86-64 siginfo");
_Static_assert(__builtin_offsetof(struct signal_context, rax) == 144 &&
               __builtin_offsetof(struct signal_context, mask) == 296, "Linux x86-64 ucontext");

static const word child_bit = 1ul << (SIGCHLD - 1);
static const word original = (1ul << (SIGCHLD - 1)) | (1ul << (10 - 1));
static const word temporary = 1ul << (12 - 1), action_mask = 1ul << (14 - 1);
static volatile word seen_mask, context_mask;
static volatile long seen_tid, context_result;
static volatile unsigned calls;
static volatile struct child_info received;
static char sibling_stack[16384] __attribute__((aligned(16)));
static word sibling_tls;
static int sibling_pipe[2], sibling_parent_tid;
static int sibling_clear_tid, sibling_result;

extern long clone_sibling(word stack, int *parent_tid, int *clear_tid, const word *tls);

__asm__(
    ".text\n"
    "clone_sibling:\n"
    "mov %rdi,%r11\n"
    "mov %rcx,%r8\n"
    "mov %rdx,%r10\n"
    "mov %rsi,%rdx\n"
    "mov %r11,%rsi\n"
    "mov $0x3d0f00,%edi\n"
    "mov $56,%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "call sibling_main\n"
    "ud2\n"
    "1: ret\n"
);

static long call(word number, word a0, word a1, word a2, word a3, word a4) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long simple(word number, word a0) { return call(number, a0, 0, 0, 0, 0); }
static long read_fd(int fd, char *byte) { return call(SYS_READ, fd, (word)byte, 1, 0, 0); }
static long write_fd(int fd) { return call(SYS_WRITE, fd, (word)"g", 1, 0, 0); }

static __attribute__((noreturn)) void finish(int status) {
    simple(SYS_EXIT, status);
    __builtin_trap();
}

static __attribute__((naked)) void restore_signal(void) {
    __asm__ volatile("mov $15,%eax; syscall; ud2");
}

static long mask(const word *set, word *old) {
    return call(SYS_RT_SIGPROCMASK, SIG_SETMASK, (word)set, (word)old, sizeof(word), 0);
}

static void on_child(int signal) {
    word current;
    if (signal != SIGCHLD || mask(0, &current)) finish(2);
    seen_mask = current;
    seen_tid = simple(SYS_GETTID, 0);
    ++calls;
}

static void on_child_info(int signal, const struct child_info *info, const struct signal_context *context) {
    received = *info;
    context_mask = context->mask;
    context_result = context->rax;
    on_child(signal);
}

static long action(word handler, word flags) {
    const struct signal_action value = {handler, flags | SA_RESTORER, restore_signal, action_mask};
    return call(SYS_RT_SIGACTION, SIGCHLD, (word)&value, 0, sizeof(word), 0);
}

static long wait_child(long child, int *status) {
    return call(SYS_WAIT4, child, (word)status, 0, 0, 0);
}

static long exited_child(int exit_code) {
    long child = simple(SYS_FORK, 0);
    if (!child) finish(exit_code);
    return child;
}

static long ppoll(struct pollfd *fd, struct timespec *timeout, const word *sigmask) {
    return call(SYS_PPOLL, (word)fd, fd != 0, (word)timeout, (word)sigmask, sizeof(word));
}

static int saw_handler(unsigned count, long tid) {
    word current;
    return calls == count && seen_tid == tid && seen_mask == (temporary | action_mask | child_bit) &&
           !mask(0, &current) && current == original;
}

static int check_pending(long tid) {
    if (action((word)on_child_info, SA_SIGINFO | SA_RESTART)) return 3;
    long first = exited_child(41);
    int status;
    if (first < 0 || wait_child(first, &status) != first || status != (41 << 8) || calls) return 4;
    long second = exited_child(42);
    if (second < 0 || wait_child(second, &status) != second || status != (42 << 8) || calls) return 5;

    int ends[2];
    if (simple(SYS_PIPE, (word)ends) || write_fd(ends[1]) != 1) return 6;
    struct timespec timeout = {2, 0};
    struct pollfd fd = {ends[0], POLLIN, -1};
    if (ppoll(&fd, &timeout, &temporary) != 1 || fd.revents != POLLIN || calls) return 7;
    char byte;
    if (read_fd(ends[0], &byte) != 1 || byte != 'g') return 8;

    /* SIGCHLD остаётся ожидающим после wait4 и выдачи готового дескриптора. */
    timeout = (struct timespec){2, 0};
    fd.revents = -1;
    if (ppoll(&fd, &timeout, &temporary) != -EINTR || fd.revents || !saw_handler(1, tid)) return 9;
    if (received.signal != SIGCHLD || received.error || received.code != CLD_EXITED ||
        received.pid != first || received.uid != (unsigned)simple(SYS_GETUID, 0) || received.status != 41 ||
        context_result != -EINTR || context_mask != original) return 10;
    timeout = (struct timespec){0, 0};
    if (ppoll(0, &timeout, &temporary) || calls != 1 || simple(SYS_CLOSE, ends[0]) ||
        simple(SYS_CLOSE, ends[1])) return 11;
    return 0;
}

static int check_sleeping(long tid) {
    if (action((word)on_child, 0)) return 12;
    int ends[2];
    if (simple(SYS_PIPE, (word)ends)) return 13;
    long child = simple(SYS_FORK, 0);
    if (!child) {
        char byte;
        struct timespec delay = {0, 20000000};
        if (read_fd(ends[0], &byte) != 1 || byte != 'g' || ppoll(0, &delay, 0)) finish(3);
        finish(43);
    }
    if (child < 0 || write_fd(ends[1]) != 1) return 14;
    struct timespec timeout = {2, 0};
    if (ppoll(0, &timeout, &temporary) != -EINTR || !saw_handler(2, tid) || timeout.seconds < 0 ||
        timeout.seconds >= 2 || timeout.nanos < 0 || timeout.nanos >= 1000000000 ||
        (!timeout.seconds && !timeout.nanos)) return 15;
    int status;
    if (wait_child(child, &status) != child || status != (43 << 8) || simple(SYS_CLOSE, ends[0]) ||
        simple(SYS_CLOSE, ends[1])) return 16;
    return 0;
}

static int check_autoreap(long tid) {
    if (action((word)on_child, SA_NOCLDWAIT)) return 17;
    int status;
    long child = exited_child(44);
    if (child < 0 || wait_child(child, &status) != -ECHILD || calls != 2) return 18;
    struct timespec timeout = {1, 0};
    if (ppoll(0, &timeout, &temporary) != -EINTR || !saw_handler(3, tid)) return 19;

    if (action(SIG_IGN, 0)) return 20;
    child = exited_child(45);
    if (child < 0 || wait_child(child, &status) != -ECHILD) return 21;
    timeout = (struct timespec){0, 1000000};
    if (ppoll(0, &timeout, &temporary) || calls != 3 || timeout.seconds || timeout.nanos) return 22;
    return 0;
}

static __attribute__((noreturn, used)) void sibling_main(void) {
    if (write_fd(sibling_pipe[1]) != 1) finish(4);
    struct timespec timeout = {2, 0};
    int result = (int)ppoll(0, &timeout, &temporary);
    word current;
    if (mask(0, &current) || current != original) finish(4);
    __atomic_store_n(&sibling_result, result, __ATOMIC_RELEASE);
    if (write_fd(sibling_pipe[1]) != 1) finish(4);
    finish(0);
}

static int sibling_checkpoint(void) {
    struct timespec timeout = {2, 0};
    struct pollfd ready = {sibling_pipe[0], POLLIN, 0};
    char byte;
    return ppoll(&ready, &timeout, 0) == 1 && ready.revents == POLLIN &&
           read_fd(sibling_pipe[0], &byte) == 1 && byte == 'g';
}

static long start_sibling(void) {
    if (simple(SYS_PIPE, (word)sibling_pipe)) return -1;
    sibling_clear_tid = -1;
    long tid = clone_sibling((word)(sibling_stack + sizeof(sibling_stack)), &sibling_parent_tid,
                             &sibling_clear_tid, &sibling_tls);
    return tid > 0 && sibling_parent_tid == tid && sibling_checkpoint() ? tid : -1;
}

static int join_sibling(void) {
    if (!sibling_checkpoint()) return 0;
    struct timespec timeout = {2, 0};
    int pending = __atomic_load_n(&sibling_clear_tid, __ATOMIC_ACQUIRE);
    if (pending) {
        long result = call(SYS_FUTEX, (word)&sibling_clear_tid, 0, (unsigned)pending, (word)&timeout, 0);
        if (result && result != -EAGAIN) return 0;
    }
    return !__atomic_load_n(&sibling_clear_tid, __ATOMIC_ACQUIRE) && !simple(SYS_CLOSE, sibling_pipe[0]) &&
           !simple(SYS_CLOSE, sibling_pipe[1]);
}

static int check_sibling(void) {
    if (action((word)on_child, 0)) return 24;
    long tid = start_sibling();
    if (tid < 0) return 25;
    int status;
    long child = exited_child(46);
    if (child < 0 || wait_child(child, &status) != child || status != (46 << 8)) return 26;
    if (!join_sibling() || __atomic_load_n(&sibling_result, __ATOMIC_ACQUIRE) != -EINTR ||
        !saw_handler(4, tid)) return 27;
    return 0;
}

static int check_competing_polls(long tid) {
    long sibling = start_sibling();
    if (sibling < 0) return 28;
    long child = simple(SYS_FORK, 0);
    if (!child) {
        struct timespec delay = {0, 20000000};
        finish(ppoll(0, &delay, 0) ? 4 : 47);
    }
    int status;
    if (child < 0 || wait_child(child, &status) != child || status != (47 << 8)) return 29;

    /* Между wait4 и ppoll нет системных вызовов, которые могут передать ход соседнему потоку. */
    struct timespec immediate = {0, 0};
    long result = ppoll(0, &immediate, &temporary);
    if (!join_sibling()) return 30;
    int other_result = __atomic_load_n(&sibling_result, __ATOMIC_ACQUIRE);
    if (result == -EINTR && !other_result && saw_handler(5, tid)) return 0;
    if (!result && other_result == -EINTR && saw_handler(5, sibling)) return 0;
    return 31;
}

static __attribute__((noreturn, used)) void sigchld_main(void) {
    int result = 1;
    if (!mask(&original, 0)) {
        long tid = simple(SYS_GETTID, 0);
        result = check_pending(tid);
        if (!result) result = check_sleeping(tid);
        if (!result) result = check_autoreap(tid);
        if (!result) result = check_sibling();
        if (!result) result = check_competing_polls(tid);
    }
    static const char message[] = "Linux ELF64 SIGCHLD and ppoll probe\n";
    if (!result && call(SYS_WRITE, 1, (word)message, sizeof(message) - 1, 0, 0) != sizeof(message) - 1)
        result = 23;
    finish(result);
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("and $-16,%rsp; call sigchld_main; ud2");
}
