typedef unsigned long word;

enum {
    SYS_WRITE = 1, SYS_RT_SIGACTION = 13, SYS_YIELD = 24, SYS_GETPID = 39, SYS_CLONE = 56, SYS_FORK = 57, SYS_EXECVE = 59,
    SYS_EXIT = 60, SYS_WAIT4 = 61, SYS_GETUID = 102, SYS_GETGID = 104, SYS_PRCTL = 157,
    SYS_EXIT_GROUP = 231, SYS_SECCOMP = 317,
    PR_GET_SECCOMP = 21, PR_SET_SECCOMP = 22, PR_SET_NO_NEW_PRIVS = 38, PR_GET_NO_NEW_PRIVS = 39,
    SECCOMP_MODE_FILTER = 2, SECCOMP_SET_MODE_FILTER = 1, SECCOMP_FILTER_FLAG_TSYNC = 1,
    EACCES = 13, EFAULT = 14, EINVAL = 22, UID_ERROR = 0x123, GID_ERROR = 44, NEW_GID_ERROR = 0x234, PID_ERROR = 0x321,
    BPF_LOAD_WORD = 0x20, BPF_JUMP = 0x05, BPF_JUMP_EQUAL = 0x15, BPF_RETURN = 0x06,
    SECCOMP_RET_TRAP = 0x00030000, SECCOMP_RET_ERRNO = 0x00050000, SECCOMP_RET_ALLOW = 0x7fff0000,
    SIGSYS = 31, SYS_SECCOMP_CODE = 1, TRAP_DATA = 0x4321,
    SA_SIGINFO = 4, SA_RESTORER = 0x04000000,
};

struct instruction {
    unsigned short code;
    unsigned char yes, no;
    unsigned value;
};

struct program {
    unsigned short length;
    const struct instruction *instructions;
};

struct trap_info {
    int signal, error, code;
    word call_address;
    int syscall;
    unsigned arch;
};

struct trap_context {
    word flags, link, stack;
    int stack_flags;
    word stack_size;
    word r8, r9, r10, r11, r12, r13, r14, r15;
    word rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip;
};

struct trap_action {
    void (*handler)(int, const struct trap_info *, struct trap_context *);
    word flags;
    void (*restorer)(void);
    word mask;
};

_Static_assert(sizeof(struct instruction) == 8 && sizeof(struct program) == 16, "Linux x86-64 sock_fprog");
_Static_assert(__builtin_offsetof(struct trap_info, call_address) == 16 &&
               __builtin_offsetof(struct trap_info, syscall) == 24 && sizeof(struct trap_action) == 32,
               "Linux x86-64 SIGSYS ABI");
_Static_assert(__builtin_offsetof(struct trap_context, r8) == 40 &&
               __builtin_offsetof(struct trap_context, rax) == 144 &&
               __builtin_offsetof(struct trap_context, rip) == 168, "Linux x86-64 ucontext ABI");

static const struct instruction base_filter[] = {
    {BPF_LOAD_WORD, 0, 0, 4},
    {BPF_JUMP_EQUAL, 1, 0, 0xc000003e}, /* AUDIT_ARCH_X86_64 */
    {BPF_RETURN, 0, 0, SECCOMP_RET_ERRNO | EINVAL},
    {BPF_LOAD_WORD, 0, 0, 0},
    {BPF_JUMP_EQUAL, 0, 1, SYS_GETUID},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ERRNO | UID_ERROR},
    {BPF_JUMP_EQUAL, 0, 1, SYS_GETGID},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ERRNO | GID_ERROR},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ALLOW},
};

static const struct instruction sync_filter[] = {
    {BPF_LOAD_WORD, 0, 0, 0},
    {BPF_JUMP_EQUAL, 0, 1, SYS_GETGID},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ERRNO | NEW_GID_ERROR},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ALLOW},
};

static const struct instruction private_filter[] = {
    {BPF_LOAD_WORD, 0, 0, 0},
    {BPF_JUMP_EQUAL, 0, 1, SYS_GETPID},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ERRNO | PID_ERROR},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ALLOW},
};

static const struct instruction invalid_filter[] = {
    {BPF_JUMP, 0, 0, 2},
    {BPF_RETURN, 0, 0, SECCOMP_RET_ALLOW},
};

#define PROGRAM(filter) {sizeof(filter) / sizeof((filter)[0]), (filter)}
static const struct program base = PROGRAM(base_filter), sync = PROGRAM(sync_filter),
                            private = PROGRAM(private_filter), invalid = PROGRAM(invalid_filter);

static char thread_stack[16384] __attribute__((aligned(16)));
static const word tls;
static int parent_tid;
static unsigned child_tid = 1, stage, worker_stage;
static const char path[] = "/myos/test.elf";

extern long clone_thread(word stack_top, int *ptid, unsigned *ctid, const word *fs);
extern word trap_call(word a0, word a1, word a2, word a3, word a4, word a5);
extern const char trap_resume[];
extern void trap_restorer(void);

/* Поток начинает выполнение с новым стеком. */
__asm__(
    ".text\n"
    "clone_thread:\n"
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
    "call seccomp_worker\n"
    "ud2\n"
    "1: ret\n"
    "trap_call:\n"
    "mov %rcx,%r10\n"
    "mov $102,%eax\n"
    "syscall\n"
    "trap_resume:\n"
    "ret\n"
    "trap_restorer:\n"
    "mov $15,%eax\n"
    "syscall\n"
    "ud2\n"
    ".global _start\n"
    "_start:\n"
    "mov %rsp,%rdi\n"
    "and $-16,%rsp\n"
    "call seccomp_entry\n"
    "ud2\n"
);

static long call(word number, word a0, word a1, word a2, word a3) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = 0;
    register word sixth __asm__("r9") = 0;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long simple(word number) {
    return call(number, 0, 0, 0, 0);
}

static long prctl(word option, word value, word argument) {
    return call(SYS_PRCTL, option, value, argument, option == PR_SET_SECCOMP ? 1 : 0);
}

static long install(word flags, const struct program *filter) {
    return call(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, flags, (word)filter, 0);
}

static __attribute__((noreturn)) void finish(word number, word status) {
    call(number, status, 0, 0, 0);
    __builtin_trap();
}

static void wait_stage(const unsigned *state, unsigned expected) {
    while (__atomic_load_n(state, __ATOMIC_ACQUIRE) < expected) simple(SYS_YIELD);
}

static void set_stage(unsigned *state, unsigned next) {
    __atomic_store_n(state, next, __ATOMIC_RELEASE);
}

static int filtered(long gid_error) {
    return prctl(PR_GET_SECCOMP, 0, 0) == SECCOMP_MODE_FILTER &&
           simple(SYS_GETUID) == -UID_ERROR && simple(SYS_GETGID) == -gid_error;
}

__attribute__((noreturn, used)) void seccomp_worker(void) {
    if (!filtered(GID_ERROR) || simple(SYS_GETPID) <= 0) goto fail;
    set_stage(&worker_stage, 1);
    wait_stage(&stage, 1);
    if (!filtered(NEW_GID_ERROR) || simple(SYS_GETPID) <= 0) goto fail;
    set_stage(&worker_stage, 2);
    wait_stage(&stage, 2);
    if (install(0, &private) || simple(SYS_GETPID) != -PID_ERROR) goto fail;
    set_stage(&worker_stage, 3);
    wait_stage(&stage, 3);
    finish(SYS_EXIT, 0);

fail:
    set_stage(&worker_stage, 255);
    finish(SYS_EXIT, 1);
}

static int check_threads(long pid) {
    word top = (word)(thread_stack + sizeof(thread_stack));
    long tid = clone_thread(top, &parent_tid, &child_tid, &tls);
    if (tid <= 0 || tid != parent_tid) return 4;
    wait_stage(&worker_stage, 1);
    if (worker_stage != 1 || install(SECCOMP_FILTER_FLAG_TSYNC, &sync) || !filtered(NEW_GID_ERROR)) return 5;
    set_stage(&stage, 1);
    wait_stage(&worker_stage, 2);
    if (worker_stage != 2) return 6;

    /* Разошедшиеся цепочки запрещают TSYNC. Родительский фильтр не должен измениться. */
    set_stage(&stage, 2);
    wait_stage(&worker_stage, 3);
    if (worker_stage != 3 || install(SECCOMP_FILTER_FLAG_TSYNC, &private) != tid ||
        simple(SYS_GETPID) != pid || !filtered(NEW_GID_ERROR)) return 7;
    set_stage(&stage, 3);
    while (__atomic_load_n(&child_tid, __ATOMIC_ACQUIRE)) simple(SYS_YIELD);
    return 0;
}

static int check_fork_exec(long pid) {
    long child = simple(SYS_FORK);
    if (child < 0) return 8;
    if (!child) {
        if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0) != 1 || !filtered(NEW_GID_ERROR) || simple(SYS_GETPID) <= 0 ||
            install(0, &private) || simple(SYS_GETPID) != -PID_ERROR) finish(SYS_EXIT, 9);
        const char *arguments[] = {path, "inherited", 0};
        const char *environment[] = {0};
        call(SYS_EXECVE, (word)path, (word)arguments, (word)environment, 0);
        finish(SYS_EXIT, 10);
    }
    int status = -1;
    if (call(SYS_WAIT4, child, (word)&status, 0, 0) != child || status ||
        simple(SYS_GETPID) != pid || !filtered(NEW_GID_ERROR)) return status > 0 ? status >> 8 : 11;
    return 0;
}

static int check_fatal_action(long pid) {
    static const struct instruction code[] = {
        {BPF_LOAD_WORD, 0, 0, 0},
        {BPF_JUMP_EQUAL, 0, 1, SYS_GETPID},
        {BPF_RETURN, 0, 0, 0x60000000u},
        {BPF_RETURN, 0, 0, SECCOMP_RET_ALLOW},
    };
    static const struct program program = PROGRAM(code);
    long child = simple(SYS_FORK);
    if (child < 0) return 17;
    if (!child) {
        if (install(0, &program)) finish(SYS_EXIT, 18);
        simple(SYS_GETPID);
        finish(SYS_EXIT, 19);
    }
    int status = -1;
    if (call(SYS_WAIT4, child, (word)&status, 0, 0) != child ||
        (status & 0x7f) != SIGSYS || simple(SYS_GETPID) != pid) return 20;
    return 0;
}

static const word trap_arguments[] = {
    0x1234567800000001ul, 0x2345678900000002ul, 0x3456789a00000003ul,
    0x456789ab00000004ul, 0x56789abc00000005ul, 0x6789abcd00000006ul,
};
static const word trap_result = 0x5aabbccd11223344ul;
static volatile int trap_status;

static void trap_handler(int signal, const struct trap_info *info, struct trap_context *context) {
    if (signal != SIGSYS || info->signal != SIGSYS || info->code != SYS_SECCOMP_CODE || info->error != TRAP_DATA ||
        info->syscall != SYS_GETUID || info->arch != 0xc000003e || info->call_address != (word)trap_resume) {
        trap_status = 23;
        return;
    }
    if (context->rip != (word)trap_resume || context->rax != SYS_GETUID ||
        context->rdi != trap_arguments[0] || context->rsi != trap_arguments[1] || context->rdx != trap_arguments[2] ||
        context->r10 != trap_arguments[3] || context->r8 != trap_arguments[4] || context->r9 != trap_arguments[5]) {
        trap_status = 24;
        return;
    }
    context->rax = trap_result;
    trap_status = 1;
}

static int check_trap(void) {
    static const struct instruction code[] = {
        {BPF_LOAD_WORD, 0, 0, 0},
        {BPF_JUMP_EQUAL, 0, 1, SYS_GETUID},
        {BPF_RETURN, 0, 0, SECCOMP_RET_TRAP | TRAP_DATA},
        {BPF_RETURN, 0, 0, SECCOMP_RET_ALLOW},
    };
    static const struct program program = PROGRAM(code);
    const struct trap_action action = {trap_handler, SA_SIGINFO | SA_RESTORER, trap_restorer, 0};
    if (call(SYS_RT_SIGACTION, SIGSYS, (word)&action, 0, sizeof(action.mask))) return 21;
    if (install(0, &program)) return 22;
    word result = trap_call(trap_arguments[0], trap_arguments[1], trap_arguments[2],
                            trap_arguments[3], trap_arguments[4], trap_arguments[5]);
    if (trap_status != 1) return trap_status ? trap_status : 25;
    return result == trap_result ? 0 : 26;
}

static int check_seccomp(void) {
    long pid = simple(SYS_GETPID);
    if (pid <= 0 || prctl(PR_GET_SECCOMP, 0, 0) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0) != 0) return 1;
    if (install(0, 0) != -EFAULT || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0) != -EFAULT) return 14;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (word)&base) != -EACCES) return 15;
    if (simple(SYS_GETUID) < 0) return 16;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (word)&base) ||
        !filtered(GID_ERROR) || simple(SYS_GETPID) != pid) return 2;
    if (install(0, &invalid) != -EINVAL || !filtered(GID_ERROR) || simple(SYS_GETPID) != pid) return 3;

    int status = check_threads(pid);
    if (status) return status;
    status = check_fork_exec(pid);
    if (status) return status;
    status = check_fatal_action(pid);
    return status ? status : check_trap();
}

__attribute__((noreturn, used)) void seccomp_entry(const word *stack) {
    if (stack[0] == 2) {
        int inherited = prctl(PR_GET_NO_NEW_PRIVS, 0, 0) == 1 && filtered(NEW_GID_ERROR) &&
                        simple(SYS_GETPID) == -PID_ERROR;
        finish(SYS_EXIT, inherited ? 0 : 12);
    }
    int status = check_seccomp();
    if (!status) {
        static const char passed[] = "Seccomp guest PASS\n";
        if (call(SYS_WRITE, 1, (word)passed, sizeof(passed) - 1, 0) != sizeof(passed) - 1) status = 13;
    }
    finish(SYS_EXIT_GROUP, status);
}
