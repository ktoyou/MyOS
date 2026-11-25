typedef unsigned long word;

enum {
    SYS_WRITE = 1, SYS_YIELD = 24, SYS_GETPID = 39, SYS_CLONE = 56, SYS_FORK = 57, SYS_EXECVE = 59,
    SYS_EXIT = 60, SYS_WAIT4 = 61, SYS_GETUID = 102, SYS_GETGID = 104, SYS_PRCTL = 157,
    SYS_EXIT_GROUP = 231, SYS_SECCOMP = 317,
    PR_GET_SECCOMP = 21, PR_SET_SECCOMP = 22, PR_SET_NO_NEW_PRIVS = 38, PR_GET_NO_NEW_PRIVS = 39,
    SECCOMP_MODE_FILTER = 2, SECCOMP_SET_MODE_FILTER = 1, SECCOMP_FILTER_FLAG_TSYNC = 1,
    EACCES = 13, EFAULT = 14, EINVAL = 22, UID_ERROR = 0x123, GID_ERROR = 44, NEW_GID_ERROR = 0x234, PID_ERROR = 0x321,
    BPF_LOAD_WORD = 0x20, BPF_JUMP = 0x05, BPF_JUMP_EQUAL = 0x15, BPF_RETURN = 0x06,
    SECCOMP_RET_ERRNO = 0x00050000, SECCOMP_RET_ALLOW = 0x7fff0000,
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

_Static_assert(sizeof(struct instruction) == 8 && sizeof(struct program) == 16, "Linux x86-64 sock_fprog");

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
    return call(SYS_PRCTL, option, value, argument, 0);
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
        (status & 0x7f) != 31 || simple(SYS_GETPID) != pid) return 20;
    return 0;
}

static int check_seccomp(void) {
    long pid = simple(SYS_GETPID);
    if (pid <= 0 || prctl(PR_GET_SECCOMP, 0, 0) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0) != 0) return 1;
    if (install(0, 0) != -EFAULT) return 14;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (word)&base) != -EACCES) return 15;
    if (simple(SYS_GETUID) < 0) return 16;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (word)&base) ||
        !filtered(GID_ERROR) || simple(SYS_GETPID) != pid) return 2;
    if (install(0, &invalid) != -EINVAL || !filtered(GID_ERROR) || simple(SYS_GETPID) != pid) return 3;

    int status = check_threads(pid);
    if (status) return status;
    status = check_fork_exec(pid);
    return status ? status : check_fatal_action(pid);
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
