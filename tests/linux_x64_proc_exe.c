typedef unsigned long word;

enum {
    SYS_READ = 0, SYS_WRITE = 1, SYS_CLOSE = 3, SYS_PIPE = 22, SYS_GETPID = 39,
    SYS_CLONE = 56, SYS_FORK = 57, SYS_EXECVE = 59, SYS_EXIT = 60, SYS_WAIT4 = 61,
    SYS_UNAME = 63, SYS_READLINK = 89, SYS_CHROOT = 161, SYS_WAITID = 247, SYS_OPENAT = 257,
    SYS_READLINKAT = 267,
    AT_FDCWD = -100, O_DIRECTORY = 0200000, ENOENT = 2, ESRCH = 3, EACCES = 13, EINVAL = 22,
    P_PID = 1, WEXITED = 4, WNOWAIT = 0x01000000,
    SIGCHLD = 17, CLONE_NEWUSER = 0x10000000, CLONE_NEWPID = 0x20000000,
    PATH_LIMIT = 4096,
};

static long call(word number, word a0, word a1, word a2, word a3, word a4) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long simple(word number, word value) { return call(number, value, 0, 0, 0, 0); }
static long readlink(const char *path, char *out, word size) {
    return call(SYS_READLINK, (word)path, (word)out, size, 0, 0);
}
static long readlinkat(long dir, const char *path, char *out, word size) {
    return call(SYS_READLINKAT, dir, (word)path, (word)out, size, 0);
}
static long open_dir(const char *path) { return call(SYS_OPENAT, AT_FDCWD, (word)path, O_DIRECTORY, 0, 0); }

static __attribute__((noreturn)) void finish(int status) {
    simple(SYS_EXIT, status);
    __builtin_trap();
}

static int same_bytes(const char *left, const char *right, word count) {
    for (word i = 0; i < count; ++i)
        if (left[i] != right[i]) return 0;
    return 1;
}

static word string_length(const char *text) {
    word length = 0;
    while (text[length]) ++length;
    return length;
}

static char *decimal(char *text, unsigned value) {
    char reverse[10];
    unsigned length = 0;
    do {
        reverse[length++] = '0' + value % 10;
        value /= 10;
    } while (value);
    while (length) *text++ = reverse[--length];
    *text = 0;
    return text;
}

static long parse_fd(const char *text) {
    long fd = 0;
    if (!*text) return -1;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || fd > 100000) return -1;
        fd = fd * 10 + (*text - '0');
    }
    return fd;
}

static void append_exe(char *end) {
    const char suffix[] = "/exe";
    for (unsigned i = 0; i < sizeof(suffix); ++i) end[i] = suffix[i];
}

static int pipe_byte(long fd, int write) {
    char byte = 'g';
    return call(write ? SYS_WRITE : SYS_READ, fd, (word)&byte, 1, 0, 0) == 1 && byte == 'g';
}

static long wait_child(long child, int *status) { return call(SYS_WAIT4, child, (word)status, 0, 0, 0); }

static __attribute__((noreturn)) void child_entry(const char *ready_fd, const char *gate_fd) {
    long ready = parse_fd(ready_fd), gate = parse_fd(gate_fd);
    if (ready < 0 || gate < 0 || !pipe_byte(ready, 1) || simple(SYS_CLOSE, ready) || !pipe_byte(gate, 0))
        finish(2);
    finish(43);
}

static int check_live_child(const char *target, int myos) {
    static char self[PATH_LIMIT], actual[PATH_LIMIT];
    long self_size = readlink("/proc/self/exe", self, sizeof(self));
    word length = string_length(target);
    if (self_size <= 0 || !length || length >= PATH_LIMIT ||
        (self_size == (long)length && same_bytes(self, target, length))) return 3;
    int ready[2], gate[2];
    if (simple(SYS_PIPE, (word)ready) || simple(SYS_PIPE, (word)gate)) return 4;
    long child = simple(SYS_FORK, 0);
    if (!child) {
        if (simple(SYS_CLOSE, ready[0]) || simple(SYS_CLOSE, gate[1])) finish(4);
        char ready_fd[11], gate_fd[11];
        decimal(ready_fd, (unsigned)ready[1]);
        decimal(gate_fd, (unsigned)gate[0]);
        const char *const args[] = {target, "child", ready_fd, gate_fd, 0};
        call(SYS_EXECVE, (word)target, (word)args, 0, 0, 0);
        finish(5);
    }
    if (child < 0 || simple(SYS_CLOSE, ready[1]) || simple(SYS_CLOSE, gate[0]) ||
        !pipe_byte(ready[0], 0) || simple(SYS_CLOSE, ready[0])) return 5;

    char path[32] = "/proc/";
    char *end = decimal(path + 6, (unsigned)child);
    long proc = open_dir("/proc"), process = open_dir(path);
    append_exe(end);
    if (readlink(path, actual, sizeof(actual)) != (long)length || !same_bytes(actual, target, length)) return 6;
    if (proc < 0 || readlinkat(proc, path + 6, actual, sizeof(actual)) != (long)length ||
        !same_bytes(actual, target, length)) return 7;
    if (process < 0 || readlinkat(process, "exe", actual, sizeof(actual)) != (long)length ||
        !same_bytes(actual, target, length)) return 8;

    char short_path[] = {'?', '?', '?', '!'};
    if (readlinkat(process, "exe", short_path, 3) != 3 || !same_bytes(short_path, target, 3) ||
        short_path[3] != '!' || readlinkat(process, "exe", short_path, 0) != -EINVAL) return 9;

    char leading_zero[32] = "/proc/0";
    append_exe(decimal(leading_zero + 7, (unsigned)child));
    const char *const missing[] = {
        leading_zero, "/proc/0/exe", "/proc/-1/exe", "/proc/2147483647/exe",
        "/proc/2147483648/exe", "/proc/4294967297/exe",
    };
    for (unsigned i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i)
        if (readlink(missing[i], actual, sizeof(actual)) != -ENOENT) return 10;

    /* WNOWAIT подтверждает выход, пока запись процесса ещё доступна wait4. */
    if (!pipe_byte(gate[1], 1) || simple(SYS_CLOSE, gate[1]) ||
        call(SYS_WAITID, P_PID, child, 0, WEXITED | WNOWAIT, 0)) return 11;
    if (readlink(path, actual, sizeof(actual)) != -ENOENT ||
        readlinkat(proc, path + 6, actual, sizeof(actual)) != -ENOENT ||
        readlinkat(process, "exe", actual, sizeof(actual)) != -ENOENT) return 12;
    int status;
    if (wait_child(child, &status) != child || status != (43 << 8) ||
        readlink(path, actual, sizeof(actual)) != -ENOENT ||
        readlinkat(process, "exe", actual, sizeof(actual)) != (myos ? -ENOENT : -ESRCH) ||
        simple(SYS_CLOSE, proc) || simple(SYS_CLOSE, process)) return 13;
    return 0;
}

static __attribute__((noreturn)) void check_namespace_child(void) {
    unsigned parent = (unsigned)simple(SYS_GETPID, 0);
    char outside[32] = "/proc/";
    append_exe(decimal(outside + 6, parent));
    int gate[2];
    long inherited = open_dir("/proc/1");
    if (parent <= 1 || inherited < 0 || simple(SYS_PIPE, (word)gate)) finish(15);
    long child = call(SYS_CLONE, CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD, 0, 0, 0, 0);
    char actual[PATH_LIMIT];
    if (!child) {
        if (simple(SYS_CLOSE, gate[1]) || !pipe_byte(gate[0], 0)) finish(16);
        if (simple(SYS_GETPID, 0) != 1 || readlink(outside, actual, sizeof(actual)) != -ENOENT) finish(17);
        static char self[PATH_LIMIT];
        long length = readlink("/proc/self/exe", self, sizeof(self));
        if (length <= 0 || readlink("/proc/1/exe", actual, sizeof(actual)) != length ||
            !same_bytes(self, actual, (word)length)) finish(18);
        /* Унаследованный каталог относится к внешнему PID 1, которого здесь не видно. */
        if (readlinkat(inherited, "exe", actual, sizeof(actual)) != -ENOENT ||
            simple(SYS_CLOSE, inherited)) finish(24);
        if (simple(SYS_CHROOT, (word)"/proc") || readlink("/1/exe", actual, sizeof(actual)) != -EACCES) finish(19);
        finish(0);
    }
    if (child < 0 || simple(SYS_CLOSE, gate[0]) || simple(SYS_CLOSE, inherited)) finish(16);
    char peer[32] = "/proc/";
    append_exe(decimal(peer + 6, (unsigned)child));
    if (readlink(peer, actual, sizeof(actual)) != -EACCES) finish(20);
    int status;
    if (!pipe_byte(gate[1], 1) || simple(SYS_CLOSE, gate[1]) || wait_child(child, &status) != child ||
        (status & 0xff)) finish(21);
    finish(status >> 8);
}

static int check_isolation(void) {
    long child = simple(SYS_FORK, 0);
    if (!child) check_namespace_child();
    int status;
    if (child < 0 || wait_child(child, &status) != child || (status & 0xff)) return 22;
    return status >> 8;
}

static __attribute__((noreturn, used)) void proc_exe_main(const word *stack) {
    if (stack[0] == 4) child_entry((const char *)stack[3], (const char *)stack[4]);
    const char *target = stack[0] == 2 ? (const char *)stack[2] : "/myos/proc-peer-exec-target";
    char uts[390];
    if (simple(SYS_UNAME, (word)uts)) finish(14);
    int myos = uts[0] == 'M';
    int result = check_live_child(target, myos);
    if (!result && myos) result = check_isolation();
    static const char marker[] = "Linux ELF64 proc peer exe probe\n";
    if (!result && call(SYS_WRITE, 1, (word)marker, sizeof(marker) - 1, 0, 0) != sizeof(marker) - 1) result = 23;
    finish(result);
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("mov %rsp,%rdi; and $-16,%rsp; call proc_exe_main; ud2");
}
