typedef unsigned long word;

enum { SIGCHLD = 17, CLONE_FS = 0x200, NEWUSER = 0x10000000, AT_FDCWD = -100, O_DIRECTORY = 0x10000 };
static const word child_tls __attribute__((used)) = 0xabc123;
static const word parent_tls = 0xdef456;
static char child_stack[16384] __attribute__((aligned(16)));
static volatile word helper_inode;

extern long launch_helper(word stack);
__asm__(
    ".text\n"
    "launch_helper:\n"
    "mov %rdi,%rsi\n"
    "lea child_tls(%rip),%r8\n"
    "xor %edx,%edx\n"
    "xor %r10d,%r10d\n"
    "mov $0x84311,%edi\n"
    "mov $56,%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "call shared_fs_helper\n"
    "ud2\n"
    "1: ret\n"
);

static long call(word number, word a0, word a1, word a2, word a3) {
    register word fourth __asm__("r10") = a3;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth) : "rcx", "r11", "memory");
    return (long)number;
}

__attribute__((noreturn)) static void finish(int status) {
    call(60, status, 0, 0, 0);
    __builtin_unreachable();
}

static long open_path(const char *path, word flags) {
    return call(2, (word)path, flags, 0, 0);
}

static long chdir(const char *path) {
    return call(80, (word)path, 0, 0, 0);
}

static long chroot(const char *path) {
    return call(161, (word)path, 0, 0, 0);
}

static int status_of(long child) {
    int status;
    if (child < 1 || call(61, child, (word)&status, 0, 0) != child) return -1;
    return status;
}

static long exec_path(const char *path) {
    const char *argv[] = {path, 0};
    return call(59, (word)path, (word)argv, 0, 0);
}

static word tls_value(void) {
    word value;
    __asm__ volatile("mov %%fs:0,%0" : "=r"(value));
    return value;
}

__attribute__((noreturn)) void shared_fs_helper(void) {
    word stat[18];
    if (tls_value() != child_tls || call(95, 077, 0, 0, 0) != 022 ||
        chroot("/proc/self/fdinfo/") || chdir("/") ||
        call(4, (word)"/", (word)stat, 0, 0)) finish(2);
    helper_inode = stat[1];
    finish(0);
}

static void check_jail_exec(int missing) {
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        if (chroot("/sandbox") || chdir("/") || chdir("sub") ||
            open_path("/../../dev/null", 0) != -2 ||
            call(272, NEWUSER, 0, 0, 0) != -1 ||
            call(56, NEWUSER | SIGCHLD, 0, 0, 0) != -1 ||
            exec_path("/outside.elf") != -2) finish(3);
        finish(exec_path("probe") == -2 ? 40 : 4);
    }
    if (status_of(child) != ((missing ? 40 : 42) << 8)) finish(5);
    long fd = open_path("/dev/null", 0);
    if (fd < 0 || call(3, fd, 0, 0, 0)) finish(6);
}

struct address { unsigned short family; char path[32]; };

static void check_jail_socket(void) {
    if (call(83, (word)"/tmp/jail", 0700, 0, 0) ||
        call(83, (word)"/tmp/jail/sub", 0700, 0, 0) ||
        call(88, (word)"/sub/socket", (word)"/tmp/jail/alias", 0, 0)) finish(7);
    long listener = call(41, 1, 1, 0, 0);
    const struct address local = {1, "socket"};
    if (listener < 0 || chdir("/tmp/jail/sub") ||
        call(49, listener, (word)&local, sizeof(local), 0) ||
        call(50, listener, 1, 0, 0) || chdir("/")) finish(8);
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        const struct address outside = {1, "/tmp/jail/sub/socket"}, alias = {1, "/alias"};
        long client = call(41, 1, 1, 0, 0);
        if (chroot("/tmp/jail") || chdir("/") || client < 0 ||
            call(42, client, (word)&outside, sizeof(outside), 0) != -2 ||
            call(42, client, (word)&alias, sizeof(alias), 0)) finish(9);
        finish(0);
    }
    if (status_of(child)) finish(10);
    long accepted = call(43, listener, 0, 0, 0);
    if (accepted < 0 || call(3, accepted, 0, 0, 0) || call(3, listener, 0, 0, 0)) finish(11);
}

static void check_socket_retry(void) {
    const struct address local = {1, "retry"}, replacement = {1, "/tmp/jail/retry"};
    long old = call(41, 1, 1 | 0x800, 0, 0), next = call(41, 1, 1 | 0x800, 0, 0);
    long filler = call(41, 1, 1, 0, 0);
    if (old < 0 || next < 0 || filler < 0 || chdir("/tmp/jail/sub") ||
        call(49, old, (word)&local, sizeof(local), 0) || call(50, old, 0, 0, 0) ||
        call(49, next, (word)&replacement, sizeof(replacement), 0) || call(50, next, 0, 0, 0) ||
        call(42, filler, (word)&local, sizeof(local), 0)) finish(22);

    long child = call(56, CLONE_FS | SIGCHLD, 0, 0, 0);
    if (!child) {
        long client = call(41, 1, 1, 0, 0);
        finish(client < 0 || call(42, client, (word)&local, sizeof(local), 0) ? 23 : 0);
    }
    if (child < 0 || call(7, 0, 0, 10, 0) || chdir("/tmp/jail")) finish(24);
    long first = call(43, old, 0, 0, 0);
    if (first < 0 || status_of(child)) finish(25);
    long accepted = call(43, next, 0, 0, 0);
    if (accepted < 0 || call(3, accepted, 0, 0, 0) || call(3, first, 0, 0, 0) ||
        call(3, filler, 0, 0, 0) || call(3, old, 0, 0, 0) || call(3, next, 0, 0, 0) ||
        chdir("/")) finish(26);
}

static void check_shared_root(void) {
    long proc = open_path("/proc", O_DIRECTORY);
    long outside = open_path("/dev/null", 0);
    if (proc < 0 || outside < 0 || call(158, 0x1002, (word)&parent_tls, 0, 0)) finish(12);
    long child = launch_helper((word)(child_stack + sizeof(child_stack)));
    word stat[18], task[18];
    if (status_of(child) || tls_value() != parent_tls || call(95, 022, 0, 0, 0) != 077 ||
        !helper_inode || call(4, (word)"/", (word)stat, 0, 0) || stat[1] != helper_inode ||
        call(4, (word)".", (word)stat, 0, 0) || stat[1] != helper_inode ||
        call(4, (word)"/../", (word)stat, 0, 0) || stat[1] != helper_inode ||
        open_path("/proc", 0) != -2 || open_path("/dev/null", 0) != -2 ||
        call(83, (word)"/new", 0700, 0, 0) != -30) finish(13);
    long retained = call(257, proc, (word)".", O_DIRECTORY, 0);
    if (retained < 0 || call(262, retained, (word)"self/task/", (word)task, 0) ||
        (task[3] & 0170000) != 0040000 ||
        call(257, proc, (word)"/proc", O_DIRECTORY, 0) != -2 ||
        call(3, retained, 0, 0, 0) || call(3, proc, 0, 0, 0) || call(3, outside, 0, 0, 0)) finish(14);
}

static void check_namespace_detach(void) {
    long child = call(56, CLONE_FS | SIGCHLD, 0, 0, 0);
    if (!child) {
        if (call(272, NEWUSER, 0, 0, 0) ||
            chroot("/sandbox") || chdir("/") || open_path("/proc", 0) != -2) finish(15);
        finish(0);
    }
    if (status_of(child) || call(56, CLONE_FS | NEWUSER | SIGCHLD, 0, 0, 0) != -22) finish(16);
    long fd = open_path("/dev/null", 0);
    if (fd < 0 || call(3, fd, 0, 0, 0)) finish(17);
}

void _start(void) {
    if (chroot("/") != -1 || chroot("/outside.elf") != -20 || chroot("/no-such-path") != -2)
        finish(1);
    check_namespace_detach();
    long marker = open_path("/loader-missing", 0);
    if (marker >= 0 && call(3, marker, 0, 0, 0)) finish(18);
    long child = call(56, NEWUSER | SIGCHLD, 0, 0, 0);
    if (!child) {
        check_jail_exec(marker >= 0);
        check_jail_socket();
        check_socket_retry();
        check_shared_root();
        finish(0);
    }
    int status = status_of(child);
    if (status) finish(status < 0 ? 19 : status >> 8);
    long fd = open_path("/dev/null", 0);
    if (fd < 0 || call(3, fd, 0, 0, 0)) finish(20);
    static const char success[] = "Linux ELF64 shared filesystem probe\n";
    if (call(1, 1, (word)success, sizeof(success) - 1, 0) != sizeof(success) - 1) finish(21);
    finish(0);
}
