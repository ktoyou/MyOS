typedef unsigned long word;

enum { SIGCHLD = 17, NEWUSER = 0x10000000, NEWPID = 0x20000000, CHILD_SETTID = 0x01000000 };
static int child_tid;
static volatile int worker_tid __attribute__((used));
static int parked_pipe, ready_pipe;
static volatile int leader_tid;
static word inner_inode;
static word thread_tls __attribute__((used));
static char thread_stack[16384] __attribute__((aligned(16)));

extern long start_worker(word stack);
__asm__(
    ".text\n"
    "start_worker:\n"
    "mov %rdi,%rsi\n"
    "lea worker_tid(%rip),%rdx\n"
    "xor %r10d,%r10d\n"
    "lea thread_tls(%rip),%r8\n"
    "mov $0x3d0f00,%edi\n"
    "mov $56,%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "call pidns_worker\n"
    "ud2\n"
    "1: ret\n"
);

static long call5(word number, word a0, word a1, word a2, word a3, word a4) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth) : "rcx", "r11", "memory");
    return (long)number;
}

static long call(word number, word a0, word a1, word a2, word a3) {
    return call5(number, a0, a1, a2, a3, 0);
}

__attribute__((noreturn)) static void finish(int status) {
    call(60, status, 0, 0, 0);
    __builtin_unreachable();
}

static long close_fd(int fd) {
    return call(3, fd, 0, 0, 0);
}

static long wait_for(long child, int expected) {
    int status;
    long found = call(61, child, (word)&status, 0, 0);
    return found > 0 && status == expected ? found : -1;
}

static word namespace_inode(void) {
    static const char path[] = "/proc/self/ns/pid";
    char link[26];
    word target[18], opened[18], symbolic[18];
    long fd = call(2, (word)path, 0x80000, 0, 0);
    if (fd < 0 || call(4, (word)path, (word)target, 0, 0) ||
        call(5, fd, (word)opened, 0, 0) || call(6, (word)path, (word)symbolic, 0, 0) ||
        opened[1] != target[1] || (symbolic[3] & 0170000) != 0120000 ||
        close_fd(fd)) finish(1);
    long length = call(89, (word)path, (word)link, sizeof(link), 0);
    if (length < 7 || link[0] != 'p' || link[1] != 'i' || link[2] != 'd' ||
        link[3] != ':' || link[4] != '[' || link[length - 1] != ']') finish(2);
    word inode = 0;
    for (long i = 5; i < length - 1; ++i) {
        if (link[i] < '0' || link[i] > '9') finish(2);
        inode = inode * 10 + (unsigned)(link[i] - '0');
    }
    if (inode != target[1]) finish(2);
    return inode;
}

static long passcred(int fd) {
    int enabled = 1;
    register word fourth __asm__("r10") = (word)&enabled;
    register word fifth __asm__("r8") = sizeof(enabled);
    register word number __asm__("rax") = 54;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((word)fd), "S"(1ul), "d"(16ul), "r"(fourth), "r"(fifth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long receive(int fd, word *value, unsigned flags) {
    struct { word address, length; } iov = {(word)value, sizeof(*value)};
    struct { word length; int level, type, pid; unsigned uid, gid; } cred;
    struct {
        word name, name_length, iov, count, control, control_length, flags;
    } message = {.iov = (word)&iov, .count = 1, .control = (word)&cred, .control_length = sizeof(cred)};
    if (call(47, fd, (word)&message, flags, 0) != sizeof(*value) ||
        cred.length != 28 || cred.level != 1 || cred.type != 2) finish(3);
    return cred.pid;
}

static void check_local_credentials(void) {
    int sockets[2];
    const word sent = 42;
    if (call(53, 1, 5, 0, (word)sockets) || passcred(sockets[0])) finish(25);
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        if (call(1, sockets[1], (word)&sent, sizeof(sent), 0) != sizeof(sent)) finish(26);
        finish(0);
    }
    word received;
    if (child <= 1 || wait_for(child, 0) != child ||
        receive(sockets[0], &received, 0) != child || received != sent ||
        close_fd(sockets[0]) || close_fd(sockets[1])) finish(27);
}

static void check_adoption(void) {
    int gate[2];
    if (call(22, (word)gate, 0, 0, 0)) finish(4);
    long parent = call(57, 0, 0, 0, 0);
    if (parent < 0) finish(4);
    if (!parent) {
        long orphan = call(57, 0, 0, 0, 0);
        if (orphan < 0) finish(5);
        if (!orphan) {
            char byte;
            if (call(0, gate[0], (word)&byte, 1, 0) != 1 ||
                call(110, 0, 0, 0, 0) != 1) finish(6);
            finish(0);
        }
        finish(0);
    }
    if (wait_for(0, 0) != parent || call(1, gate[1], (word)"x", 1, 0) != 1 ||
        wait_for(0, 0) <= parent || close_fd(gate[0]) || close_fd(gate[1])) finish(7);
}

static void leave_nested_processes(void) {
    int ready[2], parked[2];
    if (call(22, (word)ready, 0, 0, 0) || call(22, (word)parked, 0, 0, 0)) finish(8);
    long nested = call(56, NEWPID | SIGCHLD, 0, 0, 0);
    if (nested < 0) finish(8);
    if (!nested) {
        if (call(39, 0, 0, 0, 0) != 1 || call(110, 0, 0, 0, 0)) finish(9);
        long child = call(57, 0, 0, 0, 0);
        if (child < 0) finish(9);
        if (!child) {
            char byte;
            if (call(39, 0, 0, 0, 0) != 2 || call(110, 0, 0, 0, 0) != 1 ||
                call(1, ready[1], (word)"r", 1, 0) != 1 ||
                call(0, parked[0], (word)&byte, 1, 0) != 1 || byte != 'p' ||
                call(1, ready[1], (word)"a", 1, 0) != 1) finish(10);
            call(0, parked[0], (word)&byte, 1, 0);
        }
        call(7, 0, 0, 10000, 0);
        finish(11);
    }
    char byte;
    if (call(0, ready[0], (word)&byte, 1, 0) != 1 || byte != 'r') finish(12);
    parked_pipe = parked[1];
    ready_pipe = ready[0];
}

__attribute__((noreturn)) void pidns_worker(void) {
    while (leader_tid) call(202, (word)&leader_tid, 0, 1, 0);
    char byte;
    if (call(39, 0, 0, 0, 0) != 1 || worker_tid <= 1 ||
        call(186, 0, 0, 0, 0) != worker_tid || namespace_inode() != inner_inode ||
        call(1, parked_pipe, (word)"p", 1, 0) != 1 ||
        call(0, ready_pipe, (word)&byte, 1, 0) != 1 || byte != 'a') finish(23);
    finish(42);
}

__attribute__((noreturn)) static void check_inner(word initial, int socket, int inherited) {
    if (child_tid != 1 || call(39, 0, 0, 0, 0) != 1 || call(186, 0, 0, 0, 0) != 1 ||
        call(110, 0, 0, 0, 0) || call(111, 0, 0, 0, 0)) finish(13);
    word stat[18], payload;
    word inode = namespace_inode();
    if (inode == initial || call(5, inherited, (word)stat, 0, 0) || stat[1] != initial ||
        receive(socket, &payload, 0) != 0 || payload != initial) finish(14);
    struct { int pid; unsigned uid, gid; } peer;
    unsigned length = sizeof(peer);
    if (call5(55, socket, 1, 17, (word)&peer, (word)&length) || length != sizeof(peer) ||
        peer.pid || peer.uid != (unsigned)call(107, 0, 0, 0, 0) ||
        peer.gid != (unsigned)call(108, 0, 0, 0, 0)) finish(28);
    check_local_credentials();
    check_adoption();
    if (call(112, 0, 0, 0, 0) != 1 || call(111, 0, 0, 0, 0) != 1) finish(15);
    if (call(1, socket, (word)&inode, sizeof(inode), 0) != sizeof(inode)) finish(16);
    leave_nested_processes();
    inner_inode = inode;
    leader_tid = 1;
    if (call(218, (word)&leader_tid, 0, 0, 0) != 1 ||
        start_worker((word)(thread_stack + sizeof(thread_stack))) <= 1) finish(24);
    finish(42);
}

void _start(void) {
    word initial = namespace_inode(), previous = 0;
    int inherited = (int)call(2, (word)"/proc/self/ns/pid", 0, 0, 0);
    if (inherited < 0 || call(56, NEWPID | SIGCHLD, 0, 0, 0) != -1) finish(17);
    for (unsigned i = 0; i < 10; ++i) {
        int sockets[2], hold[2];
        if (call(53, 1, 5, 0, (word)sockets) || passcred(sockets[0]) || passcred(sockets[1]) ||
            call(22, (word)hold, 0, 0, 0) ||
            call(1, sockets[0], (word)&initial, sizeof(initial), 0) != sizeof(initial)) finish(18);
        long child = call(56, NEWUSER | NEWPID | CHILD_SETTID | SIGCHLD, 0, 0, (word)&child_tid);
        if (!child) check_inner(initial, sockets[1], inherited);
        if (child == -1 && !i) finish(77);
        if (child <= 1 || close_fd(hold[1]) || close_fd(sockets[1]) ||
            wait_for(child, 42 << 8) != child) finish(19);
        char byte;
        if (call(0, hold[0], (word)&byte, 1, 0) != 0 || close_fd(hold[0]) ||
            call(61, -1, 0, 1, 0) != -10) finish(20);
        long recycled = call(57, 0, 0, 0, 0);
        if (!recycled) finish(0);
        word inode;
        if (recycled <= child || wait_for(recycled, 0) != recycled ||
            receive(sockets[0], &inode, 2) != child || inode == initial || inode == previous ||
            receive(sockets[0], &inode, 0) != child || close_fd(sockets[0])) finish(21);
        previous = inode;
    }
    static const char marker[] = "Linux ELF64 PID namespace probe\n";
    if (namespace_inode() != initial || close_fd(inherited) ||
        call(1, 1, (word)marker, sizeof(marker) - 1, 0) != sizeof(marker) - 1) finish(22);
    finish(0);
}
