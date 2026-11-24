typedef unsigned long word;

#define NEWUSER 0x10000000
#define CAP_V3 0x20080522

static char stack[16384] __attribute__((aligned(16)));
static const char uid_map[] = "/proc/self/uid_map";
static const char gid_map[] = "/proc/self/gid_map";
static const char setgroups[] = "/proc/self/setgroups";
static const char namespace_path[] = "/proc/self/ns/user";
static unsigned host_uid, host_gid;
static long backing;
static word initial_namespace;

struct cap_header { unsigned version; int pid; };
struct cap_data { unsigned effective, permitted, inheritable; };
struct stat {
    word dev, inode, nlink;
    unsigned mode, uid, gid, padding;
    word rest[13];
};

extern long fork_namespace(word child_stack);

__asm__(
    ".text\n"
    "fork_namespace:\n"
    "mov %rdi,%rsi\n"
    "mov $0x10000011,%edi\n"
    "xor %edx,%edx\n"
    "xor %r10d,%r10d\n"
    "xor %r8d,%r8d\n"
    "mov $56,%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "call namespace_child\n"
    "ud2\n"
    "1: ret\n"
);

static long call(word number, word a0, word a1, word a2, word a3) {
    register word fourth __asm__("r10") = a3;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth) : "rcx", "r11", "memory");
    return (long)number;
}

static long open_file(const char *path, unsigned flags) {
    return call(2, (word)path, flags, 0, 0);
}

static void finish(int status) __attribute__((noreturn));
static void finish(int status) {
    call(60, status, 0, 0, 0);
    __builtin_unreachable();
}

static char *append_id(char *out, unsigned id) {
    char digits[10];
    unsigned count = 0;
    do {
        digits[count++] = (char)('0' + id % 10);
        id /= 10;
    } while (id);
    while (count) *out++ = digits[--count];
    return out;
}

static long write_map(const char *path, unsigned lower) {
    char map[32] = {'0', ' '};
    char *end = append_id(map + 2, lower);
    *end++ = ' ';
    *end++ = '1';
    *end++ = '\n';
    long fd = open_file(path, 1);
    if (fd < 0) return fd;
    long result = call(1, fd, (word)map, (word)(end - map), 0);
    if (call(3, fd, 0, 0, 0)) return -9;
    return result;
}

static int caps_empty(const struct cap_data data[2]) {
    return !(data[0].effective | data[0].permitted | data[0].inheritable |
             data[1].effective | data[1].permitted | data[1].inheritable);
}

static word check_namespace_path(void) {
    struct stat target, link, opened;
    if (call(21, (word)namespace_path, 0, 0, 0) || call(21, (word)namespace_path, 4, 0, 0) ||
        call(21, (word)namespace_path, 2, 0, 0) != -1 ||
        call(21, (word)namespace_path, 3, 0, 0) != -13 ||
        call(4, (word)namespace_path, (word)&target, 0, 0) || (target.mode & 0170777) != 0100444 ||
        call(6, (word)namespace_path, (word)&link, 0, 0) || (link.mode & 0170000) != 0120000 ||
        target.dev == link.dev || call(2, (word)namespace_path, 0x20000, 0, 0) != -40 ||
        call(2, (word)namespace_path, 0x10000, 0, 0) != -20 ||
        call(2, (word)namespace_path, 0x30000, 0, 0) != -20 ||
        call(21, (word)"/proc/self/ns/user/", 0, 0, 0) != -20) finish(19);
    long fd = open_file(namespace_path, 0x80000);
    if (fd < 0 || call(5, fd, (word)&opened, 0, 0) || opened.inode != target.inode ||
        opened.dev != target.dev || call(72, fd, 1, 0, 0) != 1 ||
        call(262, fd, (word)"", (word)&opened, 0x1000) || opened.inode != target.inode ||
        call(3, fd, 0, 0, 0)) finish(20);
    char text[32];
    for (unsigned i = 0; i < sizeof(text); ++i) text[i] = 'z';
    long bytes = call(89, (word)namespace_path, (word)text, sizeof(text), 0);
    if (bytes < 8 || (word)bytes >= sizeof(text) || text[0] != 'u' || text[1] != 's' ||
        text[2] != 'e' || text[3] != 'r' || text[4] != ':' || text[5] != '[' ||
        text[bytes - 1] != ']' || text[bytes] != 'z') finish(21);
    word inode = 0;
    for (long i = 6; i < bytes - 1; ++i) {
        if (text[i] < '0' || text[i] > '9') finish(22);
        inode = inode * 10 + (unsigned)(text[i] - '0');
    }
    long proc = open_file("/proc/", 0x90000);
    text[3] = 'z';
    if (inode != target.inode || proc < 0 ||
        call(262, proc, (word)"self/ns/user", (word)&opened, 0x100) ||
        opened.inode != link.inode || opened.mode != link.mode ||
        call(267, proc, (word)"self/ns/user", (word)text, 3) != 3 || text[3] != 'z' ||
        call(3, proc, 0, 0, 0)) finish(23);
    return inode;
}

__attribute__((noreturn)) void namespace_child(void) {
    word outer_namespace = check_namespace_path();
    if (outer_namespace == initial_namespace) finish(24);
    if (call(102, 0, 0, 0, 0) != 65534 || call(104, 0, 0, 0, 0) != 65534 ||
        call(272, NEWUSER, 0, 0, 0) != -1) finish(1);
    struct cap_header caps = {CAP_V3, 0};
    struct cap_data initial[2], dropped[2] = {{0}, {0}};
    if (call(125, (word)&caps, (word)initial, 0, 0) || caps_empty(initial)) finish(2);
    if (call(21, (word)setgroups, 0, 0, 0) || write_map(gid_map, host_gid) != -1 ||
        write_map(uid_map, host_uid == 1 ? 2 : 1) != -1) finish(3);
    long fd = open_file(setgroups, 1);
    if (fd < 0 || call(1, fd, 1, 4, 0) != -14 ||
        call(1, fd, (word)"deny", 4, 0) != 4 || call(3, fd, 0, 0, 0)) finish(4);
    if (write_map(gid_map, host_gid) < 0 || write_map(uid_map, host_uid) < 0 ||
        write_map(uid_map, host_uid) != -1 ||
        call(102, 0, 0, 0, 0) || call(104, 0, 0, 0, 0)) finish(5);
    fd = open_file(setgroups, 1);
    if (fd < 0 || call(1, fd, (word)"allow", 5, 0) != -1 ||
        call(3, fd, 0, 0, 0)) finish(6);

    struct stat stat;
    long proc = open_file("/proc/", 0x90000);
    if (proc < 0 || call(262, proc, (word)"self/task/", (word)&stat, 0) ||
        stat.nlink != 3 || (stat.mode & 0170000) != 0040000 || call(3, proc, 0, 0, 0) ||
        call(5, backing, (word)&stat, 0, 0) || stat.uid || stat.gid) finish(7);
    if (call(126, (word)&caps, (word)dropped, 0, 0) ||
        call(126, (word)&caps, (word)initial, 0, 0) != -1 ||
        call(125, (word)&caps, (word)dropped, 0, 0) || !caps_empty(dropped)) finish(8);

    long previous = open_file(uid_map, 0);
    long ns_fd = open_file(namespace_path, 0);
    if (previous < 0 || ns_fd < 0 || call(272, NEWUSER, 0, 0, 0) ||
        call(102, 0, 0, 0, 0) != 65534) finish(9);
    word nested_namespace = check_namespace_path();
    if (nested_namespace == initial_namespace || nested_namespace == outer_namespace ||
        call(5, ns_fd, (word)&stat, 0, 0) || stat.inode != outer_namespace ||
        call(3, ns_fd, 0, 0, 0)) finish(25);
    if (write_map(uid_map, 0) != -1) finish(17);
    if (call(126, (word)&caps, (word)dropped, 0, 0) ||
        write_map(gid_map, 0) != -1 || open_file(setgroups, 1) != -13) finish(18);
    char contents[64];
    long current = open_file(uid_map, 0);
    if (current < 0 || call(0, previous, (word)contents, sizeof(contents), 0) <= 0 ||
        call(0, current, (word)contents, sizeof(contents), 0) ||
        call(3, previous, 0, 0, 0) || call(3, current, 0, 0, 0)) finish(10);
    finish(0);
}

void _start(void) {
    initial_namespace = check_namespace_path();
    host_uid = (unsigned)call(102, 0, 0, 0, 0);
    host_gid = (unsigned)call(104, 0, 0, 0, 0);
    backing = call(319, (word)"userns-test", 0, 0, 0);
    if (backing < 0 || !host_uid) finish(11);
    struct cap_header caps = {CAP_V3, 0};
    struct cap_data parent[2];
    if (call(125, (word)&caps, (word)parent, 0, 0) || !caps_empty(parent)) finish(12);
    long child = fork_namespace((word)(stack + sizeof(stack)));
    if (child == -1) finish(77);
    if (child < 0) finish(13);
    int status;
    if (call(61, child, (word)&status, 0, 0) != child || (status & 0x7f)) finish(14);
    if (status) finish(status >> 8);
    if (check_namespace_path() != initial_namespace) finish(26);
    if (call(102, 0, 0, 0, 0) != host_uid || call(104, 0, 0, 0, 0) != host_gid ||
        call(125, (word)&caps, (word)parent, 0, 0) || !caps_empty(parent) ||
        call(3, backing, 0, 0, 0)) finish(15);
    const char marker[] = "Linux ELF64 user namespace probe\n";
    if (call(1, 1, (word)marker, sizeof(marker) - 1, 0) != sizeof(marker) - 1) finish(16);
    finish(0);
}
