typedef unsigned long word;
typedef unsigned int u32;
typedef unsigned short u16;

enum {
    SYS_WRITE = 1, SYS_OPEN = 2, SYS_CLOSE = 3, SYS_STAT = 4, SYS_FSTAT = 5, SYS_LSTAT = 6,
    SYS_GETPID = 39, SYS_SOCKET = 41, SYS_CONNECT = 42, SYS_SENDTO = 44, SYS_RECVFROM = 45, SYS_BIND = 49,
    SYS_CLONE = 56, SYS_FORK = 57, SYS_EXIT = 60, SYS_WAIT4 = 61, SYS_READLINK = 89, SYS_GETPPID = 110,
    SYS_UNSHARE = 272, AF_INET = 2, SOCK_STREAM = 1, SOCK_DGRAM = 2, MSG_DONTWAIT = 0x40,
    O_CLOEXEC = 0x80000, SIGCHLD = 17, CLONE_NEWUSER = 0x10000000, CLONE_NEWPID = 0x20000000,
    CLONE_NEWNET = 0x40000000, EPERM = 1, EAGAIN = 11, EADDRINUSE = 98, EADDRNOTAVAIL = 99,
    ENETUNREACH = 101, PORT = 42040,
};

struct file_stat {
    word device, inode, links;
    u32 mode, uid, gid, padding;
    word rest[13];
};

struct address {
    u16 family, port;
    u32 ip;
    unsigned char padding[8];
};

struct namespace_fd {
    long fd;
    word device, inode;
};

_Static_assert(sizeof(struct file_stat) == 144 && sizeof(struct address) == 16, "Linux x86-64 ABI");

static long call6(word number, word a0, word a1, word a2, word a3, word a4, word a5) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    register word sixth __asm__("r9") = a5;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth) : "rcx", "r11", "memory");
    return (long)number;
}

static long call(word number, word a0, word a1, word a2) {
    return call6(number, a0, a1, a2, 0, 0, 0);
}

static void __attribute__((noreturn)) finish(int status) {
    call(SYS_EXIT, status, 0, 0);
    __builtin_trap();
}

static long close_fd(long fd) {
    return call(SYS_CLOSE, fd, 0, 0);
}

static struct address address(u32 ip) {
    return (struct address){.family = AF_INET, .port = __builtin_bswap16(PORT), .ip = __builtin_bswap32(ip)};
}

static long bind_socket(long fd, const struct address *local) {
    return call(SYS_BIND, fd, (word)local, sizeof(*local));
}

static long send_byte(long fd, const struct address *peer, char byte) {
    return call6(SYS_SENDTO, fd, (word)&byte, 1, 0, (word)peer, sizeof(*peer));
}

static long receive_byte(long fd, char *byte) {
    return call6(SYS_RECVFROM, fd, (word)byte, 1, MSG_DONTWAIT, 0, 0);
}

static int same_fd(const struct namespace_fd *ns) {
    struct file_stat info;
    return !call(SYS_FSTAT, ns->fd, (word)&info, 0) && info.device == ns->device && info.inode == ns->inode;
}

static int open_namespace(struct namespace_fd *ns) {
    static const char path[] = "/proc/self/ns/net";
    struct file_stat target, symbolic;
    char link[32];
    ns->fd = call(SYS_OPEN, (word)path, O_CLOEXEC, 0);
    if (ns->fd < 0 || call(SYS_STAT, (word)path, (word)&target, 0) ||
        call(SYS_LSTAT, (word)path, (word)&symbolic, 0) || (symbolic.mode & 0170000) != 0120000) return 0;
    ns->device = target.device;
    ns->inode = target.inode;
    if (!ns->inode || !same_fd(ns)) return 0;
    long length = call(SYS_READLINK, (word)path, (word)link, sizeof(link));
    if (length < 7 || (word)length >= sizeof(link) || link[0] != 'n' || link[1] != 'e' || link[2] != 't' ||
        link[3] != ':' || link[4] != '[' || link[length - 1] != ']') return 0;
    word inode = 0;
    for (long i = 5; i < length - 1; ++i) {
        if (link[i] < '0' || link[i] > '9') return 0;
        inode = inode * 10 + (unsigned)(link[i] - '0');
    }
    return inode == ns->inode;
}

static int child_status(long child, int fallback) {
    int status;
    if (child < 1 || call(SYS_WAIT4, child, (word)&status, 0) != child || (status & 0x7f)) return fallback;
    return status >> 8;
}

static void check_root_scope(const struct namespace_fd *root) {
    struct namespace_fd fresh;
    const struct address local = address(0);
    long udp = call(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    long tcp = call(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
    if (!open_namespace(&fresh) || fresh.inode != root->inode || fresh.device != root->device ||
        !same_fd(root) || udp < 0 || tcp < 0 || bind_socket(udp, &local) != -EADDRINUSE ||
        bind_socket(tcp, &local) != -EADDRINUSE) finish(8);
    finish(0);
}

static void check_private_scope(const struct namespace_fd *root, long inherited_sender, char marker) {
    struct namespace_fd fresh;
    const struct address local = address(0), loop = address(0x7f000001u), external = address(0xc6336407u);
    long udp = call(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    long tcp = call(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
    if (!open_namespace(&fresh) || fresh.inode == root->inode || !same_fd(root)) finish(10);
    if (udp < 0 || tcp < 0 || bind_socket(udp, &loop) != -EADDRNOTAVAIL ||
        bind_socket(tcp, &loop) != -EADDRNOTAVAIL || bind_socket(udp, &local) || bind_socket(tcp, &local)) finish(11);
    if (send_byte(udp, &loop, 'x') != -ENETUNREACH || send_byte(udp, &external, 'x') != -ENETUNREACH ||
        call(SYS_CONNECT, tcp, (word)&loop, sizeof(loop)) != -ENETUNREACH ||
        call(SYS_CONNECT, tcp, (word)&external, sizeof(external)) != -ENETUNREACH) finish(12);
    /* Сокет, открытый до создания namespace, по-прежнему передаёт в исходную очередь. */
    char byte;
    if (send_byte(inherited_sender, &loop, marker) != 1 || receive_byte(udp, &byte) != -EAGAIN) finish(13);
    /* На этом порту есть только изолированный получатель. */
    struct address private_local = local, private_loop = loop;
    private_local.port = private_loop.port = __builtin_bswap16(PORT + 1);
    long private_udp = call(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    if (private_udp < 0 || bind_socket(private_udp, &private_local) ||
        send_byte(inherited_sender, &private_loop, 'x') != 1 || receive_byte(private_udp, &byte) != -EAGAIN)
        finish(18);
    finish(0);
}

void _start(void) {
    struct namespace_fd root;
    if (!open_namespace(&root)) finish(1);
    long rejected = call(SYS_CLONE, CLONE_NEWNET | SIGCHLD, 0, 0);
    if (!rejected) finish(2);
    if (rejected != -EPERM || call(SYS_UNSHARE, CLONE_NEWNET, 0, 0) != -EPERM || !same_fd(&root)) finish(2);

    const struct address local = address(0);
    long listener = call(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    long tcp = call(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
    long sender = call(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    if (listener < 0 || tcp < 0 || sender < 0 || bind_socket(listener, &local) || bind_socket(tcp, &local)) finish(3);
    long child = call(SYS_FORK, 0, 0, 0);
    if (!child) check_root_scope(&root);
    int status = child_status(child, 4);
    if (status) finish(status);

    child = call(SYS_CLONE, CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | SIGCHLD, 0, 0);
    if (!child) {
        if (call(SYS_GETPID, 0, 0, 0) != 1 || call(SYS_GETPPID, 0, 0, 0)) finish(9);
        check_private_scope(&root, sender, 'c');
    }
    status = child_status(child, 5);
    char data;
    if (status) finish(status);
    if (receive_byte(listener, &data) != 1 || data != 'c' || receive_byte(listener, &data) != -EAGAIN) finish(14);

    child = call(SYS_FORK, 0, 0, 0);
    if (!child) {
        if (call(SYS_UNSHARE, CLONE_NEWUSER | CLONE_NEWNET, 0, 0)) finish(15);
        check_private_scope(&root, sender, 'u');
    }
    status = child_status(child, 6);
    if (status) finish(status);
    if (receive_byte(listener, &data) != 1 || data != 'u' || receive_byte(listener, &data) != -EAGAIN) finish(16);
    struct namespace_fd reused;
    if (!open_namespace(&reused) || reused.inode != root.inode || reused.device != root.device || !same_fd(&root) ||
        close_fd(reused.fd) || close_fd(root.fd) || close_fd(sender) || close_fd(listener) || close_fd(tcp)) finish(17);

    static const char passed[] = "Linux ELF64 netns probe\n";
    finish(call(SYS_WRITE, 1, (word)passed, sizeof(passed) - 1) == sizeof(passed) - 1 ? 0 : 7);
}
