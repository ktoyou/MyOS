typedef unsigned long word;

struct iovec {
    void *base;
    word length;
};

struct msghdr {
    void *name;
    unsigned name_length;
    struct iovec *iov;
    word iov_count;
    void *control;
    word control_length;
    unsigned flags;
};

struct credentials {
    word length;
    int level, type, pid;
    unsigned uid, gid;
};

enum {
    AF_UNIX = 1, SOCK_SEQPACKET = 5, SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000,
    SOL_SOCKET = 1, SO_TYPE = 3, SO_PASSCRED = 16,
    MSG_PEEK = 2, MSG_CTRUNC = 8, MSG_TRUNC = 0x20, MSG_NOSIGNAL = 0x4000,
    SHUT_RD = 0, SHUT_WR = 1, SHUT_RDWR = 2,
};

static long call(word number, word a0, word a1, word a2, word a3, word a4) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long pair(int *ends) {
    return call(53, AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, (word)ends, 0);
}

static long passcred(int fd, const int *enabled, word length) {
    return call(54, fd, SOL_SOCKET, SO_PASSCRED, (word)enabled, length);
}

static long option(int fd, int key, int *value, unsigned *length) {
    return call(55, fd, SOL_SOCKET, key, (word)value, (word)length);
}

static long close_fd(int fd) {
    return call(3, fd, 0, 0, 0, 0);
}

static long shutdown(int fd, int how) {
    return call(48, fd, how, 0, 0, 0);
}

static long send(int fd, const struct msghdr *msg) {
    return call(46, fd, (word)msg, MSG_NOSIGNAL, 0, 0);
}

static long receive(int fd, struct msghdr *msg, unsigned flags) {
    return call(47, fd, (word)msg, flags, 0, 0);
}

static long check_options(int fd) {
    int value;
    unsigned length = sizeof(value);
    if (option(fd, SO_TYPE, &value, &length) || length != sizeof(value) || value != SOCK_SEQPACKET ||
        option(fd, SO_PASSCRED, &value, &length) || value != 0) return 1;
    const int enabled = 1;
    if (passcred(fd, &enabled, 3) != -22 || passcred(fd, 0, 4) != -14 ||
        passcred(fd, &enabled, 4) || option(fd, SO_PASSCRED, &value, &length) || value != 1) return 2;
    return 0;
}

static long check_packets(int left, int right) {
    static char pages[8192] __attribute__((aligned(4096)));
    char *send_bytes = pages + 4094;
    send_bytes[0] = 'a'; send_bytes[1] = 'b'; send_bytes[2] = 'c'; send_bytes[3] = 'd';
    struct iovec tx[2] = {{send_bytes, 3}, {send_bytes + 3, 1}};
    struct msghdr out = {.iov = tx, .iov_count = 2};
    struct iovec bad_iov[2] = {{send_bytes, 3}, {0, 1}};
    struct msghdr bad = {.iov = bad_iov, .iov_count = 2};
    char small[2], big[4];
    struct credentials cred;
    struct iovec rx = {small, sizeof(small)};
    struct msghdr in = {.iov = &rx, .iov_count = 1, .control = &cred,
                        .control_length = sizeof(cred)};
    if (send(left, &bad) != -14 || receive(right, &in, 0) != -11 ||
        send(left, &out) != 4 || call(1, left, (word)"xy", 2, 0, 0) != 2) return 3;
    struct iovec bad_rx[2] = {{big, sizeof(big)}, {(void *)0xffff800000000000ul, 1}};
    struct msghdr bad_in = {.iov = bad_rx, .iov_count = 2};
    if (receive(right, &bad_in, 0) != -14) return 17;
    in.control_length = 21;
    if (receive(right, &in, MSG_PEEK | MSG_TRUNC) != 4 || in.flags != (MSG_TRUNC | MSG_CTRUNC) ||
        small[0] != 'a' || small[1] != 'b' || in.control_length != 21 ||
        cred.length != 21 || cred.level != 1 || cred.type != 2) return 4;
    rx = (struct iovec){big, sizeof(big)};
    in.control_length = sizeof(cred);
    if (receive(right, &in, 0) != 4 || in.flags != 0 || in.control_length != sizeof(cred) ||
        cred.length != 28 || cred.level != 1 || cred.type != 2 ||
        cred.pid != call(39, 0, 0, 0, 0, 0) || cred.uid != (word)call(102, 0, 0, 0, 0, 0) ||
        cred.gid != (word)call(104, 0, 0, 0, 0, 0) ||
        big[0] != 'a' || big[1] != 'b' || big[2] != 'c' || big[3] != 'd') return 5;
    if (call(0, right, (word)big, 1, 0, 0) != 1 || big[0] != 'x' ||
        call(0, right, (word)big, sizeof(big), 0, 0) != -11) return 6;
    out = (struct msghdr){0};
    in.control_length = sizeof(cred);
    if (send(left, &out) != 0 || call(0, right, 0, 0, 0, 0) ||
        receive(right, &in, 0) != 0 || in.control_length != sizeof(cred) ||
        receive(right, &in, 0) != -11) return 7;
    int disabled = 0, enabled = 1;
    in.control_length = sizeof(cred);
    if (passcred(right, &disabled, 4) || send(left, &out) ||
        passcred(right, &enabled, 4) ||
        receive(right, &in, 0) || in.control_length != sizeof(cred) ||
        cred.pid != 0 || cred.uid != 65534 || cred.gid != 65534) return 18;
    return 0;
}

static long check_close(int left, int right) {
    char byte = 'q', received;
    struct iovec tx = {&byte, 1}, rx = {&received, 1};
    struct msghdr out = {.iov = &tx, .iov_count = 1}, in = {.iov = &rx, .iov_count = 1};
    if (send(left, &out) != 1 || send(right, &out) != 1 || close_fd(right) ||
        shutdown(left, SHUT_RDWR) ||
        receive(left, &in, 0) != -104 || receive(left, &in, 0) != 1 || received != 'q' ||
        receive(left, &in, 0) != 0 || send(left, &out) != -32 || close_fd(left)) return 8;
    return 0;
}

static long check_shutdown(void) {
    char byte = 's', received = 0;
    struct credentials cred;
    struct iovec tx = {&byte, 1}, rx = {&received, 1};
    struct msghdr out = {.iov = &tx, .iov_count = 1};
    struct msghdr in = {.iov = &rx, .iov_count = 1, .control = &cred};
    const int enabled = 1;
    if (shutdown(-1, 3) != -9 || shutdown(1, 3) != -88) return 22;
    for (int how = SHUT_RD; how <= SHUT_WR; ++how) {
        int ends[2];
        if (pair(ends) || shutdown(ends[0], -1) != -22 || shutdown(ends[1], 3) != -22 ||
            passcred(ends[1], &enabled, sizeof(enabled)) || send(ends[0], &out) != 1) return 23;
        int initiator = how == SHUT_RD ? ends[1] : ends[0];
        if (shutdown(initiator, how) || shutdown(initiator, how) ||
            send(ends[0], &out) != -32) return 24;
        in.control_length = sizeof(cred);
        if (receive(ends[1], &in, MSG_PEEK) != 1 || received != 's' ||
            in.control_length != sizeof(cred) || cred.pid != call(39, 0, 0, 0, 0, 0) ||
            call(0, ends[1], (word)&received, 1, 0, 0) != 1) return 25;
        in.control_length = sizeof(cred);
        if (receive(ends[1], &in, 0) || in.control_length ||
            send(ends[1], &out) != 1 || call(0, ends[0], (word)&received, 1, 0, 0) != 1 ||
            close_fd(ends[0]) || close_fd(ends[1])) return 26;
    }
    int ends[2];
    if (pair(ends) || send(ends[0], &out) != 1 || send(ends[1], &out) != 1 ||
        shutdown(ends[0], SHUT_RDWR) || call(72, ends[0], 1, 0, 0, 0) != 1) return 27;
    for (unsigned i = 0; i < 2; ++i)
        if (send(ends[i], &out) != -32 || call(0, ends[i], (word)&received, 1, 0, 0) != 1 ||
            call(0, ends[i], (word)&received, 1, 0, 0)) return 28;
    return close_fd(ends[0]) || close_fd(ends[1]) ? 29 : 0;
}

static long check_fd_limit(void) {
    int ends[14][2], spare[2];
    for (unsigned i = 0; i < 14; ++i)
        if (pair(ends[i])) return 9;
    if (pair(spare) != -24) return 10;
    long last = call(319, (word)"", 0, 0, 0, 0);
    if (last != 31 || close_fd(last)) return 11;
    for (unsigned i = 0; i < 14; ++i)
        if (close_fd(ends[i][0]) || close_fd(ends[i][1])) return 12;
    if (pair(spare) || spare[0] != 3 || spare[1] != 4 ||
        close_fd(spare[0]) || close_fd(spare[1])) return 13;
    int survivors[27];
    for (unsigned i = 0; i < 27; ++i) {
        if (pair(spare) || close_fd(spare[1])) return 19;
        survivors[i] = spare[0];
    }
    if (pair(spare) || close_fd(spare[0]) || close_fd(spare[1])) return 20;
    for (unsigned i = 0; i < 27; ++i)
        if (close_fd(survivors[i])) return 21;
    return 0;
}

static long check(void) {
    int ends[2];
    for (unsigned i = 0; i < 40; ++i)
        if (pair(0) != -14) return 14;
    if (pair(ends) || ends[0] != 3 || ends[1] != 4 ||
        call(72, ends[0], 1, 0, 0, 0) != 1 ||
        call(72, ends[0], 3, 0, 0, 0) != 0x802) return 15;
    long status = check_options(ends[1]);
    if (!status) status = check_packets(ends[0], ends[1]);
    if (!status) status = check_close(ends[0], ends[1]);
    if (!status) status = check_shutdown();
    return status ? status : check_fd_limit();
}

__attribute__((noreturn)) void _start(void) {
    long status = check();
    if (!status) {
        static const char message[] = "Linux ELF64 seqpacket probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0, 0) != sizeof(message) - 1) status = 16;
    }
    call(60, status, 0, 0, 0, 0);
    __builtin_trap();
}
