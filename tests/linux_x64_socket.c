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
    AF_UNIX = 1, SOCK_STREAM = 1, SOCK_SEQPACKET = 5, SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000,
    SOL_SOCKET = 1, SCM_RIGHTS = 1, SO_TYPE = 3, SO_PASSCRED = 16,
    MSG_PEEK = 2, MSG_CTRUNC = 8, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40, MSG_NOSIGNAL = 0x4000,
    MSG_CMSG_CLOEXEC = 0x40000000, SHUT_RD = 0, SHUT_WR = 1, SHUT_RDWR = 2,
};

static long call6(word number, word a0, word a1, word a2, word a3, word a4, word a5) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    register word sixth __asm__("r9") = a5;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long call(word number, word a0, word a1, word a2, word a3, word a4) {
    return call6(number, a0, a1, a2, a3, a4, 0);
}

static long send_bytes(int fd, const void *data, word size, word flags) {
    return call(44, fd, (word)data, size, flags, 0);
}

static long pair_type(int *ends, word type) {
    return call(53, AF_UNIX, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, (word)ends, 0);
}

static long pair(int *ends) {
    return pair_type(ends, SOCK_SEQPACKET);
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

static long stream(word flags) {
    return call(41, AF_UNIX, SOCK_STREAM | flags, 0, 0, 0);
}

static long check_stream(void) {
    if (call(41, 999, SOCK_STREAM, 0, 0, 0) != -97 ||
        call(41, AF_UNIX, SOCK_STREAM | 0x40000000, 0, 0, 0) != -22 ||
        call(41, AF_UNIX, 4, 0, 0, 0) != -94 ||
        call(41, AF_UNIX, 4, 2, 0, 0) != -93) return 30;
    long fd = stream(0);
    if (fd < 3 || call(72, fd, 1, 0, 0, 0) || call(72, fd, 3, 0, 0, 0) != 2) return 31;
    int type;
    unsigned length = sizeof(type);
    word info[18];
    if (option(fd, SO_TYPE, &type, &length) || type != SOCK_STREAM || length != sizeof(type) ||
        call(5, fd, (word)info, 0, 0, 0) || (info[3] & 0177777) != 0140777 ||
        !info[1] || info[2] != 1 || info[6] != 0) return 32;

    long duplicate = call(32, fd, 0, 0, 0, 0);
    if (duplicate <= fd || call(72, fd, 4, 0x400 | SOCK_NONBLOCK, 0, 0) ||
        call(72, duplicate, 3, 0, 0, 0) != (2 | 0x400 | SOCK_NONBLOCK) ||
        call(72, fd, 4, 0x4000, 0, 0) != -22 ||
        call(72, duplicate, 4, 0, 0, 0) || call(72, fd, 3, 0, 0, 0) != 2 ||
        call(72, fd, 2, 1, 0, 0) || call(72, fd, 1, 0, 0, 0) != 1 ||
        call(72, duplicate, 1, 0, 0, 0) || close_fd(fd)) return 33;

    char byte;
    const word invalid = 0xffff800000000000ul;
    struct msghdr message = {0};
    struct { int fd; short events, revents; } pollfd = {(int)duplicate, 0x2205, 0};
    if (call(0, duplicate, (word)&byte, 0, 0, 0) ||
        call(0, duplicate, (word)&byte, 1, 0, 0) != -22 ||
        call(1, duplicate, (word)&byte, 0, 0, 0) != -107 ||
        send(duplicate, &message) != -107 || receive(duplicate, &message, 0) != -22 ||
        send(duplicate, 0) != -14 || receive(duplicate, 0, 0) != -14) return 34;
    if (call(0, duplicate, invalid, 1, 0, 0) != -14 ||
        call(1, duplicate, invalid, 1, 0, 0) != -14 ||
        call(17, duplicate, (word)&byte, 1, 0, 0) != -29 ||
        call(18, duplicate, (word)&byte, 1, 0, 0) != -29) return 42;
    if (call(7, (word)&pollfd, 1, 0, 0, 0) != 1 || pollfd.revents != 0x214 ||
        shutdown(duplicate, -1) != -22 || shutdown(duplicate, SHUT_RD) ||
        call(7, (word)&pollfd, 1, 0, 0, 0) != 1 || pollfd.revents != 0x2215 ||
        close_fd(duplicate)) return 35;

    fd = stream(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 3 || call(72, fd, 1, 0, 0, 0) != 1 ||
        call(72, fd, 3, 0, 0, 0) != (2 | SOCK_NONBLOCK) || close_fd(fd)) return 36;
    return 0;
}

static long check_stream_fd_limit(void) {
    int descriptors[29];
    for (unsigned i = 0; i < sizeof(descriptors) / sizeof(*descriptors); ++i) {
        long fd = stream(0);
        if (fd < 3) return 37;
        descriptors[i] = (int)fd;
    }
    for (unsigned i = 0; i < 300; ++i)
        if (stream(0) != -24) return 38;
    if (close_fd(descriptors[0])) return 39;
    long fd = stream(0);
    if (fd != descriptors[0] || close_fd(fd)) return 40;
    for (unsigned i = 1; i < sizeof(descriptors) / sizeof(*descriptors); ++i)
        if (close_fd(descriptors[i])) return 41;
    return 0;
}

struct unix_address {
    unsigned short family;
    char path[108];
};

static long named_call(word number, long fd, const struct unix_address *address) {
    return call(number, fd, (word)address, sizeof(*address), 0, 0);
}

static long check_named(const struct unix_address *address) {
    long listener = stream(SOCK_NONBLOCK), client = stream(0), second = stream(SOCK_NONBLOCK);
    if (listener < 3 || client < 3 || second < 3 || call(50, listener, 0, 0, 0, 0) != -22 ||
        named_call(42, client, address) != -2 || call(49, listener, (word)address, 111, 0, 0) != -22 ||
        call(49, listener, 0, sizeof(*address), 0, 0) != -14) return 43;
    long mask = call(95, 0077, 0, 0, 0, 0);
    if (mask < 0 || named_call(49, listener, address) || call(95, mask, 0, 0, 0, 0) != 0077 ||
        named_call(49, second, address) != -98 || named_call(42, client, address) != -111) return 44;
    word info[18], descriptor[18];
    if (call(4, (word)address->path, (word)info, 0, 0, 0) || (info[3] & 0177777) != 0140700 ||
        call(5, listener, (word)descriptor, 0, 0, 0) ||
        (info[0] == descriptor[0] && info[1] == descriptor[1]) ||
        call(2, (word)address->path, 0, 0, 0, 0) != -6 ||
        call(21, (word)address->path, 7, 0, 0, 0)) return 45;

    struct { int fd; short events, revents; } pollfd = {(int)listener, 0x2255, 0};
    if (call(50, listener, 0, 0, 0, 0) || call(43, listener, 0, 0, 0, 0) != -11 ||
        call(7, (word)&pollfd, 1, 0, 0, 0) || pollfd.revents) return 46;
    int extra[26];
    for (unsigned i = 0; i < sizeof(extra) / sizeof(*extra); ++i) {
        long fd = stream(0);
        if (fd < 3) return 63;
        extra[i] = (int)fd;
    }
    if (call(43, listener, 0, 0, 0, 0) != -24 || named_call(42, client, address) ||
        named_call(42, second, address) != -11 || call(43, listener, 0, 0, 0, 0) != -24 ||
        call(7, (word)&pollfd, 1, 0, 0, 0) != 1 || pollfd.revents != 0x41) return 64;
    for (unsigned i = 0; i < sizeof(extra) / sizeof(*extra); ++i)
        if (close_fd(extra[i])) return 65;
    struct unix_address remote;
    unsigned len = sizeof(remote);
    if (call(288, listener, 0, 0, 1, 0) != -22) return 47;
    long accepted = call(288, listener, (word)&remote, (word)&len, SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (accepted < 3 || len != 2 || remote.family != AF_UNIX ||
        call(72, accepted, 1, 0, 0, 0) != 1 || call(72, accepted, 3, 0, 0, 0) != 0x802 ||
        call(52, client, (word)&remote, (word)&len, 0, 0) || len <= 2 || remote.family != AF_UNIX ||
        named_call(42, second, address)) return 48;
    if (call(43, listener, 1, 0, 0, 0) != -14 || call(43, listener, 0, 0, 0, 0) != -11 ||
        close_fd(second)) return 49;

    char bytes[8];
    struct iovec rx = {bytes, 2};
    struct msghdr message = {.iov = &rx, .iov_count = 1};
    if (receive(accepted, &message, 0) != -11 || call(1, client, 0, 0, 0, 0) ||
        call(1, client, (word)"ab", 2, 0, 0) != 2 || call(1, client, (word)"cdef", 4, 0, 0) != 4 ||
        call(0, accepted, (word)bytes, 3, 0, 0) != 3 || bytes[0] != 'a' || bytes[2] != 'c' ||
        receive(accepted, &message, MSG_PEEK) != 2 || bytes[0] != 'd' || bytes[1] != 'e' ||
        receive(accepted, &message, MSG_TRUNC) != 2 || bytes[0] != 'd' || bytes[1] != 'e') return 50;
    if (shutdown(client, SHUT_WR) || call(0, accepted, (word)bytes, sizeof(bytes), 0, 0) != 1 ||
        bytes[0] != 'f' || call(0, accepted, (word)bytes, sizeof(bytes), 0, 0)) return 51;

    if (call(87, (word)address->path, 0, 0, 0, 0) ||
        call(1, accepted, (word)"x", 1, 0, 0) != 1 || call(0, client, (word)bytes, 1, 0, 0) != 1 ||
        bytes[0] != 'x' || close_fd(listener) || close_fd(accepted) || close_fd(client)) return 52;
    listener = stream(0);
    client = stream(0);
    if (listener < 3 || client < 3 || named_call(49, listener, address) ||
        call(50, listener, 1, 0, 0, 0) || named_call(42, client, address) || close_fd(listener) ||
        call(0, client, (word)bytes, 1, 0, 0) != -104 || call(0, client, (word)bytes, 1, 0, 0)) return 53;
    second = stream(0);
    if (second < 3 || named_call(42, second, address) != -111 || named_call(49, second, address) != -98 ||
        call(87, (word)address->path, 0, 0, 0, 0) || close_fd(second) || close_fd(client)) return 60;
    return 0;
}

static unsigned char transfer[384 * 1024];

static long check_blocking_stream(const struct unix_address *address, int use_sendto) {
    long listener = stream(0);
    if (listener < 3 || named_call(49, listener, address) || call(50, listener, 4, 0, 0, 0)) return 54;
    long pid = call(57, 0, 0, 0, 0, 0);
    if (!pid) {
        long client = stream(0);
        if (client < 3 || close_fd(listener) || named_call(42, client, address)) goto child_fail;
        for (word i = 0; i < sizeof(transfer); ++i) transfer[i] = (unsigned char)i;
        long sent = use_sendto ? send_bytes(client, transfer, sizeof(transfer), MSG_NOSIGNAL)
                              : call(1, client, (word)transfer, sizeof(transfer), 0, 0);
        if (sent == sizeof(transfer) &&
            !shutdown(client, SHUT_WR) && !close_fd(client)) {
            call(60, 0, 0, 0, 0, 0);
        }
    child_fail:
        call(60, 1, 0, 0, 0, 0);
        __builtin_trap();
    }
    if (pid < 0) return 55;
    long accepted = call(43, listener, 0, 0, 0, 0);
    if (accepted < 3 || call(72, accepted, 1, 0, 0, 0) || call(72, accepted, 3, 0, 0, 0) != 2) return 56;
    unsigned char bytes[7777];
    word total = 0;
    for (;;) {
        long got = call(0, accepted, (word)bytes, sizeof(bytes), 0, 0);
        if (got < 0 || (word)got > sizeof(transfer) - total) return 57;
        if (!got) break;
        for (long i = 0; i < got; ++i)
            if (bytes[i] != (unsigned char)(total + (word)i)) return 58;
        total += (word)got;
    }
    int status;
    if (total != sizeof(transfer) || call(61, pid, (word)&status, 0, 0, 0) != pid || status ||
        close_fd(accepted) || close_fd(listener) || call(87, (word)address->path, 0, 0, 0, 0)) return 59;
    return 0;
}

static long check_listener_shutdown(const struct unix_address *address) {
    long listener = stream(0);
    if (listener < 3 || named_call(49, listener, address) || call(50, listener, 0, 0, 0, 0)) return 61;
    long pid = call(57, 0, 0, 0, 0, 0);
    if (!pid) {
        call(24, 0, 0, 0, 0, 0);
        call(60, shutdown(listener, SHUT_RD) != 0, 0, 0, 0, 0);
        __builtin_trap();
    }
    int status;
    if (pid < 0 || call(43, listener, 0, 0, 0, 0) != -22 ||
        call(61, pid, (word)&status, 0, 0, 0) != pid || status ||
        call(72, listener, 4, SOCK_NONBLOCK, 0, 0) || call(43, listener, 0, 0, 0, 0) != -11 ||
        close_fd(listener) || call(87, (word)address->path, 0, 0, 0, 0)) return 62;
    return 0;
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

static long check_fd_limit(word type) {
    int ends[14][2], spare[2];
    for (unsigned i = 0; i < 14; ++i)
        if (pair_type(ends[i], type)) return 9;
    if (pair_type(spare, type) != -24) return 10;
    long last = call(319, (word)"", 0, 0, 0, 0);
    if (last != 31 || close_fd(last)) return 11;
    for (unsigned i = 0; i < 14; ++i)
        if (close_fd(ends[i][0]) || close_fd(ends[i][1])) return 12;
    if (pair_type(spare, type) || spare[0] != 3 || spare[1] != 4 ||
        close_fd(spare[0]) || close_fd(spare[1])) return 13;
    int survivors[27];
    for (unsigned i = 0; i < 27; ++i) {
        if (pair_type(spare, type) || close_fd(spare[1])) return 19;
        survivors[i] = spare[0];
    }
    if (pair_type(spare, type) || close_fd(spare[0]) || close_fd(spare[1])) return 20;
    for (unsigned i = 0; i < 27; ++i)
        if (close_fd(survivors[i])) return 21;
    return 0;
}

static long check_seqpacket_receive_wait(void) {
    int ends[2];
    char bytes[8];
    struct iovec rx = {bytes, sizeof(bytes)};
    struct msghdr in = {.iov = &rx, .iov_count = 1};
    if (call(53, AF_UNIX, SOCK_SEQPACKET, 0, (word)ends, 0) ||
        receive(ends[0], &in, MSG_DONTWAIT) != -11 ||
        call(72, ends[0], 4, SOCK_NONBLOCK, 0, 0) || receive(ends[0], &in, 0) != -11 ||
        call(72, ends[0], 4, 0, 0, 0)) return 66;

    long pid = call(57, 0, 0, 0, 0, 0);
    if (!pid) {
        call(24, 0, 0, 0, 0, 0);
        int failed = close_fd(ends[0]) || call(1, ends[1], (word)"one", 3, 0, 0) != 3 ||
                     call(1, ends[1], (word)"two", 3, 0, 0) != 3 || close_fd(ends[1]);
        call(60, failed, 0, 0, 0, 0);
        __builtin_trap();
    }
    int status;
    if (pid < 0 || close_fd(ends[1]) || receive(ends[0], &in, 0) != 3 || bytes[0] != 'o' ||
        call(0, ends[0], (word)bytes, sizeof(bytes), 0, 0) != 3 || bytes[0] != 't' ||
        receive(ends[0], &in, 0) || call(61, pid, (word)&status, 0, 0, 0) != pid || status ||
        close_fd(ends[0])) return 67;
    return 0;
}

static long check_seqpacket_send_wait(void) {
    int ends[2];
    if (call(53, AF_UNIX, SOCK_SEQPACKET, 0, (word)ends, 0)) return 68;
    struct iovec tx = {(char *)"old", 3};
    struct msghdr out = {.iov = &tx, .iov_count = 1};
    unsigned filled = 0;
    for (;;) {
        long result = call(46, ends[0], (word)&out, MSG_DONTWAIT | MSG_NOSIGNAL, 0, 0);
        if (result == -11) break;
        if (result != 3 || ++filled > 4096) return 69;
    }
    if (!filled) return 69;

    long pid = call(57, 0, 0, 0, 0, 0);
    if (!pid) {
        char bytes[8];
        int failed = close_fd(ends[0]) != 0;
        call(24, 0, 0, 0, 0, 0);
        for (unsigned i = 0; i < filled && !failed; ++i)
            failed = call(0, ends[1], (word)bytes, sizeof(bytes), 0, 0) != 3 || bytes[0] != 'o';
        if (!failed)
            failed = call(0, ends[1], (word)bytes, sizeof(bytes), 0, 0) != 4 || bytes[0] != 't' ||
                     call(0, ends[1], (word)bytes, sizeof(bytes), 0, 0) || close_fd(ends[1]);
        call(60, failed, 0, 0, 0, 0);
        __builtin_trap();
    }
    int status;
    if (pid < 0 || close_fd(ends[1]) || call(1, ends[0], (word)"tail", 4, 0, 0) != 4 ||
        close_fd(ends[0]) || call(61, pid, (word)&status, 0, 0, 0) != pid || status) return 70;
    return 0;
}

static long check_stream_pair_queue(int left, int right, int use_sendto) {
    static char block[2048];
    long queued = 0;
    while (queued < 16 * 1024 * 1024) {
        long sent = use_sendto ? send_bytes(left, block, sizeof(block), MSG_DONTWAIT | MSG_NOSIGNAL)
                              : call(1, left, (word)block, sizeof(block), 0, 0);
        if (sent == -11) break;
        if (sent <= 0) return 77;
        queued += sent;
    }
    if (!queued || queued >= 16 * 1024 * 1024) return 77;
    while (queued) {
        long received = call(0, right, (word)block, sizeof(block), 0, 0);
        if (received <= 0 || received > queued) return 78;
        queued -= received;
    }
    return call(1, left, (word)"p", 1, 0, 0) != 1 ||
           call(0, right, (word)block, 1, 0, 0) != 1 || block[0] != 'p' ? 79 : 0;
}

static long check_stream_pair(void) {
    int ends[2];
    for (unsigned i = 0; i < 40; ++i)
        if (pair_type(0, SOCK_STREAM) != -14) return 71;
    if (pair_type(ends, SOCK_STREAM) || ends[0] != 3 || ends[1] != 4) return 72;
    for (unsigned i = 0; i < 2; ++i) {
        int type = 0;
        unsigned length = sizeof(type);
        unsigned short family = 0;
        unsigned name_length = sizeof(family);
        if (option(ends[i], SO_TYPE, &type, &length) || type != SOCK_STREAM ||
            length != sizeof(type) || call(72, ends[i], 1, 0, 0, 0) != 1 ||
            call(72, ends[i], 3, 0, 0, 0) != 0x802 ||
            call(51, ends[i], (word)&family, (word)&name_length, 0, 0) ||
            family != AF_UNIX || name_length != sizeof(family)) return 73;
        family = 0;
        if (call(52, ends[i], (word)&family, (word)&name_length, 0, 0) ||
            family != AF_UNIX || name_length != sizeof(family)) return 73;
    }
    char bytes[4];
    if (call(0, ends[1], (word)bytes, 1, 0, 0) != -11 ||
        call(1, ends[0], (word)"ab", 2, 0, 0) != 2 ||
        call(1, ends[0], (word)"cd", 2, 0, 0) != 2 ||
        call(0, ends[1], (word)bytes, 1, 0, 0) != 1 || bytes[0] != 'a' ||
        call(0, ends[1], (word)bytes, sizeof(bytes), 0, 0) != 3 ||
        bytes[0] != 'b' || bytes[1] != 'c' || bytes[2] != 'd') return 74;
    long queue_status = check_stream_pair_queue(ends[0], ends[1], 0);
    if (queue_status) return queue_status;
    if (call(72, ends[0], 4, 0, 0, 0) || call(72, ends[1], 4, 0, 0, 0)) return 75;
    long pid = call(57, 0, 0, 0, 0, 0);
    if (!pid) {
        int failed = close_fd(ends[0]) || call(0, ends[1], (word)bytes, 1, 0, 0) != 1 ||
                     bytes[0] != 'q' || call(0, ends[1], (word)bytes, 1, 0, 0) ||
                     call(1, ends[1], (word)"r", 1, 0, 0) != 1;
        call(60, failed, 0, 0, 0, 0);
        __builtin_trap();
    }
    int status;
    long duplicate = call(32, ends[0], 0, 0, 0, 0);
    if (pid < 0 || duplicate < 3 || close_fd(ends[1]) ||
        call(1, ends[0], (word)"q", 1, 0, 0) != 1 || shutdown((int)duplicate, SHUT_WR) ||
        close_fd((int)duplicate) || call(0, ends[0], (word)bytes, 1, 0, 0) != 1 ||
        bytes[0] != 'r' || call(0, ends[0], (word)bytes, 1, 0, 0) ||
        call(61, pid, (word)&status, 0, 0, 0) != pid || status || close_fd(ends[0])) return 76;
    return 0;
}

static long check_sendto(void) {
    unsigned short address = AF_UNIX;
    int ends[2];
    if (send_bytes(-1, "C", 1, MSG_NOSIGNAL) != -9 ||
        send_bytes(1, "C", 1, MSG_NOSIGNAL) != -88 ||
        call(53, AF_UNIX, SOCK_STREAM, 0, (word)ends, 0)) return 80;
    char byte;
    if (send_bytes(ends[0], 0, 1, MSG_NOSIGNAL) != -14 ||
        call6(44, ends[0], (word)"C", 1, MSG_NOSIGNAL, 1, sizeof(address)) != -14 ||
        call6(44, ends[0], (word)"C", 1, MSG_NOSIGNAL, (word)&address, 129) != -22 ||
        call6(44, ends[0], (word)"C", 1, MSG_NOSIGNAL, (word)&address, sizeof(address)) != -106 ||
        send_bytes(ends[0], "C", 1, MSG_NOSIGNAL) != 1 ||
        call(0, ends[1], (word)&byte, 1, 0, 0) != 1 || byte != 'C') return 81;
    long result = check_stream_pair_queue(ends[0], ends[1], 1);
    if (result) return result;
    if (call(72, ends[0], 3, 0, 0, 0) != 2 || shutdown(ends[0], SHUT_WR) ||
        send_bytes(ends[0], "C", 1, MSG_NOSIGNAL) != -32 ||
        call(0, ends[1], (word)&byte, 1, 0, 0) || close_fd(ends[0]) || close_fd(ends[1])) return 82;
    long unconnected = stream(0);
    if (unconnected < 3 || send_bytes((int)unconnected, "C", 1, MSG_NOSIGNAL) != -107 ||
        call6(44, unconnected, (word)"C", 1, MSG_NOSIGNAL, (word)&address, sizeof(address)) != -95 ||
        close_fd(unconnected)) return 83;
    if (pair(ends) ||
        call6(44, ends[0], (word)"qr", 2, MSG_NOSIGNAL, (word)&address, sizeof(address)) != 2 ||
        call(0, ends[1], (word)&byte, 1, 0, 0) != 1 || byte != 'q' ||
        call(0, ends[1], (word)&byte, 1, 0, 0) != -11 ||
        close_fd(ends[0]) || close_fd(ends[1])) return 84;
    return 0;
}

struct rights {
    word length;
    int level, type;
    int fds[4];
};

static long send_rights(int fd, const char *bytes, word length, const int *fds, unsigned count) {
    struct rights rights = {16 + 4 * count, SOL_SOCKET, SCM_RIGHTS, {0}};
    for (unsigned i = 0; i < count; ++i) rights.fds[i] = fds[i];
    struct iovec data = {(void *)bytes, length};
    struct msghdr message = {.iov = &data, .iov_count = 1, .control = &rights,
                             .control_length = rights.length};
    return send(fd, &message);
}

static long recv_rights(int fd, char *bytes, word length, struct rights *control, word capacity,
                        unsigned flags, unsigned *received_flags) {
    struct iovec data = {bytes, length};
    struct msghdr message = {.iov = &data, .iov_count = 1, .control = control, .control_length = capacity};
    long result = receive(fd, &message, flags);
    if (received_flags) *received_flags = message.flags;
    return result;
}

static long check_rights_fork(word type) {
    int ends[2], gate[2];
    if (call(53, AF_UNIX, type, 0, (word)ends, 0) || call(22, (word)gate, 0, 0, 0, 0)) return 85;
    long child = call(57, 0, 0, 0, 0, 0);
    if (!child) {
        int peer = ends[1];
        struct rights rights = {0};
        char byte;
        if (close_fd(ends[0]) || close_fd(gate[1]) || call(0, gate[0], (word)&byte, 1, 0, 0) ||
            close_fd(gate[0]) || recv_rights(peer, &byte, 1, &rights, sizeof(rights),
                                             MSG_CMSG_CLOEXEC, 0) != 1 || byte != 'X' ||
            rights.length != 28 || rights.level != SOL_SOCKET || rights.type != SCM_RIGHTS)
            call(60, 1, 0, 0, 0, 0);
        if (call(72, rights.fds[0], 1, 0, 0, 0) != 1 ||
            call(72, rights.fds[2], 1, 0, 0, 0) != 1 ||
            call(0, rights.fds[0], (word)&byte, 1, 0, 0) != 1 || byte != 'A' ||
            call(0, rights.fds[1], (word)&byte, 1, 0, 0) != 1 || byte != 'B' ||
            call(1, rights.fds[2], (word)"K", 1, 0, 0) != 1)
            call(60, 2, 0, 0, 0, 0);
        call(60, 0, 0, 0, 0, 0);
        __builtin_trap();
    }
    if (child < 0 || close_fd(ends[1]) || close_fd(gate[0])) return 85;
    int sockets[2];
    long memfd = call(319, (word)"rights", 0, 0, 0, 0);
    if (memfd < 3 || call(77, memfd, 4096, 0, 0, 0) ||
        call(53, AF_UNIX, SOCK_STREAM, 0, (word)sockets, 0)) return 86;
    long address = call6(9, 0, 4096, 3, 1, memfd, 0);
    if (address < 0) return 86;
    char *memory = (char *)(word)address;
    memory[0] = 'A';
    memory[1] = 'B';
    int fds[] = {(int)memfd, (int)memfd, sockets[0]};
    int status = 0;
    char byte;
    if (send_rights(ends[0], "X", 1, fds, 3) != 1 || close_fd((int)memfd) || close_fd(sockets[0]) ||
        call(11, address, 4096, 0, 0, 0) || close_fd(gate[1]) ||
        call(61, child, (word)&status, 0, 0, 0) != child || status ||
        call(0, sockets[1], (word)&byte, 1, 0, 0) != 1 || byte != 'K' ||
        close_fd(sockets[1]) || close_fd(ends[0])) return 87 + ((status >> 8) & 3);
    return 0;
}

static long check_rights_stream(void) {
    int ends[2], pipe_fds[2];
    if (pair_type(ends, SOCK_STREAM) || call(22, (word)pipe_fds, 0, 0, 0, 0) ||
        call(1, ends[0], (word)"X", 1, 0, 0) != 1 ||
        send_rights(ends[0], "AB", 2, &pipe_fds[1], 1) != 2 ||
        send_rights(ends[0], "CD", 2, &pipe_fds[1], 1) != 2 ||
        call(1, ends[0], (word)"Z", 1, 0, 0) != 1 || close_fd(pipe_fds[1])) return 91;
    struct rights peek = {0}, first = {0}, second = {0};
    char bytes[8];
    if (recv_rights(ends[1], bytes, sizeof(bytes), &peek, 20, MSG_PEEK, 0) != 3 ||
        bytes[0] != 'X' || bytes[1] != 'A' || bytes[2] != 'B' || peek.length != 20 ||
        recv_rights(ends[1], bytes, 2, &first, sizeof(first), 0, 0) != 2 ||
        bytes[0] != 'X' || bytes[1] != 'A' || first.length != 20 || first.fds[0] == peek.fds[0] ||
        recv_rights(ends[1], bytes, sizeof(bytes), &second, sizeof(second), 0, 0) != 3 ||
        bytes[0] != 'B' || bytes[1] != 'C' || bytes[2] != 'D' || second.length != 20) return 92;
    if (call(0, ends[1], (word)bytes, sizeof(bytes), 0, 0) != 1 || bytes[0] != 'Z' ||
        close_fd(peek.fds[0]) || close_fd(first.fds[0]) || close_fd(second.fds[0]) ||
        call(0, pipe_fds[0], (word)bytes, 1, 0, 0) || close_fd(pipe_fds[0]) ||
        close_fd(ends[0]) || close_fd(ends[1])) return 93;
    return 0;
}

static long check_rights_discard(void) {
    int ends[2], pipe_fds[2], invalid = -1;
    if (pair_type(ends, SOCK_STREAM) || call(22, (word)pipe_fds, 0, 0, 0, 0) ||
        send_rights(ends[0], "x", 1, &invalid, 1) != -9) return 94;
    int fds[] = {pipe_fds[1], pipe_fds[1]};
    if (send_rights(ends[0], "ab", 2, fds, 2) != 2 ||
        send_rights(ends[0], "cd", 2, fds, 2) != 2 || close_fd(pipe_fds[1])) return 94;
    struct rights control = {0};
    unsigned flags;
    char bytes[4];
    if (recv_rights(ends[1], bytes, 2, &control, 20, 0, &flags) != 2 ||
        !(flags & MSG_CTRUNC) || control.length != 20 || close_fd(control.fds[0]) ||
        call(0, ends[1], (word)bytes, 1, 0, 0) != 1 || bytes[0] != 'c' ||
        call(0, pipe_fds[0], (word)bytes, 1, 0, 0) || close_fd(pipe_fds[0]) ||
        close_fd(ends[0]) || close_fd(ends[1])) return 95;
    return 0;
}

static long check_rights_fault(void) {
    int ends[2], pipe_fds[2];
    if (pair(ends) || call(293, (word)pipe_fds, SOCK_NONBLOCK, 0, 0, 0)) return 98;
    struct iovec data = {(void *)"x", 1};
    struct msghdr bad = {.iov = &data, .iov_count = 1, .control = (void *)1, .control_length = 20};
    if (send(ends[0], &bad) != -14 || send_rights(ends[0], "x", 1, &pipe_fds[1], 1) != 1 ||
        close_fd(pipe_fds[1])) return 98;
    char byte;
    unsigned flags;
    if (recv_rights(ends[1], &byte, 1, (struct rights *)1, 20, 0, &flags) != 1 ||
        byte != 'x' || !(flags & MSG_CTRUNC) || call(0, pipe_fds[0], (word)&byte, 1, 0, 0) ||
        close_fd(pipe_fds[0]) || close_fd(ends[0]) || close_fd(ends[1])) return 99;
    return 0;
}

static long check_rights_metadata_fault(void) {
    int ends[2], pipe_fds[2];
    if (pair(ends) || call(293, (word)pipe_fds, SOCK_NONBLOCK, 0, 0, 0)) return 102;
    static unsigned char page[4096] __attribute__((aligned(4096)));
    struct msghdr *message = (void *)page;
    char byte;
    struct iovec data = {&byte, 1};
    struct rights rights = {.fds = {-1}};
    *message = (struct msghdr){.iov = &data, .iov_count = 1, .control = &rights,
                               .control_length = sizeof(rights)};
    if (send_rights(ends[0], "x", 1, &pipe_fds[1], 1) != 1 || close_fd(pipe_fds[1]) ||
        call(10, (word)page, sizeof(page), 1, 0, 0) || receive(ends[1], message, 0) != -14 ||
        call(10, (word)page, sizeof(page), 3, 0, 0) || byte != 'x' ||
        rights.length != 20 || rights.fds[0] < 3) return 102;
    char system[390];
    if (call(63, (word)system, 0, 0, 0, 0)) return 103;
    long closed = close_fd(rights.fds[0]);
    /* Linux может оставить установленный FD, если заголовок recvmsg недоступен для записи. */
    if ((system[0] == 'M' ? closed != -9 : closed && closed != -9) ||
        call(0, pipe_fds[0], (word)&byte, 1, 0, 0) ||
        close_fd(pipe_fds[0]) || close_fd(ends[0]) || close_fd(ends[1])) return 103;
    return 0;
}

static long check_rights_wait(void) {
    int ends[2];
    if (pair(ends)) return 100;
    unsigned filled = 0;
    for (;;) {
        long result = call(1, ends[0], (word)"p", 1, 0, 0);
        if (result == -11) break;
        if (result != 1 || ++filled > 4096) return 100;
    }
    if (call(72, ends[0], 4, 0, 0, 0) || call(72, ends[1], 4, 0, 0, 0)) return 100;
    long child = call(57, 0, 0, 0, 0, 0);
    if (!child) {
        char byte;
        if (close_fd(ends[0]) || call(7, 0, 0, 20, 0, 0)) call(60, 1, 0, 0, 0, 0);
        for (unsigned i = 0; i < filled; ++i)
            if (call(0, ends[1], (word)&byte, 1, 0, 0) != 1 || byte != 'p')
                call(60, 2, 0, 0, 0, 0);
        struct rights rights = {0};
        if (recv_rights(ends[1], &byte, 1, &rights, sizeof(rights), 0, 0) != 1 ||
            byte != 'r' || rights.length != 20 || call(1, rights.fds[0], (word)"w", 1, 0, 0) != 1)
            call(60, 3, 0, 0, 0, 0);
        call(60, 0, 0, 0, 0, 0);
        __builtin_trap();
    }
    int pipe_fds[2], status;
    char byte;
    if (child < 0 || close_fd(ends[1]) || call(22, (word)pipe_fds, 0, 0, 0, 0) ||
        send_rights(ends[0], "r", 1, &pipe_fds[1], 1) != 1 || close_fd(pipe_fds[1]) ||
        call(61, child, (word)&status, 0, 0, 0) != child || status ||
        call(0, pipe_fds[0], (word)&byte, 1, 0, 0) != 1 || byte != 'w' ||
        close_fd(pipe_fds[0]) || close_fd(ends[0])) return 101;
    return 0;
}

static long check_rights_gc(void) {
    int left[2], right[2], pipe_fds[2];
    if (pair_type(left, SOCK_STREAM) || pair(right) || call(22, (word)pipe_fds, 0, 0, 0, 0)) return 96;
    int fds[] = {right[1], pipe_fds[1]};
    if (send_rights(left[0], "x", 1, fds, 2) != 1 ||
        send_rights(right[0], "y", 1, &left[1], 1) != 1 ||
        close_fd(pipe_fds[1]) || close_fd(left[0]) || close_fd(right[0]) ||
        close_fd(left[1])) return 96;
    struct { int fd; short events, revents; } ready = {pipe_fds[0], 1, 0};
    char byte;
    if (call(7, (word)&ready, 1, 0, 0, 0) || close_fd(right[1]) ||
        call(7, (word)&ready, 1, 500, 0, 0) != 1 || !(ready.revents & 16) ||
        call(0, pipe_fds[0], (word)&byte, 1, 0, 0) || close_fd(pipe_fds[0])) return 97;
    return 0;
}

static long check(void) {
    long status = check_stream();
    if (!status) status = check_stream_fd_limit();
    if (!status) status = check_stream_pair();
    if (!status) status = check_sendto();
    if (!status) status = check_rights_fork(SOCK_STREAM);
    if (!status) status = check_rights_fork(SOCK_SEQPACKET);
    if (!status) status = check_rights_stream();
    if (!status) status = check_rights_discard();
    if (!status) status = check_rights_fault();
    if (!status) status = check_rights_metadata_fault();
    if (!status) status = check_rights_wait();
    if (!status) status = check_rights_gc();
    struct unix_address address = {AF_UNIX, "/tmp/myos-socket-0000000000"};
    unsigned pid = (unsigned)call(39, 0, 0, 0, 0, 0);
    for (unsigned i = sizeof("/tmp/myos-socket-0000000000") - 2; pid; --i, pid /= 10)
        address.path[i] = (char)('0' + pid % 10);
    if (!status) status = check_named(&address);
    if (!status) status = check_blocking_stream(&address, 0);
    if (!status) status = check_blocking_stream(&address, 1);
    if (!status) status = check_listener_shutdown(&address);
    if (!status) status = check_seqpacket_receive_wait();
    if (!status) status = check_seqpacket_send_wait();
    if (status) return status;
    int ends[2];
    for (unsigned i = 0; i < 40; ++i)
        if (pair(0) != -14) return 14;
    if (pair(ends) || ends[0] != 3 || ends[1] != 4 ||
        call(72, ends[0], 1, 0, 0, 0) != 1 ||
        call(72, ends[0], 3, 0, 0, 0) != 0x802) return 15;
    status = check_options(ends[1]);
    if (!status) status = check_packets(ends[0], ends[1]);
    if (!status) status = check_close(ends[0], ends[1]);
    if (!status) status = check_shutdown();
    if (!status) status = check_fd_limit(SOCK_SEQPACKET);
    return status ? status : check_fd_limit(SOCK_STREAM);
}

__attribute__((noreturn)) void _start(void) {
    long status = check();
    if (!status) {
        static const char message[] = "Linux ELF64 socket probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0, 0) != sizeof(message) - 1) status = 16;
    }
    call(60, status, 0, 0, 0, 0);
    __builtin_trap();
}
