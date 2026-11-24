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
    SOL_SOCKET = 1, SO_TYPE = 3, SO_PASSCRED = 16,
    MSG_PEEK = 2, MSG_CTRUNC = 8, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40, MSG_NOSIGNAL = 0x4000,
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

static long check_blocking_stream(const struct unix_address *address) {
    long listener = stream(0);
    if (listener < 3 || named_call(49, listener, address) || call(50, listener, 4, 0, 0, 0)) return 54;
    long pid = call(57, 0, 0, 0, 0, 0);
    if (!pid) {
        long client = stream(0);
        if (client < 3 || close_fd(listener) || named_call(42, client, address)) goto child_fail;
        for (word i = 0; i < sizeof(transfer); ++i) transfer[i] = (unsigned char)i;
        if (call(1, client, (word)transfer, sizeof(transfer), 0, 0) == sizeof(transfer) &&
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

static long check(void) {
    long status = check_stream();
    if (!status) status = check_stream_fd_limit();
    struct unix_address address = {AF_UNIX, "/tmp/myos-socket-0000000000"};
    unsigned pid = (unsigned)call(39, 0, 0, 0, 0, 0);
    for (unsigned i = sizeof("/tmp/myos-socket-0000000000") - 2; pid; --i, pid /= 10)
        address.path[i] = (char)('0' + pid % 10);
    if (!status) status = check_named(&address);
    if (!status) status = check_blocking_stream(&address);
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
    return status ? status : check_fd_limit();
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
