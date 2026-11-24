typedef unsigned long word;

enum {
    IN = 0x001, OUT = 0x004, ERR = 0x008, HUP = 0x010, NVAL = 0x020,
    RDNORM = 0x040, WRNORM = 0x100, WRBAND = 0x200, RDHUP = 0x2000,
};

struct pollfd {
    int fd;
    unsigned short events, revents;
} __attribute__((packed));

static unsigned char pages[8192] __attribute__((aligned(4096)));

static long call5(word number, word a0, word a1, word a2, word a3, word a4) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long call(word number, word a0, word a1, word a2, word a3) {
    return call5(number, a0, a1, a2, a3, 0);
}

static long poll(struct pollfd *fds, unsigned count, int timeout) {
    return call(7, (word)fds, count, (word)timeout, 0);
}

static long close_fd(int fd) {
    return call(3, fd, 0, 0, 0);
}

static void finish(int status) __attribute__((noreturn));
static void finish(int status) {
    call(60, status, 0, 0, 0);
    __builtin_unreachable();
}

static int check_pipe(void) {
    int ends[2];
    if (call(22, (word)ends, 0, 0, 0)) return 1;
    struct pollfd fds[] = {
        {ends[0], IN | RDNORM | RDHUP, 0xffff}, {ends[1], OUT | WRNORM, 0xffff},
        {-1, IN, 0xffff}, {31, 0, 0xffff}, {ends[1], OUT, 0xffff},
    };
    if (poll(fds, 5, 0) != 3 || fds[0].revents || fds[1].revents != (OUT | WRNORM) ||
        fds[2].revents || fds[3].revents != NVAL || fds[4].revents != OUT) return 2;
    if (call(1, ends[1], (word)"x", 1, 0) != 1 || close_fd(ends[1])) return 3;
    if (poll(fds, 1, 0) != 1 || fds[0].revents != (IN | RDNORM | HUP)) return 4;
    char byte;
    if (call(0, ends[0], (word)&byte, 1, 0) != 1 || byte != 'x' ||
        poll(fds, 1, 0) != 1 || fds[0].revents != HUP || close_fd(ends[0])) return 5;
    if (call(22, (word)ends, 0, 0, 0) || close_fd(ends[0])) return 6;
    fds[0] = (struct pollfd){ends[1], 0, 0xffff};
    if (poll(fds, 1, 0) != 1 || fds[0].revents != ERR) return 7;
    fds[0].events = OUT;
    if (poll(fds, 1, 0) != 1 || fds[0].revents != (ERR | OUT) || close_fd(ends[1])) return 8;
    return 0;
}

static int check_socket(void) {
    int ends[2];
    if (call(53, 1, 5, 0, (word)ends)) return 9;
    struct pollfd fd = {ends[0], IN | RDNORM | RDHUP, 0xffff};
    if (poll(&fd, 1, 0) || fd.revents || call(1, ends[1], (word)"y", 1, 0) != 1 ||
        poll(&fd, 1, 0) != 1 || fd.revents != (IN | RDNORM)) return 10;
    char byte;
    if (call(0, ends[0], (word)&byte, 1, 0) != 1 || byte != 'y' ||
        call(48, ends[1], 1, 0, 0)) return 11;
    fd.events |= OUT | WRNORM | WRBAND;
    if (poll(&fd, 1, 0) != 1 || fd.revents != (IN | RDNORM | RDHUP | OUT | WRNORM | WRBAND) ||
        call(0, ends[0], (word)&byte, 1, 0)) return 12;
    if (call(1, ends[0], (word)"z", 1, 0) != 1 || close_fd(ends[1])) return 13;
    fd.events = 0;
    if (poll(&fd, 1, 0) != 1 || fd.revents != (HUP | ERR) ||
        call(0, ends[0], (word)&byte, 1, 0) != -104 ||
        poll(&fd, 1, 0) != 1 || fd.revents != HUP || close_fd(ends[0])) return 14;
    return 0;
}

static int check_copy(void) {
    word split = (word)(pages + 4096);
    struct pollfd *fds = (void *)(split - 6);
    if (poll(0, 1, 0) != -14 || poll(0, 33, 0) != -22 || poll(0, 0, 0)) return 15;
    fds[0] = (struct pollfd){-2, IN, 0xffff};
    if (call(10, (word)pages, 4096, 1, 0) || poll(fds, 1, 0) ||
        fds[0].fd != -2 || fds[0].events != IN || fds[0].revents ||
        call(10, (word)pages, 4096, 3, 0)) return 16;

    fds = (void *)(split - 15);
    fds[0] = fds[1] = (struct pollfd){-2, IN, 0xffff};
    if (call(10, split, 4096, 0, 0) || poll(fds, 2, 0) != -14 ||
        fds[0].revents != 0xffff || call(10, split, 4096, 1, 0)) return 17;
    if (poll(fds, 2, 0) != -14 || fds[0].revents || fds[1].revents != 0xffff ||
        call(10, split, 4096, 3, 0)) return 18;
    return 0;
}

static int check_blocking(void) {
    int ends[2], status;
    if (call(22, (word)ends, 0, 0, 0)) return 19;
    struct pollfd fd = {ends[0], IN, 0xffff};
    word before[2], after[2];
    if (call(228, 1, (word)before, 0, 0) || poll(&fd, 1, 20) || fd.revents ||
        call(228, 1, (word)after, 0, 0)) return 20;
    if ((after[0] - before[0]) * 1000000000ul + after[1] - before[1] < 19000000u) return 21;

    long child = call(57, 0, 0, 0, 0);
    if (child < 0) return 22;
    if (!child) {
        if (close_fd(ends[0]) || poll(0, 0, 20) ||
            call(1, ends[1], (word)"w", 1, 0) != 1 || close_fd(ends[1])) finish(23);
        finish(0);
    }
    if (close_fd(ends[1]) || poll(&fd, 1, -2) != 1 || !(fd.revents & IN)) return 24;
    char byte;
    if (call(0, ends[0], (word)&byte, 1, 0) != 1 || byte != 'w' ||
        call(61, child, (word)&status, 0, 0) != child || status ||
        poll(&fd, 1, -1) != 1 || fd.revents != HUP || close_fd(ends[0])) return 25;
    return 0;
}

static long event_write(int fd, word value) {
    return call(1, fd, (word)&value, sizeof(value), 0);
}

static long event_read(int fd, word *value) {
    return call(0, fd, (word)value, sizeof(*value), 0);
}

static int check_eventfd(void) {
    const word maximum = (word)-2;
    if (call(290, 0, 2, 0, 0) != -22) return 36;
    long fd = call(290, 0, 0x80800, 0, 0);
    if (fd < 3 || call(72, fd, 1, 0, 0) != 1 || call(72, fd, 3, 0, 0) != 0x802)
        return 36;
    long alias = call(32, fd, 0, 0, 0);
    struct pollfd ready = {fd, IN | OUT | RDNORM | WRNORM, 0};
    word value[2] = {0, 1};
    if (alias < 3 || call(72, alias, 1, 0, 0) || event_read(fd, value) != -11 ||
        poll(&ready, 1, 0) != 1 || ready.revents != OUT ||
        call(1, alias, (word)value, 7, 0) != -22 || call(0, fd, (word)value, 7, 0) != -22 ||
        call(1, alias, 1, 8, 0) != -14 || event_write(fd, (word)-1) != -22) return 37;
    if (event_write(alias, maximum) != 8 || event_write(fd, 0) != 8 ||
        event_write(alias, 1) != -11 || poll(&ready, 1, 0) != 1 || ready.revents != IN ||
        call(0, fd, (word)value, sizeof(value), 0) != 8 || value[0] != maximum || value[1] != 1 ||
        event_write(alias, 3) != 8 || call(0, fd, 1, 8, 0) != -14 ||
        event_read(alias, value) != -11) return 38;
    word split = (word)(pages + 4096);
    if (call(10, split, 4096, 0, 0) || event_write(alias, 1) != 8 ||
        call(0, fd, split - 4, 8, 0) != -14 || event_read(alias, value) != -11 ||
        call(10, split, 4096, 3, 0)) return 38;
    if (call(72, alias, 4, 0, 0) || call(72, fd, 3, 0, 0) != 2 ||
        call(17, fd, (word)value, 8, 0) != -29 || call(18, fd, (word)value, 8, 0) != -29 ||
        close_fd(fd) || event_write(alias, 7) != 8 || event_read(alias, value) != 8 ||
        value[0] != 7 || close_fd(alias)) return 39;

    fd = call(290, 2, 0x801, 0, 0);
    if (fd < 3 || call(72, fd, 3, 0, 0) != 0x802 || event_read(fd, value) != 8 || value[0] != 1 ||
        event_read(fd, value) != 8 || value[0] != 1 || event_read(fd, value) != -11 ||
        close_fd(fd)) return 40;
    return 0;
}

static int check_eventfd_blocking(void) {
    long fd = call(284, 0, 0, 0, 0);
    int ack[2];
    if (fd < 3 || call(22, (word)ack, 0, 0, 0)) return 41;
    long child = call(57, 0, 0, 0, 0);
    if (child < 0) return 41;
    if (!child) {
        char byte;
        if (poll(0, 0, 20) || event_write(fd, 3) != 8 ||
            call(0, ack[0], (word)&byte, 1, 0) != 1 || poll(0, 0, 20) ||
            event_write(fd, 5) != 8) finish(42);
        finish(0);
    }
    struct pollfd ready = {fd, IN, 0};
    word value;
    int status;
    if (event_read(fd, &value) != 8 || value != 3 || call(1, ack[1], (word)"x", 1, 0) != 1 ||
        poll(&ready, 1, 1000) != 1 ||
        ready.revents != IN || event_read(fd, &value) != 8 || value != 5 ||
        call(61, child, (word)&status, 0, 0) != child || status ||
        close_fd(ack[0]) || close_fd(ack[1])) return 43;

    if (event_write(fd, (word)-2) != 8) return 44;
    child = call(57, 0, 0, 0, 0);
    if (child < 0) return 44;
    if (!child) finish(event_write(fd, 9) != 8 ? 45 : 0);
    if (poll(0, 0, 20) || event_read(fd, &value) != 8 || value != (word)-2 ||
        event_read(fd, &value) != 8 || value != 9 ||
        call(61, child, (word)&status, 0, 0) != child || status || close_fd(fd)) return 45;
    return 0;
}

static long ppoll(struct pollfd *fds, unsigned count, long *timeout, const word *mask) {
    return call5(271, (word)fds, count, (word)timeout, (word)mask, sizeof(*mask));
}

static int check_ppoll(void) {
    const word temporary = 1ul << 11, original = 1ul << 9;
    word saved, old;
    if (call(14, 2, (word)&original, (word)&saved, 8)) return 27;
    long timeout[2] = {0, -1};
    if (call5(271, 0, 0, (word)timeout, (word)&temporary, 0) != -22 ||
        call5(271, 0, 0, 1, (word)&temporary, 0) != -14) return 28;
    timeout[1] = 1000000000;
    if (ppoll(0, 0, timeout, 0) != -22) return 28;
    timeout[0] = -1;
    timeout[1] = 0;
    if (ppoll(0, 0, timeout, 0) != -22) return 28;
    timeout[0] = 0;
    if (call5(271, 0, 0, (word)timeout, (word)&temporary, 4) != -22 ||
        call5(271, 0, 0, (word)timeout, 1, 8) != -14 ||
        call5(271, 0, 0, (word)timeout, 0, 4) ||
        ppoll(0, 1, timeout, &temporary) != -14) return 29;

    word before[2], after[2];
    timeout[1] = 1250000;
    if (call(228, 1, (word)before, 0, 0) || ppoll(0, 0, timeout, &temporary) ||
        timeout[0] || timeout[1] || call(228, 1, (word)after, 0, 0) ||
        (after[0] - before[0]) * 1000000000ul + after[1] - before[1] < 1250000ul ||
        call(14, 0, 0, (word)&old, 8) || old != original) return 30;

    long *readonly_timeout = (void *)pages;
    readonly_timeout[0] = 5;
    readonly_timeout[1] = 0;
    struct pollfd fd = {1, OUT, 0};
    struct pollfd *readonly_fd = (void *)(pages + 128);
    *readonly_fd = fd;
    if (call(10, (word)pages, 4096, 1, 0) ||
        ppoll(&fd, 1, readonly_timeout, &temporary) != 1 || fd.revents != OUT ||
        readonly_timeout[0] != 5 || readonly_timeout[1] ||
        ppoll(readonly_fd, 1, timeout, &temporary) != -14 ||
        call(14, 0, 0, (word)&old, 8) || old != original ||
        call(10, (word)pages, 4096, 3, 0)) return 31;
    timeout[0] = 5;
    if (ppoll(&fd, 1, timeout, &temporary) != 1 || timeout[0] < 0 || timeout[0] >= 5 ||
        timeout[1] < 0 || timeout[1] >= 1000000000) return 32;
    timeout[0] = 1ul << 40;
    timeout[1] = 0;
    if (ppoll(&fd, 1, timeout, &temporary) != 1 ||
        timeout[0] < (1ul << 40) - 1 || timeout[0] > (1ul << 40)) return 32;

    int ends[2], status;
    if (call(22, (word)ends, 0, 0, 0)) return 33;
    long child = call(57, 0, 0, 0, 0);
    if (child < 0) return 33;
    if (!child) {
        if (poll(0, 0, 20) || call(1, ends[1], (word)"p", 1, 0) != 1) finish(34);
        finish(0);
    }
    fd = (struct pollfd){ends[0], IN, 0};
    if (ppoll(&fd, 1, 0, &temporary) != 1 || !(fd.revents & IN) ||
        call(14, 0, 0, (word)&old, 8) || old != original ||
        call(61, child, (word)&status, 0, 0) != child || status ||
        close_fd(ends[0]) || close_fd(ends[1]) || call(14, 2, (word)&saved, 0, 8)) return 35;
    return 0;
}

void _start(void) {
    int error = check_pipe();
    if (!error) error = check_socket();
    if (!error) error = check_copy();
    if (!error) error = check_blocking();
    if (!error) error = check_ppoll();
    if (!error) error = check_eventfd();
    if (!error) error = check_eventfd_blocking();
    if (error) finish(error);
    static const char marker[] = "Linux ELF64 poll probe\n";
    if (call(1, 1, (word)marker, sizeof(marker) - 1, 0) != sizeof(marker) - 1) finish(26);
    finish(0);
}
