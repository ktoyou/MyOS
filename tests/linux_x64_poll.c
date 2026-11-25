typedef unsigned long word;

enum {
    FD_LIMIT = 256,
    IN = 0x001, OUT = 0x004, ERR = 0x008, HUP = 0x010, NVAL = 0x020,
    RDNORM = 0x040, WRNORM = 0x100, WRBAND = 0x200, RDHUP = 0x2000,
};

struct pollfd {
    int fd;
    unsigned short events, revents;
} __attribute__((packed));

static unsigned char pages[8192] __attribute__((aligned(4096)));

static long call6(word number, word a0, word a1, word a2, word a3, word a4, word a5) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    register word sixth __asm__("r9") = a5;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long call5(word number, word a0, word a1, word a2, word a3, word a4) {
    return call6(number, a0, a1, a2, a3, a4, 0);
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
    if (poll(0, 1, 0) != -14 || poll(0, FD_LIMIT + 1, 0) != -22 || poll(0, 0, 0)) return 15;
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

struct epoll_event {
    unsigned events;
    word data;
} __attribute__((packed));

enum { ADD = 1, DEL = 2, MOD = 3, ONESHOT = 1u << 30 };

static long epoll_ctl(int epoll, int op, int fd, struct epoll_event *event) {
    return call(233, epoll, op, fd, (word)event);
}

static long epoll_wait(int epoll, struct epoll_event *events, int count, int timeout) {
    return call(232, epoll, (word)events, count, (word)timeout);
}

static int check_epoll(void) {
    struct epoll_event event = {IN | ONESHOT, 0x1234567800000001ul}, out[2];
    long epoll = call(291, 0x80000, 0, 0, 0), wake = call(290, 0, 0x800, 0, 0);
    long regular = call(319, (word)"", 0, 0, 0);
    if (epoll < 3 || wake < 3 || regular < 3 || call(72, epoll, 1, 0, 0) != 1 ||
        call(291, 1, 0, 0, 0) != -22 || call(213, 0, 0, 0, 0) != -22 ||
        epoll_ctl(epoll, ADD, regular, &event) != -1 || close_fd(regular) ||
        epoll_ctl(epoll, ADD, epoll, &event) != -22 || epoll_ctl(epoll, MOD, wake, &event) != -2 ||
        epoll_ctl(epoll, ADD, wake, 0) != -14 || epoll_ctl(epoll, ADD, wake, &event) ||
        epoll_ctl(epoll, ADD, wake, &event) != -17 || epoll_wait(epoll, out, 0, 0) != -22 ||
        epoll_wait(-1, out, 1, 0) != -9 || epoll_wait(wake, out, 1, 0) != -22) return 46;
    struct pollfd ready = {epoll, IN | OUT, 0};
    if (poll(&ready, 1, 0) || epoll_wait(epoll, out, 2, 0) || event_write(wake, 1) != 8 ||
        poll(&ready, 1, 0) != 1 || ready.revents != IN ||
        epoll_wait(epoll, (struct epoll_event *)1, 1, 0) != -14 ||
        epoll_wait(epoll, out, 2, 0) != 1 || out[0].events != IN || out[0].data != event.data ||
        epoll_wait(epoll, out, 1, 0) || poll(&ready, 1, 0)) return 47;
    event.data = 0xabcdef0198765432ul;
    if (epoll_ctl(epoll, MOD, wake, &event) || epoll_wait(epoll, out, 1, 0) != 1 ||
        out[0].events != IN || out[0].data != event.data || epoll_ctl(epoll, DEL, wake, 0) ||
        epoll_ctl(epoll, DEL, wake, 0) != -2 || close_fd(wake) || close_fd(epoll)) return 48;
    return 0;
}

static int check_epoll_aliases(void) {
    long epoll = call(213, 1, 0, 0, 0), watched = call(290, 1, 0, 0, 0);
    if (epoll < 3 || watched < 3) return 49;
    long alias = call(32, watched, 0, 0, 0);
    struct epoll_event event = {IN, 1}, out[2];
    if (alias < 3 || epoll_ctl(epoll, ADD, watched, &event) || close_fd(watched)) return 49;
    long reused = call(290, 1, 0, 0, 0);
    event.data = 2;
    if (reused != watched || epoll_ctl(epoll, ADD, reused, &event) ||
        epoll_wait(epoll, out, 1, 0) != 1) return 50;
    word first = out[0].data;
    if (epoll_wait(epoll, out, 1, 0) != 1 ||
        !((first == 1 && out[0].data == 2) || (first == 2 && out[0].data == 1))) return 50;
    if (close_fd(alias) || epoll_wait(epoll, out, 2, 0) != 1 || out[0].data != 2 ||
        close_fd(reused) || epoll_wait(epoll, out, 2, 0)) return 51;
    int ends[2];
    char byte;
    if (call(22, (word)ends, 0, 0, 0) || epoll_ctl(epoll, ADD, ends[1], &event) || close_fd(ends[1]) ||
        call(0, ends[0], (word)&byte, 1, 0) || close_fd(ends[0]) || close_fd(epoll)) return 52;
    return 0;
}

static int check_epoll_blocking(void) {
    long epoll = call(291, 0, 0, 0, 0), wake = call(290, 0, 0, 0, 0);
    struct epoll_event event = {IN, 1}, out[2];
    word before[2], after[2];
    if (epoll < 3 || wake < 3 || epoll_ctl(epoll, ADD, wake, &event) ||
        call(228, 1, (word)before, 0, 0) || epoll_wait(epoll, out, 2, 20) ||
        call(228, 1, (word)after, 0, 0) ||
        (after[0] - before[0]) * 1000000000ul + after[1] - before[1] < 19000000u) return 53;
    long child = call(57, 0, 0, 0, 0);
    if (child < 0) return 54;
    if (!child) finish(poll(0, 0, 20) || event_write(wake, 1) != 8 ? 54 : 0);
    int status;
    if (epoll_wait(epoll, out, 2, -1) != 1 || out[0].events != IN || out[0].data != 1 ||
        call(61, child, (word)&status, 0, 0) != child || status || close_fd(wake)) return 54;
    int ends[2];
    if (call(53, 1, 1, 0, (word)ends)) return 55;
    event = (struct epoll_event){IN | RDHUP, 3};
    if (epoll_ctl(epoll, ADD, ends[0], &event) || call(48, ends[1], 1, 0, 0) ||
        epoll_wait(epoll, out, 2, 0) != 1 || out[0].events != (IN | RDHUP) || out[0].data != 3)
        return 55;
    event.events = 0;
    if (epoll_ctl(epoll, MOD, ends[0], &event) || close_fd(ends[1]) ||
        epoll_wait(epoll, out, 2, 0) != 1 || out[0].events != HUP ||
        close_fd(ends[0]) || close_fd(epoll)) return 56;
    return 0;
}

static int check_epoll_delivery(void) {
    long epoll = call(291, 0, 0, 0, 0), first = call(290, 1, 0, 0, 0);
    if (epoll < 3 || first < 3) return 57;
    long alias = call(32, first, 0, 0, 0), last = call(290, 1, 0, 0, 0);
    struct epoll_event event = {IN, 1}, out;
    if (alias < 3 || last < 3 || epoll_ctl(epoll, ADD, first, &event)) return 57;
    event.data = 2;
    if (epoll_ctl(epoll, ADD, alias, &event)) return 57;
    event.data = 3;
    if (epoll_ctl(epoll, ADD, last, &event) || epoll_wait(epoll, &out, 1, 0) != 1 || out.data != 1 ||
        epoll_wait(epoll, &out, 1, 0) != 1 || out.data != 2 || epoll_ctl(epoll, DEL, alias, 0) ||
        epoll_wait(epoll, &out, 1, 0) != 1 || out.data != 3 || close_fd(alias)) return 58;

    event.events = IN | ONESHOT;
    if (epoll_ctl(epoll, MOD, last, &event)) return 59;
    event.data = 1;
    if (epoll_ctl(epoll, MOD, first, &event)) return 59;
    word split = (word)(pages + 4096);
    struct epoll_event *pair = (void *)(split - sizeof(*pair));
    if (call(10, split, 4096, 0, 0) || epoll_wait(epoll, pair, 2, 0) != 1 ||
        call(10, split, 4096, 3, 0) || epoll_wait(epoll, &out, 1, 0) != 1 ||
        !((pair->data == 1 && out.data == 3) || (pair->data == 3 && out.data == 1)) ||
        epoll_wait(epoll, &out, 1, 0) || close_fd(last) || close_fd(first) || close_fd(epoll)) return 59;
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

static int check_high_fd(void) {
    const int high = FD_LIMIT - 1;
    long fd = call(290, 0, 0, 0, 0), epoll = call(291, 0, 0, 0, 0);
    if (fd < 3 || epoll < 3 || call(292, fd, high, 0x80000, 0) != high ||
        call(72, high, 1, 0, 0) != 1 || call(33, high, FD_LIMIT, 0, 0) != -9 ||
        close_fd(fd)) return 60;
    struct pollfd fds[FD_LIMIT];
    for (unsigned i = 0; i < FD_LIMIT; ++i) fds[i] = (struct pollfd){-1, IN, 0xffff};
    fds[high].fd = high;
    struct epoll_event event = {IN, 0xcdef0000abcdu}, out;
    if (epoll_ctl(epoll, ADD, high, &event) || poll(fds, FD_LIMIT, 0) ||
        fds[0].revents || fds[high].revents || event_write(high, 1) != 8) return 61;
    long immediate[2] = {0, 0};
    word value;
    if (ppoll(fds, FD_LIMIT, immediate, 0) != 1 || fds[high].revents != IN ||
        epoll_wait(epoll, &out, 1, 0) != 1 || out.events != IN || out.data != event.data ||
        event_read(high, &value) != 8 || value != 1 || close_fd(high) ||
        poll(fds, FD_LIMIT, 0) != 1 || fds[high].revents != NVAL ||
        epoll_wait(epoll, &out, 1, 0) || close_fd(epoll)) return 62;
    return 0;
}

static long select_call(int count, word *read, word *write, word *except, long *timeout) {
    return call5(23, count, (word)read, (word)write, (word)except, (word)timeout);
}

static long pselect_call(int count, word *read, long *timeout, const word *signal) {
    return call6(270, count, (word)read, 0, 0, (word)timeout, (word)signal);
}

static int check_select(void) {
    long immediate[2] = {0, 0};
    int ends[2];
    if (call(53, 1, 1, 0, (word)ends)) return 66;
    int count = ends[0] + 1;
    word bit = 1ul << ends[0], read = bit, write = bit, except = bit;
    if (select_call(count, &read, &write, &except, immediate) != 1 || read || write != bit || except)
        return 67;
    if (call(1, ends[1], (word)"x", 1, 0) != 1) return 67;
    read = write = except = bit;
    if (select_call(count, &read, &write, &except, immediate) != 2 || read != bit || write != bit || except)
        return 68;
    char byte;
    if (call(0, ends[0], (word)&byte, 1, 0) != 1 || byte != 'x') return 68;

    const word mask = 1ul << 11;
    const word bad_signal[] = {(word)&mask, 4};
    const word signal[] = {(word)&mask, sizeof(mask)};
    long bad_time[2] = {0, 1000000000}, overflow[2] = {0x7fffffffffffffffL, 1000000};
    if (pselect_call(count, &read, immediate, bad_signal) != -22 ||
        pselect_call(count, &read, bad_time, (const word *)1) != -14 ||
        select_call(count, &read, 0, 0, overflow) != -22 ||
        select_call(-1, 0, 0, 0, immediate) != -22 ||
        select_call(count, (word *)1, 0, 0, immediate) != -14) return 69;

    long timeout[2] = {0, 20000};
    if (select_call(count, &read, 0, 0, timeout) || read || timeout[0] || timeout[1]) return 70;
    long child = call(57, 0, 0, 0, 0);
    if (child < 0) return 71;
    if (!child) {
        if (close_fd(ends[0]) || poll(0, 0, 20) ||
            call(1, ends[1], (word)"ACK", 3, 0) != 3 || call(48, ends[1], 1, 0, 0))
            finish(72);
        finish(0);
    }
    if (close_fd(ends[1])) return 71;
    word before, after;
    timeout[0] = 5;
    read = bit;
    char response[3];
    int status;
    if (call(14, 0, 0, (word)&before, 8) ||
        pselect_call(count, &read, timeout, signal) != 1 || read != bit ||
        timeout[0] < 0 || timeout[0] >= 5 || timeout[1] < 0 || timeout[1] >= 1000000000 ||
        call(14, 0, 0, (word)&after, 8) || before != after ||
        call(0, ends[0], (word)response, sizeof(response), 0) != sizeof(response) ||
        response[0] != 'A' || response[1] != 'C' || response[2] != 'K' ||
        call(61, child, (word)&status, 0, 0) != child || status) return 73;
    except = bit;
    if (select_call(count, &read, 0, &except, immediate) != 1 || read != bit || except ||
        close_fd(ends[0]) || select_call(count, &read, 0, 0, immediate) != -9 || read != bit)
        return 74;
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
    if (!error) error = check_epoll();
    if (!error) error = check_epoll_aliases();
    if (!error) error = check_epoll_blocking();
    if (!error) error = check_epoll_delivery();
    if (!error) error = check_high_fd();
    if (!error) error = check_select();
    if (error) finish(error);
    static const char marker[] = "Linux ELF64 poll probe\n";
    if (call(1, 1, (word)marker, sizeof(marker) - 1, 0) != sizeof(marker) - 1) finish(26);
    finish(0);
}
