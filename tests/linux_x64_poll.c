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

static long call(word number, word a0, word a1, word a2, word a3) {
    register word fourth __asm__("r10") = a3;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth) : "rcx", "r11", "memory");
    return (long)number;
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

void _start(void) {
    int error = check_pipe();
    if (!error) error = check_socket();
    if (!error) error = check_copy();
    if (!error) error = check_blocking();
    if (error) finish(error);
    static const char marker[] = "Linux ELF64 poll probe\n";
    if (call(1, 1, (word)marker, sizeof(marker) - 1, 0) != sizeof(marker) - 1) finish(26);
    finish(0);
}
