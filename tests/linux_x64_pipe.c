typedef unsigned long word;

enum { O_NONBLOCK = 0x800, O_CLOEXEC = 0x80000 };
static char source[16384], destination[16384];

static long call(word number, word a0, word a1, word a2, word a3) {
    register word fourth __asm__("r10") = a3;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long read_fd(int fd, void *buffer, word size) {
    return call(0, fd, (word)buffer, size, 0);
}

static long write_fd(int fd, const void *buffer, word size) {
    return call(1, fd, (word)buffer, size, 0);
}

static long close_fd(int fd) {
    return call(3, fd, 0, 0, 0);
}

static void finish(int status) __attribute__((noreturn));
static void finish(int status) {
    call(60, status, 0, 0, 0);
    __builtin_unreachable();
}

static int check_nonblocking(void) {
    int ends[2];
    char data[4];
    if (call(293, (word)ends, 0x40, 0, 0) != -22) return 1;
    for (int i = 0; i < 40; ++i)
        if (call(293, 0, 0, 0, 0) != -14) return 2;
    if (call(293, (word)ends, O_NONBLOCK | O_CLOEXEC, 0, 0) ||
        ends[0] != 3 || ends[1] != 4) return 3;
    if (call(72, ends[0], 1, 0, 0) != 1 || call(72, ends[1], 1, 0, 0) != 1 ||
        call(72, ends[0], 3, 0, 0) != O_NONBLOCK ||
        call(72, ends[1], 3, 0, 0) != (O_NONBLOCK | 1)) return 4;
    if (read_fd(ends[0], data, 1) != -11 || read_fd(ends[1], data, 1) != -9 ||
        write_fd(ends[0], "a", 1) != -9 || call(8, ends[0], 0, 0, 0) != -29 ||
        call(17, ends[1], (word)data, 1, 0) != -29) return 5;
    if (write_fd(ends[1], "ab", 2) != 2 || write_fd(ends[1], "cd", 2) != 2 ||
        read_fd(ends[0], data, 3) != 3 || data[0] != 'a' || data[1] != 'b' ||
        data[2] != 'c' || close_fd(ends[1]) ||
        read_fd(ends[0], data, 4) != 1 || data[0] != 'd' ||
        read_fd(ends[0], data, 1) != 0 || close_fd(ends[0])) return 6;
    const word ignore[4] = {1, 0, 0, 0};
    if (call(13, 13, (word)ignore, 0, 8) || call(293, (word)ends, 0, 0, 0) ||
        close_fd(ends[0]) || write_fd(ends[1], "a", 1) != -32 || close_fd(ends[1])) return 18;
    return 0;
}

static int check_atomic_writes(void) {
    int ends[2];
    if (call(293, (word)ends, O_NONBLOCK, 0, 0)) return 20;
    for (word i = 0; i < sizeof(source); ++i) source[i] = (char)(i % 251);
    if (write_fd(ends[1], source, 3072) != 3072 ||
        read_fd(ends[0], destination, 2048) != 2048 ||
        write_fd(ends[1], source + 3072, 2048) != 2048 ||
        read_fd(ends[0], destination + 2048, 3072) != 3072) return 21;
    for (word i = 0; i < 5120; ++i)
        if (source[i] != destination[i]) return 22;

    unsigned blocks = 0;
    while (blocks < 1024) {
        long written = write_fd(ends[1], source, 4096);
        if (written == -11) break;
        if (written != 4096) return 23;
        ++blocks;
    }
    if (!blocks || blocks == 1024 || read_fd(ends[0], destination, 4096) != 4096 ||
        write_fd(ends[1], source, 3000) != 3000 ||
        write_fd(ends[1], source, 2048) != -11) return 24;
    while (--blocks)
        if (read_fd(ends[0], destination, 4096) != 4096) return 25;
    if (read_fd(ends[0], destination, 4096) != 3000 ||
        read_fd(ends[0], destination, 1) != -11 ||
        close_fd(ends[0]) || close_fd(ends[1])) return 26;
    return 0;
}

static int check_blocking(void) {
    int ends[2], status;
    if (call(22, (word)ends, 0, 0, 0)) return 7;
    if (call(72, ends[0], 4, O_NONBLOCK, 0) ||
        call(72, ends[0], 3, 0, 0) != O_NONBLOCK ||
        call(72, ends[0], 4, 0, 0)) return 8;
    for (word i = 0; i < sizeof(source); ++i) source[i] = (char)(i % 251);
    long child = call(57, 0, 0, 0, 0);
    if (child < 0) return 9;
    if (!child) {
        if (close_fd(ends[1])) finish(10);
        word offset = 0;
        while (offset < sizeof(destination)) {
            long copied = read_fd(ends[0], destination + offset, sizeof(destination) - offset);
            if (copied <= 0) finish(11);
            offset += (word)copied;
        }
        for (word i = 0; i < sizeof(destination); ++i)
            if (destination[i] != source[i]) finish(12);
        if (read_fd(ends[0], destination, 1) || close_fd(ends[0])) finish(13);
        finish(0);
    }
    if (close_fd(ends[0])) return 14;
    for (int i = 0; i < 4; ++i) call(24, 0, 0, 0, 0);
    if (write_fd(ends[1], source, sizeof(source)) != sizeof(source) || close_fd(ends[1])) return 15;
    if (call(61, child, (word)&status, 0, 0) != child) return 16;
    return (status & 0x7f) ? 19 : status >> 8;
}

void _start(void) {
    int status = check_nonblocking();
    if (!status) status = check_atomic_writes();
    if (!status) status = check_blocking();
    if (status) finish(status);
    static const char marker[] = "Linux ELF64 pipe probe\n";
    if (write_fd(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) finish(17);
    finish(0);
}
