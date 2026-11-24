typedef unsigned long word;

static const char path[] = FILE_PATH;
static unsigned char buffer[8192] __attribute__((aligned(4096)));

static long call(word number, word a0, word a1, word a2, word a3) {
    register word fourth __asm__("r10") = a3;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a0), "S"(a1), "d"(a2), "r"(fourth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long check_files(void) {
    if (call(21, (word)path, 4, 0, 0) ||
        call(21, (word)(FILE_PATH ".missing"), 0, 0, 0) != -2) return 1;
    if (call(257, (unsigned)-7, (word)"relative", 0, 0) != -9) return 2;
    long fd = call(257, (unsigned)-7, (word)path, 0x80000, 0);
    if (fd < 3 || call(0, fd, (word)path, 1, 0) != -14) return 3;

    unsigned char *cross = buffer + 4094;
    if (call(17, fd, (word)cross, 1, 4) != 1 || cross[0] != 2 ||
        call(17, fd, (word)cross, 1, (word)-1) != -22 ||
        call(17, fd, (word)cross, 1, 0x100000) != 0) return 4;
    if (call(0, fd, 0xffff800000000000ul, 0, 0) != -14 ||
        call(17, fd, 0xffff800000000000ul, 1, 0x100000) != -14) return 13;
    if (call(0, fd, (word)cross, 4, 0) != 4 ||
        cross[0] != 0x7f || cross[1] != 'E' || cross[2] != 'L' || cross[3] != 'F') return 5;
    if (call(0, fd, (word)cross, 1, 0) != 1 || cross[0] != 2) return 6;

    word *stat = (void *)(buffer + 4096 - 72);
    if (call(262, fd, (word)"", (word)stat, 0x1000) ||
        (stat[3] & 0170000) != 0100000 || stat[6] < 64 ||
        call(17, fd, (word)cross, 1, stat[6]) != 0) return 7;
    word size = stat[6], inode = stat[1];
    if (call(5, fd, (word)path, 0, 0) != -14 ||
        call(262, (unsigned)-100, (word)path, (word)stat, 0) ||
        stat[6] != size || stat[1] != inode) return 8;
    if (call(3, fd, 0, 0, 0) || call(0, fd, (word)cross, 1, 0) != -9) return 9;

    for (unsigned i = 0; i < sizeof(path); ++i) cross[i] = (unsigned char)path[i];
    if (call(257, (unsigned)-100, (word)cross, 0x80000, 0) != fd ||
        call(0, fd, (word)cross, 1, 0) != 1 || cross[0] != 0x7f) return 10;
    return call(3, fd, 0, 0, 0) ? 11 : 0;
}

struct action {
    word handler, flags, restorer, mask;
};

static long sigaction(word signal, const struct action *action, struct action *old) {
    return call(13, signal, (word)action, (word)old, sizeof(word));
}

static long check_signals(void) {
    struct action *cross = (void *)(buffer + 4096 - 16);
    struct action old = {1, 1, 1, 1};
    if (sigaction(13, 0, &old) || old.handler || old.flags || old.restorer || old.mask)
        return 14;
    *cross = (struct action){1, 0x14001c04ul, 0x123450ul, ~0ul};
    if (sigaction(13, cross, cross) || cross->handler || cross->flags ||
        cross->restorer || cross->mask) return 15;
    if (sigaction(13, 0, cross) || cross->handler != 1 || cross->flags != 0x14000804ul ||
        cross->restorer != 0x123450ul || cross->mask != ~(0x40100ul)) return 16;

    if (sigaction(9, 0, &old) || sigaction(19, 0, &old) ||
        sigaction(9, cross, 0) != -22 || sigaction(19, cross, 0) != -22 ||
        sigaction(65, 0, 0) != -22 ||
        call(13, 0, 0xffff800000000000ul, 0, 16) != -22 ||
        call(13, 0, 0xffff800000000000ul, 0, 8) != -14) return 17;

    const struct action handler = {0x123456ul, 0, 0, 0};
    if (sigaction(64, &handler, (void *)path) != -14 ||
        sigaction(64, 0, &old) || old.handler != handler.handler) return 18;
    const struct action initial = {0};
    if (sigaction(13, &initial, &old) || old.handler != 1 ||
        sigaction(13, 0, &old) || old.handler) return 19;
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    long status = check_files();
    if (!status) status = check_signals();
    if (!status) {
        static const char message[] = "Linux ELF64 files probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0) != sizeof(message) - 1)
            status = 12;
    }
    call(60, status, 0, 0, 0);
    __builtin_trap();
}
