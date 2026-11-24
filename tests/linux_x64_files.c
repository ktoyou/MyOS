#include "build_info.h"

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

static long sigprocmask(word how, const void *set, void *old) {
    return call(14, how, (word)set, (word)old, sizeof(word));
}

static long check_signal_mask(void) {
    struct __attribute__((packed)) mask { word bits; };
    struct mask *cross = (void *)(buffer + 4096 - 4);
    const word high = 1ul << 63, pipe = 1ul << 12, user1 = 1ul << 9;
    const word zero = 0, extra = user1 | 0x40100ul;
    word inherited, old;
    if (sigprocmask(2, &zero, &inherited)) return 20;
    cross->bits = high | pipe | 0x40100ul;
    if (sigprocmask(2, cross, cross) || cross->bits ||
        sigprocmask(99, 0, cross) || cross->bits != (high | pipe)) return 21;
    if (sigprocmask(0, &extra, &old) || old != (high | pipe) ||
        sigprocmask(1, &pipe, &old) || old != (high | pipe | user1)) return 22;
    if (call(14, 99, 0xffff800000000000ul, 0, 16) != -22 ||
        call(14, 99, 0xffff800000000000ul, 0, 8) != -14 ||
        sigprocmask(99, &zero, 0) != -22 ||
        sigprocmask(2, 0, &old) || old != (high | user1)) return 23;
    if (sigprocmask(2, &pipe, (void *)path) != -14 ||
        sigprocmask(2, &inherited, &old) || old != pipe) return 24;
    return 0;
}

static int field_matches(const unsigned char field[65], const char *value) {
    for (unsigned i = 0; i < 65; ++i) {
        if (field[i] != (unsigned char)*value) return 0;
        if (*value) ++value;
    }
    return !*value;
}

static long check_uname(void) {
    unsigned char (*name)[65] = (void *)(buffer + 4096 - 195);
    for (unsigned i = 0; i < 392; ++i) buffer[4096 - 196 + i] = 0xa5;
    if (call(63, (word)name, 0, 0, 0) || buffer[4096 - 196] != 0xa5 ||
        buffer[4096 + 195] != 0xa5 || !field_matches(name[4], "x86_64")) return 25;
    for (unsigned field = 0; field < 6; ++field) {
        unsigned i = 0;
        while (i < 65 && name[field][i]) ++i;
        if (i == 65) return 26;
    }
    int myos = field_matches(name[0], "MyOS");
    if (myos) {
        if (!field_matches(name[1], "myos") || !field_matches(name[2], MYOS_VERSION) ||
            !field_matches(name[3], "MyOS " MYOS_VERSION) || !field_matches(name[5], "")) return 27;
    } else if (!field_matches(name[0], "Linux")) {
        return 27;
    }
    if (call(63, 0, 0, 0, 0) != -14 || call(63, (word)path, 0, 0, 0) != -14 ||
        call(10, (word)(buffer + 4096), 4096, 1, 0) ||
        call(63, (word)name, 0, 0, 0) != -14 ||
        call(10, (word)(buffer + 4096), 4096, 3, 0)) return 28;
    const char *marker = myos ? "Linux uname: MyOS\n" : "Linux uname: Linux\n";
    word length = myos ? sizeof("Linux uname: MyOS\n") - 1 : sizeof("Linux uname: Linux\n") - 1;
    return call(1, 1, (word)marker, length, 0) == (long)length ? 0 : 29;
}

static long check_ids(word syscall, word get_real, word get_effective) {
    const unsigned sentinel = 0xa5a5a5a5u;
    const unsigned real = (unsigned)call(get_real, 0, 0, 0, 0);
    const unsigned effective = (unsigned)call(get_effective, 0, 0, 0, 0);
    unsigned ids[4] = {sentinel, sentinel, sentinel, sentinel};
    word first = (word)&ids[0], second = (word)&ids[1], third = (word)&ids[2];
    if (call(syscall, first, second, third, 0) || ids[0] != real || ids[1] != effective ||
        ids[2] != effective || ids[3] != sentinel) return 30;
    ids[0] = ids[1] = ids[2] = sentinel;
    if (call(syscall, 0, second, third, 0) != -14 || ids[1] != sentinel || ids[2] != sentinel ||
        call(syscall, first, second, 0, 0) != -14 || ids[0] != real || ids[1] != effective)
        return 31;

    unsigned char *cross = buffer + 4094;
    for (unsigned i = 0; i < 4; ++i) cross[i] = 0xa5;
    ids[0] = sentinel;
    if (call(10, (word)(buffer + 4096), 4096, 1, 0) ||
        call(syscall, first, (word)cross, third, 0) != -14 ||
        ids[0] != real || ids[2] != sentinel ||
        cross[0] != 0xa5 || cross[1] != 0xa5 || cross[2] != 0xa5 || cross[3] != 0xa5 ||
        call(10, (word)(buffer + 4096), 4096, 3, 0)) return 32;
    if (call(syscall, first, (word)cross, third, 0) || ids[2] != effective) return 33;
    for (unsigned i = 0; i < 4; ++i)
        if (cross[i] != (unsigned char)(effective >> (i * 8))) return 34;
    return 0;
}

static long check_null(void) {
    static const char dev[] = "/dev/null";
    const word bad = 0xffff800000000000ul;
    if (call(21, (word)dev, 6, 0, 0) || call(21, (word)dev, 1, 0, 0) != -13 ||
        call(2, (word)"/dev/null/", 0, 0, 0) != -20 ||
        call(2, (word)"/dev/null/child", 0, 0, 0) != -20 ||
        call(2, (word)dev, 0x10000, 0, 0) != -20 ||
        call(2, (word)dev, 0xc0, 0600, 0) != -17) return 35;
    long rd = call(257, (unsigned)-100, (word)dev, 0x80000, 0);
    long wr = call(2, (word)dev, 1, 0, 0);
    if (rd < 3 || wr < 3 || call(72, rd, 1, 0, 0) != 1 ||
        call(0, rd, 0, 8, 0) || call(0, rd, bad, 8, 0) != -14 ||
        call(1, rd, 0, 8, 0) != -9 || call(0, wr, 0, 8, 0) != -9 ||
        call(1, wr, 0, 8, 0) != 8 || call(1, wr, bad, 8, 0) != -14) return 36;
    if (call(17, rd, 0, 8, 12) || call(18, wr, 0, 8, 12) != 8 ||
        call(17, rd, 0, 8, -1) != -22 || call(18, wr, 0, 8, -1) != -22 ||
        call(8, rd, -12, 4, 0) || call(8, wr, 12, 1, 0) ||
        call(8, rd, 0, 5, 0) != -22) return 37;
    struct {
        word dev, inode, links;
        unsigned mode, uid, gid, padding;
        word rdev, size, blksize, blocks, tail[9];
    } stat, opened;
    if (call(4, (word)dev, (word)&stat, 0, 0) || call(5, rd, (word)&opened, 0, 0) ||
        (stat.mode & 0170777) != 0020666 || stat.rdev != 0x103 || stat.size || stat.blocks ||
        opened.dev != stat.dev || opened.inode != stat.inode || opened.rdev != stat.rdev)
        return 38;
    struct pollfd { int fd; unsigned short events, revents; };
    struct pollfd fds[2] = {{(int)rd, 5, 0}, {(int)wr, 5, 0}};
    if (call(7, (word)fds, 2, 0, 0) != 2 || fds[0].revents != 5 || fds[1].revents != 5) return 39;
    int status;
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        call(60, call(0, rd, 0, 1, 0) || call(1, wr, 0, 1, 0) != 1, 0, 0, 0);
        __builtin_trap();
    }
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status ||
        call(3, rd, 0, 0, 0) || call(3, wr, 0, 0, 0)) return 40;
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    long status = check_files();
    if (!status) status = check_signals();
    if (!status) status = check_signal_mask();
    if (!status) status = check_uname();
    if (!status) status = check_ids(118, 102, 107);
    if (!status) status = check_ids(120, 104, 108);
    if (!status) status = check_null();
    if (!status) {
        static const char message[] = "Linux ELF64 files probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0) != sizeof(message) - 1)
            status = 12;
    }
    call(60, status, 0, 0, 0);
    __builtin_trap();
}
