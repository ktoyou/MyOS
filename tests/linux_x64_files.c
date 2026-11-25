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
    long alias = call(32, fd, 0, 0, 0);
    if (alias < 0 || call(8, alias, 0, 1, 0) != 5 || call(8, fd, (word)-2, 1, 0) != 3 ||
        call(0, alias, (word)cross, 1, 0) != 1 || cross[0] != 'F' ||
        call(8, fd, (word)-1, 2, 0) != (long)size - 1 || call(0, alias, (word)cross, 1, 0) != 1 ||
        call(8, fd, 2, 1, 0) != (long)size + 2 || call(0, alias, (word)cross, 1, 0) != 0)
        return 112;
    if (call(8, fd, 0, 5, 0) != -22 || call(8, fd, (word)-1, 0, 0) != -22 ||
        call(8, fd, __LONG_MAX__, 1, 0) != -22 || call(8, alias, 0, 1, 0) != (long)size + 2 ||
        call(8, alias, 0, 0, 0) || call(3, alias, 0, 0, 0)) return 113;
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

static long check_urandom(void) {
    static const char dev[] = "/dev/urandom";
    if (call(21, (word)dev, 6, 0, 0) || call(21, (word)dev, 1, 0, 0) != -13 ||
        call(2, (word)"/dev/urandom/", 0, 0, 0) != -20 ||
        call(2, (word)dev, 0x10000, 0, 0) != -20 ||
        call(2, (word)dev, 0xc0, 0600, 0) != -17) return 77;
    long dir = call(2, (word)"/dev", 0x10000, 0, 0);
    long rd = call(257, dir, (word)"urandom", 0x80800, 0);
    long wr = call(2, (word)dev, 1, 0, 0);
    long flags = call(72, rd, 3, 0, 0);
    if (dir < 3 || rd < 3 || wr < 3 || call(72, rd, 1, 0, 0) != 1 ||
        flags < 0 || (flags & 0x803) != 0x800 || call(3, dir, 0, 0, 0) ||
        call(1, rd, (word)buffer, 1, 0) != -9 ||
        call(0, wr, (word)buffer, 1, 0) != -9) return 78;

    word stat[18], opened[18], null_stat[18];
    if (call(6, (word)dev, (word)stat, 0, 0) || call(5, rd, (word)opened, 0, 0) ||
        call(4, (word)"/dev/null", (word)null_stat, 0, 0) ||
        (stat[3] & 0170777) != 0020666 || stat[5] != 0x109 || stat[6] || stat[8] ||
        (stat[0] == null_stat[0] && stat[1] == null_stat[1]) ||
        opened[0] != stat[0] || opened[1] != stat[1] ||
        opened[5] != stat[5]) return 79;
    long dup = call(32, rd, 0, 0, 0);
    if (dup < 3 || call(72, dup, 1, 0, 0) || call(8, dup, 12, 1, 0) ||
        call(17, dup, (word)buffer, 1, -1) != -22 ||
        call(0, dup, 0xffff800000000000ul, 1, 0) != -14 ||
        call(0, dup, 0, 1, 0) != -14) return 80;

    for (unsigned i = 1; i <= 513; ++i) buffer[i] = 0;
    buffer[0] = 0x5a;
    buffer[514] = 0x5a;
    if (call(0, rd, (word)(buffer + 1), 513, 0) != 513 ||
        buffer[0] != 0x5a || buffer[514] != 0x5a) return 81;
    unsigned nonzero = 0;
    for (unsigned i = 1; i <= 513; ++i) nonzero |= buffer[i];
    if (!nonzero || call(17, dup, (word)buffer, 33, 12) != 33 ||
        call(10, (word)(buffer + 4096), 4096, 0, 0) ||
        call(0, rd, (word)(buffer + 4080), 32, 0) != 16 ||
        call(10, (word)(buffer + 4096), 4096, 3, 0)) return 81;
    if (call(3, dup, 0, 0, 0) || call(3, rd, 0, 0, 0) ||
        call(3, wr, 0, 0, 0)) return 82;
    return 0;
}

static long check_dup(void) {
    long rd = call(2, (word)"/dev/null", 0x80000, 0, 0);
    if (rd < 3 || call(33, rd, rd, 0, 0) != rd || call(72, rd, 1, 0, 0) != 1 ||
        call(33, -1, rd, 0, 0) != -9 || call(33, rd, -1, 0, 0) != -9 ||
        call(292, -1, -1, 0, 0) != -22 || call(292, rd, 0, 1, 0) != -22 ||
        call(72, rd, 0, -1, 0) != -22 || call(72, -1, 0, -1, 0) != -9) return 41;
    long smallest = call(32, rd, 0, 0, 0);
    long minimum = call(72, rd, 1030, 12, 0);
    if (smallest != rd + 1 || minimum != 12 || call(72, smallest, 1, 0, 0) ||
        call(72, minimum, 1, 0, 0) != 1 || call(3, smallest, 0, 0, 0) ||
        call(3, minimum, 0, 0, 0) || call(33, rd, 0, 0, 0) || call(3, rd, 0, 0, 0) ||
        call(72, 0, 1, 0, 0) || call(0, 0, 1, 8, 0)) return 42;

    int ends[2], status;
    if (call(22, (word)ends, 0, 0, 0)) return 43;
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        int error = call(3, ends[0], 0, 0, 0) || call(33, ends[1], 1, 0, 0) != 1 ||
                    call(292, ends[1], 2, 0x80000, 0) != 2 || call(72, 2, 1, 0, 0) != 1 ||
                    call(3, ends[1], 0, 0, 0) || call(3, 0, 0, 0, 0) ||
                    call(32, 1, 0, 0, 0) || call(1, 0, (word)"x", 1, 0) != 1 ||
                    call(1, 1, (word)"y", 1, 0) != 1 || call(1, 2, (word)"z", 1, 0) != 1;
        call(60, error, 0, 0, 0);
        __builtin_trap();
    }
    char byte;
    if (child < 0 || call(3, ends[1], 0, 0, 0)) return 44;
    for (char expected = 'x'; expected <= 'z'; ++expected)
        if (call(0, ends[0], (word)&byte, 1, 0) != 1 || byte != expected) return 45;
    if (call(0, ends[0], (word)&byte, 1, 0) ||
        call(61, child, (word)&status, 0, 0) != child || status ||
        call(3, ends[0], 0, 0, 0)) return 46;
    return 0;
}

static long check_links(long dir, const char *directory) {
    static const char lock[] = "lock";
    static const char target[] = "myos-123";
    char path[64];
    unsigned length = 0;
    while (directory[length]) { path[length] = directory[length]; ++length; }
    path[length++] = '/';
    for (unsigned i = 0; i < sizeof(lock); ++i) path[length + i] = lock[i];

    if (call(266, 0, dir, (word)lock, 0) != -14 ||
        call(266, (word)"", dir, (word)lock, 0) != -2 ||
        call(266, (word)target, -1, (word)lock, 0) != -9 ||
        call(266, (word)target, dir, (word)"lock/", 0) != -2 ||
        call(88, (word)target, (word)path, 0, 0)) return 68;
    word first[18], other[18];
    if (call(266, (word)"different", dir, (word)lock, 0) != -17 ||
        call(266, (word)target, dir, (word)"lock/", 0) != -17 ||
        call(262, dir, (word)lock, (word)first, 0x100) ||
        (first[3] & 0177777) != 0120777 || first[6] != sizeof(target) - 1 ||
        call(262, dir, (word)lock, (word)other, 0) != -2 ||
        call(257, dir, (word)lock, 0x20000, 0) != -40 ||
        call(257, dir, (word)lock, 0xc0, 0600) != -17 ||
        call(258, dir, (word)lock, 0700, 0) != -17) return 69;
    char bytes[16] = {0};
    bytes[3] = 'z';
    if (call(89, (word)path, (word)bytes, 3, 0) != 3 ||
        bytes[0] != 'm' || bytes[1] != 'y' || bytes[2] != 'o' || bytes[3] != 'z' ||
        call(267, dir, (word)lock, 0xffff800000000000ul, 8) != -14 ||
        call(267, dir, (word)lock, (word)bytes, 0) != -22 ||
        call(267, dir, (word)lock, (word)bytes, sizeof(bytes)) != sizeof(target) - 1 ||
        bytes[7] != '3' || call(263, dir, (word)"lock/", 0, 0) != -20 ||
        call(87, (word)path, 0, 0, 0) || call(87, (word)path, 0, 0, 0) != -2) return 70;

    long nested = call(257, dir, (word)"child", 0x10000, 0);
    if (nested < 3 || call(266, (word)"../shared", nested, (word)"parent", 0) ||
        call(266, (word)"child", dir, (word)"alias", 0) ||
        call(266, (word)FILE_PATH, dir, (word)"absolute", 0) ||
        call(262, dir, (word)"alias/parent", (word)other, 0) ||
        call(262, dir, (word)"shared", (word)first, 0) || first[1] != other[1] ||
        call(262, dir, (word)"alias/", (word)other, 0x100) || (other[3] & 0170000) != 0040000 ||
        call(262, dir, (word)"absolute/", (word)other, 0) != -20) return 71;
    long opened = call(257, dir, (word)"absolute", 0, 0);
    if (opened < 3 || call(0, opened, (word)bytes, 4, 0) != 4 ||
        bytes[0] != '\x7f' || bytes[1] != 'E' || call(3, opened, 0, 0, 0) ||
        call(263, dir, (word)"absolute", 0, 0) || call(263, dir, (word)"alias", 0, 0) ||
        call(263, nested, (word)"parent", 0, 0) || call(3, nested, 0, 0, 0)) return 72;

    if (call(266, (word)"longer/self", dir, (word)"loop", 0) ||
        call(266, (word)"loop/..", dir, (word)"longer", 0) ||
        call(262, dir, (word)"loop", (word)other, 0) != -40 ||
        call(267, dir, (word)"loop", (word)bytes, sizeof(bytes)) != 11 ||
        call(263, dir, (word)"loop", 0, 0) || call(263, dir, (word)"longer", 0, 0)) return 73;

    unsigned char *query = buffer + 4096;
    for (unsigned i = 0; i < 3000; i += 2) { buffer[i] = '.'; buffer[i + 1] = '/'; }
    for (unsigned i = 0; i < sizeof("child"); ++i) buffer[3000 + i] = (unsigned char)"child"[i];
    for (unsigned i = 0; i < 5; ++i) query[i] = (unsigned char)"wide/"[i];
    for (unsigned i = 5; i < 1605; i += 2) { query[i] = '.'; query[i + 1] = '/'; }
    query[1605] = 0;
    if (call(266, (word)buffer, dir, (word)"wide", 0) ||
        call(262, dir, (word)query, (word)other, 0) || (other[3] & 0170000) != 0040000 ||
        call(263, dir, (word)"wide", 0, 0)) return 75;

    if (call(102, 0, 0, 0, 0) != 0 &&
        (call(258, dir, (word)"sealed", 0500, 0) ||
         call(266, (word)target, dir, (word)"sealed/link", 0) != -13)) return 76;
    for (unsigned i = 0; i < 260; ++i)
        if (call(266, (word)target, dir, (word)lock, 0) || call(263, dir, (word)lock, 0, 0)) return 74;
    return 0;
}

static long check_named_file(long dir) {
    static const char name[] = "profile-data";
    static const char alias[] = "profile-alias";
    word stat[18], original[18];
    if (call(266, (word)name, dir, (word)alias, 0)) return 156;
    long old_mask = call(95, 0077, 0, 0, 0);
    long fd = call(257, dir, (word)alias, 0x80042, 0666);
    if (call(95, old_mask, 0, 0, 0) != 0077 || fd < 3 ||
        call(72, fd, 1, 0, 0) != 1 || call(262, dir, (word)name, (word)original, 0) ||
        (original[3] & 0177777) != 0100600 || original[2] != 1 || original[6] ||
        call(257, dir, (word)name, 0xc2, 0600) != -17) return 157;
    long write_only = call(257, dir, (word)name, 1, 0);
    long read_only = call(257, dir, (word)name, 0, 0);
    if (write_only < 3 || read_only < 3 || call(0, write_only, (word)buffer, 1, 0) != -9 ||
        call(1, read_only, (word)"x", 1, 0) != -9 || call(77, write_only, 2, 0, 0) ||
        call(18, fd, (word)"AB", 2, 0) != 2 || call(8, fd, 4097, 0, 0) != 4097 ||
        call(1, fd, (word)"Z", 1, 0) != 1) return 158;
    long duplicate = call(32, fd, 0, 0, 0);
    if (duplicate < 3 || call(8, duplicate, 0, 1, 0) != 4098 ||
        call(8, read_only, 0, 1, 0) || call(17, read_only, (word)buffer, 2, 4096) != 2 ||
        buffer[0] || buffer[1] != 'Z') return 159;
    long append = call(257, dir, (word)name, 0x401, 0);
    if (append < 3 || call(18, append, (word)"X", 1, 0) != 1 || call(8, append, 0, 1, 0) ||
        call(8, fd, 0, 2, 0) != 4099 || call(17, fd, (word)buffer, 2, 4097) != 2 ||
        buffer[0] != 'Z' || buffer[1] != 'X' || call(17, fd, (word)buffer, 2, 0) != 2 ||
        buffer[0] != 'A' || buffer[1] != 'B') return 160;
    int pipe[2];
    if (call(22, (word)pipe, 0, 0, 0) || call(74, pipe[0], 0, 0, 0) != -22 ||
        call(75, pipe[1], 0, 0, 0) != -22 || call(3, pipe[0], 0, 0, 0) ||
        call(3, pipe[1], 0, 0, 0) || call(74, fd, 0, 0, 0) || call(75, read_only, 0, 0, 0) ||
        call(74, dir, 0, 0, 0) || call(75, dir, 0, 0, 0) ||
        call(74, -1, 0, 0, 0) != -9 || call(75, -1, 0, 0, 0) != -9) return 183;
    register word offset __asm__("r9") = 0;
    register word descriptor __asm__("r8") = (word)fd;
    register word flags __asm__("r10") = 1;
    word mapped = 9;
    __asm__ volatile("syscall" : "+a"(mapped) : "D"(0), "S"(4096), "d"(1),
                     "r"(flags), "r"(descriptor), "r"(offset) : "rcx", "r11", "memory");
    if ((long)mapped < 0 || *(const char *)mapped != 'A' ||
        call(18, fd, (word)"C", 1, 0) != 1 || *(const char *)mapped != 'C') return 161;
    if (call(263, dir, (word)name, 0, 0) || call(5, fd, (word)stat, 0, 0) ||
        stat[1] != original[1] || stat[2] || stat[6] != 4099 ||
        call(262, dir, (word)alias, (word)stat, 0) != -2) return 162;
    char proc[] = "/proc/self/fd/0";
    if (fd > 9) return 163;
    proc[sizeof(proc) - 2] += (char)fd;
    long reopen = call(2, (word)proc, 0, 0, 0);
    long next = call(257, dir, (word)name, 0xc2, 0600);
    if (reopen < 3 || next < 3 || call(0, reopen, (word)buffer, 1, 0) != 1 || buffer[0] != 'C' ||
        call(5, reopen, (word)stat, 0, 0) || stat[1] != original[1] || stat[2] ||
        call(5, next, (word)stat, 0, 0) || stat[1] == original[1] || stat[2] != 1 ||
        call(1, next, (word)"D", 1, 0) != 1) return 164;
    if (call(3, fd, 0, 0, 0) || call(3, write_only, 0, 0, 0) || call(3, read_only, 0, 0, 0) ||
        call(3, duplicate, 0, 0, 0) || call(3, append, 0, 0, 0) || call(3, reopen, 0, 0, 0) ||
        *(const char *)mapped != 'C' || call(11, mapped, 4096, 0, 0)) return 165;
    long empty = call(257, dir, (word)name, 0x202, 0);
    if (empty < 3 || call(8, next, 0, 2, 0) || call(5, empty, (word)stat, 0, 0) || stat[6] ||
        call(3, empty, 0, 0, 0) || call(1, next, (word)"Q", 1, 0) != 1) return 166;
    int descriptors[256];
    unsigned count = 0;
    long fd_result;
    while ((fd_result = call(32, next, 0, 0, 0)) >= 0) {
        if (count == sizeof(descriptors) / sizeof(*descriptors)) return 167;
        descriptors[count++] = (int)fd_result;
    }
    if (fd_result != -24 || call(257, dir, (word)"uncreated", 0xc2, 0600) != -24 ||
        call(257, dir, (word)name, 0x202, 0) != -24 ||
        call(262, dir, (word)"uncreated", (word)stat, 0) != -2 ||
        call(17, next, (word)buffer, 1, 0) != 1 || buffer[0] != 'Q') return 168;
    for (unsigned i = 0; i < count; ++i) {
        if (call(3, (word)descriptors[i], 0, 0, 0)) return 169;
    }
    if (call(3, next, 0, 0, 0) || call(263, dir, (word)alias, 0, 0) ||
        call(263, dir, (word)name, 0, 0)) return 169;
    return 0;
}

static long check_flock(long dir) {
    enum { SHARED = 1, EXCLUSIVE = 2, NONBLOCK = 4, UNLOCK = 8 };
    static const char name[] = "profile-lock";
    if (call(73, -1, EXCLUSIVE, 0, 0) != -9 ||
        call(73, dir, SHARED | EXCLUSIVE, 0, 0) != -22) return 170;
    long first = call(257, dir, (word)name, 0xc0, 0600);
    long second = call(257, dir, (word)name, 0x800, 0);
    long third = call(257, dir, (word)name, 0, 0);
    if (first < 3 || second < 3 || third < 3 ||
        call(73, first, SHARED, 0, 0) || call(73, first, SHARED, 0, 0) ||
        call(73, second, SHARED, 0, 0) ||
        call(73, first, EXCLUSIVE | NONBLOCK, 0, 0) != -11 ||
        call(73, third, EXCLUSIVE | NONBLOCK, 0, 0) != -11 ||
        call(73, second, UNLOCK, 0, 0) || call(73, third, EXCLUSIVE | NONBLOCK, 0, 0)) return 171;

    long duplicate = call(32, third, 0, 0, 0);
    if (duplicate < 3 || call(3, third, 0, 0, 0) ||
        call(73, first, SHARED | NONBLOCK, 0, 0) != -11 || call(3, duplicate, 0, 0, 0) ||
        call(73, first, EXCLUSIVE | NONBLOCK, 0, 0)) return 172;

    int pipe[2];
    if (call(22, (word)pipe, 0, 0, 0)) return 173;
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        unsigned status = call(73, first, EXCLUSIVE | NONBLOCK, 0, 0) ||
            call(3, first, 0, 0, 0) || call(3, pipe[0], 0, 0, 0) ||
            call(1, pipe[1], (word)"R", 1, 0) != 1 || call(73, second, EXCLUSIVE, 0, 0);
        call(60, status, 0, 0, 0);
        __builtin_trap();
    }
    int status = 0;
    char ready;
    if (child < 0 || call(3, second, 0, 0, 0) || call(3, pipe[1], 0, 0, 0) ||
        call(0, pipe[0], (word)&ready, 1, 0) != 1 || ready != 'R' ||
        call(24, 0, 0, 0, 0) || call(61, child, (word)&status, 1, 0) ||
        call(3, first, 0, 0, 0) || call(61, child, (word)&status, 0, 0) != child || status ||
        call(3, pipe[0], 0, 0, 0)) return 174;

    first = call(257, dir, (word)name, 0, 0);
    if (first < 3 || call(73, first, EXCLUSIVE | NONBLOCK, 0, 0) ||
        call(263, dir, (word)name, 0, 0)) return 175;
    second = call(257, dir, (word)name, 0xc2, 0600);
    if (second < 3 || call(73, second, EXCLUSIVE | NONBLOCK, 0, 0) ||
        call(73, first, UNLOCK | NONBLOCK, 0, 0) ||
        call(3, first, 0, 0, 0) || call(3, second, 0, 0, 0) ||
        call(263, dir, (word)name, 0, 0)) return 176;
    return 0;
}

enum { RECORD_READ = 0, RECORD_WRITE = 1, RECORD_UNLOCK = 2, RECORD_GET = 5, RECORD_SET = 6 };

struct record_request {
    short type, whence;
    long start, length;
    int pid;
};

static long set_record(long fd, short type, short whence, long start, long length) {
    struct record_request lock = {.type = type, .whence = whence, .start = start, .length = length};
    return call(72, fd, RECORD_SET, (word)&lock, 0);
}

static int record_matches(long fd, short requested, long start, long length, short type,
                          long first, long extent, long owner) {
    struct record_request lock = {.type = requested, .start = start, .length = length, .pid = 123};
    if (call(72, fd, RECORD_GET, (word)&lock, 0) || lock.type != type || lock.whence) return 0;
    if (type == RECORD_UNLOCK) return lock.start == start && lock.length == length && lock.pid == 123;
    return lock.start == first && lock.length == extent && lock.pid == owner;
}

static long check_record_locks(long dir) {
    static const char name[] = "profile-record-lock";
    long fd = call(257, dir, (word)name, 0xc2, 0600);
    long independent = call(257, dir, (word)name, 0, 0);
    long owner = call(39, 0, 0, 0, 0);
    word stat[18];
    if (fd < 3 || independent < 3 || set_record(independent, RECORD_WRITE, 0, 0, 0) != -9 ||
        call(72, fd, RECORD_SET, 1, 0) != -14 || set_record(fd, RECORD_WRITE, 0, -1, 1) != -22 ||
        set_record(fd, RECORD_WRITE, 0, 0x7fffffffffffffffL, 2) != -75 ||
        set_record(fd, RECORD_READ, 0, 0x40000000, 1) ||
        call(5, fd, (word)stat, 0, 0) || stat[6]) return 177;
    if (set_record(fd, RECORD_WRITE, 0, 0, 0) || call(8, fd, 30, 0, 0) != 30 ||
        set_record(fd, RECORD_READ, 1, 0, -10) || set_record(fd, RECORD_UNLOCK, 2, 24, 2) ||
        !record_matches(fd, RECORD_WRITE, 0, 0, RECORD_UNLOCK, 0, 0, 0)) return 178;

    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        unsigned result = 0;
        if (call(3, independent, 0, 0, 0) ||
            !record_matches(fd, RECORD_READ, 0, 1, RECORD_WRITE, 0, 20, owner) ||
            !record_matches(fd, RECORD_WRITE, 21, 1, RECORD_READ, 20, 4, owner) ||
            !record_matches(fd, RECORD_WRITE, 24, 2, RECORD_UNLOCK, 0, 0, 0) ||
            !record_matches(fd, RECORD_WRITE, 26, 1, RECORD_READ, 26, 4, owner) ||
            !record_matches(fd, RECORD_READ, 30, 1, RECORD_WRITE, 30, 0, owner) ||
            set_record(fd, RECORD_WRITE, 0, 0, 0) != -11 || set_record(fd, RECORD_WRITE, 0, 24, 2))
            result = 1;
        call(60, result, 0, 0, 0);
        __builtin_trap();
    }
    int status = 0;
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status ||
        set_record(fd, RECORD_WRITE, 0, 20, 10)) return 179;

    long duplicate = call(32, fd, 0, 0, 0);
    if (duplicate < 3) return 180;
    child = call(57, 0, 0, 0, 0);
    if (!child) {
        call(60, !record_matches(fd, RECORD_READ, 24, 1, RECORD_WRITE, 0, 0, owner), 0, 0, 0);
        __builtin_trap();
    }
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status ||
        call(73, fd, 2, 0, 0) || call(3, duplicate, 0, 0, 0)) return 180;
    child = call(57, 0, 0, 0, 0);
    if (!child) {
        call(60, set_record(fd, RECORD_WRITE, 0, 0, 0) != 0, 0, 0, 0);
        __builtin_trap();
    }
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status ||
        set_record(fd, RECORD_WRITE, 0, 0, 0) || call(3, independent, 0, 0, 0)) return 181;
    child = call(57, 0, 0, 0, 0);
    if (!child) {
        call(60, set_record(fd, RECORD_WRITE, 0, 0, 0) != 0, 0, 0, 0);
        __builtin_trap();
    }
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status ||
        call(3, fd, 0, 0, 0) || call(263, dir, (word)name, 0, 0)) return 182;
    return 0;
}

static long check_rename(long dir, const char *directory) {
    static const char old[] = "CURRENT.tmp", target[] = "CURRENT", alias[] = "profile-link";
    long nested = call(257, dir, (word)"child", 0x10000, 0);
    long original = call(257, dir, (word)old, 0xc2, 0600);
    long replaced = call(257, nested, (word)target, 0xc2, 0600);
    word old_stat[18], replaced_stat[18], info[18];
    if (nested < 3 || original < 3 || replaced < 3 ||
        call(1, original, (word)"src", 3, 0) != 3 || call(1, replaced, (word)"dst", 3, 0) != 3 ||
        call(5, original, (word)old_stat, 0, 0) || call(5, replaced, (word)replaced_stat, 0, 0) ||
        call(73, original, 2, 0, 0) || set_record(original, RECORD_WRITE, 0, 0, 0) ||
        set_record(replaced, RECORD_WRITE, 0, 0, 0)) return 184;

    if (call(264, -1, (word)old, nested, (word)target) != -9 ||
        call(264, dir, (word)old, original, (word)target) != -20 ||
        call(264, dir, (word)old, dir, (word)"child") != -21 ||
        call(264, dir, (word)old, nested, (word)"missing/") != -20 ||
        call(264, dir, (word)old, nested, (word)"missing/CURRENT") != -2 ||
        call(264, dir, (word)old, dir, (word)"./CURRENT.tmp") ||
        call(262, nested, (word)target, (word)info, 0) || info[1] != replaced_stat[1]) return 185;

    if (call(264, dir, (word)old, nested, (word)target) ||
        call(262, dir, (word)old, (word)info, 0) != -2 ||
        call(262, nested, (word)target, (word)info, 0) || info[1] != old_stat[1] || info[2] != 1 ||
        call(5, replaced, (word)info, 0, 0) || info[1] != replaced_stat[1] || info[2] ||
        call(17, replaced, (word)buffer, 3, 0) != 3 || buffer[0] != 'd' || buffer[2] != 't' ||
        call(8, original, 0, 1, 0) != 3) return 186;

    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        long current = call(257, nested, (word)target, 2, 0);
        unsigned fail = current < 3 || call(0, current, (word)buffer, 3, 0) != 3 ||
            buffer[0] != 's' || buffer[2] != 'c' || call(73, current, 6, 0, 0) != -11 ||
            set_record(current, RECORD_WRITE, 0, 0, 0) != -11 ||
            set_record(replaced, RECORD_WRITE, 0, 0, 0) != -11;
        call(60, fail, 0, 0, 0);
        __builtin_trap();
    }
    int status;
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status) return 187;

    char from[64], to[64];
    unsigned length = 0;
    while (directory[length]) { from[length] = to[length] = directory[length]; ++length; }
    static const char from_suffix[] = "/child/CURRENT", to_suffix[] = "/profile-link";
    for (unsigned i = 0; i < sizeof(from_suffix); ++i) from[length + i] = from_suffix[i];
    for (unsigned i = 0; i < sizeof(to_suffix); ++i) to[length + i] = to_suffix[i];
    if (call(266, (word)"child/CURRENT", dir, (word)alias, 0) || call(82, (word)from, (word)to, 0, 0) ||
        call(262, nested, (word)target, (word)info, 0) != -2 ||
        call(262, dir, (word)alias, (word)info, 0x100) || info[1] != old_stat[1] ||
        call(263, dir, (word)alias, 0, 0) || call(3, original, 0, 0, 0) ||
        call(3, replaced, 0, 0, 0) || call(3, nested, 0, 0, 0)) return 188;
    return 0;
}

static long check_directories(void) {
    static char path[] = "/tmp/myos-dir-0000000000";
    unsigned pid = (unsigned)call(39, 0, 0, 0, 0);
    for (unsigned i = sizeof(path) - 2; pid; --i, pid /= 10) path[i] = (char)('0' + pid % 10);
    word root[18], info[18], opened[18];
    if (call(4, (word)"/", (word)root, 0, 0) || (root[3] & 0170000) != 0040000 ||
        call(83, (word)"/", 0700, 0, 0) != -17 || call(83, 1, 0700, 0, 0) != -14 ||
        call(258, -1, (word)"relative", 0700, 0) != -9 ||
        call(258, -1, (word)"/", 0700, 0) != -17) return 47;
    if (call(4, (word)"/proc", (word)info, 0, 0) ||
        call(4, (word)"/proc/.", (word)opened, 0, 0) || info[0] != opened[0] || info[1] != opened[1])
        return 56;
    if (call(6, (word)"/proc/self/./exe", (word)opened, 0, 0) ||
        (opened[3] & 0170000) != 0120000 ||
        call(2, (word)"/proc/self/exe", 0x20000, 0, 0) != -40) return 58;
    long root_fd = call(2, (word)"/", 0x10000, 0, 0);
    long null = call(257, root_fd, (word)"./dev//null", 0, 0);
    if (root_fd < 0 || null < 0 || call(0, null, 0, 1, 0) ||
        call(3, null, 0, 0, 0) || call(3, root_fd, 0, 0, 0)) return 57;
    long mask = call(95, 0077, 0, 0, 0);
    if (mask < 0 || call(83, (word)path, 0777, 0, 0) ||
        call(95, mask, 0, 0, 0) != 0077 || call(83, (word)path, 0700, 0, 0) != -17)
        return 48;
    long tmp = call(2, (word)"/tmp/", 0x10000, 0, 0);
    long dir = call(257, tmp, (word)(path + 5), 0x90000, 0);
    if (tmp < 0 || dir < 0 || call(3, tmp, 0, 0, 0) ||
        call(4, (word)path, (word)info, 0, 0) || call(5, dir, (word)opened, 0, 0) ||
        (info[3] & 0170777) != 0040700 || info[0] != opened[0] || info[1] != opened[1] ||
        call(0, dir, (word)buffer, 1, 0) != -21 || call(2, (word)path, 1, 0, 0) != -21 ||
        call(21, (word)path, 7, 0, 0)) return 49;
    if (call(83, (word)FILE_PATH, 0700, 0, 0) != -17 ||
        call(83, (word)(FILE_PATH "/missing"), 0700, 0, 0) != -20 ||
        call(258, dir, (word)"missing/../child", 0700, 0) != -2 ||
        call(258, dir, (word)"child/", 0700, 0) ||
        call(262, dir, (word)"./child/../.", (word)opened, 0) ||
        opened[0] != info[0] || opened[1] != info[1]) return 50;
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        call(60, call(258, dir, (word)"shared", 0700, 0) != 0, 0, 0, 0);
        __builtin_trap();
    }
    int status;
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status ||
        call(262, dir, (word)"shared", (word)opened, 0) ||
        (opened[3] & 0170777) != 0040700) return 51;
    long links = check_links(dir, path);
    if (links) return links;
    long named = check_named_file(dir);
    if (named) return named;
    long locks = check_flock(dir);
    if (locks) return locks;
    long records = check_record_locks(dir);
    if (records) return records;
    long rename = check_rename(dir, path);
    if (rename) return rename;
    if (call(3, dir, 0, 0, 0)) return 51;
    if (call(63, (word)buffer, 0, 0, 0)) return 52;
    if (buffer[0] == 'M') {
        long ro = call(2, (word)"/", 0x10000, 0, 0);
        if (ro < 0 || call(258, ro, (word)(path + 5), 0700, 0) != -30 ||
            call(266, (word)"nowhere", ro, (word)(path + 5), 0) != -30 ||
            call(263, ro, (word)(path + 5), 0, 0) != -30) return 53;
        call(3, ro, 0, 0, 0);
    } else {
        char nested[sizeof(path) + 8];
        for (unsigned i = 0; i < sizeof(path) - 1; ++i) nested[i] = path[i];
        const char *names[] = {"/child", "/shared", "/sealed"};
        unsigned count = call(102, 0, 0, 0, 0) == 0 ? 2 : 3;
        for (unsigned n = 0; n < count; ++n) {
            for (unsigned i = 0; (nested[sizeof(path) - 1 + i] = names[n][i]); ++i) {}
            if (call(84, (word)nested, 0, 0, 0)) return 54;
        }
        if (call(84, (word)path, 0, 0, 0)) return 55;
    }
    return 0;
}

static long check_realtime(void) {
    const word invalid = 0xffff800000000000ul;
    struct { long sec, nsec; } start, end;
    struct { long sec, usec; } tv;
    struct { int west, dst; unsigned guard; } tz = {-1, -1, 0xa5a5a5a5u};
    if (call(96, 0, 0, 0, 0) || call(96, 0, (word)&tz, 0, 0) ||
        tz.west == -1 || tz.dst == -1 || tz.guard != 0xa5a5a5a5u) return 59;
    if (call(63, (word)buffer, 0, 0, 0) || (buffer[0] == 'M' && (tz.west || tz.dst))) return 59;
    if (call(228, 0, (word)&start, 0, 0) || call(96, (word)&tv, (word)&tz, 0, 0) ||
        call(228, 0, (word)&end, 0, 0) || tz.guard != 0xa5a5a5a5u) return 60;
    if (start.nsec < 0 || start.nsec >= 1000000000 || end.nsec < 0 || end.nsec >= 1000000000 ||
        tv.sec <= 0 || tv.usec < 0 || tv.usec >= 1000000) return 61;
    long usec = tv.sec * 1000000 + tv.usec;
    if (usec < start.sec * 1000000 + start.nsec / 1000 ||
        usec > end.sec * 1000000 + end.nsec / 1000) return 62;
    if (call(228, -1, invalid, 0, 0) != -22 || call(228, 0, 0, 0, 0) != -14 ||
        call(96, invalid, 0, 0, 0) != -14 || call(96, 0, invalid, 0, 0) != -14) return 63;
    long timestamp = tv.sec;
    tv.sec = -1;
    if (call(96, (word)&tv, invalid, 0, 0) != -14 || tv.sec < timestamp) return 64;
    if (call(228, 1, (word)&start, 0, 0) || start.sec < 0 ||
        start.nsec < 0 || start.nsec >= 1000000000) return 65;

    long *page_end = (void *)(buffer + 4096 - sizeof(long));
    *page_end = -1;
    tz.west = tz.dst = -1;
    if (call(10, (word)(buffer + 4096), 4096, 0, 0) ||
        call(96, (word)page_end, (word)&tz, 0, 0) != -14 || *page_end < timestamp ||
        tz.west != -1 || tz.dst != -1 || call(10, (word)(buffer + 4096), 4096, 3, 0)) return 66;

    char message[] = "Linux UTC seconds: 000000000000\n";
    for (unsigned i = sizeof(message) - 3; i >= sizeof("Linux UTC seconds: ") - 1; --i, timestamp /= 10)
        message[i] = (char)('0' + timestamp % 10);
    return call(1, 1, (word)message, sizeof(message) - 1, 0) == sizeof(message) - 1 ? 0 : 67;
}

struct proc_dirent {
    word inode, next;
    unsigned short length;
    unsigned char type;
    char name[5];
};

static int same_name(const char *actual, const char *expected, unsigned capacity) {
    while (capacity && *expected && *actual == *expected) {
        ++actual;
        ++expected;
        --capacity;
    }
    return capacity && *actual == *expected;
}

static long check_live_directory(void) {
    static const char directory[] = "/myos/live-directory";
    static const char font[] = "scan-this-font-name.ttf";
    long dir = call(2, (word)directory, 0x10000, 0, 0);
    if (dir == -2) return 0;
    struct proc_dirent *entry = (void *)buffer;
    long other = call(2, (word)directory, 0x10000, 0, 0);
    long duplicate = call(32, dir, 0, 0, 0);
    if (dir < 3 || other < 3 || duplicate < 3 ||
        call(217, dir, (word)buffer, 23, 0) != -22 || call(217, dir, 0, 24, 0) != -14 ||
        call(217, dir, (word)buffer, 24, 0) != 24 || entry->type != 4 ||
        !same_name(entry->name, ".", 5)) return 142;
    if (call(217, duplicate, (word)buffer, 24, 0) != 24 ||
        !same_name(entry->name, "..", 5)) return 143;
    word first = entry->next;
    if (call(217, other, (word)buffer, 24, 0) != 24 || !same_name(entry->name, ".", 5) ||
        call(8, other, first, 0, 0) != (long)first) return 144;
    long count = call(217, dir, (word)buffer, 512, 0);
    if (count < 48 || call(217, duplicate, (word)(buffer + 512), 512, 0) != 0) return 145;
    long same = call(217, other, (word)(buffer + 512), 512, 0);
    if (same != count) return 146;
    unsigned seen = 0;
    for (long offset = 0; offset < count;) {
        const struct proc_dirent *record = (const void *)(buffer + offset);
        if (count - offset < 24 || record->length < 24 || record->length % 8 ||
            record->length > count - offset || !record->inode) return 147;
        const unsigned char *bytes = (const void *)record;
        for (unsigned i = 0; i < record->length; ++i) {
            if (bytes[i] != buffer[512 + offset + i]) return 148;
        }
        const char *name = (const char *)bytes + 19;
        unsigned name_capacity = record->length - 19;
        unsigned bit;
        if (record->type == 4 && same_name(name, "nested", name_capacity)) bit = 1;
        else if (record->type == 8 && same_name(name, font, name_capacity)) bit = 2;
        else return 149;
        if (seen & bit) return 150;
        seen |= bit;
        offset += record->length;
    }
    long file = call(257, dir, (word)font, 0, 0);
    if (seen != 3 || file < 3 || call(0, file, (word)buffer, 1, 0) != 1 || buffer[0] != 'F')
        return 151;
    static const char empty[] = "/tmp/myos-empty-dir";
    if (call(83, (word)empty, 0700, 0, 0)) return 152;
    long empty_fd = call(2, (word)empty, 0x10000, 0, 0);
    if (empty_fd < 3 || call(217, empty_fd, (word)buffer, 512, 0) != 48 ||
        call(217, empty_fd, (word)buffer, 512, 0)) return 153;
    if (call(3, empty_fd, 0, 0, 0) || call(3, file, 0, 0, 0) || call(3, duplicate, 0, 0, 0) ||
        call(3, other, 0, 0, 0) || call(3, dir, 0, 0, 0)) return 154;
    static const char marker[] = "Linux ELF64 Live directory listing\n";
    return call(1, 1, (word)marker, sizeof(marker) - 1, 0) == sizeof(marker) - 1 ? 0 : 155;
}

static long proc_entries(long scanner, unsigned *seen, word *inode_29) {
    long count = call(217, scanner, (word)buffer, 512, 0);
    if (count <= 0) return count;
    word next = 0;
    for (long offset = 0; offset < count;) {
        const struct proc_dirent *entry = (const void *)(buffer + offset);
        if (count - offset < 24 || entry->length < 24 || entry->length % 8 ||
            entry->length > count - offset) return -1;
        offset += entry->length;
        next = entry->next;
        if (entry->name[0] == '.') {
            if (entry->type != 4) return -1;
            continue;
        }
        if (entry->type != 10) return -1;
        unsigned number = 0, digits = 0;
        while (digits < sizeof(entry->name) && entry->name[digits]) {
            char digit = entry->name[digits++];
            if (digit < '0' || digit > '9') return -1;
            number = number * 10 + (unsigned)(digit - '0');
        }
        if (!digits || digits == sizeof(entry->name) || number >= 32 || (*seen & (1u << number)))
            return -1;
        *seen |= 1u << number;
        if (number == 29) *inode_29 = entry->inode;
    }
    return call(8, scanner, 0, 1, 0) == (long)next ? count : -1;
}

static long check_proc_fds(void) {
    long proc = call(2, (word)"/proc", 0x10000, 0, 0);
    long dir = call(257, proc, (word)"self/fd/", 0x90000, 0);
    long device = call(2, (word)"/dev/null", 0, 0, 0);
    long outside = call(2, (word)"/tmp", 0x10000, 0, 0);
    struct proc_dirent *entry = (void *)buffer;
    if (proc < 3 || dir < 3 || device < 3 || outside < 3 ||
        call(72, dir, 1, 0, 0) != 1 || call(217, -1, (word)buffer, 512, 0) != -9 ||
        call(217, device, (word)buffer, 512, 0) != -20 ||
        call(217, dir, (word)buffer, 23, 0) != -22 || call(217, dir, 0, 24, 0) != -14 ||
        call(217, dir, (word)entry, 24, 0) != 24 || entry->type != 4 ||
        entry->name[0] != '.' || entry->name[1]) return 83;
    long dup = call(32, dir, 0, 0, 0);
    if (dup < 3 || call(217, dup, (word)entry, 24, 0) != 24 ||
        entry->name[0] != '.' || entry->name[1] != '.' || entry->name[2] ||
        call(3, dup, 0, 0, 0) || call(8, dir, 0, 0, 0)) return 84;
    if (call(10, (word)(buffer + 4096), 4096, 0, 0) ||
        call(217, dir, (word)(buffer + 4096 - 24), 48, 0) != 24 ||
        call(10, (word)(buffer + 4096), 4096, 3, 0) ||
        call(217, dir, (word)entry, 24, 0) != 24 || entry->name[1] != '.' ||
        call(8, dir, 0, 0, 0)) return 85;

    for (long n = 8; n <= 31; ++n)
        if (call(33, device, n, 0, 0) != n) return 86;
    unsigned seen = 0;
    word inode_29 = 0;
    if (proc_entries(dir, &seen, &inode_29) <= 0 || (seen & (1u << 30)) ||
        call(3, 30, 0, 0, 0) || call(33, outside, 29, 0, 0) != 29) return 87;
    long count;
    do { count = proc_entries(dir, &seen, &inode_29); } while (count > 0);
    if (count || (seen & (1u << 30)) || !(seen & (1u << 31)) ||
        !(seen & (1u << dir)) || !inode_29) return 88;

    word followed[18], original[18], link[18];
    if (call(262, dir, (word)"29", (word)followed, 0) ||
        call(262, dir, (word)"29", (word)link, 0x100) ||
        call(5, outside, (word)original, 0, 0) ||
        (followed[3] & 0170000) != 0040000 || followed[1] != original[1] ||
        (link[3] & 0170000) != 0120000 || link[1] != inode_29 ||
        call(3, 29, 0, 0, 0) || call(262, dir, (word)"29", (word)followed, 0) != -2 ||
        call(33, device, 29, 0, 0) != 29 || call(262, dir, (word)"29", (word)followed, 0) ||
        (followed[3] & 0170000) != 0020000 || followed[5] != 0x103) return 89;
    for (long n = 8; n <= 31; ++n)
        if (n != 30 && call(3, n, 0, 0, 0)) return 90;
    long memory = call(319, (word)"proc-fd", 0, 0, 0);
    if (memory < 3 || memory >= 32 || call(77, memory, 1, 0, 0) ||
        call(0, memory, (word)buffer, 1, 0) != 1) return 91;
    char name[3] = {0};
    if (memory >= 10) {
        name[0] = (char)('0' + memory / 10);
        name[1] = (char)('0' + memory % 10);
    } else {
        name[0] = (char)('0' + memory);
    }
    long saved = call(257, dir, (word)name, 0x80000, 0);
    if (saved < 3 || (call(72, saved, 3, 0, 0) & 3) != 0 ||
        call(0, saved, (word)buffer, 1, 0) != 1 || buffer[0] ||
        call(0, memory, (word)buffer, 1, 0) || call(3, saved, 0, 0, 0) ||
        call(3, memory, 0, 0, 0)) return 92;
    long independent = call(257, proc, (word)"self/fd", 0x10000, 0);
    if (independent < 3 || call(217, independent, (word)entry, 24, 0) != 24 ||
        entry->name[0] != '.' || entry->name[1] || call(3, independent, 0, 0, 0) ||
        call(3, outside, 0, 0, 0) || call(3, device, 0, 0, 0) ||
        call(3, dir, 0, 0, 0) || call(3, proc, 0, 0, 0)) return 93;
    return 0;
}

static long check_high_proc_fd(void) {
    const long high = 255;
    long dir = call(2, (word)"/proc/self/fd", 0x10000, 0, 0);
    long device = call(2, (word)"/dev/null", 0, 0, 0);
    if (dir < 3 || device < 3 || call(72, device, 1030, high, 0) != high ||
        call(72, high, 1, 0, 0) != 1 || call(3, device, 0, 0, 0)) return 94;
    long child = call(57, 0, 0, 0, 0);
    if (!child) {
        long error = call(72, high, 1, 0, 0) != 1 || call(3, high, 0, 0, 0);
        call(60, error, 0, 0, 0);
        __builtin_trap();
    }
    int status;
    if (child < 0 || call(61, child, (word)&status, 0, 0) != child || status ||
        call(72, high, 1, 0, 0) != 1) return 94;
    word info[18];
    if (call(262, dir, (word)"255", (word)info, 0) || (info[3] & 0170000) != 0020000 ||
        info[5] != 0x103 || call(262, dir, (word)"256", (word)info, 0) != -2) return 95;
    long size = call(217, dir, (word)buffer, 512, 0);
    word inode = 0;
    for (long offset = 0; offset < size;) {
        const struct proc_dirent *entry = (const void *)(buffer + offset);
        if (size - offset < 24 || entry->length < 24 || entry->length > size - offset) return 96;
        if (entry->name[0] == '2' && entry->name[1] == '5' && entry->name[2] == '5' && !entry->name[3]) {
            if (entry->type != 10 || inode) return 96;
            inode = entry->inode;
        }
        offset += entry->length;
    }
    if (!inode || call(262, dir, (word)"255", (word)info, 0x100) || info[1] != inode ||
        call(3, high, 0, 0, 0) || call(262, dir, (word)"255", (word)info, 0) != -2 ||
        call(3, dir, 0, 0, 0)) return 97;
    return 0;
}

static long check_limits(void) {
    enum { DATA = 2, NPROC = 6, NOFILE = 7, NICE = 13 };
    struct {
        word before, values[2], after;
    } out = {0x31415926, {0, 0}, 0x27182818};
    word address = (word)out.values;
    long pid = call(39, 0, 0, 0, 0);
    if (pid <= 0 || call(97, DATA, address, 0, 0)) return 98;
    word data_soft = out.values[0], data_hard = out.values[1];
    out.values[0] = out.values[1] = 0;
    if (call(302, 0, DATA, 0, address) ||
        out.values[0] != data_soft || out.values[1] != data_hard ||
        call(302, pid, NOFILE, 0, address) || out.values[0] != 256 || out.values[1] != 256 ||
        call(302, 0, NOFILE, 0, 0) || out.before != 0x31415926 || out.after != 0x27182818)
        return 98;
    if (call(302, (word)-1, DATA, 0, address) != -3 ||
        call(302, 0, 16, 0, address) != -22 || call(97, 16, address, 0, 0) != -22 ||
        call(97, NOFILE, 0, 0, 0) != -14 || call(302, 0, DATA, 0, 1) != -14)
        return 99;
    if (call(10, (word)(buffer + 4096), 4096, 1, 0) ||
        call(302, 0, NOFILE, 0, (word)(buffer + 4096 - sizeof(word))) != -14 ||
        call(10, (word)(buffer + 4096), 4096, 3, 0)) return 100;
    char system[390];
    if (call(63, (word)system, 0, 0, 0)) return 101;
    if (system[0] == 'M') {
        const word proposed[2] = {8, 8};
        if (data_soft != (word)-1 || data_hard != (word)-1 ||
            call(302, 0, NOFILE, (word)proposed, address) != -38 ||
            call(302, 0, NICE, 0, address) != -38 ||
            out.values[0] != 256 || out.values[1] != 256 ||
            call(97, NOFILE, address, 0, 0) || out.values[0] != 256 || out.values[1] != 256)
            return 101;
    }
    if (call(97, NPROC, address, 0, 0)) return 102;
    word nproc_soft = out.values[0], nproc_hard = out.values[1];
    if (system[0] == 'M' && (nproc_soft != 256 || nproc_hard != 256)) return 102;
    out.values[0] = out.values[1] = 0;
    if (call(302, 0, NPROC, 0, address) || call(302, 0, NPROC, 0, 0) ||
        out.values[0] != nproc_soft || out.values[1] != nproc_hard) return 102;
    volatile unsigned char *protected = buffer + 4096;
    for (unsigned i = 0; i < 16; ++i) protected[i] = 0xa5;
    if (call(10, (word)protected, 4096, 1, 0) ||
        call(97, NPROC, (word)protected, 0, 0) != -14 ||
        call(302, 0, NPROC, 0, (word)protected) != -14 ||
        call(10, (word)protected, 4096, 3, 0)) return 103;
    for (unsigned i = 0; i < 16; ++i)
        if (protected[i] != 0xa5) return 103;
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
    if (!status) status = check_urandom();
    if (!status) status = check_dup();
    if (!status) status = check_directories();
    if (!status) status = check_live_directory();
    if (!status) status = check_proc_fds();
    if (!status) status = check_high_proc_fd();
    if (!status) status = check_limits();
    if (!status) status = check_realtime();
    if (!status) {
        static const char message[] = "Linux ELF64 files probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0) != sizeof(message) - 1)
            status = 12;
    }
    call(60, status, 0, 0, 0);
    __builtin_trap();
}
