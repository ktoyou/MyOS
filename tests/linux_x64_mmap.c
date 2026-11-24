typedef unsigned long word;

static volatile unsigned char relro[4096] __attribute__((aligned(4096))) = {0x5a};

static long call(word number, word a0, word a1, word a2, word a3, word a4, word a5) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    register word sixth __asm__("r9") = a5;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long mmap(word address, word length, word protection, word flags, long fd, word offset) {
    return call(9, address, length, protection, flags, (word)fd, offset);
}

static long open_data(void) {
    return call(257, (unsigned)-100, (word)FILE_PATH, 0x80000, 0, 0, 0);
}

static long mprotect(word address, word length, word protection) {
    return call(10, address, length, protection, 0, 0, 0);
}

static long munmap(word address, word length) {
    return call(11, address, length, 0, 0, 0, 0);
}

static long discard(word address, word length) {
    return call(28, address, length, 4, 0, 0, 0);
}

static long wake(word address, word op, word count) {
    return call(202, address, op, count, (word)-1, (word)-1, (word)-1);
}

static long check_futex(word file_address) {
    unsigned int word_in_memory = 1;
    word rw = (word)&word_in_memory;
    if (wake(rw, 1, 0x7fffffff) || wake(rw, 129, 0) || wake(rw, 129, (unsigned)-1) ||
        wake(rw, 0x100000081ul, 1) || wake(file_address, 1, 1)) return 30;
    if (wake(rw + 1, 129, 0) != -22 || wake(0, 129, 1) ||
        wake(0, 1, 1) != -14 || wake(0xffff800000000000ul, 129, 1) != -14 ||
        wake(rw + 1, 0x181, 1) != -38) return 31;
    long page = mmap(0, 0x1000, 0, 0x22, -1, 0);
    if (page < 0 || wake(page, 129, 1) || wake(page, 1, 1) != -14 ||
        mprotect(page, 0x1000, 1) || wake(page, 129, 1) ||
        wake(page, 1, 1) != -14 || munmap(page, 0x1000)) return 32;
    return 0;
}

static long check_stack(void) {
    const word size = 0x9000, stack_flags = 0x20022;
    long base = mmap(0, size, 3, stack_flags, -1, 0);
    if (base < 0 || (base & 0xfff)) return 62;
    volatile unsigned char *bytes = (void *)base;
    if (bytes[0] || bytes[size - 1]) return 63;
    bytes[0] = 0x31;
    bytes[size - 1] = 0x52;
    if (bytes[0] != 0x31 || bytes[size - 1] != 0x52 ||
        mmap(base, size, 3, stack_flags | 0x100000, -1, 0) != -17) return 64;
    if (munmap(base, size) ||
        mmap(base, size, 3, stack_flags | 0x100000, -1, 0) != base) return 65;
    if (bytes[0] || bytes[size - 1] || munmap(base, size)) return 66;
    return 0;
}

static long check_sparse(void) {
    const word size = 0x800000000ul;
    const word hint = 0x30000000000ul;
    long base = mmap(hint, size, 0, 0x22, -1, 0);
    if (base != (long)hint || munmap(base, 0x1000) ||
        munmap(base + size - 0x1000, 0x1000)) return 21;
    word middle = base + 0x400002000ul;
    if (mmap(middle, 0x1000, 0, 0x100022, -1, 0) != -17 ||
        mprotect(middle, 0x3000, 3)) return 22;
    volatile unsigned char *items = (void *)middle;
    if (items[0] || items[0x1000] || items[0x2000]) return 23;
    items[0] = 0x31;
    items[0x1000] = 0x42;
    items[0x2000] = 0x53;
    if (mprotect(middle + 0x1000, 0x1000, 0) ||
        mprotect(middle + 0x1000, 0x1000, 3) || items[0x1000] != 0x42) return 24;
    if (munmap(middle + 0x1000, 0x1000) ||
        mmap(middle + 0x1000, 0x1000, 3, 0x100022, -1, 0) != (long)(middle + 0x1000) ||
        items[0] != 0x31 || items[0x1000] || items[0x2000] != 0x53) return 25;
    if (mmap(middle, 0x1000, 0, 0x32, -1, 0) != (long)middle ||
        mprotect(middle, 0x1000, 3) || items[0] || items[0x2000] != 0x53) return 26;
    if (discard(base + 0x1000, size - 0x2000) || items[0x2000] ||
        discard(base + size - 0x2000, 0x2000) != -12) return 67;
    if (munmap(base, size) ||
        mmap(base, size, 0, 0x100022, -1, 0) != base || munmap(base, size)) return 27;
    return 0;
}

static long check_mprotect(long fd, word file_address) {
    long address = mmap(0, 0x1000, 0, 0x22, -1, 0);
    if (address < 0 || mprotect(address + 1, 0, 1) != -22 || mprotect(address, 0, 1) ||
        mprotect(0, 0x1000, 1) != -12 || mprotect(address, 1, 3)) return 14;
    volatile unsigned char *code = (void *)address;
    const volatile unsigned char *source = (void *)file_address;
    for (unsigned i = 0; i < 6; ++i) code[i] = source[i];
    if (mprotect(address, 1, 5) || ((int (*)(void))address)() != 42 ||
        mprotect(address, 0x1000, 3)) return 15;
    code[1] = 43;
    if (mprotect(address, 0x1000, 5) || ((int (*)(void))address)() != 43 ||
        mprotect(address, 0x1000, 0) || call(1, 1, address, 1, 0, 0, 0) != -14 ||
        mprotect(address, 0x1000, 1) || code[1] != 43) return 16;
    if (mprotect((word)relro, sizeof(relro), 1) || relro[0] != 0x5a ||
        call(0, fd, (word)relro, 1, 0, 0, 0) != -14 ||
        mprotect((word)relro, sizeof(relro), 3)) return 17;
    relro[0] = 0xa5;
    return relro[0] == 0xa5 ? 0 : 18;
}

static long check_shared(void) {
    long fd = open_data();
    if (fd < 0 || mmap(0, 1, 1, 1, -1, 0) != -9 ||
        mmap(0, 1, 3, 1, fd, 0) != -13) return 33;
    long address = mmap(0, 0x2000, 1, 1, fd, 0x1000);
    long private = mmap(0, 0x1000, 3, 2, fd, 0x1000);
    if (address < 0 || private < 0 ||
        mmap(address, 0x1000, 3, 0x100001, fd, 0x1000) != -17 ||
        call(3, (word)fd, 0, 0, 0, 0, 0)) return 34;
    volatile unsigned char *bytes = (void *)address;
    *(volatile unsigned char *)private = 0xa5;
    if (bytes[0] != 0x5a || bytes[1] || bytes[0xfff] ||
        mprotect(address, 0x1000, 3) != -13 || mprotect(address, 0x2000, 0) ||
        mprotect(address + 0x1000, 0x1000, 3) != -13 ||
        mprotect(address, 0x2000, 1) || bytes[0] != 0x5a) return 35;
    if (mmap(address, 0x1000, 0, 0x32, -1, 0) != address ||
        mprotect(address, 0x1000, 3) || bytes[0]) return 36;
    bytes[0] = 0x31;
    if (bytes[0] != 0x31 || munmap(address, 0x2000) || munmap(private, 0x1000)) return 37;
    return 0;
}

static long open_proc_fd(char path[], word flags) {
    return call(257, (unsigned)-100, (word)path, flags, 0, 0, 0);
}

static long close_fd(long fd) {
    return call(3, fd, 0, 0, 0, 0, 0);
}

static long resize_fd(long fd, word size) {
    return call(77, fd, size, 0, 0, 0, 0);
}

static long fcntl(long fd, word command, word value) {
    return call(72, fd, command, value, 0, 0, 0);
}

static long check_memfd(void) {
    const word size = 0x10020;
    static const char name[] = "shared-memory-region";
    if (call(319, 0, 0xb, 0, 0, 0, 0) != -14 ||
        call(319, (word)name, 0x8000, 0, 0, 0, 0) != -22) return 40;
    long fd = call(319, (word)name, 0xb, 0, 0, 0, 0);
    if (fd < 3 || fd > 99 || fcntl(fd, 1, 0) != 1 || fcntl(fd, 1034, 0) != 0x20 ||
        resize_fd(fd, size) || fcntl(fd, 1033, 0x8000) != -22 ||
        fcntl(fd, 1033, 7) || fcntl(fd, 1034, 0) != 0x27 || fcntl(fd, 1033, 0) != -1 ||
        resize_fd(fd, size) || resize_fd(fd, size - 1) != -1 || resize_fd(fd, size + 1) != -1)
        return 41;
    char path[] = "/proc/self/fd/00";
    char *digit = path + sizeof("/proc/self/fd/") - 1;
    digit[1] += fd % 10;
    if (fd < 10 && open_proc_fd(path, 0) != -2) return 42;
    digit[0] = fd < 10 ? digit[1] : (char)('0' + fd / 10);
    if (fd < 10) digit[1] = 0;
    if (open_proc_fd(path, 0x20000) != -40) return 43;
    long ro = open_proc_fd(path, 0x80000);
    if (ro < 0 || ro == fd || fcntl(ro, 1, 0) != 1 || (fcntl(ro, 3, 0) & 3) != 0 ||
        (fcntl(fd, 3, 0) & 3) != 2 || fcntl(ro, 1034, 0) != 0x27 ||
        resize_fd(ro, size) != -22 || mmap(0, size, 3, 1, ro, 0) != -13) return 44;
    word stat_rw[18], stat_ro[18];
    if (call(5, fd, (word)stat_rw, 0, 0, 0, 0) || call(5, ro, (word)stat_ro, 0, 0, 0, 0) ||
        stat_rw[0] != stat_ro[0] || stat_rw[1] != stat_ro[1] ||
        stat_rw[6] != size || stat_ro[6] != size) return 45;
    long rw_map = mmap(0, size, 3, 1, fd, 0), ro_map = mmap(0, size, 1, 1, ro, 0);
    if (rw_map < 0 || ro_map < 0 || mprotect(ro_map, 0x1000, 3) != -13) return 46;
    volatile unsigned char *rw_bytes = (void *)rw_map, *ro_bytes = (void *)ro_map;
    if (rw_bytes[0] || ro_bytes[size - 1]) return 47;
    rw_bytes[0] = 0x51;
    rw_bytes[size - 1] = 0x72;
    unsigned char byte;
    if (mmap(rw_map, 0x1000, 3, 0x11, fd, 0) != rw_map || rw_bytes[0] != 0x51 ||
        call(17, ro, (word)&byte, 1, size - 1, 0, 0) != 1 || byte != 0x72 ||
        call(0, ro, (word)&byte, 1, 0, 0, 0) != 1 || byte != 0x51 ||
        call(0, fd, (word)&byte, 1, 0, 0, 0) != 1 || byte != 0x51 ||
        close_fd(fd) || open_proc_fd(path, 0) != -2 || close_fd(ro)) return 48;
    if (mprotect(ro_map, size, 0) || mprotect(ro_map, size, 1) ||
        mprotect(ro_map, size, 3) != -13 || ro_bytes[size - 1] != 0x72) return 49;
    rw_bytes[0] = 0x33;
    if (ro_bytes[0] != 0x33 || munmap(rw_map, size) || ro_bytes[0] != 0x33 ||
        munmap(ro_map, size)) return 50;
    return 0;
}

static long check_memfd_resize(void) {
    const word size = 0x201010;
    long fd = call(319, (word)"", 0, 0, 0, 0, 0);
    if (fd < 0 || fcntl(fd, 1034, 0) != 1 || resize_fd(fd, size)) return 51;
    long last = mmap(0, 0x2000, 3, 1, fd, 0x200000);
    if (last < 0) return 52;
    volatile unsigned char *bytes = (void *)last;
    bytes[0] = 0x25;
    bytes[0x1010 - 1] = 0x30;
    if (munmap(last, 0x2000) || resize_fd(fd, 0x200001) || resize_fd(fd, size)) return 53;
    last = mmap(0, 0x2000, 1, 1, fd, 0x200000);
    if (last < 0) return 54;
    bytes = (void *)last;
    if (bytes[0] != 0x25 || bytes[0x1010 - 1] || munmap(last, 0x2000) || close_fd(fd)) return 55;
    return 0;
}

static long check_mmap(void) {
    long fd = open_data();
    if (fd < 0) return 1;
    if (mmap(0, 1, 1, 2, fd, 1) != -22 || mmap(0, 1, 1, 2, -1, 0) != -9) return 2;
    long address = mmap(0, 0x3010, 1, 0x802, fd, 0);
    if (address < 0) return 3;
    volatile unsigned char *bytes = (void *)address;
    if (bytes[0] != 0xb8 || bytes[0x1000] != 0x5a ||
        bytes[0x1001] || bytes[0x1fff]) return 4;
    long wake_result = check_futex((word)address);
    if (wake_result) return wake_result;
    long result = check_mprotect(fd, (word)address);
    if (result) return result;
    if (mmap(address + 0x2000, 0x2000, 1, 0x100002, fd, 0) != -17) return 5;
    long code = mmap(address + 0x2000, 0x1000, 5, 0x812, fd, 0);
    if (code != address + 0x2000 || ((int (*)(void))code)() != 42) return 6;
    if (mmap(address + 0x2000, 0x1000, 3, 0x812, fd, 0x1000) != code ||
        bytes[0x2000] != 0x5a || bytes[0x2001]) return 7;
    bytes[0x2000] = 0xeb;
    if (bytes[0x1000] != 0x5a || call(3, (word)fd, 0, 0, 0, 0, 0)) return 8;
    if (mmap(address + 0x3000, 0x1000, 3, 0x32, -1, 0) != address + 0x3000 ||
        bytes[0x3000] || bytes[0x3fff] || bytes[0x2000] != 0xeb) return 9;
    return 0;
}

static __attribute__((noreturn)) void finish(long status) {
    call(60, (word)status, 0, 0, 0, 0, 0);
    __builtin_trap();
}

static long check_discard(void) {
    const word page = 4096;
    long base = mmap(0, 5 * page, 3, 0x22, -1, 0);
    if (base < 0 || discard(base + 1, 0) != -22 || discard(base, (word)-1) != -22) return 68;
    volatile unsigned char *bytes = (void *)base;
    for (word i = 0; i < 5; ++i) bytes[i * page] = (unsigned char)(i + 1);
    bytes[2 * page - 1] = 0xff;
    if (mprotect(base + page, page, 1) || mprotect(base + 2 * page, page, 0) ||
        discard(base + page, 1) || discard(base + 2 * page, page) ||
        mmap(base + page, page, 3, 0x100022, -1, 0) != -17 || bytes[0] != 1 ||
        bytes[page] || bytes[2 * page - 1] || bytes[3 * page] != 4) return 69;
    long fd = open_data();
    if (fd < 0 || call(17, fd, base + page, 1, 0, 0, 0) != -14 ||
        call(17, fd, base + 2 * page, 1, 0, 0, 0) != -14 || mprotect(base + 2 * page, page, 3) ||
        call(17, fd, base + 2 * page, 1, 0, 0, 0) != 1 || bytes[2 * page] != 0xb8 ||
        bytes[2 * page + 1]) return 70;

    if (mprotect(base, page, 1)) return 71;
    long pid = call(57, 0, 0, 0, 0, 0, 0);
    if (!pid) finish(discard(base, page) || bytes[0]);
    int status;
    if (pid < 0 || call(61, pid, (word)&status, 0, 0, 0, 0) != pid || status || bytes[0] != 1) return 72;
    if (munmap(base + 3 * page, page) || discard(base + 3 * page, 0) ||
        discard(base + 2 * page, 3 * page) != -12 || bytes[2 * page] || bytes[4 * page] ||
        munmap(base, 5 * page)) return 73;

    long file = mmap(0, page, 3, 2, fd, 0);
    if (file < 0 || call(3, fd, 0, 0, 0, 0, 0)) return 74;
    volatile unsigned char *file_bytes = (void *)file;
    *file_bytes = 0x71;
    char uname[390];
    if (call(63, (word)uname, 0, 0, 0, 0, 0)) return 75;
    long result = discard(file, page);
    if (uname[0] == 'M' ? result != -38 || *file_bytes != 0x71 : result || *file_bytes != 0xb8) return 75;
    return munmap(file, page) ? 76 : 0;
}

__attribute__((noreturn)) void _start(void) {
    long status = check_mmap();
    if (!status) status = check_shared();
    if (!status) status = check_memfd();
    if (!status) status = check_memfd_resize();
    if (!status) status = check_stack();
    if (!status) status = check_sparse();
    if (!status) status = check_discard();
    if (!status) {
        static const char message[] = "Linux ELF64 mmap and mprotect probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0, 0, 0) != sizeof(message) - 1)
            status = 10;
    }
    finish(status);
}

__attribute__((noreturn)) void mmap_memfd_nx(void) {
    long fd = call(319, (word)"", 0xb, 0, 0, 0, 0);
    if (fd < 0 || resize_fd(fd, 0x1000)) finish(56);
    long rw = mmap(0, 0x1000, 3, 1, fd, 0);
    if (rw < 0) finish(57);
    *(volatile unsigned char *)rw = 0xc3;
    if (resize_fd(fd, 0x2000) != -16 || munmap(rw, 0x1000)) finish(59);
    word stat[18];
    if (resize_fd(fd, 0x10000000) != -12 || call(5, fd, (word)stat, 0, 0, 0, 0) ||
        stat[6] != 0x1000 || resize_fd(fd, 0x201000)) finish(60);
    rw = mmap(0, 0x1000, 3, 1, fd, 0);
    if (rw < 0 || mmap(0, 0x1000, 5, 1, fd, 0) != -13 ||
        mprotect(rw, 0x1000, 5) != -13 || *(volatile unsigned char *)rw != 0xc3) finish(61);
    ((void (*)(void))rw)();
    finish(58);
}

__attribute__((noreturn)) void mmap_past_eof(void) {
    long fd = open_data();
    long address = mmap(0, 0x3010, 1, 0x802, fd, 0);
    if (address < 0 || mprotect(address + 0x2000, 0x1000, 3)) finish(11);
    volatile unsigned char *bytes = (void *)address;
    finish(bytes[0x2000]);
}

__attribute__((noreturn)) void mmap_shared_past_eof(void) {
    long fd = open_data();
    long address = mmap(0, 0x2000, 0, 1, fd, 0x1000);
    if (address < 0 || mprotect(address, 0x2000, 1)) finish(38);
    volatile unsigned char *bytes = (void *)address;
    finish(bytes[0x1000]);
}

__attribute__((noreturn)) void mmap_protection(void) {
    long fd = open_data();
    long address = mmap(0, 0x1000, 5, 2, fd, 0);
    if (address < 0) finish(12);
    if (mmap((word)&_start & ~0xffful, 0x1000, 3, 0x32, -1, 0) != -12 ||
        mmap(address, 0x1000, 7, 0x812, fd, 0) != -13 ||
        mprotect(address, 0x1000, 7) != -13 ||
        mprotect(address, 0x2000, 0) != -12 ||
        mmap(address, 0x10000000, 3, 0x32, -1, 0) != -12 ||
        ((int (*)(void))address)() != 42) finish(13);
    finish(0);
}

__attribute__((noreturn)) void mprotect_relro_fault(void) {
    if (mprotect((word)relro, sizeof(relro), 1)) finish(19);
    relro[0] = 0;
    finish(20);
}

__attribute__((noreturn)) void mprotect_sparse_oom(void) {
    const word size = 0x800000000ul;
    long base = mmap(0, size, 0, 0x22, -1, 0);
    if (base < 0 || mprotect(base, 0x1000, 3)) finish(28);
    volatile unsigned char *data = (void *)base;
    data[0] = 0x5a;
    if (mprotect(base, size, 3) != -12 || data[0] != 0x5a ||
        mmap(base + 0x1000, 0x1000, 3, 0x100022, -1, 0) != -17 ||
        mprotect(base + 0x1000, 0x1000, 3) || data[0x1000] != 0 ||
        munmap(base, size)) finish(29);
    finish(0);
}
