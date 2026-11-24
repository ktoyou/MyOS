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

__attribute__((noreturn)) void _start(void) {
    long status = check_mmap();
    if (!status) status = check_shared();
    if (!status) status = check_sparse();
    if (!status) {
        static const char message[] = "Linux ELF64 mmap and mprotect probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0, 0, 0) != sizeof(message) - 1)
            status = 10;
    }
    finish(status);
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
