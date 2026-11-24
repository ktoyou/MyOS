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

static long check_mmap(void) {
    long fd = open_data();
    if (fd < 0) return 1;
    if (mmap(0, 1, 1, 2, fd, 1) != -22 || mmap(0, 1, 1, 2, -1, 0) != -9) return 2;
    long address = mmap(0, 0x3010, 1, 0x802, fd, 0);
    if (address < 0) return 3;
    volatile unsigned char *bytes = (void *)address;
    if (bytes[0] != 0xb8 || bytes[0x1000] != 0x5a ||
        bytes[0x1001] || bytes[0x1fff]) return 4;
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
