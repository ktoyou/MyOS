#ifndef TEST_LINUX_X64_EXEC_H
#define TEST_LINUX_X64_EXEC_H

typedef unsigned long word;

#define TARGET_FILE "linux-exec-target.elf"
#define TARGET_PATH "./" TARGET_FILE
#define PRIVATE_ADDRESS 0x30000000000ul

struct exec_sync {
    volatile unsigned ready, ack;
    volatile long pid;
    unsigned permitted[2];
};

static inline long sys(word number, word a0, word a1, word a2, word a3, word a4, word a5) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    register word sixth __asm__("r9") = a5;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static inline long exec_permitted_caps(unsigned permitted[2]) {
    unsigned header[] = {0x20080522, 0};
    struct { unsigned effective, permitted, inheritable; } caps[2];
    long status = sys(125, (word)header, (word)caps, 0, 0, 0, 0);
    if (status) return status;
    for (unsigned i = 0; i < 2; ++i) permitted[i] = caps[i].permitted;
    return 0;
}

static inline __attribute__((noreturn)) void finish(long status) {
    sys(231, status, 0, 0, 0, 0, 0);
    __builtin_trap();
}

static inline int equal(const char *a, const char *b) {
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

#endif
