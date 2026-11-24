typedef unsigned long word;

struct observation {
    word stack_base, stack_top, reserve;
    long fd;
    volatile int phase;
    volatile long exec_error;
    int fault;
};

extern long clone_vfork(word stack, struct observation *result);

/* Нельзя возвращаться в родительский кадр C с новым стеком ребёнка. */
__asm__(
    ".text\n"
    "clone_vfork:\n"
    "mov %rsi,%r9\n"
    "mov %rdi,%rsi\n"
    "mov $0x4111,%edi\n"
    "xor %edx,%edx\n"
    "xor %r10d,%r10d\n"
    "xor %r8d,%r8d\n"
    "mov $56,%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "mov %r9,%rdi\n"
    "call vfork_child\n"
    "ud2\n"
    "1: ret\n"
);

static long call(word number, word a0, word a1, word a2, word a3, word a4, word a5) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    register word sixth __asm__("r9") = a5;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static __attribute__((noreturn)) void finish(long status) {
    call(231, status, 0, 0, 0, 0, 0);
    __builtin_trap();
}

static long waitid(long pid, void *info, word options) {
    return call(247, 1, pid, (word)info, options, 0, 0);
}

__attribute__((noreturn)) void vfork_child(struct observation *result) {
    word rsp;
    __asm__ volatile("mov %%rsp,%0" : "=r"(rsp));
    if (rsp < result->stack_base || rsp >= result->stack_top ||
        call(3, result->fd, 0, 0, 0, 0, 0)) finish(40);
    result->phase = 1;
    call(24, 0, 0, 0, 0, 0, 0);
    if (call(9, result->reserve, 4096, 0, 0x100022, -1, 0) != (long)result->reserve) finish(41);
    if (result->fault) {
        result->phase = 2;
        __builtin_trap();
    }
    const char *argv[] = {"/missing-vfork-handler", 0};
    const char *envp[] = {0};
    result->exec_error = call(59, (word)argv[0], (word)argv, (word)envp, 0, 0, 0);
    call(24, 0, 0, 0, 0, 0, 0);
    result->phase = 2;
    finish(127);
}

static long collect_child(long pid, unsigned attempt) {
    if (attempt == 0) {
        int info[32];
        for (unsigned i = 0; i < 32; ++i) info[i] = -92;
        if (waitid(pid, info, 0x1000004) || info[0] != 17 || info[1] || info[2] != 1 ||
            info[3] != -92 || info[4] != pid || info[5] != call(102, 0, 0, 0, 0, 0, 0) ||
            info[6] != 127 || info[7] != -92) return 5;
        if (waitid(pid, (void *)1, 0x1000004) != -14 ||
            waitid(pid, (void *)1, 4) != -14 || waitid(pid, 0, 4) != -10 ||
            waitid(pid, (void *)1, 4) != -14) return 6;
        return 0;
    }
    if (attempt == 1) {
        int status;
        if (call(61, pid, (word)&status, 0, 0, 0, 0) != pid || (status & 0x7f) != 4) return 7;
        return 0;
    }
    if (attempt == 2) {
        long base = call(9, 0, 8192, 3, 0x22, -1, 0);
        if (base < 0 || call(10, base + 4096, 4096, 0, 0, 0, 0)) return 13;
        int *info = (void *)(base + 4096 - 28);
        info[3] = -92;
        if (waitid(pid, info, 0x1000004) || info[3] != -92 || info[6] != 127 ||
            waitid(pid, info + 1, 4) != -14 || waitid(pid, 0, 4) != -10 ||
            call(11, base, 8192, 0, 0, 0, 0)) return 14;
        return 0;
    }
    if (waitid(pid, 0, 4) || waitid(pid, 0, 4) != -10) return 8;
    return 0;
}

static long wait_blocking(long fd) {
    if (call(77, fd, 4096, 0, 0, 0, 0)) return 15;
    long base = call(9, 0, 4096, 3, 1, fd, 0);
    if (base < 0) return 16;
    volatile int *ready = (void *)base;
    long child = call(57, 0, 0, 0, 0, 0, 0);
    if (!child) {
        while (!*ready) call(24, 0, 0, 0, 0, 0, 0);
        call(24, 0, 0, 0, 0, 0, 0);
        finish(29);
    }
    if (child < 0) return 17;
    int info[32];
    for (unsigned i = 0; i < 32; ++i) info[i] = -72;
    long result = waitid(child, info, 5);
    *ready = 1;
    if (result || info[0] || info[1] || info[2] || info[4] || info[5] || info[6] ||
        info[3] != -72 || info[7] != -72) return 18;
    if (waitid(child, info, 4) || info[4] != child || info[6] != 29 ||
        waitid(child, info, 4) != -10 || info[4] || info[6] ||
        call(11, base, 4096, 0, 0, 0, 0)) return 19;
    return 0;
}

static long probe(void) {
    const word stack_size = 0x9000;
    long stack = call(9, 0, stack_size, 3, 0x20022, -1, 0);
    long reserve = call(9, 0, 4096, 0, 0x22, -1, 0);
    long fd = call(319, (word)"vfork-probe", 1, 0, 0, 0, 0);
    if (stack < 0 || reserve < 0 || fd < 0 || call(11, reserve, 4096, 0, 0, 0, 0)) return 1;
    for (unsigned i = 0; i < 16; ++i) {
        struct observation result = {
            .stack_base = stack, .stack_top = stack + stack_size, .reserve = reserve,
            .fd = fd, .fault = i == 1,
        };
        long child = clone_vfork(result.stack_top, &result);
        if (child <= 0 || result.phase != 2 || call(72, fd, 1, 0, 0, 0, 0) != 1) return 2;
        if (!result.fault && result.exec_error != -2 && result.exec_error != -38) return 3;
        if (call(9, reserve, 4096, 3, 0x100022, -1, 0) != -17 ||
            call(10, reserve, 4096, 3, 0, 0, 0)) return 4;
        volatile unsigned char *page = (void *)reserve;
        if (*page) return 9;
        *page = 0xa5;
        if (*page != 0xa5 || call(11, reserve, 4096, 0, 0, 0, 0)) return 10;
        long error = collect_child(child, i);
        if (error) return error;
    }
    long error = wait_blocking(fd);
    if (error) return error;
    if (call(3, fd, 0, 0, 0, 0, 0) || call(11, stack, stack_size, 0, 0, 0, 0)) return 11;
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    long status = probe();
    if (!status) {
        static const char marker[] = "Linux ELF64 vfork probe\n";
        if (call(1, 1, (word)marker, sizeof(marker) - 1, 0, 0, 0) != sizeof(marker) - 1)
            status = 12;
    }
    finish(status);
}
