typedef unsigned long word;

static char stack[16384] __attribute__((aligned(16)));
static const word tls = 0x123456789abcdef0ul;
static volatile unsigned ready, clear_tid, leader_tid;
static volatile int parent_tid, result;
static long pid, pipe_write, inherited_no_new_privs;

extern long clone_thread(word stack_top, volatile int *ptid, volatile unsigned *ctid, const word *fs);

/* Поток начинает выполнение на новом стеке, где нет адреса возврата в родителя. */
__asm__(
    ".text\n"
    "clone_thread:\n"
    "mov %rdi,%r11\n"
    "mov %rcx,%r8\n"
    "mov %rdx,%r10\n"
    "mov %rsi,%rdx\n"
    "mov %r11,%rsi\n"
    "mov $0x3d0f00,%edi\n"
    "mov $56,%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "call worker\n"
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

static long simple(word number, word arg) {
    return call(number, arg, 0, 0, 0, 0, 0);
}

static long futex(volatile unsigned *address, unsigned op, unsigned value, unsigned bits) {
    return call(202, (word)address, op, value, 0, 0, bits);
}

static __attribute__((noreturn)) void finish(word number, long status) {
    simple(number, status);
    __builtin_trap();
}

static int mode;

__attribute__((noreturn)) void worker(void) {
    while (mode == 2) futex(&ready, 0x80, 0, 0);
    if (mode) {
        while (leader_tid) futex(&leader_tid, 0x109, 1, -1);
        finish(60, 0);
    }

    word value, mask = 1ul << (12 - 1);
    __asm__ volatile("mov %%fs:0,%0" : "=r"(value));
    if (value != tls || simple(39, 0) != pid || simple(186, 0) != parent_tid || parent_tid == pid)
        result = 1;
    if (simple(157, 39) != inherited_no_new_privs ||
        call(157, 38, 1, 0, 0, 0, 0) || simple(157, 39) != 1) result = 15;
    const word action[4] = {1, 0, 0, 0};
    if (simple(3, pipe_write) || call(13, 10, (word)action, 0, 8, 0, 0) ||
        call(14, 2, (word)&mask, 0, 8, 0, 0)) result = 2;
    if (futex(&ready, 1, 1, 0) || futex(&ready, 0x8a, 1, 2)) result = 3;
    long woken;
    do {
        woken = futex(&ready, 0x8a, 1, 1);
        if (woken < 0) finish(231, 4);
        if (!woken) simple(24, 0);
    } while (!woken);
    finish(60, 0);
}

static int check_thread(void) {
    int ends[2];
    if (simple(22, (word)ends)) return 5;
    pipe_write = ends[1];
    clear_tid = 1;
    parent_tid = 0;
    long child = clone_thread((word)(stack + sizeof(stack)), &parent_tid, &clear_tid, &tls);
    if (child <= 0 || parent_tid != child || simple(186, 0) != pid) return 6;
    if (futex(&ready, 0x80, 1, 0) != -11 || futex(&ready, 0x89, 0, 0) != -22 ||
        futex(&ready, 0x89, 0, 1)) return 7;
    while (clear_tid) {
        long error = futex(&clear_tid, 0x109, 1, -1);
        if (error && error != -11) return 8;
    }
    if (result) return result;
    if (simple(157, 39) != inherited_no_new_privs) return 16;
    char byte;
    word action[4], mask;
    if (simple(3, pipe_write) != -9 || call(0, ends[0], (word)&byte, 1, 0, 0, 0) ||
        simple(3, ends[0]) || call(13, 10, 0, (word)action, 8, 0, 0) || action[0] != 1 ||
        call(14, 2, 0, (word)&mask, 8, 0, 0) || mask & (1ul << (12 - 1))) return 9;
    if (call(61, child, 0, 1, 0, 0, 0) != -10) return 10;
    return 0;
}

static int check_process_exit(int test_mode) {
    long child = simple(57, 0);
    if (child < 0) return 11;
    if (!child) {
        mode = test_mode;
        leader_tid = 1;
        if (simple(218, (word)&leader_tid) != simple(39, 0) ||
            clone_thread((word)(stack + sizeof(stack)), &parent_tid, &clear_tid, &tls) <= 0)
            finish(231, 12);
        finish(test_mode == 1 ? 60 : 231, 23);
    }
    int status;
    if (call(61, child, (word)&status, 0, 0, 0, 0) != child ||
        status != (test_mode == 1 ? 0 : 23 << 8)) return 13;
    return 0;
}

void _start(void) {
    pid = simple(39, 0);
    inherited_no_new_privs = simple(157, 39);
    char system[390];
    if (inherited_no_new_privs < 0 || inherited_no_new_privs > 1 || simple(63, (word)system) ||
        (system[0] == 'M' && inherited_no_new_privs)) finish(231, 17);
    for (int i = 0; i < 10; ++i) {
        int status = check_thread();
        if (status) finish(231, status);
    }
    if (call(157, 38, 1, 0, 0, 0, 0)) finish(231, 18);
    inherited_no_new_privs = 1;
    int inherited = check_thread();
    if (inherited) finish(231, inherited);
    for (int i = 1; i <= 2; ++i) {
        int status = check_process_exit(i);
        if (status) finish(231, status);
    }
    static const char marker[] = "Linux ELF64 pthread probe\n";
    if (call(1, 1, (word)marker, sizeof(marker) - 1, 0, 0, 0) != sizeof(marker) - 1) finish(231, 14);
    finish(231, 0);
}
