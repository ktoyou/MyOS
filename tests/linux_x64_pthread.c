typedef unsigned long word;

static char stack[16384] __attribute__((aligned(16)));
static const word tls = 0x123456789abcdef0ul;
static volatile unsigned ready, clear_tid, leader_tid;
static volatile unsigned timed_word;
static volatile int parent_tid, result;
static long pid, pipe_write, inherited_no_new_privs;

enum { MAX_WORKERS = 255, MAX_CHILDREN = 63 };
static char worker_stacks[MAX_WORKERS + 1][4096] __attribute__((aligned(16)));
static struct worker_slot {
    word index;
    volatile unsigned clear_tid;
    volatile int parent_tid;
} workers[MAX_WORKERS + 1];
static unsigned arrived, gate;
static unsigned preempt_started, preempt_stop;

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

struct timespec {
    long seconds, nanos;
};

static long futex_timed(volatile unsigned *address, unsigned op, unsigned value, unsigned bits,
                        const struct timespec *timeout) {
    return call(202, (word)address, op, value, (word)timeout, 0, bits);
}

static long clock_time(unsigned clock, struct timespec *time) {
    return call(228, clock, (word)time, 0, 0, 0, 0);
}

static long clock_ns(unsigned clock) {
    struct timespec time;
    if (clock_time(clock, &time) || time.seconds < 0 || time.nanos < 0 || time.nanos >= 1000000000)
        return -1;
    return time.seconds * 1000000000 + time.nanos;
}

static __attribute__((noreturn)) void finish(word number, long status) {
    simple(number, status);
    __builtin_trap();
}

static int mode;

__attribute__((noreturn)) void worker(void) {
    if (mode == 6) {
        word pattern = 0xc9b087e6543210ful;
        __asm__ volatile("movq %0,%%xmm0" :: "r"(pattern) : "memory");
        word rcx, r11, observed;
        __asm__ volatile("mov %[pattern],%%rcx; mov %[inverse],%%r11\n"
                         "movl $1,%[started]\n"
                         "1: pause; cmpl $0,%[stop]; je 1b\n"
                         "mov %%r11,%[r11]; movq %%xmm0,%[xmm]"
                         : "=&c"(rcx), [r11] "=&r"(r11), [xmm] "=r"(observed), [started] "=m"(preempt_started)
                         : [pattern] "r"(pattern), [inverse] "r"(~pattern), [stop] "m"(preempt_stop)
                         : "r11", "cc", "memory");
        if (rcx != pattern || observed != pattern || r11 != ~pattern) finish(231, 39);
        finish(60, 0);
    }
    if (mode == 5) {
        long start = clock_ns(3), wall = clock_ns(1), now;
        if (start < 0 || wall < 0) finish(231, 35);
        do {
            now = clock_ns(1);
            if (now < wall) finish(231, 35);
        } while (now - wall < 60000000);
        if (clock_ns(3) <= start) finish(231, 35);
        finish(60, 0);
    }
    if (mode == 4) {
        word index;
        __asm__ volatile("mov %%fs:0,%0" : "=r"(index));
        if (index > MAX_WORKERS || simple(186, 0) != workers[index].parent_tid ||
            simple(39, 0) != pid) finish(231, 24);
        word pattern = 0x34df5b37abc15850ul + index;
        __asm__ volatile("movq %0,%%xmm0" :: "r"(pattern) : "memory");
        __atomic_add_fetch(&arrived, 1, __ATOMIC_RELEASE);
        futex(&arrived, 0x81, 1, 0);
        while (!__atomic_load_n(&gate, __ATOMIC_ACQUIRE)) {
            long rc = futex(&gate, 0x80, 0, 0);
            if (rc && rc != -11) finish(231, 24);
        }
        word observed;
        __asm__ volatile("movq %%xmm0,%0" : "=r"(observed) :: "memory");
        if (observed != pattern) finish(231, 32);
        finish(60, 0);
    }
    if (mode == 3) {
        const struct timespec delay = {0, 25000000};
        result = futex_timed(&timed_word, 0x80, 0, 0, &delay) == -110 ? 0 : 21;
        timed_word = 1;
        futex(&timed_word, 0x8a, 1, 2);
        finish(60, 0);
    }
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

static int check_thread_capacity(unsigned count, int check_limit) {
    word info[14];
    if (check_limit && simple(99, (word)info)) return 33;
    word free_before = check_limit ? info[5] : 0;
    mode = 4;
    __atomic_store_n(&gate, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&arrived, 0, __ATOMIC_RELAXED);
    for (unsigned i = 0; i < count + (unsigned)check_limit; ++i) {
        struct worker_slot *slot = &workers[i];
        *slot = (struct worker_slot){.index = i, .clear_tid = 1};
        word top = (word)(worker_stacks[i] + sizeof(worker_stacks[i]));
        long tid = clone_thread(top, &slot->parent_tid, &slot->clear_tid, &slot->index);
        if (i == count) {
            if (tid != -11 || slot->parent_tid) return 25;
        } else if (tid <= 0 || tid != slot->parent_tid) return 25;
    }
    for (;;) {
        unsigned seen = __atomic_load_n(&arrived, __ATOMIC_ACQUIRE);
        if (seen >= count) {
            if (seen != count) return 26;
            break;
        }
        long rc = futex(&arrived, 0x80, seen, 0);
        if (rc && rc != -11) return 26;
    }
    if (check_limit && (simple(99, (word)info) || (unsigned short)info[10] != count + 1 ||
                        info[5] + count * 4096ul > free_before)) return 33;
    __atomic_store_n(&gate, 1, __ATOMIC_RELEASE);
    if (futex(&gate, 0x81, 0x7fffffff, 0) < 0) return 26;
    for (unsigned i = 0; i < count; ++i) {
        while (workers[i].clear_tid) {
            long rc = futex(&workers[i].clear_tid, 0x109, 1, -1);
            if (rc && rc != -11) return 27;
        }
    }
    if (check_limit && (simple(99, (word)info) || (unsigned short)info[10] != 1 ||
                        info[5] != free_before)) return 33;
    mode = 0;
    return 0;
}

static int check_process_capacity(unsigned count, int check_limit) {
    int ends[2];
    long children[MAX_CHILDREN];
    if (simple(22, (word)ends)) return 28;
    for (unsigned i = 0; i < count + (unsigned)check_limit; ++i) {
        long child = simple(57, 0);
        if (!child) {
            char byte;
            if (simple(3, ends[1]) || call(0, ends[0], (word)&byte, 1, 0, 0, 0)) finish(60, 1);
            finish(60, 0);
        }
        if (i == count) {
            if (child != -11) return 28;
        } else {
            if (child < 0) return 28;
            children[i] = child;
        }
    }
    if (simple(3, ends[0]) || simple(3, ends[1])) return 29;
    for (unsigned i = 0; i < count; ++i) {
        int status;
        if (call(61, children[i], (word)&status, 0, 0, 0, 0) != children[i] || status) return 29;
    }
    return 0;
}

static int check_thread(void) {
    int ends[2];
    if (simple(22, (word)ends)) return 5;
    pipe_write = ends[1];
    clear_tid = 1;
    parent_tid = 0;
    long child = clone_thread((word)(stack + sizeof(stack)), &parent_tid, &clear_tid, &tls);
    if (child <= 0 || parent_tid != child || simple(186, 0) != pid) return 6;
    const struct timespec distant = {__LONG_MAX__, 999999999};
    if (futex(&ready, 0x80, 1, 0) != -11 || futex(&ready, 0x89, 0, 0) != -22 ||
        futex_timed(&ready, 0x89, 0, 1, &distant)) return 7;
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

static int check_timeout(void) {
    const struct timespec past = {0, 0};
    const struct timespec bad_seconds = {-1, 0}, bad_nanos = {0, 1000000000};
    if (futex_timed(&timed_word, 0x89, 0, 1, &past) != -110 ||
        futex_timed(&timed_word, 0x189, 0, 1, &past) != -110 ||
        futex_timed(&timed_word, 0x89, 1, 1, &past) != -11 ||
        futex_timed(&timed_word, 0x89, 0, 0, &past) != -22 ||
        futex_timed(&timed_word, 0x89, 0, 1, &bad_seconds) != -22 ||
        futex_timed(&timed_word, 0x80, 0, 0, &bad_nanos) != -22 ||
        futex_timed(&timed_word, 0x89, 0, 1, (const struct timespec *)1) != -14) return 19;

    const unsigned operations[] = {0x80, 0x89, 0x189};
    for (unsigned i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        struct timespec before, after, timeout = {0, 20000000};
        unsigned op = operations[i];
        if (clock_time(1, &before)) return 20;
        if (op != 0x80) {
            if (clock_time(op == 0x189 ? 0 : 1, &timeout)) return 20;
            timeout.nanos += 20000000;
            if (timeout.nanos >= 1000000000) {
                ++timeout.seconds;
                timeout.nanos -= 1000000000;
            }
        }
        if (futex_timed(&timed_word, op, 0, 1, &timeout) != -110 || clock_time(1, &after) ||
            (after.seconds - before.seconds) * 1000000000 + after.nanos - before.nanos < 20000000)
            return 20;
    }
    return 0;
}

static int check_timeout_from_other_thread(void) {
    mode = 3;
    clear_tid = 1;
    result = 21;
    struct timespec timeout;
    if (clock_time(1, &timeout)) return 22;
    timeout.seconds += 2;
    if (clone_thread((word)(stack + sizeof(stack)), &parent_tid, &clear_tid, &tls) <= 0) return 22;
    long woke = futex_timed(&timed_word, 0x89, 0, 2, &timeout);
    if (woke && woke != -11) return 22;
    while (clear_tid) {
        long error = futex(&clear_tid, 0x109, 1, -1);
        if (error && error != -11) return 22;
    }
    mode = 0;
    return result;
}

static int check_cpu_clock(void) {
    const struct timespec timeout = {0, 60000000};
    volatile unsigned sleeping = 0;
    if (clock_time(3, (void *)1) != -14) return 36;
    long cpu_before = clock_ns(3), wall_before = clock_ns(1);
    if (cpu_before < 0 || wall_before < 0 ||
        futex_timed(&sleeping, 0x80, 0, 0, &timeout) != -110) return 36;
    long cpu_after = clock_ns(3), wall_after = clock_ns(1);
    if (wall_after - wall_before < 60000000 ||
        cpu_after < cpu_before || cpu_after - cpu_before >= (wall_after - wall_before) / 2)
        return 36;

    mode = 5;
    clear_tid = 1;
    if (clone_thread((word)(stack + sizeof(stack)), &parent_tid, &clear_tid, &tls) <= 0) return 37;
    while (clear_tid) {
        long error = futex(&clear_tid, 0x109, 1, -1);
        if (error && error != -11) return 37;
    }
    mode = 0;
    cpu_before = cpu_after;
    wall_before = wall_after;
    cpu_after = clock_ns(3);
    wall_after = clock_ns(1);
    if (wall_after - wall_before < 60000000 ||
        cpu_after < cpu_before || cpu_after - cpu_before >= (wall_after - wall_before) / 2)
        return 37;
    return 0;
}

static int check_elapsed_clocks(int guest) {
    const unsigned clocks[] = {4, 7, 6};
    long before[sizeof(clocks) / sizeof(clocks[0])];
    const struct timespec timeout = {0, 20000000};
    volatile unsigned sleeping = 0;
    for (unsigned i = 0; i < sizeof(clocks) / sizeof(clocks[0]); ++i) {
        if (clock_time(clocks[i], (void *)1) != -14) return 38;
        before[i] = clock_ns(clocks[i]);
        if (before[i] < 0) return 38;
    }
    if (futex_timed(&sleeping, 0x80, 0, 0, &timeout) != -110) return 38;
    for (unsigned i = 0; i < sizeof(clocks) / sizeof(clocks[0]); ++i) {
        long after = clock_ns(clocks[i]);
        if (after - before[i] < 10000000 ||
            (guest && clocks[i] == 6 && (before[i] % 1000000 || after % 1000000))) return 38;
    }
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

__attribute__((naked, noreturn)) static void invalid_stack_loop(void) {
    __asm__("movabs $0x4000000000000000,%rsp\n1: pause\njmp 1b");
}

static int check_invalid_irq_return(void) {
    char system[390];
    if (simple(63, (word)system)) return 43;
    if (system[0] != 'M') return 0;

    long child = simple(57, 0);
    if (!child) {
        /* Даже установленный обработчик нельзя вызвать с неканоническим RSP. */
        const word action[4] = {(word)invalid_stack_loop};
        if (call(13, 11, (word)action, 0, 8, 0, 0)) finish(60, 44);
        invalid_stack_loop();
    }
    int status;
    if (child < 0 || call(61, child, (word)&status, 0, 0, 0, 0) != child || status != 11) return 45;
    return 0;
}

__attribute__((noreturn)) void pthread_preemption(void) {
    mode = 6;
    clear_tid = 1;
    if (clone_thread((word)(stack + sizeof(stack)), &parent_tid, &clear_tid, &tls) <= 0)
        finish(231, 40);
    while (!__atomic_load_n(&preempt_started, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause");
    /* Потоки должны видеть разные значения XMM0 после переключения по IRQ. */
    word pattern = 0x543210fedcba9876ul, observed;
    __asm__ volatile("movq %0,%%xmm0" :: "r"(pattern) : "memory");
    __atomic_store_n(&preempt_stop, 1, __ATOMIC_RELEASE);
    while (clear_tid) {
        long error = futex(&clear_tid, 0x109, 1, -1);
        if (error && error != -11) finish(231, 41);
    }
    __asm__ volatile("movq %%xmm0,%0" : "=r"(observed) :: "memory");
    if (observed != pattern) finish(231, 42);
    int status = check_invalid_irq_return();
    if (status) finish(231, status);
    static const char marker[] = "Linux ELF64 pthread preemption probe\n";
    if (call(1, 1, (word)marker, sizeof(marker) - 1, 0, 0, 0) != sizeof(marker) - 1)
        finish(231, 42);
    finish(231, 0);
}

void _start(void) {
    pid = simple(39, 0);
    inherited_no_new_privs = simple(157, 39);
    char system[390];
    if (inherited_no_new_privs < 0 || inherited_no_new_privs > 1 || simple(63, (word)system) ||
        (system[0] == 'M' && inherited_no_new_privs)) finish(231, 17);
    int timed = check_timeout();
    if (!timed) timed = check_timeout_from_other_thread();
    if (!timed) timed = check_cpu_clock();
    if (!timed) timed = check_elapsed_clocks(system[0] == 'M');
    if (timed) finish(231, timed);
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
    int guest = system[0] == 'M';
    for (unsigned wave = 0; wave < 2; ++wave) {
        int status = check_thread_capacity(guest ? MAX_WORKERS : 12, guest);
        if (!status) status = check_process_capacity(guest ? MAX_CHILDREN : 10, guest);
        if (status) finish(231, status);
    }
    static const char marker[] = "Linux ELF64 pthread probe\n";
    if (call(1, 1, (word)marker, sizeof(marker) - 1, 0, 0, 0) != sizeof(marker) - 1) finish(231, 14);
    finish(231, 0);
}
