typedef unsigned long word;

struct iovec {
    void *base;
    word length;
};

struct msghdr {
    void *name;
    unsigned name_length;
    struct iovec *iov;
    word iov_count;
    void *control;
    word control_length;
    unsigned flags;
};

struct credentials {
    word length;
    int level, type, pid;
    unsigned uid, gid;
};

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

static long protect(word address, word protection) {
    return call(10, address, 4096, protection, 0, 0, 0);
}

static long wait_child(long pid, int *status, unsigned options) {
    return call(61, pid, (word)status, options, 0, 0, 0);
}

static long read_byte(long fd, char *byte) {
    return call(0, fd, (word)byte, 1, 0, 0, 0);
}

static long set_fs(const volatile word *base) {
    return call(158, 0x1002, (word)base, 0, 0, 0, 0);
}

static word read_fs(void) {
    word value;
    __asm__ volatile("mov %%fs:0,%0" : "=r"(value) : : "memory");
    return value;
}

static void set_xmm(word value) {
    __asm__ volatile("movq %0,%%xmm0" : : "r"(value) : "memory");
}

static word read_xmm(void) {
    word value;
    __asm__ volatile("movq %%xmm0,%0" : "=r"(value) : : "memory");
    return value;
}

static int check_process_turnover(void) {
    enum { CHILDREN = 24, ROUNDS = 3, FIRST_STATUS = 64 };
    for (unsigned round = 0; round < ROUNDS; ++round) {
        int ready[2], gate[2];
        if (call(22, (word)ready, 0, 0, 0, 0, 0) || call(22, (word)gate, 0, 0, 0, 0, 0)) return 33;

        long children[CHILDREN];
        char release[CHILDREN];
        for (unsigned i = 0; i < CHILDREN; ++i) {
            long child = call(57, 0, 0, 0, 0, 0, 0);
            if (!child) {
                char token;
                if (call(3, ready[0], 0, 0, 0, 0, 0) || call(3, gate[1], 0, 0, 0, 0, 0) ||
                    call(1, ready[1], (word)"r", 1, 0, 0, 0) != 1 || call(3, ready[1], 0, 0, 0, 0, 0) ||
                    read_byte(gate[0], &token) != 1 || token != 'g') finish(34);
                finish(FIRST_STATUS + round * CHILDREN + i);
            }
            if (child < 0) return 35;
            children[i] = child;
            release[i] = 'g';
        }

        /* Сначала все потомки сообщают о готовности, затем родитель открывает барьер. */
        if (call(3, ready[1], 0, 0, 0, 0, 0) || call(3, gate[0], 0, 0, 0, 0, 0)) return 36;
        for (unsigned i = 0; i < CHILDREN; ++i) {
            char token;
            if (read_byte(ready[0], &token) != 1 || token != 'r') return 37;
        }
        if (wait_child(-1, 0, 1) != 0 || call(3, ready[0], 0, 0, 0, 0, 0)) return 38;
        if (call(1, gate[1], (word)release, sizeof(release), 0, 0, 0) != sizeof(release) ||
            call(3, gate[1], 0, 0, 0, 0, 0)) return 39;

        for (unsigned i = CHILDREN; i > 0; --i) {
            long child = children[i - 1];
            int status;
            int expected = FIRST_STATUS + round * CHILDREN + i - 1;
            if (wait_child(child, &status, 0) != child || status != expected * 256) return 40;
        }
        if (wait_child(-1, 0, 1) != -10) return 41;
    }
    return 0;
}

static long probe(void) {
    const word xmm = 0x34edbc0191db5164ul;
    volatile word tls = 0xdead5149;
    volatile int child_tid = -13;
    long parent = call(39, 0, 0, 0, 0, 0, 0);
    long fd = call(319, (word)"fork-probe", 1, 0, 0, 0, 0);
    if (fd < 0 || call(77, fd, 4096, 0, 0, 0, 0) || set_fs(&tls)) return 1;
    long shared_address = call(9, 0, 4096, 3, 1, fd, 0);
    long private_address = call(9, 0, 12288, 3, 0x22, -1, 0);
    long sparse = call(9, 0, 32768, 0, 0x22, -1, 0);
    if (shared_address < 0 || private_address < 0 || sparse < 0) return 2;

    volatile char *shared = (void *)shared_address, *memory = (void *)private_address;
    shared[0] = 'a'; shared[1] = 'b'; shared[2] = 'c';
    memory[0] = 1; memory[4096] = 2; memory[8192] = 3;
    char byte;
    if (read_byte(fd, &byte) != 1 || byte != 'a' ||
        protect(private_address + 4096, 1) || protect(private_address + 8192, 0)) return 3;
    word mask = 1ul << 9;
    if (call(14, 2, (word)&mask, 0, 8, 0, 0)) return 4;
    int peers[2], enable = 1;
    if (call(53, 1, 5, 0, (word)peers, 0, 0) ||
        call(54, peers[0], 1, 16, (word)&enable, 4, 0)) return 5;
    set_xmm(xmm);
    long child = call(56, 0x1200011, 0, 0, (word)&child_tid, 0, 0);
    if (child < 0) return 6;
    if (!child) {
        long self = call(39, 0, 0, 0, 0, 0, 0);
        if (self != child_tid || self <= 0 || self == parent ||
            call(110, 0, 0, 0, 0, 0, 0) != parent ||
            call(112, 0, 0, 0, 0, 0, 0) != self ||
            call(112, 0, 0, 0, 0, 0, 0) != -1) finish(7);
        const volatile word child_tls = 0x053ced;
        if (read_fs() != tls || read_xmm() != xmm || set_fs(&child_tls) ||
            read_fs() != child_tls) finish(8);
        set_xmm(xmm + 1);
        word old_mask, empty_mask = 0;
        if (call(14, 2, (word)&empty_mask, (word)&old_mask, 8, 0, 0) || old_mask != mask ||
            call(3, peers[0], 0, 0, 0, 0, 0) || call(72, fd, 2, 0, 0, 0, 0)) finish(9);
        if (read_byte(fd, &byte) != 1 || byte != 'b' || memory[0] != 1 || memory[4096] != 2 ||
            protect(private_address + 4096, 3) || protect(private_address + 8192, 3) ||
            memory[8192] != 3) finish(10);
        memory[0] = 9; memory[4096] = 10; memory[8192] = 11;
        if (call(11, sparse, 4096, 0, 0, 0, 0) ||
            call(9, sparse, 4096, 3, 0x100022, -1, 0) != sparse) finish(11);
        if (call(3, fd, 0, 0, 0, 0, 0)) finish(12);
        shared[3] = 'd';
        if (call(1, peers[1], (word)"x", 1, 0, 0, 0) != 1) finish(13);
        finish(37);
    }
    int status = 0;
    if (call(3, peers[1], 0, 0, 0, 0, 0) || wait_child(child, &status, 0) != child) return 14;
    if (status != 37 * 256) return status >> 8 ?: 22;
    if (child_tid != -13 || read_fs() != tls || read_xmm() != xmm ||
        call(14, 2, 0, (word)&mask, 8, 0, 0) || mask != (1ul << 9)) return 23;
    if (call(72, fd, 1, 0, 0, 0, 0) != 1 || read_byte(fd, &byte) != 1 || byte != 'c' ||
        memory[0] != 1 || memory[4096] != 2 || protect(private_address + 8192, 1) ||
        memory[8192] != 3 || shared[3] != 'd' ||
        call(9, sparse, 4096, 3, 0x100022, -1, 0) != -17) return 15;
    struct iovec input = {&byte, 1};
    struct credentials credentials;
    struct msghdr msg = {.iov = &input, .iov_count = 1, .control = &credentials,
                         .control_length = sizeof(credentials)};
    if (call(47, peers[0], (word)&msg, 0, 0, 0, 0) != 1 || byte != 'x' ||
        msg.control_length != sizeof(credentials) || credentials.length != 28 ||
        credentials.pid != child || credentials.level != 1 || credentials.type != 2 ||
        read_byte(peers[0], &byte) || wait_child(-1, 0, 1) != -10) return 16;
    if (call(3, peers[0], 0, 0, 0, 0, 0) || call(3, fd, 0, 0, 0, 0, 0)) return 17;
    int turnover = check_process_turnover();
    if (turnover) return turnover;
    child = call(57, 0, 0, 0, 0, 0, 0);
    if (!child) finish(0);
    if (child < 0 || wait_child(child, (void *)1, 0) != -14 || wait_child(child, 0, 0) != -10)
        return 20;
    child = call(57, 0, 0, 0, 0, 0, 0);
    if (!child) __builtin_trap();
    if (child < 0 || wait_child(child, &status, 0) != child || (status & 0x7f) != 4) return 24;
    child = call(57, 0, 0, 0, 0, 0, 0);
    if (!child) {
        __asm__ volatile("int3");
        finish(27);
    }
    if (child < 0 || wait_child(child, &status, 0) != child || (status & 0x7f) != 5) return 27;
    word sigchld[4] = {1, 0, 0, 0};
    if (call(13, 17, (word)sigchld, 0, 8, 0, 0) ||
        wait_child(-0x7fffffff - 1, 0, 0) != -3) return 25;
    /* Число завершений с игнорируемым SIGCHLD превышает размер таблицы процессов. */
    for (unsigned i = 0; i < 72; ++i) {
        child = call(57, 0, 0, 0, 0, 0, 0);
        if (!child) finish(0);
        if (child < 0 || wait_child(child, &status, 0) != -10) return 26;
    }
    return 0;
}

__attribute__((noreturn)) void fork_oom(void) {
    const word size = 0x9000000, page = 4096;
    long address = call(9, 0, size, 3, 0x22, -1, 0);
    if (address < 0) finish(28);
    volatile char *bytes = (void *)address;
    for (word offset = 0; offset < size; offset += page) bytes[offset] = 0;
    bytes[0] = 0x22;
    bytes[size - 1] = 0x33;
    if (call(57, 0, 0, 0, 0, 0, 0) != -12 || wait_child(-1, 0, 1) != -10 ||
        bytes[0] != 0x22 || bytes[size - 1] != 0x33 ||
        call(11, address, size, 0, 0, 0, 0)) finish(29);
    address = call(9, 0, size, 1, 0x22, -1, 0);
    if (address < 0) finish(30);
    bytes = (void *)address;
    for (word offset = 0; offset < size; offset += page)
        if (bytes[offset]) finish(30);
    long child = call(57, 0, 0, 0, 0, 0, 0);
    if (!child) {
        if (call(10, address, size, 3, 0, 0, 0) != -12 || bytes[0] || bytes[size - 1] ||
            protect(address, 3) || protect(address + size - 4096, 3)) finish(31);
        bytes[0] = 0x44;
        bytes[size - 1] = 0x55;
        finish(0);
    }
    int status;
    if (child < 0 || wait_child(child, &status, 0) != child || status ||
        bytes[0] || bytes[size - 1] || call(11, address, size, 0, 0, 0, 0)) finish(32);
    finish(0);
}

__attribute__((noreturn)) void _start(void) {
    long status = probe();
    if (!status) {
        static const char message[] = "Linux ELF64 fork probe\n";
        if (call(1, 1, (word)message, sizeof(message) - 1, 0, 0, 0) != sizeof(message) - 1)
            status = 21;
    }
    finish(status);
}
