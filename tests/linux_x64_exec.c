#include "linux_x64_exec.h"

extern long clone_exec(word stack, unsigned empty_argv);
__attribute__((noreturn)) void child_exec(unsigned empty_argv);
__attribute__((noreturn)) void exec_shared(word argc);
__attribute__((noreturn)) void exec_self(const word *stack);

__asm__(
    ".text\n"
    "clone_exec:\n"
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
    "call child_exec\n"
    "ud2\n"
    "1: ret\n"
    ".global exec_shared_entry\n"
    "exec_shared_entry:\n"
    "mov (%rsp),%rdi\n"
    "call exec_shared\n"
    "ud2\n"
    ".global exec_self_entry\n"
    "exec_self_entry:\n"
    "mov %rsp,%rdi\n"
    "call exec_self\n"
    "ud2\n"
);

static char huge[131073];
static volatile unsigned failed_phase;

__attribute__((noreturn)) void child_exec(unsigned empty_argv) {
    const char *argv[] = {"alternate-name", "argument", 0};
    const char *envp[] = {"EXEC_SMOKE=ready", 0};
    if (sys(157, 39, 0, 0, 0, 0, 0) != 1) finish(45);
    if (empty_argv == 2) {
        word fs;
        if (sys(59, (word)"./linux-exec-bad.elf", (word)argv, 0, 0, 0, 0) != -8 ||
            sys(72, 4, 1, 0, 0, 0, 0) != 1 ||
            sys(158, 0x1003, (word)&fs, 0, 0, 0, 0) || !fs ||
            sys(157, 39, 0, 0, 0, 0, 0) != 1) finish(42);
        failed_phase = 1;
        sys(24, 0, 0, 0, 0, 0, 0);
        failed_phase = 2;
        finish(43);
    }
    long input = sys(2, (word)"/dev/null", 0x80000, 0, 0, 0, 0);
    if (input < 5 || sys(33, input, 0, 0, 0, 0, 0) ||
        sys(3, input, 0, 0, 0, 0, 0) || sys(72, 2, 2, 1, 0, 0, 0)) finish(44);
    sys(59, (word)TARGET_PATH, empty_argv ? 0 : (word)argv,
        empty_argv ? 0 : (word)envp, 0, 0, 0);
    finish(41);
}

static long bad_exec(void) {
    const char *bad[] = {(void *)1, 0};
    const char *large[] = {huge, 0};
    const char *argv[] = {"probe", 0};
    for (unsigned i = 0; i < sizeof(huge) - 1; ++i) huge[i] = 'a';
    if (sys(59, 1, 0, 0, 0, 0, 0) != -14 ||
        sys(59, (word)"./not-present", 1, 1, 0, 0, 0) != -2 ||
        sys(59, (word)"./linux-exec-bad.elf", (word)argv, 0, 0, 0, 0) != -8 ||
        sys(59, (word)TARGET_PATH, (word)bad, 0, 0, 0, 0) != -14 ||
        sys(59, (word)TARGET_PATH, (word)argv, 1, 0, 0, 0) != -14 ||
        sys(59, (word)TARGET_PATH, (word)large, 0, 0, 0, 0) != -7) return 2;
    return 0;
}

static long probe(void) {
    long initial = sys(157, 39, 0, 0, 0, 0, 0);
    if (initial < 0 || initial > 1 || sys(157, 38, 1ul << 32 | 1, 0, 0, 0, 0) != -22 ||
        sys(157, 38, 1, 1, 0, 0, 0) != -22 || sys(157, 38, 1, 0, 1, 0, 0) != -22 ||
        sys(157, 38, 1, 0, 0, 1, 0) != -22 || sys(157, 39, 1, 0, 0, 0, 0) != -22 ||
        sys(157, 39, 0, 1, 0, 0, 0) != -22 || sys(157, 39, 0, 0, 1, 0, 0) != -22 ||
        sys(157, 39, 0, 0, 0, 1, 0) != -22 || sys(157, 39, 0, 0, 0, 0, 0) != initial ||
        sys(157, 38, 1, 0, 0, 0, 0) || sys(157, 38, 1, 0, 0, 0, 0) ||
        sys(157, 38, 0, 0, 0, 0, 0) != -22 || sys(157, 39, 0, 0, 0, 0, 0) != 1) return 14;
    const word stack_size = 0x9000, tls = 0x128892;
    word mask = 1ul << 9, caught[] = {0x401000, 0, 0, 0}, ignored[] = {1, 0, 0, 0};
    long fd = sys(319, (word)"exec-state", 0, 0, 0, 0, 0);
    long cloexec = sys(319, (word)"exec-closed", 1, 0, 0, 0, 0);
    if (fd != 3 || cloexec != 4 || sys(77, fd, 4096, 0, 0, 0, 0) ||
        sys(158, 0x1002, (word)&tls, 0, 0, 0, 0) ||
        sys(14, 2, (word)&mask, 0, 8, 0, 0) ||
        sys(13, 10, (word)caught, 0, 8, 0, 0) ||
        sys(13, 12, (word)ignored, 0, 8, 0, 0)) return 1;
    char original[4096], after[4096];
    long n = sys(89, (word)"/proc/self/exe", (word)original, sizeof(original) - 1, 0, 0, 0);
    if (n <= 0) return 3;
    original[n] = 0;
    long error = bad_exec();
    if (error) return error;
    word fs;
    if (sys(72, cloexec, 1, 0, 0, 0, 0) != 1 ||
        sys(158, 0x1003, (word)&fs, 0, 0, 0, 0) || fs != (word)&tls ||
        sys(13, 10, 0, (word)caught, 8, 0, 0) || caught[0] != 0x401000 ||
        sys(157, 39, 0, 0, 0, 0, 0) != 1) return 4;
    long stack = sys(9, 0, stack_size, 3, 0x20022, -1, 0);
    long shared = sys(9, 0, 4096, 3, 1, fd, 0);
    if (stack < 0 || shared < 0 ||
        sys(9, PRIVATE_ADDRESS, 4096, 3, 0x100022, -1, 0) != PRIVATE_ADDRESS) return 5;
    volatile unsigned char *private = (void *)PRIVATE_ADDRESS;
    *private = 0x7a;
    struct exec_sync *sync = (void *)shared;
    if (exec_permitted_caps(sync->permitted)) return 15;
    for (unsigned i = 0; i < 3; ++i) {
        sync->ready = sync->ack = 0;
        sync->pid = 0;
        long pid = i < 2 ? clone_exec(stack + stack_size, i) : sys(57, 0, 0, 0, 0, 0, 0);
        if (!pid) child_exec(0);
        if (pid < 0) return 6;
        int status = 0;
        if (sys(61, pid, (word)&status, 1, 0, 0, 0) != 0) return status >> 8 ?: 7;
        sync->ack = 1;
        if (sys(61, pid, (word)&status, 0, 0, 0, 0) != pid || status != 37 * 256)
            return status >> 8 ?: 8;
        if (!sync->ready || sync->pid != pid || *private != 0x7a ||
            sys(72, cloexec, 1, 0, 0, 0, 0) != 1) return 9;
    }
    long failed = clone_exec(stack + stack_size, 2);
    int status;
    if (failed < 0 || failed_phase != 2 ||
        sys(61, failed, (word)&status, 0, 0, 0, 0) != failed || status != 43 * 256) return 13;
    long len = sys(89, (word)"/proc/self/exe", (word)after, sizeof(after) - 1, 0, 0, 0);
    if (len != n) return 10;
    after[len] = 0;
    return equal(original, after) ? 0 : 11;
}

__attribute__((noreturn)) void _start(void) {
    long status = probe();
    if (!status) {
        static const char marker[] = "Linux ELF64 execve probe\n";
        if (sys(1, 1, (word)marker, sizeof(marker) - 1, 0, 0, 0) != sizeof(marker) - 1) status = 12;
    }
    finish(status);
}

__attribute__((noreturn)) void exec_self(const word *stack) {
    static const char proc_exe[] = "/proc/self/exe";
    static const char proc_alias[] = "/proc/./self//exe";
    char actual[4096];
    long length = sys(89, (word)proc_exe, (word)actual, sizeof(actual), 0, 0, 0);
    if (length <= 0 || length >= (long)sizeof(actual)) finish(70);
    actual[length] = 0;
    const char *path = proc_exe, *stage = "first";
    if (stack[0] != 1) {
        const char *const *argv = (const void *)(stack + 1);
        if (stack[0] != 3 || stack[4] || stack[5] || !equal(actual, argv[2])) finish(71);
        const word *aux = stack + 6;
        for (; aux[0] && aux[0] != 31; aux += 2) {}
        if (!aux[0] || !equal((const char *)aux[1], argv[1])) finish(72);
        if (equal(argv[0], "second") && equal(argv[1], proc_alias)) finish(0);
        if (!equal(argv[0], "first") || !equal(argv[1], proc_exe)) finish(73);
        path = proc_alias;
        stage = "second";
    }
    const char *const argv[] = {stage, path, actual, 0};
    sys(59, (word)path, (word)argv, 0, 0, 0, 0);
    finish(74);
}

__attribute__((noreturn)) void exec_shared(word argc) {
    const word address = 0x50000000, tail = 52ul * 1024 * 1024;
    volatile unsigned char *bytes = (void *)address;
    if (bytes[0] != 0x29 || bytes[tail] != 0x63 || bytes[tail + 1]) finish(60);
    if (argc == 2) {
        if (sys(10, address, 4096, 7, 0, 0, 0) != -13 ||
            sys(10, address, 4096, 0, 0, 0, 0) || sys(10, address, 4096, 1, 0, 0, 0) ||
            bytes[0] != 0x29 || sys(10, address, 4096, 3, 0, 0, 0)) finish(61);
        bytes[0] = 0x5a;
        char byte;
        if (sys(1, 4, address, 1, 0, 0, 0) != 1 || sys(3, 4, 0, 0, 0, 0, 0) ||
            sys(0, 5, (word)&byte, 1, 0, 0, 0) || bytes[0] != 0x5a) finish(62);
        finish(0);
    }
    int ready[2], release[2];
    if (argc != 1 || sys(22, (word)ready, 0, 0, 0, 0, 0) ||
        sys(22, (word)release, 0, 0, 0, 0, 0) || ready[0] != 3 || ready[1] != 4 ||
        release[0] != 5 || release[1] != 6) finish(63);
    long children[3];
    for (unsigned i = 0; i < 3; ++i) {
        long pid = sys(57, 0, 0, 0, 0, 0, 0);
        if (pid < 0) finish(64);
        if (!pid) {
            if (sys(3, ready[0], 0, 0, 0, 0, 0) || sys(3, release[1], 0, 0, 0, 0, 0)) finish(64);
            const char *args[] = {"/myos/test.elf", "child", 0};
            sys(59, (word)args[0], (word)args, 0, 0, 0, 0);
            finish(65);
        }
        children[i] = pid;
    }
    if (sys(3, ready[1], 0, 0, 0, 0, 0) || sys(3, release[0], 0, 0, 0, 0, 0)) finish(66);
    for (unsigned i = 0; i < 3; ++i) {
        unsigned char byte;
        if (sys(0, ready[0], (word)&byte, 1, 0, 0, 0) != 1 || byte != 0x5a || bytes[0] != 0x29)
            finish(67);
    }
    if (sys(3, release[1], 0, 0, 0, 0, 0)) finish(68);
    for (unsigned i = 0; i < 3; ++i) {
        int status;
        if (sys(61, children[i], (word)&status, 0, 0, 0, 0) != children[i] || status) finish(69);
    }
    finish(0);
}

__attribute__((noreturn)) void exec_oom(void) {
    const word size = 0x9000000;
    long address = sys(9, 0, size, 3, 0x22, -1, 0);
    long fd = sys(319, (word)"exec-oom", 1, 0, 0, 0, 0);
    if (address < 0 || fd < 0) finish(50);
    volatile unsigned char *memory = (void *)address;
    memory[0] = 0xa1;
    memory[size - 1] = 0x2b;
    if (sys(59, (word)"./linux-exec-oom.elf", 0, 0, 0, 0, 0) != -12 ||
        sys(72, fd, 1, 0, 0, 0, 0) != 1 || memory[0] != 0xa1 || memory[size - 1] != 0x2b ||
        sys(11, address, size, 0, 0, 0, 0)) finish(51);
    long reused = sys(9, 0, size, 3, 0x22, -1, 0);
    if (reused < 0) finish(52);
    memory = (void *)reused;
    if (memory[0] || memory[size - 1]) finish(53);
    memory[size - 1] = 1;
    finish(memory[size - 1] == 1 ? 0 : 54);
}
