#include "linux_x64_exec.h"

__attribute__((noreturn)) void exec_target(const word *stack, word rcx, word r11);

__asm__(
    ".text\n"
    ".global _start\n"
    "_start:\n"
    "mov %rsp,%rdi\n"
    "mov %rcx,%rsi\n"
    "mov %r11,%rdx\n"
    "call exec_target\n"
    "ud2\n"
);

__attribute__((noreturn)) void exec_target(const word *stack, word rcx, word r11) {
    if (((word)stack & 15) || rcx || r11) finish(31);
    const char *const *p = (void *)(stack + 1);
    if (stack[0] == 2) {
        if (!equal(p[0], "alternate-name") || !equal(p[1], "argument") || p[2] ||
            !p[3] || !equal(p[3], "EXEC_SMOKE=ready") || p[4]) finish(32);
        p += 5;
    } else {
        if (stack[0] != 1 || !p[0] || *p[0] || p[1] || p[2]) finish(33);
        p += 3;
    }
    const word *aux = (const word *)p;
    const char *execfn = 0;
    const unsigned char *random = 0;
    for (; aux[0]; aux += 2) {
        if (aux[0] == 31) execfn = (const char *)aux[1];
        if (aux[0] == 25) random = (const unsigned char *)aux[1];
    }
    if (!execfn || !equal(execfn, TARGET_PATH) || !random || (word)execfn == stack[1]) finish(34);
    unsigned char entropy = 0;
    for (unsigned i = 0; i < 16; ++i) entropy |= random[i];
    if (!entropy) finish(35);
    char link[4096];
    long n = sys(89, (word)"/proc/self/exe", (word)link, sizeof(link) - 1, 0, 0, 0);
    if (n < (long)sizeof(TARGET_FILE) || link[0] != '/') finish(36);
    link[n] = 0;
    if (link[n - sizeof(TARGET_FILE)] != '/' ||
        !equal(link + n - sizeof(TARGET_FILE) + 1, TARGET_FILE)) finish(37);

    word fs, mask, caught[4], ignored[4];
    if (sys(158, 0x1003, (word)&fs, 0, 0, 0, 0) || fs ||
        sys(14, 2, 0, (word)&mask, 8, 0, 0) || !(mask & (1ul << 9)) ||
        sys(13, 10, 0, (word)caught, 8, 0, 0) || caught[0] ||
        sys(13, 12, 0, (word)ignored, 8, 0, 0) || ignored[0] != 1) finish(38);
    if (sys(72, 3, 1, 0, 0, 0, 0) || sys(72, 4, 1, 0, 0, 0, 0) != -9 ||
        sys(9, PRIVATE_ADDRESS, 4096, 3, 0x100022, -1, 0) != PRIVATE_ADDRESS) finish(39);
    long shared = sys(9, 0, 4096, 3, 1, 3, 0);
    if (shared < 0) finish(40);
    struct exec_sync *sync = (void *)shared;
    sync->pid = sys(39, 0, 0, 0, 0, 0, 0);
    sync->ready = 1;
    while (!sync->ack) sys(24, 0, 0, 0, 0, 0, 0);
    finish(37);
}
