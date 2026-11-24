#include "myos.h"

static volatile unsigned process_value = 23;
static _Thread_local volatile unsigned initialized = 17;
static _Alignas(64) _Thread_local volatile unsigned zeroed;

static unsigned thread_pointer(void) {
    unsigned base;
    __asm__ volatile("movl %%gs:0, %0" : "=r"(base));
    return base;
}

static int fresh(void) {
    return process_value == 23 && initialized == 17 && zeroed == 0 &&
           !((unsigned)&zeroed & 63) && thread_pointer() > (unsigned)&initialized;
}

static void worker(void *arg) {
    if (!fresh()) thread_exit(1);
    unsigned marker = (unsigned)arg;
    initialized = marker;
    zeroed = marker + 1;
    for (int i = 0; i < 6; i++) {
        sleep_ms(10);
        if (initialized != marker || zeroed != marker + 1) thread_exit(2);
    }
}

static int fail(const char *stage) {
    printf("TLS FAIL %s\n", stage);
    return 1;
}

int main(int argc, char **argv) {
    if (!fresh()) return fail("initial image");
    if (argc > 1) {
        puts("TLS PASS static image, threads, fork and exec");
        return 0;
    }
    void *tcb = (void *)(thread_pointer() & ~4095u);
    if (munmap(tcb, 4096) != -EINVAL || mprotect(tcb, 4096, PROT_READ) != -EINVAL)
        return fail("TLS mapping ownership");

    enum { THREADS = 8, STACK = 65536 };
    void *stacks[THREADS];
    int ids[THREADS];
    initialized = 123;
    zeroed = 456;
    for (unsigned i = 0; i < THREADS; i++) {
        stacks[i] = malloc(STACK);
        if (!stacks[i]) return fail("allocate stack");
        ids[i] = thread_create(worker, (void *)(i + 200), stacks[i], STACK);
        if (ids[i] < 0) return fail("create thread");
    }
    for (unsigned i = 0; i < THREADS; i++) {
        int status;
        if (thread_join(ids[i], &status) || status) return fail("thread isolation");
        free(stacks[i]);
    }
    if (initialized != 123 || zeroed != 456) return fail("main thread isolation");

    int child = fork();
    if (child < 0) return fail("fork");
    if (child == 0) {
        if (initialized != 123 || zeroed != 456) return fail("fork TLS");
        initialized = 42;
        zeroed = 99;
        return 0;
    }
    int status;
    if (waitpid(child, &status, 0) != child || status ||
        initialized != 123 || zeroed != 456) return fail("fork isolation");

    char *args[] = { argv[0], "after-exec", NULL };
    exec("/bin/tlscheck", args);
    return fail("exec");
}
