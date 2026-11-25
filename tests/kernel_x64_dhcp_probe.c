typedef unsigned long word;

static long call(word number, word first, word second, word third) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return (long)number;
}

__attribute__((noreturn)) void _start(void) {
    static const char ready[] = "DHCP guest ready\n";
    int status = 1;
    if (call(1, 1, (word)ready, sizeof(ready) - 1) == sizeof(ready) - 1) {
        /* Пустой poll оставляет единственную задачу спящей, пока ядро обслуживает сеть. */
        status = call(7, 0, 0, 25000) != 0;
    }
    call(60, status, 0, 0);
    __builtin_trap();
}
