typedef unsigned long word;

enum { KEY_A = 30, KEY_RIGHT = 106, POLLIN = 1, NONBLOCK = 0x800 };

struct input_event {
    long seconds, micros;
    unsigned short type, code;
    int value;
};

struct poll_entry { int fd; short events, revents; };
struct epoll_event { unsigned int events; word data; } __attribute__((packed));

static long call(word number, word first, word second, word third, word fourth) {
    register word arg4 __asm__("r10") = fourth;
    __asm__ volatile("syscall" : "+a"(number) : "D"(first), "S"(second), "d"(third), "r"(arg4)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static int marker(const char *message, word length) {
    return call(1, 1, (word)message, length, 0) == (long)length;
}

static int key_report(long fd, unsigned short code, int value) {
    struct input_event event[2];
    return call(0, fd, (word)event, sizeof(event), 0) == sizeof(event) &&
        event[0].type == 1 && event[0].code == code && event[0].value == value &&
        event[0].micros >= 0 && event[0].micros < 1000000 &&
        event[1].type == 0 && event[1].code == 0 && event[1].value == 0 &&
        event[1].seconds == event[0].seconds && event[1].micros == event[0].micros;
}

static int check_keyboard(void) {
    static const char path[] = "/dev/input/event0";
    static const char ready[] = "PS2 keyboard ready\n", down[] = "PS2 KEY_A down\n",
                      up[] = "PS2 KEY_A up\n", right[] = "PS2 KEY_RIGHT down\n",
                      done[] = "PS2 KEY_RIGHT up\n";
    long fd = call(2, (word)path, NONBLOCK, 0, 0);
    long mirror = call(2, (word)path, NONBLOCK, 0, 0);
    long snapshot = call(2, (word)path, NONBLOCK, 0, 0);
    long duplicate = call(32, fd, 0, 0, 0);
    struct input_event event;
    unsigned int version;
    unsigned char keys[96];
    keys[7] = keys[95] = 0xff;
    if (fd < 3 || mirror < 3 || snapshot < 3 || duplicate < 3 || call(2, (word)path, 1, 0, 0) != -13 ||
        call(0, fd, (word)&event, sizeof(event), 0) != -11 ||
        call(16, fd, 0x80044501, (word)&version, 0) || version != 0x010001 ||
        call(16, fd, 0x80084520, (word)keys, 0) != 8 || keys[0] != 3 || keys[7] ||
        call(16, fd, 0x80604521, (word)keys, 0) != sizeof(keys) || keys[95] ||
        !(keys[KEY_A / 8] & (1u << (KEY_A % 8))))
        return 1;

    struct poll_entry poll = {.fd = (int)fd, .events = POLLIN};
    if (call(7, (word)&poll, 1, 0, 0) || !marker(ready, sizeof(ready) - 1) ||
        call(7, (word)&poll, 1, (word)-1, 0) != 1 || poll.revents != POLLIN ||
        call(16, snapshot, 0x80604518, (word)keys, 0) != sizeof(keys) ||
        !(keys[KEY_A / 8] & (1u << (KEY_A % 8))) || call(0, snapshot, (word)&event, sizeof(event), 0) != -11 ||
        call(0, fd, 1, sizeof(event), 0) != -14 || !key_report(duplicate, KEY_A, 1) ||
        call(0, fd, (word)&event, sizeof(event), 0) != -11 || !key_report(mirror, KEY_A, 1) ||
        call(16, fd, 0x80604518, (word)keys, 0) != sizeof(keys) || !(keys[KEY_A / 8] & (1u << (KEY_A % 8))))
        return 2;

    long epoll = call(291, 0, 0, 0, 0);
    struct epoll_event watch = {.events = POLLIN, .data = 0x184};
    if (epoll < 3 || call(233, epoll, 1, fd, (word)&watch) || !marker(down, sizeof(down) - 1) ||
        call(232, epoll, (word)&watch, 1, (word)-1) != 1 || watch.events != POLLIN || watch.data != 0x184 ||
        !key_report(fd, KEY_A, 0) || !key_report(mirror, KEY_A, 0) ||
        call(16, fd, 0x80604518, (word)keys, 0) != sizeof(keys) || (keys[KEY_A / 8] & (1u << (KEY_A % 8))))
        return 3;

    long blocking = call(2, (word)path, 0, 0, 0);
    if (blocking < 3 || !marker(up, sizeof(up) - 1) || !key_report(blocking, KEY_RIGHT, 1) ||
        !marker(right, sizeof(right) - 1) || !key_report(blocking, KEY_RIGHT, 0) ||
        !marker(done, sizeof(done) - 1)) return 4;
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    call(60, check_keyboard(), 0, 0, 0);
    __builtin_trap();
}
