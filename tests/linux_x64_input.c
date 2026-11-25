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

static int mouse_report(long fd, unsigned short type, unsigned short code, int value, int y) {
    struct input_event events[3];
    word count = y ? 3 : 2;
    if (call(0, fd, (word)events, count * sizeof(*events), 0) != (long)(count * sizeof(*events)) ||
        events[0].type != type || events[0].code != code || events[0].value != value)
        return 0;
    if (y && (events[1].type != 2 || events[1].code != 1 || events[1].value != y)) return 0;
    const struct input_event *sync = &events[count - 1];
    return !sync->type && !sync->code && !sync->value &&
        sync->seconds == events[0].seconds && sync->micros == events[0].micros;
}

static int check_mouse(void) {
    static const char path[] = "/dev/input/event1", keyboard_path[] = "/dev/input/event0";
    static const char ready[] = "PS2 mouse ready\n", moved[] = "PS2 mouse moved\n",
                      pressed[] = "PS2 mouse buttons down\n", released[] = "PS2 mouse buttons up\n",
                      wheel_up[] = "PS2 mouse wheel up\n", wheel_down[] = "PS2 mouse wheel down\n";
    long mouse = call(2, (word)path, NONBLOCK, 0, 0);
    long keys = call(2, (word)keyboard_path, NONBLOCK, 0, 0);
    long buttons = call(2, (word)path, NONBLOCK, 0, 0);
    struct input_event event;
    unsigned char bits[96];
    word stat[18];
    if (mouse < 3 || keys < 3 || buttons < 3 || call(2, (word)path, 1, 0, 0) != -13 ||
        call(5, mouse, (word)stat, 0, 0) || (stat[3] & 0170000) != 0020000 || stat[5] != 0xd41 ||
        call(8, mouse, 0, 0, 0) != -29 || call(17, mouse, (word)&event, sizeof(event), 0) != -29 ||
        call(0, mouse, (word)&event, sizeof(event), 0) != -11 ||
        call(16, mouse, 0x80084520, (word)bits, 0) != 8 || bits[0] != 7 ||
        call(16, mouse, 0x80604521, (word)bits, 0) != sizeof(bits) || bits[34] != 7 ||
        call(16, mouse, 0x80084522, (word)bits, 0) != 8 || bits[0] != 3 || bits[1] != 1 ||
        call(16, keys, 0x80084522, (word)bits, 0) != -25)
        return 5;

    long epoll = call(291, 0, 0, 0, 0);
    struct epoll_event watch = {.events = POLLIN, .data = 0x188};
    struct poll_entry poll = {.fd = (int)keys, .events = POLLIN};
    if (epoll < 3 || call(233, epoll, 1, mouse, (word)&watch) || !marker(ready, sizeof(ready) - 1) ||
        call(232, epoll, (word)&watch, 1, (word)-1) != 1 || watch.events != POLLIN || watch.data != 0x188 ||
        !mouse_report(mouse, 2, 0, -18, 11) || !mouse_report(buttons, 2, 0, -18, 11) ||
        call(7, (word)&poll, 1, (word)-1, 0) != 1 || poll.revents != POLLIN || !key_report(keys, KEY_A, 1) ||
        !marker(moved, sizeof(moved) - 1))
        return 6;

    poll.fd = (int)mouse;
    for (int down = 1; down >= 0; --down) {
        struct input_event report[6];
        word count = down ? 6 : 4;
        if (call(7, (word)&poll, 1, (word)-1, 0) != 1 || poll.revents != POLLIN ||
            call(0, mouse, (word)report, count * sizeof(*report), 0) != (long)(count * sizeof(*report)) ||
            call(16, buttons, 0x80604518, (word)bits, 0) != sizeof(bits) || bits[34] != (down ? 7 : 0) ||
            (down && !mouse_report(buttons, 2, 0, 4, -7)) ||
            call(0, buttons, (word)&event, sizeof(event), 0) != -11)
            return 7;
        for (unsigned i = 0; i < 3; ++i)
            if (report[i].type != 1 || report[i].code != 0x110 + i || report[i].value != down) return 8;
        if (down && (report[3].type != 2 || report[3].code != 0 || report[3].value != 4 ||
                     report[4].type != 2 || report[4].code != 1 || report[4].value != -7)) return 9;
        if (report[count - 1].type || report[count - 1].code || report[count - 1].value) return 9;
        if (down ? !marker(pressed, sizeof(pressed) - 1) : !marker(released, sizeof(released) - 1)) return 10;
    }
    if (!key_report(keys, KEY_A, 0) || call(72, mouse, 4, 0, 0) ||
        !mouse_report(mouse, 2, 8, 1, 0) || !marker(wheel_up, sizeof(wheel_up) - 1) ||
        !mouse_report(mouse, 2, 8, -1, 0) || !marker(wheel_down, sizeof(wheel_down) - 1))
        return 11;
    return 0;
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
    int result = check_mouse();
    call(60, result ? result : check_keyboard(), 0, 0, 0);
    __builtin_trap();
}
