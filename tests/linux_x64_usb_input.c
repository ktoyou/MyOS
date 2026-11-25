typedef unsigned long word;

enum {
    BUS_USB = 0x03, BUS_I8042 = 0x11, O_NONBLOCK = 0x800, POLLIN = 1,
    EV_SYN = 0, EV_KEY = 1, EV_REL = 2, SYN_REPORT = 0,
    KEY_A = 30, BTN_LEFT = 0x110, REL_X = 0, REL_Y = 1, REL_WHEEL = 8,
    EVIOCGID = 0x80084502, EVIOCGBIT_KEYS = 0x80604521, EVIOCGBIT_REL = 0x80084522,
};

struct input_id { unsigned short bus, vendor, product, version; };
struct input_event {
    long seconds, micros;
    unsigned short type, code;
    int value;
};
struct event_value { unsigned short type, code; int value; };
struct poll_entry { int fd; short events, revents; };

_Static_assert(sizeof(struct input_id) == 8, "Linux input_id ABI");
_Static_assert(sizeof(struct input_event) == 24, "Linux x86-64 input_event ABI");

static long call(word number, word first, word second, word third) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return (long)number;
}

#define MARKER(message) (call(1, 1, (word)(message), sizeof(message) - 1) == sizeof(message) - 1)

static int has_bit(const unsigned char *bits, unsigned bit) {
    return (bits[bit / 8] >> (bit % 8)) & 1;
}

static int check_keyboard(long fd, unsigned bus) {
    struct input_id id;
    unsigned char keys[96];
    return fd >= 3 && !call(16, fd, EVIOCGID, (word)&id) && id.bus == bus &&
        call(16, fd, EVIOCGBIT_KEYS, (word)keys) == sizeof(keys) && has_bit(keys, KEY_A);
}

static int check_mouse(long fd, unsigned bus) {
    struct input_id id;
    unsigned char keys[96], relative[8];
    return fd >= 3 && !call(16, fd, EVIOCGID, (word)&id) && id.bus == bus &&
        call(16, fd, EVIOCGBIT_KEYS, (word)keys) == sizeof(keys) && has_bit(keys, BTN_LEFT) &&
        call(16, fd, EVIOCGBIT_REL, (word)relative) == sizeof(relative) &&
        has_bit(relative, REL_X) && has_bit(relative, REL_Y) && has_bit(relative, REL_WHEEL);
}

static int read_report(struct poll_entry *poll, unsigned fds, unsigned device,
                       const struct event_value *expected, unsigned count) {
    struct input_event events[4];
    if (call(7, (word)poll, fds, 10000) != 1 || poll[device].revents != POLLIN ||
        call(0, poll[device].fd, (word)events, sizeof(events)) != (long)((count + 1) * sizeof(*events)))
        return 0;
    if (events[0].seconds < 0 || events[0].micros < 0 || events[0].micros >= 1000000) return 0;
    for (unsigned i = 0; i < count; ++i)
        if (events[i].type != expected[i].type || events[i].code != expected[i].code ||
            events[i].value != expected[i].value || events[i].seconds != events[0].seconds ||
            events[i].micros != events[0].micros) return 0;
    const struct input_event *syn = &events[count];
    return syn->type == EV_SYN && syn->code == SYN_REPORT && syn->value == 0 &&
           syn->seconds == events[0].seconds && syn->micros == events[0].micros &&
           call(0, poll[device].fd, (word)events, sizeof(events)) == -11;
}

static int probe(void) {
    static const char mode_path[] = "/myos/usb-input-mode";
    static const char keyboard_path[] = "/dev/input/event0", mouse_path[] = "/dev/input/event1";
    char mode;
    long config = call(2, (word)mode_path, 0, 0);
    if (config < 3 || call(0, config, (word)&mode, 1) != 1 || call(3, config, 0, 0) ||
        (mode != 'u' && mode != 'k' && mode != 'm')) return 1;

    long keyboard = call(2, (word)keyboard_path, O_NONBLOCK, 0);
    long mouse = call(2, (word)mouse_path, O_NONBLOCK, 0);
    if (!check_keyboard(keyboard, BUS_USB)) return 2;
    if (mode == 'k' ? mouse != -2 : !check_mouse(mouse, mode == 'm' ? BUS_I8042 : BUS_USB)) return 3;
    struct poll_entry devices[] = {{(int)keyboard, POLLIN, 0}, {(int)mouse, POLLIN, 0}};
    unsigned device_count = mode == 'k' ? 1 : 2;
    static const struct event_value down[] = {{EV_KEY, KEY_A, 1}}, up[] = {{EV_KEY, KEY_A, 0}};
    if (call(7, (word)devices, device_count, 0) || !MARKER("USB input ready\n") ||
        !read_report(devices, device_count, 0, down, 1) || !MARKER("USB KEY_A down\n") ||
        !read_report(devices, device_count, 0, up, 1) || !MARKER("USB KEY_A up\n")) return 4;

    if (device_count == 2) {
        static const struct event_value motion[] = {{EV_REL, REL_X, -19}, {EV_REL, REL_Y, 13}},
            left_down[] = {{EV_KEY, BTN_LEFT, 1}}, left_up[] = {{EV_KEY, BTN_LEFT, 0}},
            wheel_up[] = {{EV_REL, REL_WHEEL, 1}}, wheel_down[] = {{EV_REL, REL_WHEEL, -1}};
        if (!read_report(devices, device_count, 1, motion, 2) || !MARKER("Input mouse moved\n")) return 5;
        if (!read_report(devices, device_count, 1, left_down, 1) ||
            !MARKER("Input BTN_LEFT down\n")) return 6;
        if (!read_report(devices, device_count, 1, left_up, 1) ||
            !MARKER("Input BTN_LEFT up\n")) return 7;
        if (!read_report(devices, device_count, 1, wheel_up, 1) ||
            !MARKER("Input REL_WHEEL up\n")) return 8;
        if (!read_report(devices, device_count, 1, wheel_down, 1) ||
            !MARKER("Input REL_WHEEL down\n")) return 9;
        if (mode == 'u' &&
            (!read_report(devices, device_count, 1, left_down, 1) || !MARKER("USB mouse held\n") ||
             !read_report(devices, device_count, 1, left_up, 1) || !MARKER("USB mouse removed\n"))) return 10;
        if (call(3, mouse, 0, 0)) return 11;
    }
    if (mode == 'u' &&
        (!read_report(devices, 1, 0, down, 1) || !MARKER("USB key held\n") ||
         !read_report(devices, 1, 0, up, 1) || !MARKER("USB keyboard removed\n"))) return 12;
    if (call(3, keyboard, 0, 0) || !MARKER("Linux x86-64 USB input PASS\n")) return 13;
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    call(60, probe(), 0, 0);
    __builtin_trap();
}
