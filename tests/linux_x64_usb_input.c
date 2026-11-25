typedef unsigned long word;

enum {
    BUS_USB = 0x03, BUS_I8042 = 0x11, O_NONBLOCK = 0x800, POLLIN = 1,
    EV_SYN = 0, EV_KEY = 1, EV_REL = 2, SYN_REPORT = 0,
    KEY_A = 30, BTN_LEFT = 0x110, REL_X = 0, REL_Y = 1, REL_WHEEL = 8,
    EVIOCGID = 0x80084502, EVIOCGBIT_KEYS = 0x80604521, EVIOCGBIT_REL = 0x80084522,
    CLOCK_MONOTONIC = 1, HOTPLUG_POLL_MS = 20, HOTPLUG_MAX_POLL_MS = 250,
};
enum { MISSING_INPUT = -2 };

struct input_id { unsigned short bus, vendor, product, version; };
struct input_event {
    long seconds, micros;
    unsigned short type, code;
    int value;
};
struct event_value { unsigned short type, code; int value; };
struct poll_entry { int fd; short events, revents; };
struct timespec { long seconds, nanos; };
struct sysinfo {
    unsigned char head[40];
    word freeram;
    unsigned char middle[56];
    unsigned mem_unit, pad;
};

static const char keyboard_path[] = "/dev/input/event0", mouse_path[] = "/dev/input/event1";
static const struct event_value down[] = {{EV_KEY, KEY_A, 1}}, up[] = {{EV_KEY, KEY_A, 0}},
    motion[] = {{EV_REL, REL_X, -19}, {EV_REL, REL_Y, 13}},
    left_down[] = {{EV_KEY, BTN_LEFT, 1}}, left_up[] = {{EV_KEY, BTN_LEFT, 0}};

_Static_assert(sizeof(struct input_id) == 8, "Linux input_id ABI");
_Static_assert(sizeof(struct input_event) == 24, "Linux x86-64 input_event ABI");
_Static_assert(__builtin_offsetof(struct sysinfo, freeram) == 40 &&
               __builtin_offsetof(struct sysinfo, mem_unit) == 104 && sizeof(struct sysinfo) == 112,
               "Linux x86-64 sysinfo ABI");

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

static word monotonic_ns(void) {
    struct timespec now;
    if (call(228, CLOCK_MONOTONIC, (word)&now, 0) || now.seconds < 0 ||
        now.nanos < 0 || now.nanos >= 1000000000L) return 0;
    return (word)now.seconds * 1000000000ul + (word)now.nanos;
}

static long hotplug_poll(struct poll_entry *device, word deadline) {
    /* Длинное перечисление не должно останавливать короткие тайм-ауты гостя. */
    word start = monotonic_ns();
    if (!start || start >= deadline) return -1;
    long ready = call(7, (word)device, device ? 1 : 0, HOTPLUG_POLL_MS);
    word end = monotonic_ns();
    if (!end || end < start || end - start > HOTPLUG_MAX_POLL_MS * 1000000ul) return -1;
    return ready;
}

static int open_hotplug_devices(struct poll_entry devices[2]) {
    word deadline = monotonic_ns() + 16000000000ul;
    unsigned heartbeats = 0;
    for (;;) {
        word before = monotonic_ns();
        if (hotplug_poll(0, deadline) != 0) return 0;
        ++heartbeats;
        if (devices[0].fd == MISSING_INPUT) devices[0].fd = (int)call(2, (word)keyboard_path, O_NONBLOCK, 0);
        if (devices[1].fd == MISSING_INPUT) devices[1].fd = (int)call(2, (word)mouse_path, O_NONBLOCK, 0);
        if (!before || monotonic_ns() - before > HOTPLUG_MAX_POLL_MS * 1000000ul) return 0;
        if (devices[0].fd >= 3 && devices[1].fd >= 3)
            return heartbeats >= 3 && check_keyboard(devices[0].fd, BUS_USB) &&
                   check_mouse(devices[1].fd, BUS_USB);
        if ((devices[0].fd < 3 && devices[0].fd != MISSING_INPUT) ||
            (devices[1].fd < 3 && devices[1].fd != MISSING_INPUT)) return 0;
    }
}

static int hotplug_report(struct poll_entry *device, const struct event_value *expected, unsigned count) {
    word deadline = monotonic_ns() + 16000000000ul;
    long ready;
    do { ready = hotplug_poll(device, deadline); } while (!ready);
    return ready == 1 && device->revents == POLLIN && read_report(device, 1, 0, expected, count);
}

static word free_ram(void) {
    struct sysinfo info;
    if (call(99, (word)&info, 0, 0) || info.mem_unit != 1) return 0;
    return info.freeram;
}

static int wait_free_ram(word baseline) {
    word deadline = monotonic_ns() + 5000000000ul;
    do {
        if (free_ram() == baseline) return 1;
    } while (hotplug_poll(0, deadline) == 0);
    return 0;
}

static int probe_hotplug(void) {
    struct poll_entry devices[] = {{MISSING_INPUT, POLLIN, 0}, {MISSING_INPUT, POLLIN, 0}};
    if (call(2, (word)keyboard_path, O_NONBLOCK, 0) != MISSING_INPUT ||
        call(2, (word)mouse_path, O_NONBLOCK, 0) != MISSING_INPUT) return 20;
    word baseline = free_ram();
    if (!baseline || !MARKER("USB hotplug empty controller\n")) return 20;
    if (!open_hotplug_devices(devices) || !MARKER("USB hotplug opened both devices\n")) return 21;
    if (!hotplug_report(&devices[0], down, 1) || !MARKER("USB hotplug key held\n")) return 22;
    if (!hotplug_report(&devices[1], left_down, 1) || !MARKER("USB hotplug button held\n")) return 23;
    if (!hotplug_report(&devices[0], up, 1) || !hotplug_report(&devices[1], left_up, 1) ||
        !MARKER("USB hotplug hub removal released key and button\n")) return 24;

    if (!hotplug_report(&devices[0], down, 1) || !MARKER("USB hotplug key reconnected\n") ||
        !hotplug_report(&devices[0], up, 1) || !MARKER("USB hotplug key up after reconnect\n")) return 25;
    if (!hotplug_report(&devices[1], motion, 2) || !MARKER("USB hotplug mouse reconnected\n") ||
        !hotplug_report(&devices[1], left_down, 1) || !MARKER("USB hotplug button down after reconnect\n") ||
        !hotplug_report(&devices[1], left_up, 1) || !check_keyboard(devices[0].fd, BUS_USB) ||
        !check_mouse(devices[1].fd, BUS_USB) || !MARKER("USB hotplug mouse up after reconnect\n")) return 26;
    if (!wait_free_ram(baseline) || !MARKER("USB hotplug DMA pages reclaimed\n")) return 27;
    if (call(3, devices[0].fd, 0, 0) || call(3, devices[1].fd, 0, 0) ||
        !MARKER("Linux x86-64 USB input PASS\n")) return 28;
    return 0;
}

static int probe(void) {
    static const char mode_path[] = "/myos/usb-input-mode";
    char mode;
    long config = call(2, (word)mode_path, 0, 0);
    if (config < 3 || call(0, config, (word)&mode, 1) != 1 || call(3, config, 0, 0)) return 1;
    if (mode == 'h') return probe_hotplug();
    if (mode != 'u' && mode != 'k' && mode != 'm') return 1;

    long keyboard = call(2, (word)keyboard_path, O_NONBLOCK, 0);
    long mouse = call(2, (word)mouse_path, O_NONBLOCK, 0);
    if (!check_keyboard(keyboard, BUS_USB)) return 2;
    if (mode == 'k' ? mouse != -2 : !check_mouse(mouse, mode == 'm' ? BUS_I8042 : BUS_USB)) return 3;
    struct poll_entry devices[] = {{(int)keyboard, POLLIN, 0}, {(int)mouse, POLLIN, 0}};
    unsigned device_count = mode == 'k' ? 1 : 2;
    if (call(7, (word)devices, device_count, 0) || !MARKER("USB input ready\n") ||
        !read_report(devices, device_count, 0, down, 1) || !MARKER("USB KEY_A down\n") ||
        !read_report(devices, device_count, 0, up, 1) || !MARKER("USB KEY_A up\n")) return 4;

    if (device_count == 2) {
        static const struct event_value wheel_up[] = {{EV_REL, REL_WHEEL, 1}},
            wheel_down[] = {{EV_REL, REL_WHEEL, -1}};
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
