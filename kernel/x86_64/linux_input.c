#include "linux_input.h"
#include "linux_task.h"
#include "paging.h"
#include "xhci64.h"

enum {
    PS2_DATA = 0x60, PS2_STATUS = 0x64, PS2_COMMAND = 0x64,
    OUTPUT_FULL = 1, INPUT_FULL = 2, AUX_DATA = 0x20, BAD_DATA = 0xc0,
    PORT_LIMIT = 100000, POLL_LIMIT = 32, EVENT_COUNT = 128,
    EV_SYN = 0, EV_KEY = 1, EV_REL = 2, SYN_REPORT = 0, SYN_DROPPED = 3,
    REL_X = 0, REL_Y = 1, REL_WHEEL = 8, BTN_LEFT = 0x110,
    KEY_PAUSE = 119, KEY_BITMAP_SIZE = 96, BUS_USB = 3, BUS_I8042 = 0x11,
    EAGAIN = 11, EFAULT = 14, EINVAL = 22, ENOTTY = 25,
};

struct input_event {
    long seconds, micros;
    u16 type, code;
    i32 value;
};

_Static_assert(sizeof(struct input_event) == 24, "Linux x86-64 input_event");

static struct input_device {
    struct input_event queue[EVENT_COUNT];
    uptr head;
    u8 pressed[KEY_BITMAP_SIZE];
    bool available, usb, wheel;
} devices[LINUX64_INPUT_COUNT];

static bool initialized, usb_active, probing_usb, ps2_active, extended;
static unsigned pause_byte;
static u8 mouse_id, mouse_packet[4];
static unsigned mouse_byte;
static bool mouse_packet_bad;

static void handle_scan(u8 scan);

static void reset_scan(void) {
    extended = false;
    pause_byte = 0;
}

static const u8 extended_keys[128] = {
    [0x1c] = 96, [0x1d] = 97, [0x35] = 98, [0x37] = 99, [0x38] = 100,
    [0x46] = KEY_PAUSE, [0x47] = 102, [0x48] = 103, [0x49] = 104,
    [0x4b] = 105, [0x4d] = 106, [0x4f] = 107, [0x50] = 108, [0x51] = 109,
    [0x52] = 110, [0x53] = 111, [0x5b] = 125, [0x5c] = 126, [0x5d] = 127,
};

static bool write_port(u16 port, u8 value) {
    for (unsigned i = 0; i < PORT_LIMIT; ++i) {
        u8 status = inb(PS2_STATUS);
        if (status == 0xff) return false;
        if (!(status & INPUT_FULL)) {
            outb(port, value);
            return true;
        }
    }
    return false;
}

static bool read_reply(bool auxiliary, u8 *reply) {
    for (unsigned i = 0; i < PORT_LIMIT; ++i) {
        u8 status = inb(PS2_STATUS);
        if (status == 0xff) return false;
        if (!(status & OUTPUT_FULL)) continue;
        u8 byte = inb(PS2_DATA);
        if (!(status & BAD_DATA) && ((status & AUX_DATA) != 0) == auxiliary) {
            *reply = byte;
            return true;
        }
        const struct input_device *keyboard = &devices[LINUX64_INPUT_KEYBOARD];
        if (!(status & AUX_DATA) && keyboard->available && !keyboard->usb) {
            if (status & BAD_DATA) reset_scan();
            else handle_scan(byte);
        }
    }
    return false;
}

static bool device_command(bool auxiliary, u8 command) {
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (auxiliary && !write_port(PS2_COMMAND, 0xd4)) return false;
        if (!write_port(PS2_DATA, command)) return false;
        u8 reply = 0;
        for (unsigned i = 0; i < POLL_LIMIT; ++i) {
            if (!read_reply(auxiliary, &reply)) return false;
            if (reply == 0xfa) return true;
            if (reply == 0xfe) break;
        }
        if (reply != 0xfe) return false;
    }
    return false;
}

static bool mouse_init(void) {
    if (!write_port(PS2_COMMAND, 0xa8) || !device_command(true, 0xf5)) return false;
    /* Последовательность IntelliMouse включает четвёртый байт с колесом. */
    const u8 rates[] = {200, 100, 80};
    for (unsigned i = 0; i < sizeof(rates); ++i) {
        if (!device_command(true, 0xf3) || !device_command(true, rates[i])) break;
    }
    if (!device_command(true, 0xf2) || !read_reply(true, &mouse_id) ||
        (mouse_id != 0 && mouse_id != 3 && mouse_id != 4)) return false;
    return device_command(true, 0xf4);
}

static void ps2_init(void) {
    struct input_device *keyboard = &devices[LINUX64_INPUT_KEYBOARD];
    struct input_device *mouse = &devices[LINUX64_INPUT_MOUSE];
    if (keyboard->usb && mouse->usb) return;
    if (!write_port(PS2_COMMAND, 0xad) || !write_port(PS2_COMMAND, 0xa7)) return;
    for (unsigned i = 0; i < POLL_LIMIT && (inb(PS2_STATUS) & OUTPUT_FULL); ++i) inb(PS2_DATA);
    if (inb(PS2_STATUS) & OUTPUT_FULL) return;

    u8 config;
    if (!write_port(PS2_COMMAND, 0x20) || !read_reply(false, &config)) return;
    /* Прерывания i8042 отключены. Контроллер переводит набор 2 в скан-коды набора 1. */
    config = (config & ~3u) | 0x40u;
    if (!write_port(PS2_COMMAND, 0x60) || !write_port(PS2_DATA, config)) return;
    if (!keyboard->usb) {
        keyboard->available =
            write_port(PS2_COMMAND, 0xae) && device_command(false, 0xf5) && device_command(false, 0xf0) &&
            device_command(false, 0x02) && device_command(false, 0xf4);
        if (!keyboard->available) write_port(PS2_COMMAND, 0xad);
    }
    if (!mouse->usb) {
        mouse->available = mouse_init();
        mouse->wheel = mouse->available && mouse_id;
        if (!mouse->available) write_port(PS2_COMMAND, 0xa7);
    }
    ps2_active = (keyboard->available && !keyboard->usb) || (mouse->available && !mouse->usb);
}

static void select_device(struct input_device *device, bool usb) {
    device->available = device->usb = usb;
    if (usb) return;
    device->head = 0;
    for (unsigned i = 0; i < sizeof(device->pressed); ++i) device->pressed[i] = 0;
}

void linux64_input_init(const struct boot_info *boot) {
    if (initialized) return;
    initialized = true;
    /* Первый HID-отчёт может прийти во время перечисления устройств. */
    probing_usb = true;
    usb_active = xhci64_init(boot);
    probing_usb = false;

    struct xhci64_hid hid = {0};
    if (usb_active) hid = xhci64_hid_status();
    struct input_device *keyboard = &devices[LINUX64_INPUT_KEYBOARD];
    struct input_device *mouse = &devices[LINUX64_INPUT_MOUSE];
    select_device(keyboard, hid.keyboard);
    select_device(mouse, hid.mouse);
    mouse->wheel = hid.mouse && hid.wheel;
    ps2_init();
}

bool linux64_input_available(enum linux64_input_device device) {
    return devices[device].available;
}

static struct input_event make_event(u16 type, u16 code, i32 value) {
    long seconds = 0;
    u64 nanos = 0;
    if (!linux64_clock_sample(true, &seconds, &nanos)) linux64_clock_sample(false, &seconds, &nanos);
    return (struct input_event){seconds, (long)(nanos / 1000), type, code, value};
}

static void append_event(struct input_device *device, struct input_event time, u16 type, u16 code, i32 value) {
    device->queue[device->head++ % EVENT_COUNT] = (struct input_event){time.seconds, time.micros, type, code, value};
}

static bool set_pressed(struct input_device *device, u16 key, bool down) {
    u8 bit = (u8)(1u << (key % 8));
    u8 *state = &device->pressed[key / 8];
    bool was_down = (*state & bit) != 0;
    if (down) *state |= bit;
    else *state &= (u8)~bit;
    return was_down;
}

static void key_event(u8 key, bool down) {
    if (!key) return;
    struct input_device *device = &devices[LINUX64_INPUT_KEYBOARD];
    bool was_down = set_pressed(device, key, down);
    if (!down && !was_down) return;
    struct input_event event = make_event(EV_KEY, key, down ? (was_down ? 2 : 1) : 0);
    device->queue[device->head++ % EVENT_COUNT] = event;
    append_event(device, event, EV_SYN, SYN_REPORT, 0);
}

static u8 base_key(u8 scan) {
    if (scan >= 1 && scan <= 0x53) return scan;
    if (scan >= 0x56 && scan <= 0x58) return scan;
    return scan == 0x54 ? 99 : 0;
}

void linux64_input_usb_key(u16 scancode, bool down) {
    if (!probing_usb && !devices[LINUX64_INPUT_KEYBOARD].usb) return;
    u8 code = (u8)scancode;
    if (code & 0x80) return;
    if (scancode >> 8 == 0xe0) key_event(extended_keys[code], down);
    else if (scancode <= 0x7f) key_event(base_key(code), down);
}

static void handle_scan(u8 scan) {
    static const u8 pause[] = {0xe1, 0x1d, 0x45, 0xe1, 0x9d, 0xc5};
    if (pause_byte) {
        if (scan == pause[pause_byte]) {
            if (++pause_byte == sizeof(pause)) {
                pause_byte = 0;
                key_event(KEY_PAUSE, true);
                key_event(KEY_PAUSE, false);
            }
            return;
        }
        pause_byte = 0;
    }
    if (scan == 0xe1) {
        extended = false;
        pause_byte = 1;
        return;
    }
    if (scan == 0xe0) {
        extended = true;
        return;
    }
    u8 code = scan & 0x7f;
    u8 key = extended ? extended_keys[code] : base_key(code);
    extended = false;
    key_event(key, !(scan & 0x80));
}

static void mouse_event(u32 buttons, i32 x, i32 y, i32 wheel) {
    struct input_device *device = &devices[LINUX64_INPUT_MOUSE];
    uptr before = device->head;
    struct input_event time = make_event(EV_SYN, SYN_REPORT, 0);
    for (u16 button = 0; button < 3; ++button) {
        bool down = (buttons & (1u << button)) != 0;
        u16 key = BTN_LEFT + button;
        if (set_pressed(device, key, down) != down) append_event(device, time, EV_KEY, key, down);
    }
    if (x) append_event(device, time, EV_REL, REL_X, x);
    if (y) append_event(device, time, EV_REL, REL_Y, y);
    if (wheel) append_event(device, time, EV_REL, REL_WHEEL, wheel);
    if (device->head != before) append_event(device, time, EV_SYN, SYN_REPORT, 0);
}

void linux64_input_usb_mouse(u32 buttons, i32 dx, i32 dy, i32 wheel) {
    const struct input_device *mouse = &devices[LINUX64_INPUT_MOUSE];
    if (probing_usb || mouse->usb)
        mouse_event(buttons, dx, dy, probing_usb || mouse->wheel ? wheel : 0);
}

static void handle_mouse(u8 byte, bool bad) {
    if (!mouse_byte && !bad && !(byte & 8)) return;
    mouse_packet_bad |= bad;
    mouse_packet[mouse_byte++] = byte;
    if (mouse_byte < (mouse_id ? 4u : 3u)) return;
    mouse_byte = 0;
    if (mouse_packet_bad) {
        mouse_packet_bad = false;
        return;
    }

    u8 flags = mouse_packet[0];
    /* Переполнение портит только соответствующую ось. В evdev Y направлен вниз. */
    i32 x = (i32)mouse_packet[1] - ((flags << 4) & 0x100);
    i32 y = (i32)mouse_packet[2] - ((flags << 3) & 0x100);
    i32 wheel = 0;
    if (mouse_id) {
        wheel = mouse_id == 3 ? (i8)mouse_packet[3] : mouse_packet[3] & 15;
        if (mouse_id == 4 && (wheel & 8)) wheel -= 16;
    }
    mouse_event(flags, flags & 0x40 ? 0 : x, flags & 0x80 ? 0 : -y, -wheel);
}

static void poll_input(void) {
    if (usb_active) xhci64_poll();
    if (!ps2_active) return;
    const struct input_device *keyboard = &devices[LINUX64_INPUT_KEYBOARD];
    const struct input_device *mouse = &devices[LINUX64_INPUT_MOUSE];
    for (unsigned i = 0; i < POLL_LIMIT; ++i) {
        u8 status = inb(PS2_STATUS);
        if (!(status & OUTPUT_FULL) || status == 0xff) break;
        u8 byte = inb(PS2_DATA);
        if (status & AUX_DATA) {
            if (mouse->available && !mouse->usb) handle_mouse(byte, (status & BAD_DATA) != 0);
        } else if (keyboard->available && !keyboard->usb) {
            if (status & BAD_DATA) reset_scan();
            else handle_scan(byte);
        }
    }
}

void linux64_input_open(enum linux64_input_device device, struct linux64_input_cursor *cursor) {
    poll_input();
    *cursor = (struct linux64_input_cursor){.next = devices[device].head};
}

static bool pending(const struct input_device *device, struct linux64_input_cursor *cursor) {
    if (device->head - cursor->next > EVENT_COUNT) return true;
    /* Снимок кнопок заменяет их переходы, но не отменяет движение в том же отчёте. */
    while (cursor->next < cursor->keys_before) {
        const struct input_event *event = &device->queue[cursor->next % EVENT_COUNT];
        if (event->type != EV_KEY && (event->type != EV_SYN || cursor->report_started)) break;
        ++cursor->next;
    }
    return cursor->next != device->head;
}

bool linux64_input_ready(enum linux64_input_device device, const struct linux64_input_cursor *cursor) {
    poll_input();
    struct linux64_input_cursor next = *cursor;
    return pending(&devices[device], &next);
}

long linux64_input_read(enum linux64_input_device index, struct linux64_input_cursor *cursor,
                        uptr address, uptr count) {
    const uptr size = sizeof(struct input_event);
    if (!count) return 0;
    if (count < size) return -EINVAL;
    poll_input();
    const struct input_device *device = &devices[index];
    if (!pending(device, cursor)) return -EAGAIN;
    uptr head = device->head;
    uptr copied = 0;
    while (count - copied >= size && pending(device, cursor)) {
        bool lost = head - cursor->next > EVENT_COUNT;
        struct input_event event = lost ? make_event(EV_SYN, SYN_DROPPED, 0) : device->queue[cursor->next % EVENT_COUNT];
        if (address >= X64_USER_TOP || copied > X64_USER_TOP - address ||
            paging64_copy_to_user(address + copied, &event, size) != size)
            return copied ? (long)copied : -EFAULT;
        cursor->next = lost ? head - EVENT_COUNT : cursor->next + 1;
        cursor->report_started = event.type != EV_SYN || event.code != SYN_REPORT;
        copied += size;
    }
    return (long)copied;
}

static long copy_ioctl(uptr address, u32 requested, const void *data, uptr size) {
    if (size > requested) size = requested;
    return paging64_copy_to_user(address, data, size) == size ? (long)size : -EFAULT;
}

long linux64_input_ioctl(enum linux64_input_device index, struct linux64_input_cursor *cursor,
                         u32 request, uptr address) {
    static const u32 version = 0x010001;
    static const char ps2_keyboard[] = "MyOS PS/2 keyboard", ps2_mouse[] = "MyOS PS/2 mouse";
    static const char usb_keyboard[] = "MyOS USB HID keyboard", usb_mouse[] = "MyOS USB HID mouse";
    bool mouse = index == LINUX64_INPUT_MOUSE;
    const struct input_device *device = &devices[index];
    const u16 id[] = {device->usb ? BUS_USB : BUS_I8042, 1, 1, 1};
    u32 size = (request >> 16) & 0x3fff;
    if (request == 0x80044501u) return copy_ioctl(address, size, &version, sizeof(version)) < 0 ? -EFAULT : 0;
    if (request == 0x80084502u) return copy_ioctl(address, size, id, sizeof(id)) < 0 ? -EFAULT : 0;
    if ((request & 0xc000ff00u) != 0x80004500u) return -ENOTTY;
    switch (request & 0xffu) {
    case 0x06:
        if (device->usb)
            return mouse ? copy_ioctl(address, size, usb_mouse, sizeof(usb_mouse))
                         : copy_ioctl(address, size, usb_keyboard, sizeof(usb_keyboard));
        return mouse ? copy_ioctl(address, size, ps2_mouse, sizeof(ps2_mouse))
                     : copy_ioctl(address, size, ps2_keyboard, sizeof(ps2_keyboard));
    case 0x18: {
        poll_input();
        long result = copy_ioctl(address, size, device->pressed, sizeof(device->pressed));
        if (result >= 0) {
            if (mouse) {
                cursor->keys_before = device->head;
                pending(device, cursor);
            } else {
                cursor->next = device->head;
            }
        }
        return result;
    }
    case 0x20: {
        u8 event_types[8] = {(1u << EV_SYN) | (1u << EV_KEY)};
        if (mouse) event_types[0] |= 1u << EV_REL;
        return copy_ioctl(address, size, event_types, sizeof(event_types));
    }
    case 0x21: {
        u8 keys[KEY_BITMAP_SIZE] = {0};
        if (mouse) {
            keys[BTN_LEFT / 8] = 7;
            return copy_ioctl(address, size, keys, sizeof(keys));
        }
        keys[KEY_PAUSE / 8] |= (u8)(1u << (KEY_PAUSE % 8));
        for (unsigned i = 1; i < 128; ++i) {
            u8 base = base_key((u8)i), extended = extended_keys[i];
            if (base) keys[base / 8] |= (u8)(1u << (base % 8));
            if (extended) keys[extended / 8] |= (u8)(1u << (extended % 8));
        }
        return copy_ioctl(address, size, keys, sizeof(keys));
    }
    case 0x22: {
        if (!mouse) return -ENOTTY;
        u8 axes[8] = {(1u << REL_X) | (1u << REL_Y), device->wheel ? 1 : 0};
        return copy_ioctl(address, size, axes, sizeof(axes));
    }
    default: return -ENOTTY;
    }
}
