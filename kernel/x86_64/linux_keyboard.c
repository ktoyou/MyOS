#include "linux_keyboard.h"
#include "linux_task.h"
#include "paging.h"

enum {
    PS2_DATA = 0x60, PS2_STATUS = 0x64, PS2_COMMAND = 0x64,
    OUTPUT_FULL = 1, INPUT_FULL = 2, AUX_DATA = 0x20, BAD_DATA = 0xc0,
    PORT_LIMIT = 100000, POLL_LIMIT = 32, EVENT_COUNT = 128,
    EV_SYN = 0, EV_KEY = 1, SYN_REPORT = 0, SYN_DROPPED = 3,
    KEY_PAUSE = 119, KEY_BITMAP_SIZE = 96, EAGAIN = 11, EFAULT = 14, EINVAL = 22, ENOTTY = 25,
};

struct keyboard_event {
    long seconds, micros;
    u16 type, code;
    i32 value;
};

_Static_assert(sizeof(struct keyboard_event) == 24, "Linux x86-64 input_event");

static struct keyboard_event queue[EVENT_COUNT];
static uptr head;
static bool initialized, available, extended;
static unsigned pause_byte;
static u8 pressed[KEY_BITMAP_SIZE];

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

static bool read_reply(u8 *reply) {
    for (unsigned i = 0; i < PORT_LIMIT; ++i) {
        u8 status = inb(PS2_STATUS);
        if (status == 0xff) return false;
        if (!(status & OUTPUT_FULL)) continue;
        u8 byte = inb(PS2_DATA);
        if (!(status & (AUX_DATA | BAD_DATA))) {
            *reply = byte;
            return true;
        }
    }
    return false;
}

static bool keyboard_command(u8 command) {
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (!write_port(PS2_DATA, command)) return false;
        u8 reply = 0;
        for (unsigned i = 0; i < POLL_LIMIT; ++i) {
            if (!read_reply(&reply)) return false;
            if (reply == 0xfa) return true;
            if (reply == 0xfe) break;
        }
        if (reply != 0xfe) return false;
    }
    return false;
}

static void keyboard_init(void) {
    if (!write_port(PS2_COMMAND, 0xad) || !write_port(PS2_COMMAND, 0xa7)) return;
    for (unsigned i = 0; i < POLL_LIMIT && (inb(PS2_STATUS) & OUTPUT_FULL); ++i) inb(PS2_DATA);

    u8 config;
    if (!write_port(PS2_COMMAND, 0x20) || !read_reply(&config)) return;
    /* Прерывания i8042 отключены. Контроллер переводит набор 2 в скан-коды набора 1. */
    config = (config & ~3u) | 0x40u;
    if (!write_port(PS2_COMMAND, 0x60) || !write_port(PS2_DATA, config) ||
        !write_port(PS2_COMMAND, 0xae)) return;
    available = keyboard_command(0xf5) && keyboard_command(0xf0) &&
                keyboard_command(0x02) && keyboard_command(0xf4);
}

bool linux64_keyboard_available(void) {
    if (!initialized) {
        initialized = true;
        keyboard_init();
    }
    return available;
}

static struct keyboard_event make_event(u16 type, u16 code, i32 value) {
    long seconds = 0;
    u64 nanos = 0;
    if (!linux64_clock_sample(true, &seconds, &nanos)) linux64_clock_sample(false, &seconds, &nanos);
    return (struct keyboard_event){seconds, (long)(nanos / 1000), type, code, value};
}

static void key_event(u8 key, bool down) {
    if (!key) return;
    u8 bit = (u8)(1u << (key % 8));
    u8 *state = &pressed[key / 8];
    bool was_down = (*state & bit) != 0;
    if (!down && !was_down) return;
    if (down) *state |= bit;
    else *state &= (u8)~bit;
    struct keyboard_event event = make_event(EV_KEY, key, down ? (was_down ? 2 : 1) : 0);
    queue[head++ % EVENT_COUNT] = event;
    queue[head++ % EVENT_COUNT] = (struct keyboard_event){event.seconds, event.micros, EV_SYN, SYN_REPORT, 0};
}

static u8 base_key(u8 scan) {
    if (scan >= 1 && scan <= 0x53) return scan;
    if (scan >= 0x56 && scan <= 0x58) return scan;
    return scan == 0x54 ? 99 : 0;
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

static void poll_keyboard(void) {
    if (!available) return;
    for (unsigned i = 0; i < POLL_LIMIT; ++i) {
        u8 status = inb(PS2_STATUS);
        if (!(status & OUTPUT_FULL) || status == 0xff) break;
        u8 scan = inb(PS2_DATA);
        if (status & BAD_DATA) {
            extended = false;
            pause_byte = 0;
        } else if (!(status & AUX_DATA)) {
            handle_scan(scan);
        }
    }
}

uptr linux64_keyboard_cursor(void) {
    poll_keyboard();
    return head;
}

bool linux64_keyboard_ready(uptr cursor) {
    poll_keyboard();
    return cursor != head;
}

long linux64_keyboard_read(uptr *cursor, uptr address, uptr count) {
    const uptr size = sizeof(struct keyboard_event);
    if (!count) return 0;
    if (count < size) return -EINVAL;
    if (!linux64_keyboard_ready(*cursor)) return -EAGAIN;
    uptr copied = 0;
    while (count - copied >= size && *cursor != head) {
        bool lost = head - *cursor > EVENT_COUNT;
        struct keyboard_event event = lost ? make_event(EV_SYN, SYN_DROPPED, 0) : queue[*cursor % EVENT_COUNT];
        if (address >= X64_USER_TOP || copied > X64_USER_TOP - address ||
            paging64_copy_to_user(address + copied, &event, size) != size)
            return copied ? (long)copied : -EFAULT;
        *cursor = lost ? head - EVENT_COUNT : *cursor + 1;
        copied += size;
    }
    return (long)copied;
}

static long copy_ioctl(uptr address, u32 requested, const void *data, uptr size) {
    if (size > requested) size = requested;
    return paging64_copy_to_user(address, data, size) == size ? (long)size : -EFAULT;
}

long linux64_keyboard_ioctl(uptr *cursor, u32 request, uptr address) {
    static const u32 version = 0x010001;
    static const u16 id[] = {0x11, 1, 1, 1}; /* BUS_I8042 */
    static const char name[] = "MyOS PS/2 keyboard";
    static const u8 event_types[8] = { (1u << EV_SYN) | (1u << EV_KEY) };
    u32 size = (request >> 16) & 0x3fff;
    if (request == 0x80044501u) return copy_ioctl(address, size, &version, sizeof(version)) < 0 ? -EFAULT : 0;
    if (request == 0x80084502u) return copy_ioctl(address, size, id, sizeof(id)) < 0 ? -EFAULT : 0;
    if ((request & 0xc000ff00u) != 0x80004500u) return -ENOTTY;
    switch (request & 0xffu) {
    case 0x06: return copy_ioctl(address, size, name, sizeof(name));
    case 0x18: {
        poll_keyboard();
        long result = copy_ioctl(address, size, pressed, sizeof(pressed));
        /* После снимка состояния этому описанию нужны только новые переходы. */
        if (result >= 0) *cursor = head;
        return result;
    }
    case 0x20: return copy_ioctl(address, size, event_types, sizeof(event_types));
    case 0x21: {
        u8 keys[KEY_BITMAP_SIZE] = {0};
        keys[KEY_PAUSE / 8] |= (u8)(1u << (KEY_PAUSE % 8));
        for (unsigned i = 1; i < 128; ++i) {
            u8 base = base_key((u8)i), extended = extended_keys[i];
            if (base) keys[base / 8] |= (u8)(1u << (base % 8));
            if (extended) keys[extended / 8] |= (u8)(1u << (extended % 8));
        }
        return copy_ioctl(address, size, keys, sizeof(keys));
    }
    default: return -ENOTTY;
    }
}
