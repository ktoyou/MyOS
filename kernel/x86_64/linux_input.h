#ifndef MYOS_LINUX_X64_INPUT_H
#define MYOS_LINUX_X64_INPUT_H

#include "linux.h"

enum linux64_input_device {
    LINUX64_INPUT_KEYBOARD, LINUX64_INPUT_MOUSE, LINUX64_INPUT_COUNT,
};

struct linux64_input_cursor {
    uptr next, keys_before;
    bool report_started;
};

void linux64_input_init(const struct boot_info *boot);
void linux64_input_usb_key(u16 scancode, bool down);
void linux64_input_usb_mouse(u32 buttons, i32 dx, i32 dy, i32 wheel);
bool linux64_input_available(enum linux64_input_device device);
void linux64_input_open(enum linux64_input_device device, struct linux64_input_cursor *cursor);
bool linux64_input_ready(enum linux64_input_device device, const struct linux64_input_cursor *cursor);
long linux64_input_read(enum linux64_input_device device, struct linux64_input_cursor *cursor,
                        uptr address, uptr count);
long linux64_input_ioctl(enum linux64_input_device device, struct linux64_input_cursor *cursor,
                         u32 request, uptr address);

#endif
