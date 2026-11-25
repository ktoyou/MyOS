#ifndef MYOS_LINUX_X64_KEYBOARD_H
#define MYOS_LINUX_X64_KEYBOARD_H

#include "linux.h"

bool linux64_keyboard_available(void);
uptr linux64_keyboard_cursor(void);
bool linux64_keyboard_ready(uptr cursor);
long linux64_keyboard_read(uptr *cursor, uptr address, uptr count);
long linux64_keyboard_ioctl(uptr *cursor, u32 request, uptr address);

#endif
