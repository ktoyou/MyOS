#ifndef X86_64_LINUX_H
#define X86_64_LINUX_H

#include "../types.h"

bool linux64_run(const void *image, uptr size);
bool linux64_enable_syscall(void);
void kernel64_serial_char(char ch);

#endif
