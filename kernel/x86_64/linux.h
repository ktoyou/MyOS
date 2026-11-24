#ifndef X86_64_LINUX_H
#define X86_64_LINUX_H

#include "../types.h"

typedef const void *(*linux64_resolve_interp)(const char *path, void *context, uptr *size);

bool linux64_run(const void *image, uptr size, linux64_resolve_interp resolve, void *context);
bool linux64_enable_syscall(void);
void kernel64_serial_char(char ch);

#endif
