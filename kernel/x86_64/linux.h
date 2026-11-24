#ifndef X86_64_LINUX_H
#define X86_64_LINUX_H

#include "../types.h"

struct linux64_file {
    const u8 *bytes;
    uptr size;
    u64 inode;
};

struct linux64_file_source {
    bool (*lookup)(const void *context, const char *path, struct linux64_file *file);
    const void *context;
};

bool linux64_run(const void *image, uptr size, const struct linux64_file_source *source);
void linux64_use_files(const struct linux64_file_source *source);
long linux64_file_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2, uptr arg3);
bool linux64_enable_syscall(void);
void kernel64_serial_char(char ch);

#endif
