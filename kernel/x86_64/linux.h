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
const struct linux64_file *linux64_get_file(i32 fd);
long linux64_file_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2, uptr arg3);
long linux64_mmap(uptr address, uptr length, u32 protection, u32 flags, i32 fd, uptr offset);
long linux64_mprotect(uptr address, uptr length, uptr protection);
long linux64_munmap(uptr address, uptr length);
uptr linux64_random_bytes(void *buffer, uptr length);
long linux64_getrandom(uptr address, uptr length, u32 flags);
void linux64_clock_init(void);
long linux64_clock_gettime(i32 clock, uptr address);
void linux64_reset_signals(void);
long linux64_rt_sigaction(i32 signal, uptr action, uptr previous, uptr sigset_size);
long linux64_rt_sigprocmask(i32 how, uptr set, uptr previous, uptr sigset_size);
bool linux64_enable_syscall(void);
void kernel64_serial_char(char ch);

#endif
