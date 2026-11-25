#ifndef X86_64_LINUX_SECCOMP_H
#define X86_64_LINUX_SECCOMP_H

#include "../types.h"

#define LINUX64_SECCOMP_KILL_PROCESS 0x80000000u
#define LINUX64_SECCOMP_KILL_THREAD  0x00000000u
#define LINUX64_SECCOMP_TRAP         0x00030000u
#define LINUX64_SECCOMP_ERRNO        0x00050000u
#define LINUX64_SECCOMP_USER_NOTIF   0x7fc00000u
#define LINUX64_SECCOMP_TRACE        0x7ff00000u
#define LINUX64_SECCOMP_LOG          0x7ffc0000u
#define LINUX64_SECCOMP_ALLOW        0x7fff0000u
#define LINUX64_SECCOMP_ACTION      0xffff0000u
#define LINUX64_SECCOMP_DATA        0x0000ffffu

struct linux64_frame;
struct linux64_seccomp_filter;

i32 linux64_seccomp_prepare(uptr program, bool permitted, struct linux64_seccomp_filter *previous,
                             struct linux64_seccomp_filter **output);
struct linux64_seccomp_filter *linux64_seccomp_retain(struct linux64_seccomp_filter *filter);
void linux64_seccomp_release(struct linux64_seccomp_filter *filter);
bool linux64_seccomp_ancestor(const struct linux64_seccomp_filter *ancestor,
                             const struct linux64_seccomp_filter *filter);
u32 linux64_seccomp_evaluate(const struct linux64_seccomp_filter *filter, const struct linux64_frame *frame);
i32 linux64_seccomp_action_available(uptr address);

#endif
