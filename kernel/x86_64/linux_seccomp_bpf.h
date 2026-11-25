#ifndef MYOS_X86_64_LINUX_SECCOMP_BPF_H
#define MYOS_X86_64_LINUX_SECCOMP_BPF_H

#include "../types.h"

#define LINUX64_BPF_MAX_INSNS 4096u

struct linux64_bpf_insn {
    u16 code;
    u8 jt, jf;
    u32 k;
};

struct linux64_seccomp_data {
    i32 nr;
    u32 arch;
    u64 instruction_pointer;
    u64 args[6];
};

_Static_assert(sizeof(struct linux64_bpf_insn) == 8 && __builtin_offsetof(struct linux64_bpf_insn, k) == 4,
               "Linux sock_filter ABI");
_Static_assert(sizeof(struct linux64_seccomp_data) == 64 &&
               __builtin_offsetof(struct linux64_seccomp_data, instruction_pointer) == 8 &&
               __builtin_offsetof(struct linux64_seccomp_data, args) == 16, "Linux seccomp_data ABI");

/* Вызывающий код проверяет копию из памяти ядра и сохраняет её неизменной. */
bool linux64_seccomp_bpf_validate(const struct linux64_bpf_insn *program, u32 count);
u32 linux64_seccomp_bpf_run(const struct linux64_bpf_insn *program, u32 count,
                           const struct linux64_seccomp_data *data);

#endif
