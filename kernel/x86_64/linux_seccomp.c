#include "linux_seccomp.h"
#include "linux_seccomp_bpf.h"
#include "linux_task.h"
#include "paging.h"
#include "pmm.h"

enum {
    ENOMEM = 12, EACCES = 13, EFAULT = 14, EINVAL = 22, EOPNOTSUPP = 95,
    MAX_PATH_INSNS = 32768, FILTER_COST = 4, AUDIT_ARCH_X86_64 = 0xc000003e,
};

struct sock_program {
    u16 length;
    uptr instructions;
};

struct linux64_seccomp_filter {
    struct linux64_seccomp_filter *previous;
    uptr physical;
    u32 pages, references, count, path_cost;
    struct linux64_bpf_insn instructions[];
};

_Static_assert(sizeof(struct sock_program) == 16 && __builtin_offsetof(struct sock_program, instructions) == 8,
               "Linux x86-64 sock_fprog ABI");

struct linux64_seccomp_filter *linux64_seccomp_retain(struct linux64_seccomp_filter *filter) {
    if (filter) ++filter->references;
    return filter;
}

void linux64_seccomp_release(struct linux64_seccomp_filter *filter) {
    while (filter && !--filter->references) {
        struct linux64_seccomp_filter *previous = filter->previous;
        uptr physical = filter->physical;
        u32 pages = filter->pages;
        for (u32 i = 0; i < pages; ++i) pmm64_free(physical + (uptr)i * PMM_PAGE_SIZE);
        filter = previous;
    }
}

bool linux64_seccomp_ancestor(const struct linux64_seccomp_filter *ancestor,
                             const struct linux64_seccomp_filter *filter) {
    if (!ancestor) return true;
    for (; filter; filter = filter->previous)
        if (filter == ancestor) return true;
    return false;
}

i32 linux64_seccomp_prepare(uptr address, bool permitted, struct linux64_seccomp_filter *previous,
                             struct linux64_seccomp_filter **output) {
    struct sock_program program;
    if (!address || paging64_copy_from_user(&program, address, sizeof(program)) != sizeof(program)) return -EFAULT;
    if (!program.length || program.length > LINUX64_BPF_MAX_INSNS) return -EINVAL;
    if (!permitted) return -EACCES;
    u32 cost = program.length + (previous ? previous->path_cost + FILTER_COST : 0);
    if (cost > MAX_PATH_INSNS) return -ENOMEM;

    uptr bytes = program.length * sizeof(struct linux64_bpf_insn);
    u32 pages = (sizeof(struct linux64_seccomp_filter) + bytes + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE;
    uptr physical = pmm64_alloc_contiguous(pages);
    if (!physical) return -ENOMEM;
    struct linux64_seccomp_filter *filter = pmm64_pointer(physical);
    *filter = (struct linux64_seccomp_filter){
        .physical = physical, .pages = pages, .references = 1,
        .count = program.length, .path_cost = cost,
    };
    /* Проверяем уже скопированную программу, которую потом исполняет ядро. */
    i32 result = 0;
    if (paging64_copy_from_user(filter->instructions, program.instructions, bytes) != bytes)
        result = -EFAULT;
    else if (!linux64_seccomp_bpf_validate(filter->instructions, filter->count))
        result = -EINVAL;
    if (result) {
        linux64_seccomp_release(filter);
        return result;
    }
    filter->previous = linux64_seccomp_retain(previous);
    *output = filter;
    return 0;
}

static bool known_action(u32 action) {
    switch (action) {
    case LINUX64_SECCOMP_KILL_PROCESS:
    case LINUX64_SECCOMP_KILL_THREAD:
    case LINUX64_SECCOMP_TRAP:
    case LINUX64_SECCOMP_ERRNO:
    case LINUX64_SECCOMP_USER_NOTIF:
    case LINUX64_SECCOMP_TRACE:
    case LINUX64_SECCOMP_LOG:
    case LINUX64_SECCOMP_ALLOW:
        return true;
    default:
        return false;
    }
}

u32 linux64_seccomp_evaluate(const struct linux64_seccomp_filter *filter, const struct linux64_frame *frame) {
    if (!filter) return LINUX64_SECCOMP_ALLOW;
    const struct linux64_seccomp_data data = {
        .nr = (i32)frame->rax, .arch = AUDIT_ARCH_X86_64, .instruction_pointer = frame->rip,
        .args = {frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9},
    };
    u32 result = LINUX64_SECCOMP_ALLOW;
    for (; filter; filter = filter->previous) {
        u32 next = linux64_seccomp_bpf_run(filter->instructions, filter->count, &data);
        u32 action = next & LINUX64_SECCOMP_ACTION;
        if (!known_action(action)) return LINUX64_SECCOMP_KILL_PROCESS;
        /* При равном действии данные берутся из наиболее нового фильтра. */
        if ((i32)action < (i32)(result & LINUX64_SECCOMP_ACTION)) result = next;
    }
    return result;
}

i32 linux64_seccomp_action_available(uptr address) {
    u32 action;
    if (!address || paging64_copy_from_user(&action, address, sizeof(action)) != sizeof(action)) return -EFAULT;
    switch (action) {
    case LINUX64_SECCOMP_KILL_PROCESS:
    case LINUX64_SECCOMP_KILL_THREAD:
    case LINUX64_SECCOMP_ERRNO:
    case LINUX64_SECCOMP_TRACE:
    case LINUX64_SECCOMP_ALLOW:
        return 0;
    default:
        return -EOPNOTSUPP;
    }
}
