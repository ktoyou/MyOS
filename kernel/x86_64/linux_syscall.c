#include "linux_task.h"
#include "paging.h"
#include "build_info.h"

#define EFER   0xc0000080u
#define STAR   0xc0000081u
#define LSTAR  0xc0000082u
#define FMASK  0xc0000084u
#define ARCH_SET_FS  0x1002
#define ARCH_GET_FS  0x1003

extern void linux64_syscall_entry(void);

static void set_fs_base(uptr base) {
    /* Загрузка селектора может изменить базу FS. Записываем базу после селектора. */
    __asm__ volatile("mov %0,%%fs" : : "r"((u16)0) : "memory");
    linux64_wrmsr(LINUX64_FS_BASE, base);
}

static long linux_arch_prctl(i32 operation, uptr value) {
    if (operation == ARCH_SET_FS) {
        /* Linux оставляет последнюю каноническую страницу за пределами TASK_SIZE_MAX. */
        if (value >= X64_USER_TOP - PMM_PAGE_SIZE) return -1;
        set_fs_base(value);
        return 0;
    }
    if (operation == ARCH_GET_FS) {
        return paging64_put_user_u64(value, linux64_rdmsr(LINUX64_FS_BASE)) ? 0 : -14;
    }
    return -22;
}

bool linux64_enable_syscall(void) {
    u32 eax = 0x80000000u, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (eax < 0x80000001u) return false;
    eax = 0x80000001u;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (!(edx & (1u << 11))) return false;

    linux64_wrmsr(STAR, 0x08ull << 32);
    linux64_wrmsr(LSTAR, (uptr)linux64_syscall_entry);
    /* Вход работает на одном CPU с отключёнными маскируемыми прерываниями. */
    linux64_wrmsr(FMASK, (1u << 8) | (1u << 9) | (1u << 10) | (3u << 12) |
                         (1u << 14) | (1u << 16) | (1u << 18));
    linux64_wrmsr(EFER, linux64_rdmsr(EFER) | 1u);
    set_fs_base(0);
    return true;
}

static long linux_write(uptr fd, uptr address, uptr size) {
    if (fd != 1 && fd != 2) return -9;
    if (size > 0x7ffff000u) size = 0x7ffff000u;
    uptr written = 0;
    while (written < size) {
        const u8 *bytes = paging64_user_read(address);
        if (!bytes) return written ? (long)written : -14;
        uptr chunk = PMM_PAGE_SIZE - (address & (PMM_PAGE_SIZE - 1));
        if (chunk > size - written) chunk = size - written;
        for (uptr i = 0; i < chunk; ++i) kernel64_serial_char((char)bytes[i]);
        written += chunk;
        address += chunk;
    }
    return (long)written;
}

static long linux_uname(uptr address) {
    static const struct {
        char sysname[65], nodename[65], release[65], version[65], machine[65], domainname[65];
    } name = {
        .sysname = "MyOS", .nodename = "myos", .release = MYOS_VERSION,
        .version = "MyOS " MYOS_VERSION, .machine = "x86_64",
    };
    _Static_assert(sizeof(name) == 390, "Linux x86-64 uname size");
    return paging64_copy_to_user(address, &name, sizeof(name)) == sizeof(name) ? 0 : -14;
}

static long linux_getresid(u32 id, uptr real, uptr effective, uptr saved) {
    if (!paging64_put_user_u32(real, id) ||
        !paging64_put_user_u32(effective, id) ||
        !paging64_put_user_u32(saved, id)) return -14;
    return 0;
}

__attribute__((noreturn)) void linux64_invalid_return(void) {
    linux64_task_exception(13);
    static const char message[] = "Linux x86-64 invalid syscall return\r\n";
    for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
    for (;;) __asm__ volatile("cli; hlt");
}

long linux64_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2,
                    uptr arg3, uptr arg4, uptr arg5) {
    if (number == 1 && (arg0 == 1 || arg0 == 2)) return linux_write(arg0, arg1, arg2);
    if (number == 7) return linux64_poll(arg0, (u32)arg1, (i32)arg2);
    if (number == 9) return linux64_mmap(arg0, arg1, (u32)arg2, (u32)arg3, (i32)arg4, arg5);
    if (number == 10) return linux64_mprotect(arg0, arg1, arg2);
    if (number == 11) return linux64_munmap(arg0, arg1);
    if (number == 13) return linux64_rt_sigaction((i32)arg0, arg1, arg2, arg3);
    if (number == 14) return linux64_rt_sigprocmask((i32)arg0, arg1, arg2, arg3);
    if (number == 39) return linux64_current->process->pid; /* getpid */
    if (number == 186) return linux64_current->tid; /* gettid */
    if (number == 54 || number == 55)
        return linux64_sockopt(number == 55, (i32)arg0, (i32)arg1, (i32)arg2, arg3, arg4);
    if (number == 63) return linux_uname(arg0);
    const struct linux64_userns *ns = linux64_current->process->userns;
    if (number == 102 || number == 107) return linux64_visible_id(ns, false, LINUX64_UID);
    if (number == 104 || number == 108) return linux64_visible_id(ns, true, LINUX64_GID);
    if (number == 118) return linux_getresid(linux64_visible_id(ns, false, LINUX64_UID), arg0, arg1, arg2);
    if (number == 120) return linux_getresid(linux64_visible_id(ns, true, LINUX64_GID), arg0, arg1, arg2);
    if (number == 125 || number == 126) return linux64_capabilities(number == 126, arg0, arg1);
    if (number == 158) return linux_arch_prctl((i32)arg0, arg1);
    if (number == 202) return linux64_futex(arg0, (u32)arg1, (u32)arg2, arg3, (u32)arg5);
    if (number == 228) return linux64_clock_gettime((i32)arg0, arg1);
    if (number == 318) return linux64_getrandom(arg0, arg1, (u32)arg2);
    return linux64_file_syscall(number, arg0, arg1, arg2, arg3);
}
