#include "linux.h"
#include "paging.h"

#define EFER   0xc0000080u
#define STAR   0xc0000081u
#define LSTAR  0xc0000082u
#define FMASK  0xc0000084u

extern void linux64_syscall_entry(void);

static void wrmsr(u32 reg, u64 value) {
    __asm__ volatile("wrmsr" : : "c"(reg), "a"((u32)value), "d"((u32)(value >> 32)) : "memory");
}

bool linux64_enable_syscall(void) {
    u32 eax = 0x80000000u, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (eax < 0x80000001u) return false;
    eax = 0x80000001u;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (!(edx & (1u << 11))) return false;

    wrmsr(STAR, 0x08ull << 32);
    wrmsr(LSTAR, (uptr)linux64_syscall_entry);
    /* Вход работает на одном CPU с отключёнными маскируемыми прерываниями. */
    wrmsr(FMASK, (1u << 8) | (1u << 9) | (1u << 10) | (3u << 12) |
                 (1u << 14) | (1u << 16) | (1u << 18));
    __asm__ volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(EFER));
    wrmsr(EFER, ((u64)edx << 32) | eax | 1u);
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

__attribute__((noreturn)) void linux64_invalid_return(void) {
    static const char message[] = "Linux x86-64 invalid syscall return\r\n";
    for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
    for (;;) __asm__ volatile("cli; hlt");
}

long linux64_syscall(uptr number, uptr arg0, uptr arg1, uptr arg2, uptr arg3) {
    if (number == 1) return linux_write(arg0, arg1, arg2);
    if (number == 60) {
        static const char message[] = "Linux x86-64 exit status=0x";
        static const char digits[] = "0123456789abcdef";
        for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
        kernel64_serial_char(digits[(arg0 >> 4) & 15u]);
        kernel64_serial_char(digits[arg0 & 15u]);
        kernel64_serial_char('\r');
        kernel64_serial_char('\n');
        for (;;) __asm__ volatile("cli; hlt");
    }
    return linux64_file_syscall(number, arg0, arg1, arg2, arg3);
}
