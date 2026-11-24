#include "linux.h"
#include "paging.h"

enum {
    GRND_NONBLOCK = 1, GRND_RANDOM = 2, GRND_INSECURE = 4,
    EIO = 5, EAGAIN = 11, EFAULT = 14, EINVAL = 22,
};

static bool has_rdrand(void) {
    u32 eax = 0, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (eax < 1) return false;
    eax = 1;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return (ecx & (1u << 30)) != 0;
}

static bool random_word(u64 *word) {
    for (unsigned attempt = 0; attempt < 10; ++attempt) {
        bool ready;
        __asm__ volatile("rdrand %0" : "=r"(*word), "=@ccc"(ready));
        if (ready) return true;
    }
    return false;
}

uptr linux64_random_bytes(void *buffer, uptr length) {
    u8 *bytes = buffer;
    if (!length || !has_rdrand()) return 0;
    uptr filled = 0;
    while (filled < length) {
        u64 pair[2];
        /* Некоторые неисправные реализации возвращают одну константу при CF=1. */
        if (!random_word(&pair[0]) || !random_word(&pair[1]) || pair[0] == pair[1]) break;
        uptr chunk = length - filled;
        if (chunk > sizeof(pair)) chunk = sizeof(pair);
        for (uptr i = 0; i < chunk; ++i) bytes[filled + i] = ((const u8 *)pair)[i];
        filled += chunk;
    }
    return filled;
}

long linux64_getrandom(uptr address, uptr length, u32 flags) {
    if ((flags & ~(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE)) ||
        (flags & (GRND_RANDOM | GRND_INSECURE)) == (GRND_RANDOM | GRND_INSECURE))
        return -EINVAL;
    if (length > 0x7ffff000u) length = 0x7ffff000u;
    if (address >= X64_USER_TOP || length > X64_USER_TOP - address) return -EFAULT;
    uptr copied = 0;
    while (copied < length) {
        u8 buffer[128];
        uptr chunk = length - copied;
        if (chunk > sizeof(buffer)) chunk = sizeof(buffer);
        uptr ready = linux64_random_bytes(buffer, chunk);
        if (!ready) {
            if (copied) return (long)copied;
            return (flags & GRND_NONBLOCK) ? -EAGAIN : -EIO;
        }
        uptr written = paging64_copy_to_user(address + copied, buffer, ready);
        copied += written;
        if (written < ready) return copied ? (long)copied : -EFAULT;
        if (ready < chunk) break;
    }
    return (long)copied;
}
