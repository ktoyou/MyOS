#include "linux.h"
#include "paging.h"

#define PIT_HZ 1193182ul
#define PIT_COUNT 59659u
#define NS_PER_SECOND 1000000000ul

static u64 tsc_hz, tsc_start, last_elapsed;

static u64 read_tsc(void) {
    u32 low, high;
    __asm__ volatile("lfence; rdtsc" : "=a"(low), "=d"(high) : : "memory");
    return ((u64)high << 32) | low;
}

static void cpuid(u32 leaf, u32 *a, u32 *b, u32 *c, u32 *d) {
    __asm__ volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "0"(leaf), "2"(0));
}

static u64 pit_tsc_frequency(void) {
    const u8 control = inb(0x61) & 3u;
    /* Канал 2 в режиме 0 даёт одиночный интервал около 50 мс без IRQ. */
    outb(0x61, 1u);
    outb(0x43, 0xb0);
    outb(0x42, PIT_COUNT & 0xff);
    u64 start = read_tsc();
    outb(0x42, PIT_COUNT >> 8);
    bool started = !(inb(0x61) & 0x20);
    bool finished = false;
    if (started) {
        for (u32 attempt = 0; attempt < 5000000; ++attempt) {
            if (!(inb(0x61) & 0x20)) continue;
            finished = true;
            break;
        }
    }
    u64 end = read_tsc();
    outb(0x61, control);
    if (!finished || end <= start || end - start > 1000000000ul) return 0;
    return (end - start) * PIT_HZ / PIT_COUNT;
}

void linux64_clock_init(void) {
    u32 a, b, c, d;
    cpuid(0, &a, &b, &c, &d);
    u32 max_leaf = a;
    if (max_leaf < 1) return;
    cpuid(1, &a, &b, &c, &d);
    if (!(d & (1u << 4))) return;
    u64 frequency = 0;
    if (max_leaf >= 0x15) {
        cpuid(0x15, &a, &b, &c, &d);
        if (a && b && c) frequency = (u64)c * b / a;
    }
    if (frequency < 1000000ul || frequency > 16000000000ul) {
        frequency = 0;
        for (unsigned i = 0; i < 3; ++i) {
            u64 sample = pit_tsc_frequency();
            if (sample < 1000000ul || sample > 16000000000ul) continue;
            if (!frequency || sample < frequency) frequency = sample;
        }
    }
    tsc_hz = frequency;
    tsc_start = read_tsc();
    last_elapsed = 0;
}

bool linux64_monotonic_ns(u64 *nanos) {
    if (!tsc_hz) return false;
    u64 current = read_tsc();
    u64 elapsed = current >= tsc_start ? current - tsc_start : 0;
    if (elapsed < last_elapsed) elapsed = last_elapsed;
    last_elapsed = elapsed;
    *nanos = (elapsed / tsc_hz) * NS_PER_SECOND + (elapsed % tsc_hz) * NS_PER_SECOND / tsc_hz;
    return true;
}

long linux64_clock_gettime(i32 clock, uptr address) {
    if (clock != 1) return -22; /* CLOCK_MONOTONIC */
    u64 nanos;
    if (!linux64_monotonic_ns(&nanos)) return -5;
    const u64 timespec[2] = {nanos / NS_PER_SECOND, nanos % NS_PER_SECOND};
    return paging64_copy_to_user(address, timespec, sizeof(timespec)) == sizeof(timespec) ? 0 : -14;
}
