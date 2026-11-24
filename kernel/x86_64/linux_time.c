#include "linux_task.h"
#include "paging.h"

#define PIT_HZ 1193182ul
#define PIT_COUNT 59659u
#define NS_PER_SECOND 1000000000ul
#define COARSE_CLOCK_STEP_NS 1000000ul

enum {
    CLOCK_REALTIME = 0, CLOCK_MONOTONIC = 1, CLOCK_THREAD_CPUTIME_ID = 3,
    CLOCK_MONOTONIC_RAW = 4, CLOCK_MONOTONIC_COARSE = 6, CLOCK_BOOTTIME = 7,
};

static u64 tsc_hz, tsc_start, last_elapsed;
static long rtc_epoch;
static u64 rtc_sample_ns;
static bool rtc_valid;

enum rtc_field {
    RTC_SECOND, RTC_MINUTE, RTC_HOUR, RTC_DAY, RTC_MONTH, RTC_YEAR, RTC_CENTURY,
    RTC_MODE, RTC_FIELD_COUNT,
};

static u8 cmos_read(u8 index) {
    outb(0x70, index);
    return inb(0x71);
}

static bool rtc_snapshot(u8 fields[RTC_FIELD_COUNT]) {
    static const u8 registers[RTC_FIELD_COUNT] = {0, 2, 4, 7, 8, 9, 0x32, 0x0b};
    if (cmos_read(0x0a) & 0x80) return false;
    for (unsigned field = 0; field < RTC_FIELD_COUNT; ++field)
        fields[field] = cmos_read(registers[field]);
    return !(cmos_read(0x0a) & 0x80);
}

static unsigned rtc_number(u8 value, bool binary) {
    if (binary) return value;
    if ((value >> 4) > 9 || (value & 15) > 9) return 0xff;
    return (value >> 4) * 10 + (value & 15);
}

static bool leap_year(unsigned year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static long days_before_year(unsigned year) {
    long previous = (long)year - 1;
    return previous * 365 + previous / 4 - previous / 100 + previous / 400;
}

static bool rtc_decode(const u8 fields[RTC_FIELD_COUNT], long *epoch) {
    const bool binary = fields[RTC_MODE] & 0x04;
    const bool hour24 = fields[RTC_MODE] & 0x02;
    const bool pm = fields[RTC_HOUR] & 0x80;
    unsigned second = rtc_number(fields[RTC_SECOND], binary);
    unsigned minute = rtc_number(fields[RTC_MINUTE], binary);
    unsigned hour = rtc_number(hour24 ? fields[RTC_HOUR] : fields[RTC_HOUR] & 0x7f, binary);
    unsigned day = rtc_number(fields[RTC_DAY], binary);
    unsigned month = rtc_number(fields[RTC_MONTH], binary);
    unsigned year = rtc_number(fields[RTC_YEAR], binary);
    unsigned century = rtc_number(fields[RTC_CENTURY], binary);
    if (fields[RTC_MODE] & 0x80 || second > 59 || minute > 59 ||
        month < 1 || month > 12 || year > 99) return false;
    if (hour24 ? hour > 23 : hour < 1 || hour > 12) return false;
    if (!hour24) hour = hour % 12 + (pm ? 12 : 0);
    /* На PC без регистра века двузначный год относится к диапазону 1970–2069. */
    if (century < 19 || century > 99) century = year >= 70 ? 19 : 20;
    year += century * 100;

    const unsigned month_days[] = {31, 28 + leap_year(year), 31, 30, 31, 30,
                                   31, 31, 30, 31, 30, 31};
    if (day < 1 || day > month_days[month - 1]) return false;
    long days = days_before_year(year) - days_before_year(1970) + day - 1;
    for (unsigned i = 0; i + 1 < month; ++i) days += month_days[i];
    *epoch = days * 86400 + hour * 3600 + minute * 60 + second;
    return true;
}

static bool rtc_read_epoch(long *epoch) {
    if (!(cmos_read(0x0d) & 0x80)) return false;
    /* Между чтениями календаря RTC может перейти на следующую секунду. */
    for (unsigned attempt = 0; attempt < 10000; ++attempt) {
        u8 first[RTC_FIELD_COUNT], second[RTC_FIELD_COUNT];
        if (!rtc_snapshot(first) || !rtc_snapshot(second)) continue;
        unsigned field = 0;
        while (field < RTC_FIELD_COUNT && first[field] == second[field]) ++field;
        if (field == RTC_FIELD_COUNT) return rtc_decode(second, epoch);
    }
    return false;
}

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
    /* RTC хранит UTC с точностью до секунды. Между показаниями ведём отсчёт от TSC. */
    rtc_valid = tsc_hz && rtc_read_epoch(&rtc_epoch) && linux64_monotonic_ns(&rtc_sample_ns);
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

bool linux64_clock_sample(bool realtime, long *seconds, u64 *nanoseconds) {
    if (realtime && !rtc_valid) return false;
    u64 nanos;
    if (!linux64_monotonic_ns(&nanos)) return false;
    if (realtime) nanos -= rtc_sample_ns;
    *seconds = (long)(nanos / NS_PER_SECOND) + (realtime ? rtc_epoch : 0);
    *nanoseconds = nanos % NS_PER_SECOND;
    return true;
}

long linux64_clock_gettime(i32 clock, uptr address) {
    long seconds;
    u64 nanos;
    switch (clock) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_RAW:
    case CLOCK_BOOTTIME:
        /* Ядро не корректирует ход монотонных часов и не поддерживает системный сон. */
        if (!linux64_clock_sample(clock == CLOCK_REALTIME, &seconds, &nanos)) return -5;
        break;
    case CLOCK_THREAD_CPUTIME_ID:
        if (!linux64_task_cpu_ns(&nanos)) return -5;
        seconds = (long)(nanos / NS_PER_SECOND);
        nanos %= NS_PER_SECOND;
        break;
    case CLOCK_MONOTONIC_COARSE:
        if (!linux64_clock_sample(false, &seconds, &nanos)) return -5;
        nanos -= nanos % COARSE_CLOCK_STEP_NS;
        break;
    default:
        return -22;
    }
    const u64 timespec[2] = {(u64)seconds, nanos};
    return paging64_copy_to_user(address, timespec, sizeof(timespec)) == sizeof(timespec) ? 0 : -14;
}

long linux64_gettimeofday(uptr timeval, uptr timezone) {
    if (timeval) {
        long seconds;
        u64 nanos;
        if (!linux64_clock_sample(true, &seconds, &nanos)) return -5;
        if (!paging64_put_user_u64(timeval, (u64)seconds) ||
            !paging64_put_user_u64(timeval + sizeof(u64), nanos / 1000)) return -14;
    }
    const i32 utc[2] = {0, 0};
    if (timezone && paging64_copy_to_user(timezone, utc, sizeof(utc)) != sizeof(utc)) return -14;
    return 0;
}
