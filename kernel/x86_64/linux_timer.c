#include "../acpi_smp.h"
#include "linux.h"
#include "paging.h"

enum {
    IA32_APIC_BASE = 0x1b,
    APIC_BASE_BSP = 1u << 8, APIC_BASE_X2 = 1u << 10, APIC_BASE_ENABLE = 1u << 11,
    X2APIC_FIRST_MSR = 0x800,
    APIC_VERSION = 0x30, APIC_TPR = 0x80, APIC_EOI = 0xb0, APIC_SVR = 0xf0,
    APIC_ISR = 0x100, APIC_IRR = 0x200,
    APIC_LVT_CMCI = 0x2f0, APIC_LVT_TIMER = 0x320, APIC_LVT_THERMAL = 0x330,
    APIC_LVT_PERF = 0x340, APIC_LVT_LINT0 = 0x350, APIC_LVT_LINT1 = 0x360, APIC_LVT_ERROR = 0x370,
    APIC_INITIAL_COUNT = 0x380, APIC_CURRENT_COUNT = 0x390, APIC_DIVIDE = 0x3e0,
    APIC_SVR_ENABLE = 1u << 8, APIC_LVT_MASKED = 1u << 16, APIC_LVT_PERIODIC = 1u << 17,
    APIC_DIVIDE_16 = 3,
    PERIOD_NS = 10000000, CALIBRATION_NS = 2 * PERIOD_NS, CALIBRATION_SPINS = 2000000,
    RSDP_ARENA_OFFSET = 512, RSDP_MAX_BYTES = 256, MADT_ENTRIES_OFFSET = 44, MADT_IOAPIC = 1,
    IOAPIC_LIMIT = 16, IOAPIC_SELECT = 0, IOAPIC_DATA = 0x10,
    IOAPIC_ID = 0, IOAPIC_VERSION = 1, IOAPIC_REDIRECTION = 0x10,
    IOAPIC_MAX_REDIRECTION = (0xff - IOAPIC_REDIRECTION) / 2,
};

#define APIC_PHYSICAL_MASK 0x000ffffffffff000ull

static volatile u32 *lapic;
static bool x2apic, timer_ready;
static struct ioapic_location {
    u32 physical;
    u8 id;
} ioapics[IOAPIC_LIMIT];
static unsigned ioapic_count;
static bool ioapic_discovered;

static u32 little_endian_u32(const u8 *bytes) {
    return (u32)bytes[0] | (u32)bytes[1] << 8 | (u32)bytes[2] << 16 | (u32)bytes[3] << 24;
}

/* Таблицы ACPI не входят в прямое отображение RAM после смены CR3. */
static const void *boot_acpi_map(u32 physical, u32 bytes, unsigned slot, void *context) {
    (void)slot;
    const struct boot_info *boot = context;
    u64 end = (u64)physical + bytes;
    if (!bytes || end > (1ull << 32)) return NULL;
    if (physical == boot->rsdp && bytes <= RSDP_MAX_BYTES) return (const void *)(uptr)physical;

    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    for (u32 i = 0; i < boot->map_count; ++i) {
        /* Типы ACPI Reclaim и ACPI NVS в карте, переданной UEFI. */
        if ((map[i].type == 3 || map[i].type == 4) &&
            physical >= map[i].base && end <= map[i].base + map[i].length)
            return (const void *)(uptr)physical;
    }
    return NULL;
}

bool linux64_timer_probe_ioapic(const struct boot_info *boot) {
    ioapic_count = 0;
    ioapic_discovered = false;
    if (!boot_uefi(boot) || boot->arena_bytes < RSDP_ARENA_OFFSET + RSDP_MAX_BYTES ||
        (u64)boot->rsdp != (u64)boot->arena_phys + RSDP_ARENA_OFFSET)
        return false;
    struct acpi_smp_info info;
    /* Сведения о процессорах не нужны для маскирования внешних входов. */
    if (acpi_smp_discover(boot->rsdp, 0, boot_acpi_map, (void *)boot, &info) != ACPI_SMP_OK)
        return false;
    const u8 *madt = boot_acpi_map(info.madt, MADT_ENTRIES_OFFSET, ACPI_SMP_CHILD_SLOT, (void *)boot);
    if (!madt) return false;
    u32 length = little_endian_u32(madt + 4);
    madt = boot_acpi_map(info.madt, length, ACPI_SMP_CHILD_SLOT, (void *)boot);
    if (!madt || length < MADT_ENTRIES_OFFSET || length > ACPI_SMP_TABLE_MAX) return false;

    for (u32 offset = MADT_ENTRIES_OFFSET; offset < length;) {
        if (length - offset < 2) return false;
        const u8 *entry = madt + offset;
        u32 size = entry[1];
        if (size < 2 || size > length - offset) return false;
        if (entry[0] == MADT_IOAPIC) {
            if (size < 12 || ioapic_count == IOAPIC_LIMIT) return false;
            u32 physical = little_endian_u32(entry + 4);
            if (physical < BOOT_MEMORY_LIMIT || (physical & (PMM_PAGE_SIZE - 1))) return false;
            for (unsigned i = 0; i < ioapic_count; ++i)
                if (ioapics[i].physical == physical) return false;
            ioapics[ioapic_count++] = (struct ioapic_location){.physical = physical, .id = entry[2]};
        }
        offset += size;
    }
    ioapic_discovered = true;
    return true;
}

static u64 read_msr(u32 number) {
    u32 low, high;
    __asm__ volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(number) : "memory");
    return (u64)high << 32 | low;
}

static void write_msr(u32 number, u64 value) {
    __asm__ volatile ("wrmsr" : : "c"(number), "a"((u32)value), "d"((u32)(value >> 32)) : "memory");
}

static u32 apic_read(u32 reg) {
    return x2apic ? (u32)read_msr(X2APIC_FIRST_MSR + (reg >> 4)) : lapic[reg / sizeof(*lapic)];
}

static void apic_write(u32 reg, u32 value) {
    if (x2apic) write_msr(X2APIC_FIRST_MSR + (reg >> 4), value);
    else lapic[reg / sizeof(*lapic)] = value;
}

static void mask_lvt(u32 reg) {
    apic_write(reg, apic_read(reg) | APIC_LVT_MASKED);
}

static u32 ioapic_read(volatile u32 *mapping, u32 reg) {
    mapping[IOAPIC_SELECT / sizeof(*mapping)] = reg;
    return mapping[IOAPIC_DATA / sizeof(*mapping)];
}

static bool mask_ioapic(const struct ioapic_location *controller) {
    volatile u32 *mapping = paging64_map_mmio(controller->physical, PMM_PAGE_SIZE);
    if (!mapping) return false;
    u32 version = ioapic_read(mapping, IOAPIC_VERSION);
    u32 max_entry = (version >> 16) & 0xffu;
    u32 id = ioapic_read(mapping, IOAPIC_ID) >> 24;
    bool masked = (version & 0xffu) >= 0x10 && (version & 0xffu) != 0xff &&
                  max_entry <= IOAPIC_MAX_REDIRECTION && id == controller->id;
    for (u32 input = 0; masked && input <= max_entry; ++input) {
        u32 reg = IOAPIC_REDIRECTION + 2 * input;
        u32 value = ioapic_read(mapping, reg);
        if (value & APIC_LVT_MASKED) continue;
        /* Сохраняем вектор, полярность и назначение аппаратного входа. */
        mapping[IOAPIC_DATA / sizeof(*mapping)] = value | APIC_LVT_MASKED;
        masked = (mapping[IOAPIC_DATA / sizeof(*mapping)] & APIC_LVT_MASKED) != 0;
    }
    paging64_unmap_mmio(mapping, PMM_PAGE_SIZE);
    return masked;
}

static void mask_inherited_interrupts(u32 max_lvt) {
    outb(0x21, 0xff);
    outb(0xa1, 0xff);

    /* Ненулевой вектор ошибки нужен до маскирования остальных источников. */
    apic_write(APIC_LVT_ERROR, APIC_LVT_MASKED | LINUX64_SPURIOUS_VECTOR);
    apic_write(APIC_LVT_TIMER, APIC_LVT_MASKED | LINUX64_TIMER_VECTOR);
    apic_write(APIC_INITIAL_COUNT, 0);
    mask_lvt(APIC_LVT_LINT0);
    mask_lvt(APIC_LVT_LINT1);
    if (max_lvt >= 4) mask_lvt(APIC_LVT_PERF);
    if (max_lvt >= 5) mask_lvt(APIC_LVT_THERMAL);
    if (max_lvt >= 6) mask_lvt(APIC_LVT_CMCI);
}

static bool interrupt_in_service(void) {
    for (u32 offset = 0; offset < 8 * 0x10; offset += 0x10)
        if (apic_read(APIC_ISR + offset)) return true;
    return false;
}

static bool finish_inherited_interrupts(void) {
    /* Один EOI завершает старший вектор ISR. Векторы IRR примут установленные обработчики. */
    for (u32 attempt = 0; attempt < 256; ++attempt) {
        if (!interrupt_in_service()) return true;
        apic_write(APIC_EOI, 0);
    }
    return !interrupt_in_service();
}

static bool counter_sample(u64 *sample_ns, u32 *count) {
    u64 before, after;
    if (!linux64_monotonic_ns(&before)) return false;
    *count = apic_read(APIC_CURRENT_COUNT);
    if (!linux64_monotonic_ns(&after) || after < before || after - before > CALIBRATION_NS / 20)
        return false;
    *sample_ns = before + (after - before) / 2;
    return *count != 0;
}

static u32 calibrate(void) {
    u64 start, now;
    u32 initial;
    apic_write(APIC_INITIAL_COUNT, (u32)-1);
    if (!counter_sample(&start, &initial)) return 0;

    /* Таймер пока замаскирован; предел итераций действует и при остановившихся часах. */
    for (u32 attempt = 0; attempt < CALIBRATION_SPINS; ++attempt) {
        if (!linux64_monotonic_ns(&now) || now < start) return 0;
        if (now - start >= CALIBRATION_NS) {
            u32 current;
            if (!counter_sample(&now, &current) || now <= start || initial <= current) return 0;
            u64 elapsed = now - start;
            if (elapsed > 10u * CALIBRATION_NS) return 0;
            u64 counts = ((u64)(initial - current) * PERIOD_NS + elapsed / 2) / elapsed;
            return counts <= (u32)-1 ? (u32)counts : 0;
        }
        __asm__ volatile ("pause");
    }
    return 0;
}

bool linux64_timer_init(void) {
    __asm__ volatile ("cli" : : : "memory");
    if (timer_ready) return true;
    if (!ioapic_discovered) return false;

    u32 a, b, c, d;
    __asm__ volatile ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(1), "2"(0));
    if (!(d & (1u << 9))) return false;
    u64 sample;
    if (!linux64_monotonic_ns(&sample)) return false;

    u64 base = read_msr(IA32_APIC_BASE);
    if (!(base & APIC_BASE_BSP)) return false;
    x2apic = (base & APIC_BASE_X2) != 0;
    if (x2apic) {
        if (!(c & (1u << 21)) || !(base & APIC_BASE_ENABLE)) return false;
    } else {
        lapic = paging64_map_mmio(base & APIC_PHYSICAL_MASK, PMM_PAGE_SIZE);
        if (!lapic) return false;
        if (!(base & APIC_BASE_ENABLE)) write_msr(IA32_APIC_BASE, base | APIC_BASE_ENABLE);
    }

    u32 version = apic_read(APIC_VERSION);
    u32 max_lvt = (version >> 16) & 0xffu;
    if ((version & 0xffu) < 0x10 || (version & 0xffu) == 0xffu || max_lvt < 3) goto fail;
    mask_inherited_interrupts(max_lvt);
    for (unsigned i = 0; i < ioapic_count; ++i) {
        if (ioapics[i].physical == (base & APIC_PHYSICAL_MASK) || !mask_ioapic(&ioapics[i])) goto fail;
    }
    if (!finish_inherited_interrupts()) goto fail;
    /* Векторы исключений и ложный вектор не являются внешними IRQ. */
    if (apic_read(APIC_IRR) || (apic_read(APIC_IRR + 7 * 0x10) & (1u << 31))) goto fail;

    apic_write(APIC_TPR, 0);
    apic_write(APIC_SVR, APIC_SVR_ENABLE | LINUX64_SPURIOUS_VECTOR);
    apic_write(APIC_DIVIDE, APIC_DIVIDE_16);
    u32 counts = calibrate();
    apic_write(APIC_INITIAL_COUNT, 0);
    if (!counts) goto fail;

    apic_write(APIC_LVT_TIMER, APIC_LVT_PERIODIC | LINUX64_TIMER_VECTOR);
    apic_write(APIC_INITIAL_COUNT, counts);
    timer_ready = true;
    return true;

fail:
    if (lapic) {
        paging64_unmap_mmio(lapic, PMM_PAGE_SIZE);
        lapic = NULL;
    }
    return false;
}

void linux64_timer_ack(void) {
    if (timer_ready) apic_write(APIC_EOI, 0);
}
