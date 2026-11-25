#include "xhci64.h"
#include "linux.h"
#include "paging.h"

enum {
    PCI_XHCI_CLASS = 0x0c0330, PCI_MEMORY = 2, PCI_MASTER = 4, PCI_INTX_DISABLE = 1 << 10,
    XHCI_MAP_LIMIT = 0x40000, NS_PER_MS = 1000000,
};

bool xhci64_map(const struct boot_info *boot, struct xhci64_resources *controller) {
    if (!boot_xhci_bar_valid(boot)) return false;
    const struct pci64_device pci = {
        .bus = (u8)(boot->xhci_bdf >> 8),
        .slot = (u8)((boot->xhci_bdf >> 3) & 31),
        .function = (u8)(boot->xhci_bdf & 7),
    };
    uptr base = boot_xhci_bar_address(boot);
    if (pci64_class(pci) != PCI_XHCI_CLASS || pci64_mmio_bar0(pci) != base) return false;
    u32 bytes = boot->xhci_bar_bytes;
    if (bytes > XHCI_MAP_LIMIT) bytes = XHCI_MAP_LIMIT;
    u16 original = pci64_command(pci);
    if (original == 0xffff) return false;
    volatile void *mmio = paging64_map_mmio(base, bytes);
    if (!mmio) return false;
    pci64_set_command(pci, original | PCI_MEMORY | PCI_INTX_DISABLE);
    if (!(pci64_command(pci) & PCI_MEMORY)) {
        pci64_set_command(pci, original);
        paging64_unmap_mmio(mmio, bytes);
        return false;
    }
    *controller = (struct xhci64_resources){pci, mmio, bytes, original};
    return true;
}

bool xhci64_bus_master(const struct xhci64_resources *controller, bool enabled) {
    u16 command = pci64_command(controller->pci);
    if (command == 0xffff) return false;
    u16 requested = enabled ? command | PCI_MASTER : command & ~PCI_MASTER;
    if (requested != command) pci64_set_command(controller->pci, requested);
    u16 confirmed = pci64_command(controller->pci);
    return confirmed != 0xffff && ((confirmed & PCI_MASTER) != 0) == enabled;
}

void xhci64_unmap(const struct xhci64_resources *controller, bool taken_over) {
    u16 command = controller->original_command;
    if (taken_over) command &= ~PCI_MASTER;
    pci64_set_command(controller->pci, command);
    (void)pci64_command(controller->pci);
    paging64_unmap_mmio(controller->mmio, controller->bytes);
}

void *xhci64_dma_alloc(void) {
    uptr physical = pmm64_alloc();
    return physical ? pmm64_pointer(physical) : NULL;
}

u32 xhci64_dma_address(const volatile void *pointer) {
    /* Страницы PMM находятся ниже 1 ГиБ и отображены в прямом окне ядра. */
    uptr offset = (uptr)pointer - X64_DIRECT_BASE;
    return offset < BOOT_MEMORY_LIMIT ? (u32)offset : 0;
}

void xhci64_dma_free(void *page) {
    u32 physical = xhci64_dma_address(page);
    if (physical) pmm64_free(physical);
}

u32 xhci64_ticks(void) {
    u64 nanos;
    return linux64_monotonic_ns(&nanos) ? (u32)(nanos / NS_PER_MS) : 0;
}

void xhci64_sleep_ms(unsigned ms) {
    u32 start = xhci64_ticks();
    while (xhci64_ticks() - start < ms) __asm__ volatile("pause");
}

static void serial_number(unsigned value, unsigned base) {
    static const char digits[] = "0123456789abcdef";
    char reverse[10];
    unsigned count = 0;
    do {
        reverse[count++] = digits[value % base];
        value /= base;
    } while (value);
    while (count) kernel64_serial_char(reverse[--count]);
}

void xhci64_log(const char *format, ...) {
    va_list values;
    va_start(values, format);
    while (*format) {
        if (*format == '%' && format[1]) {
            switch (*++format) {
            case 'u': serial_number(va_arg(values, unsigned), 10); break;
            case 'x': serial_number(va_arg(values, unsigned), 16); break;
            case 's': {
                const char *value = va_arg(values, const char *);
                while (*value) kernel64_serial_char(*value++);
                break;
            }
            default: kernel64_serial_char(*format); break;
            }
        } else {
            if (*format == '\n') kernel64_serial_char('\r');
            kernel64_serial_char(*format);
        }
        ++format;
    }
    va_end(values);
}
