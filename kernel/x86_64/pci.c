#include "pci.h"

enum { PCI_CONFIG_ADDRESS = 0xcf8, PCI_CONFIG_DATA = 0xcfc };

/* Обход и изменение конфигурации выполняются на одном CPU до запуска задач. */
static void select_register(struct pci64_device device, unsigned offset) {
    u32 address = 0x80000000u | (u32)device.bus << 16 | (u32)device.slot << 11 |
                  (u32)device.function << 8 | offset;
    __asm__ volatile("outl %0, %1" : : "a"(address), "Nd"((u16)PCI_CONFIG_ADDRESS) : "memory");
}

static u32 read_config(struct pci64_device device, unsigned offset) {
    u32 value;
    select_register(device, offset);
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"((u16)PCI_CONFIG_DATA) : "memory");
    return value;
}

bool pci64_find(u16 vendor, u16 device, u16 class_code, struct pci64_device *result) {
    u32 target = (u32)device << 16 | vendor;
    for (unsigned bus = 0; bus < 256; ++bus) {
        for (unsigned slot = 0; slot < 32; ++slot) {
            struct pci64_device address = {(u8)bus, (u8)slot, 0};
            u32 id = read_config(address, 0);
            if ((id & 0xffffu) == 0xffffu) continue;
            unsigned count = read_config(address, 0x0c) & (1u << 23) ? 8 : 1;
            for (unsigned fn = 0; fn < count; ++fn) {
                address.function = (u8)fn;
                if (fn) id = read_config(address, 0);
                if (id == target && (read_config(address, 8) >> 16) == class_code) {
                    *result = address;
                    return true;
                }
            }
        }
    }
    return false;
}

uptr pci64_mmio_bar0(struct pci64_device device) {
    u32 low = read_config(device, 0x10);
    if (low & 1) return 0;
    switch (low & 6) {
    case 0: return low & ~15u;
    case 4: return (uptr)read_config(device, 0x14) << 32 | (low & ~15u);
    default: return 0;
    }
}

u16 pci64_command(struct pci64_device device) {
    return (u16)read_config(device, 4);
}

void pci64_set_command(struct pci64_device device, u16 command) {
    select_register(device, 4);
    /* Запись слова сохраняет соседний регистр PCI Status с битами W1C. */
    outw(PCI_CONFIG_DATA, command);
}
