#ifndef X86_64_PCI_H
#define X86_64_PCI_H

#include "../types.h"

struct pci64_device {
    u8 bus, slot, function;
};

bool pci64_find(u16 vendor, u16 device, u16 class_code, struct pci64_device *result);
uptr pci64_mmio_bar0(struct pci64_device device);
u16 pci64_command(struct pci64_device device);
void pci64_set_command(struct pci64_device device, u16 command);

#endif
