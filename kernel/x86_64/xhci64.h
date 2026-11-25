#ifndef X86_64_XHCI64_H
#define X86_64_XHCI64_H

#include "pci.h"
#include "../bootinfo.h"

bool xhci64_init(const struct boot_info *boot);
void xhci64_poll(void);
bool xhci64_service(void);

struct xhci64_resources {
    struct pci64_device pci;
    volatile u8 *mmio;
    u32 bytes;
    u16 original_command;
};

bool xhci64_map(const struct boot_info *boot, struct xhci64_resources *controller);
bool xhci64_bus_master(const struct xhci64_resources *controller, bool enabled);
void xhci64_unmap(const struct xhci64_resources *controller, bool taken_over);
void *xhci64_dma_alloc(void);
void xhci64_dma_free(void *page);
u32 xhci64_dma_address(const volatile void *pointer);

void xhci64_worker_start(void (*entry)(void));
void xhci64_worker_step(void);
void xhci64_checkpoint(void);
u32 xhci64_ticks(void);
void xhci64_sleep_ms(unsigned ms);
void xhci64_log(const char *format, ...);

#endif
