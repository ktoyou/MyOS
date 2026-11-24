#ifndef X86_64_PMM_H
#define X86_64_PMM_H

#include "../bootinfo.h"

#define BOOT_MEMORY_LIMIT  0x40000000u
#define PMM_PAGE_SIZE      4096u

struct boot_region {
    u64 base, length;
    u32 type, attributes;
};

/* Однократная инициализация из проверенной карты до запуска других CPU. */
bool pmm64_init(const struct boot_info *boot);
uptr pmm64_alloc(void);
bool pmm64_free(uptr physical);

#endif
