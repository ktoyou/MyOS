#ifndef X86_64_PAGING_H
#define X86_64_PAGING_H

#include "pmm.h"

bool paging64_init(const struct boot_info *boot);
void *paging64_user_page(uptr address);
bool paging64_user_code(uptr address, const u8 *code, uptr length);

#endif
