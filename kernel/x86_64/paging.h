#ifndef X86_64_PAGING_H
#define X86_64_PAGING_H

#include "pmm.h"

bool paging64_init(const struct boot_info *boot);

#endif
