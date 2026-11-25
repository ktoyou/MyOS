#ifndef MYOS_X86_64_STORAGE_ALLOC_H
#define MYOS_X86_64_STORAGE_ALLOC_H

#include "../types.h"

void *storage64_alloc(uptr bytes);
void storage64_free(void *data);

#endif
