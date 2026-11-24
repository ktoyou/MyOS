#ifndef X86_64_SEGMENTS_H
#define X86_64_SEGMENTS_H

#include "../types.h"

void segments64_init(void);
bool segments64_on_entry_stack(uptr frame);
__attribute__((noreturn)) void segments64_enter_user(uptr entry, uptr stack);

#endif
