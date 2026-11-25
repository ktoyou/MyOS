#ifndef X86_64_E1000_H
#define X86_64_E1000_H

#include "../types.h"

bool e1000_init(void);
bool e1000_link(void);
void e1000_mac(u8 out[6]);
bool e1000_send(const void *frame, u32 size);
u32 e1000_receive(void *frame, u32 capacity);

#endif
