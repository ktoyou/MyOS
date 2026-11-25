#ifndef X86_64_NET_BYTES_H
#define X86_64_NET_BYTES_H

#include "../types.h"

static inline u16 net_read16(const u8 *p) {
    return (u16)((u16)p[0] << 8 | p[1]);
}

static inline u32 net_read32(const u8 *p) {
    return (u32)net_read16(p) << 16 | net_read16(p + 2);
}

static inline void net_write16(u8 *p, u16 value) {
    p[0] = (u8)(value >> 8);
    p[1] = (u8)value;
}

static inline void net_write32(u8 *p, u32 value) {
    net_write16(p, (u16)(value >> 16));
    net_write16(p + 2, (u16)value);
}

#endif
