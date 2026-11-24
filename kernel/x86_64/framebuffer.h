#ifndef X86_64_FRAMEBUFFER_H
#define X86_64_FRAMEBUFFER_H

#include "../bootinfo.h"

#define X64_FRAMEBUFFER_BASE 0xffffc00000000000ul

struct gop64_surface {
    volatile u8 *pixels;
    u32 width, height, pitch, pixel_order;
};

struct gop64_framebuffer {
    uptr physical, page_bytes;
    struct gop64_surface surface;
};

bool gop64_from_boot(const struct boot_info *boot, struct gop64_framebuffer *fb);
/* Источник хранит пиксели XRGB8888. Шаг источника задан в пикселях. */
bool gop64_blit(const struct gop64_surface *surface, u32 x, u32 y,
                u32 width, u32 height, const u32 *pixels, u32 stride);

#endif
