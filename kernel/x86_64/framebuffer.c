#include "framebuffer.h"
#include "pmm.h"
#include "../../user/lib/video_mode.h"

extern const u8 _start[], __kernel_end[];

static bool overlaps(uptr first, uptr end, uptr base, uptr limit) {
    return base < limit && first < limit && base < end;
}

bool gop64_from_boot(const struct boot_info *boot, struct gop64_framebuffer *fb) {
    uptr base = boot->fb_phys;
    if (base < 0x100000 || (base & (PMM_PAGE_SIZE - 1)) || boot->bpp != 32 ||
        boot->pixel_order > 1 ||
        !video_geometry(boot->width, boot->height, boot->pitch, video_aperture(boot->fb_phys)))
        return false;
    uptr bytes = (uptr)boot->height * boot->pitch;
    uptr end = base + ((bytes + PMM_PAGE_SIZE - 1) & ~(uptr)(PMM_PAGE_SIZE - 1));
    if (end > (1ul << 32) ||
        overlaps(base, end, (uptr)_start, (uptr)__kernel_end) ||
        overlaps(base, end, boot->arena_phys, (uptr)boot->arena_phys + boot->arena_bytes) ||
        overlaps(base, end, boot->root_phys, (uptr)boot->root_phys + boot->root_bytes))
        return false;
    *fb = (struct gop64_framebuffer){
        .physical = base, .page_bytes = end - base,
        .surface = {(volatile u8 *)X64_FRAMEBUFFER_BASE, boot->width, boot->height,
                    boot->pitch, boot->pixel_order},
    };
    return true;
}

bool gop64_blit(const struct gop64_surface *surface, u32 x, u32 y,
                u32 width, u32 height, const u32 *pixels, u32 stride) {
    if (!pixels || x >= surface->width || y >= surface->height || stride < width ||
        width > surface->width - x || height > surface->height - y) return false;
    for (u32 row = 0; row < height; ++row) {
        volatile u32 *output = (volatile u32 *)(surface->pixels + (uptr)(y + row) * surface->pitch) + x;
        const u32 *input = pixels + (uptr)row * stride;
        for (u32 col = 0; col < width; ++col) {
            output[col] = video_pixel_order(input[col] & 0x00ffffffu, surface->pixel_order);
        }
    }
    return true;
}
