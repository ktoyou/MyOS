#ifndef X86_64_LINUX_FB_H
#define X86_64_LINUX_FB_H

#include "framebuffer.h"

void linux64_fb_init(const struct gop64_surface *surface);
uptr linux64_fb_size(void);
long linux64_fb_ioctl(u32 request, uptr address);
long linux64_fb_io(bool write, uptr buffer, uptr count, uptr offset);

#endif
