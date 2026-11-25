#include "linux_fb.h"
#include "paging.h"

enum {
    EFAULT = 14, ENOTTY = 25, EFBIG = 27, ENOSPC = 28,
    FBIOGET_VSCREENINFO = 0x4600, FBIOGET_FSCREENINFO = 0x4602,
    FB_VISUAL_TRUECOLOR = 2,
};

struct fb_fixed {
    char id[16];
    u64 smem_start;
    u32 smem_len, type, type_aux, visual;
    u16 xpanstep, ypanstep, ywrapstep, padding0;
    u32 line_length, padding1;
    u64 mmio_start;
    u32 mmio_len, accel;
    u16 capabilities, reserved[2], padding2;
};

struct fb_color {
    u32 offset, length, msb_right;
};

struct fb_variable {
    u32 xres, yres, xres_virtual, yres_virtual, xoffset, yoffset, bits_per_pixel, grayscale;
    struct fb_color red, green, blue, transp;
    u32 nonstd, activate, height, width, accel_flags;
    u32 pixclock, left_margin, right_margin, upper_margin, lower_margin;
    u32 hsync_len, vsync_len, sync, vmode, rotate, colorspace, reserved[4];
};

_Static_assert(sizeof(struct fb_fixed) == 80 && __builtin_offsetof(struct fb_fixed, line_length) == 48,
               "Linux x86-64 fb_fix_screeninfo");
_Static_assert(sizeof(struct fb_variable) == 160 && __builtin_offsetof(struct fb_variable, red) == 32,
               "Linux fb_var_screeninfo");

static struct gop64_surface display;
/* Доступ к устройству выполняется на BSP, без переключения задач внутри копирования. */
static u32 staging[PMM_PAGE_SIZE / sizeof(u32)];

void linux64_fb_init(const struct gop64_surface *surface) {
    display = *surface;
}

uptr linux64_fb_size(void) {
    return (uptr)display.height * display.pitch;
}

long linux64_fb_ioctl(u32 request, uptr address) {
    if (request == FBIOGET_FSCREENINFO) {
        const struct fb_fixed info = {
            .id = "MyOS GOP", .smem_len = (u32)linux64_fb_size(),
            .visual = FB_VISUAL_TRUECOLOR, .line_length = display.pitch,
        };
        return paging64_copy_to_user(address, &info, sizeof(info)) == sizeof(info) ? 0 : -EFAULT;
    }
    if (request == FBIOGET_VSCREENINFO) {
        const struct fb_variable info = {
            .xres = display.width, .yres = display.height,
            .xres_virtual = display.width, .yres_virtual = display.height,
            .bits_per_pixel = 32,
            .red = {display.pixel_order ? 0 : 16, 8, 0},
            .green = {8, 8, 0}, .blue = {display.pixel_order ? 16 : 0, 8, 0},
            .height = (u32)-1, .width = (u32)-1,
        };
        return paging64_copy_to_user(address, &info, sizeof(info)) == sizeof(info) ? 0 : -EFAULT;
    }
    return -ENOTTY;
}

static void write_pixels(volatile u8 *pixels, uptr count) {
    uptr i = 0;
    if (!((uptr)pixels & 3u))
        for (; i + 4 <= count; i += 4) *(volatile u32 *)(pixels + i) = staging[i / 4];
    const u8 *bytes = (const u8 *)staging;
    for (; i < count; ++i) pixels[i] = bytes[i];
}

static void read_pixels(const volatile u8 *pixels, uptr count) {
    uptr i = 0;
    if (!((uptr)pixels & 3u))
        for (; i + 4 <= count; i += 4) staging[i / 4] = *(const volatile u32 *)(pixels + i);
    u8 *bytes = (u8 *)staging;
    for (; i < count; ++i) bytes[i] = pixels[i];
}

long linux64_fb_io(bool write, uptr buffer, uptr count, uptr offset) {
    if (buffer >= X64_USER_TOP || count > X64_USER_TOP - buffer) return -EFAULT;
    uptr size = linux64_fb_size();
    if (offset > size) return write ? -EFBIG : 0;
    if (!count) return 0;
    if (offset == size) return write ? -ENOSPC : 0;
    if (count > size - offset) count = size - offset;
    uptr copied = 0;
    while (copied < count) {
        uptr chunk = count - copied;
        if (chunk > sizeof(staging)) chunk = sizeof(staging);
        volatile u8 *pixels = display.pixels + offset + copied;
        uptr done;
        if (write) {
            done = paging64_copy_from_user(staging, buffer + copied, chunk);
            write_pixels(pixels, done);
        } else {
            read_pixels(pixels, chunk);
            done = paging64_copy_to_user(buffer + copied, staging, chunk);
        }
        copied += done;
        if (done < chunk) break;
    }
    return copied ? (long)copied : -EFAULT;
}
