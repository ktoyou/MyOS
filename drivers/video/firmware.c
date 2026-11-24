#include "video.h"

bool video_firmware_init(const struct boot_info *b, struct fb_info *out) {
    if(boot_uefi(b) && (b->arena_phys<0x100000 || b->arena_phys>=0x40000000 ||
       b->arena_bytes<8192 || b->arena_bytes>0x40000000u-b->arena_phys ||
       b->font_phys<b->arena_phys || b->font_phys>b->arena_phys+b->arena_bytes-4096))return false;
    if (!b || !out || b->magic!=BOOT_INFO_MAGIC || b->version<1 || b->version>5 ||
        (!boot_uefi(b) && b->font_phys!=0x5000) || !b->font_phys || !b->fb_phys || b->bpp!=32 ||
        b->width<640 || b->width>FB_MAX_W || b->height<480 || b->height>FB_MAX_H ||
        (b->fb_phys&4095) || (b->pitch&3) || b->pitch<b->width*4 ||
        b->pitch>FB_VIRT_SZ/b->height || b->fb_phys>0xffffffffu-b->pitch*b->height ||
        (b->version>=5 && b->pixel_order>1))
        return false;
    *out=(struct fb_info){
        .phys=b->fb_phys,.width=b->width,.height=b->height,.bpp=32,.pitch=b->pitch,
        .vram=b->pitch*b->height,.max_w=b->width,.max_h=b->height,
        .caps=FB_CAP_COPY|FB_CAP_FILL|FB_CAP_FIXED_MODE,.gen=1,.driver="BIOS VBE framebuffer",
        .rgb_swap=b->version>=5?b->pixel_order:0,
        .native_w=b->version>=5 && b->native_w<=65536?b->native_w:0,
        .native_h=b->version>=5 && b->native_h<=65536?b->native_h:0
    };
    if(boot_uefi(b))out->driver="UEFI GOP framebuffer";
    return true;
}
