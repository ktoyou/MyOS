#ifndef BOOTINFO_H
#define BOOTINFO_H
#include "types.h"
#define BOOT_INFO_MAGIC 0x534f594du
#define BOOT_INFO_VERSION_GOP 5u
#define BOOT_INFO_VERSION_XHCI 6u
/* Shared live-root contract; the image builder passes these limits to NASM. */
#define LIVE_ROOT_PHYS 0x01000000u
#define LIVE_ROOT_MIN_MB 64
#define LIVE_ROOT_MAX_MB 512
#define LIVE_ROOT_RESERVE_MB 64
#define BOOT_DISK_ROOT 1u
struct boot_info {
    u32 magic, version, root_phys, root_bytes, font_phys;
    u32 fb_phys, width, height, bpp, pitch;
    u32 bios_snapshot_magic; /* 0x49564256: page zero saved at 0x2000 */
    u32 root_lba,root_disk_id; /* version 2+: identifies the boot partition */
    u32 storage_flags,root_sectors; /* version 3: native installed disk, no RAM root */
    u32 firmware,rsdp,map_phys,map_count,arena_phys,arena_bytes,ap_safe; /* version 4 UEFI */
    u32 pixel_order,native_w,native_h; /* v5: 0=BGRX, 1=RGBX; предпочтительный режим EDID */
    u32 xhci_bdf,xhci_bar_lo,xhci_bar_hi,xhci_bar_bytes; /* x86-64 v6: физический BAR0, 0 байт если отсутствует */
};
static inline bool boot_uefi(const struct boot_info *b){return b && b->version>=4 && b->firmware==1;}
static inline u64 boot_xhci_bar_address(const struct boot_info *b) {
    return (u64)b->xhci_bar_hi << 32 | b->xhci_bar_lo;
}
static inline bool boot_xhci_bar_valid(const struct boot_info *b) {
    if (!boot_uefi(b) || b->version != BOOT_INFO_VERSION_XHCI || !b->xhci_bar_bytes || b->xhci_bdf > 0xffffu)
        return false;
    u64 base = boot_xhci_bar_address(b), maximum = 1ull << 52;
    return base && base < maximum && b->xhci_bar_bytes <= maximum - base &&
           !((base | b->xhci_bar_bytes) & 4095u);
}
static inline bool boot_disk_root(const struct boot_info *b) {
    return b && b->version>=3 && b->storage_flags==BOOT_DISK_ROOT &&
           !b->root_phys && !b->root_bytes && b->root_disk_id && b->root_lba>=2048 &&
           b->root_sectors>=LIVE_ROOT_MIN_MB*2048u && b->root_sectors<=16u*1024u*1024u;
}
static inline bool boot_root_valid(const struct boot_info *b) {
    bool address=b && (boot_uefi(b)?b->root_phys>=0x100000u && !(b->root_phys&4095u) &&
        b->root_phys<0x40000000u && b->root_bytes<=0x40000000u-b->root_phys:b->root_phys==LIVE_ROOT_PHYS);
    return boot_disk_root(b) || (address &&
           b->root_bytes>=LIVE_ROOT_MIN_MB*1024u*1024u &&
           b->root_bytes<=LIVE_ROOT_MAX_MB*1024u*1024u && !(b->root_bytes&511u));
}
/* Only the separate hardware build trusts the low-memory boot contract. */
static inline const struct boot_info *boot_info_get(void) {
#ifdef MYOS_HARDWARE
    extern u32 boot_info_address;
    const struct boot_info *b=(const void *)boot_info_address;
    return b->magic==BOOT_INFO_MAGIC && (b->version>=1 && b->version<=BOOT_INFO_VERSION_GOP) ? b : NULL;
#else
    return NULL;
#endif
}
#endif
