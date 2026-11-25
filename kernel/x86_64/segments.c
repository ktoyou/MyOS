#include "segments.h"

struct tss64 {
    u32 reserved0;
    u64 rsp0, rsp1, rsp2, reserved1;
    u64 ist[7], reserved2;
    u16 reserved3, io_bitmap;
} __attribute__((packed));

struct gdtr64 {
    u16 limit;
    u64 base;
} __attribute__((packed));

_Static_assert(sizeof(struct tss64) == 104, "x86-64 TSS layout");
_Static_assert(sizeof(struct gdtr64) == 10, "x86-64 GDTR layout");

static struct tss64 tss;
static _Alignas(4096) u8 entry_stack[32768];
static u64 gdt[] = {
    0,
    0x00af9a000000ffffull, /* 0x08: код ядра, также используется IDT. */
    0x00cf92000000ffffull, /* 0x10: данные ядра. */
    0x00cff2000000ffffull, /* 0x18: пользовательские данные. */
    0x00affa000000ffffull, /* 0x20: пользовательский код в long mode. */
    0, 0,                /* 0x28: 16-байтный дескриптор TSS. */
};

void segments64_init(void) {
    tss.rsp0 = (uptr)entry_stack + sizeof(entry_stack);
    /* Карта ввода-вывода находится за пределом TSS: ring 3 не получает порты. */
    tss.io_bitmap = sizeof(tss);
    uptr base = (uptr)&tss;
    gdt[5] = (sizeof(tss) - 1) | ((base & 0xffffffull) << 16) |
             (0x89ull << 40) | (((base >> 24) & 0xffull) << 56);
    gdt[6] = base >> 32;
    const struct gdtr64 gdtr = {sizeof(gdt) - 1, (uptr)gdt};
    const u16 tss_selector = 0x28;
    __asm__ volatile("lgdt %0; ltr %1" : : "m"(gdtr), "r"(tss_selector) : "memory");
}

bool segments64_on_entry_stack(uptr frame) {
    uptr bottom = (uptr)entry_stack;
    return frame >= bottom && frame <= tss.rsp0 - 7 * sizeof(u64);
}
