#ifndef X86_64_ETHERNET_H
#define X86_64_ETHERNET_H

#include "../types.h"

struct ethernet64_driver {
    const char *name;
    bool (*init)(void);
    bool (*link)(void);
    void (*mac)(u8 out[6]);
    bool (*send)(const void *frame, u32 size);
    u32 (*receive)(void *frame, u32 capacity); /* 0 или длина кадра в пределах capacity. */
};

/* Описание драйвера остаётся доступным всё время работы ядра.
 * Первый успешно подключённый драйвер не меняется при потере линка. */
bool ethernet64_attach(const struct ethernet64_driver *driver);
const char *ethernet64_name(void);
bool ethernet64_link(void);
void ethernet64_mac(u8 out[6]);
bool ethernet64_send(const void *frame, u32 size);
u32 ethernet64_receive(void *frame, u32 capacity);

#endif
