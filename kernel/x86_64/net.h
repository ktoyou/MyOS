#ifndef X86_64_NET_H
#define X86_64_NET_H

#include "../types.h"

struct net64_config {
    /* Адреса и маска в порядке байтов процессора. Нулевой шлюз отключает маршрут по умолчанию. */
    u32 address, mask, gateway;
};

enum net64_tx {
    NET64_SENT, NET64_RETRY, NET64_NO_ROUTE, NET64_LINK_DOWN, NET64_INVALID, NET64_UNREACHABLE,
};

/* Обработчик может отправить ответ. Буфер действителен до выхода из обработчика. */
typedef void (*net64_receiver)(void *context, u32 source, u32 destination, u8 protocol,
                               const u8 *data, u32 length);

bool net64_configure(struct net64_config config);
/* Время монотонное. Регулярный poll принимает кадры и продвигает таймеры ARP. */
enum net64_tx net64_send(u64 now_ns, u32 dst, u8 protocol, const void *data, u32 length);
void net64_poll(u64 now_ns, net64_receiver receive, void *context);
/* Дополнительная сумма нужна для псевдозаголовка TCP или UDP. Результат в порядке процессора. */
u16 net64_checksum(const void *data, u32 length, u32 sum);

#endif
