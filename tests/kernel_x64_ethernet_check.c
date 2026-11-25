#include "../kernel/x86_64/e1000.h"

extern void kernel64_serial_char(char ch);

enum { ARP_BYTES = 42, FIRST_HOST = 100, EXCHANGE_COUNT = 40, DOWN_HOST = 140, RECOVERY_HOST = 141 };
static const u8 arp_header[] = {0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00};
static const u8 gateway[] = {10, 0, 2, 2};

static void serial(const char *text) {
    while (*text) kernel64_serial_char(*text++);
}

static u64 tsc(void) {
    u32 low, high;
    __asm__ volatile("lfence; rdtsc" : "=a"(low), "=d"(high) : : "memory");
    return ((u64)high << 32) | low;
}

/* Запас на автосогласование QEMU. Время всего теста ограничивает стенд. */
static u64 deadline(void) {
    return tsc() + 30000000000ul;
}

static bool wait_link(bool up) {
    u64 end = deadline();
    do {
        if (e1000_link() == up) return true;
        __asm__ volatile("pause");
    } while (tsc() < end);
    serial("e1000 test: link transition timed out\n");
    return false;
}

static bool same(const u8 *left, const u8 *right, unsigned length) {
    for (unsigned i = 0; i < length; ++i)
        if (left[i] != right[i]) return false;
    return true;
}

static bool send_request(const u8 mac[6], u8 host) {
    u8 request[ARP_BYTES] = {0};
    for (unsigned i = 0; i < 6; ++i) {
        request[i] = 0xff;
        request[6 + i] = request[22 + i] = mac[i];
    }
    for (unsigned i = 0; i < sizeof(arp_header); ++i) request[12 + i] = arp_header[i];
    request[21] = 1;
    request[28] = 10;
    request[30] = 2;
    request[31] = host;
    for (unsigned i = 0; i < sizeof(gateway); ++i) request[38 + i] = gateway[i];
    return e1000_send(request, sizeof(request));
}

static bool exchange(const u8 mac[6], u8 host) {
    if (!send_request(mac, host)) {
        serial("e1000 test: ARP TX failed\n");
        return false;
    }
    u8 response[2048];
    const u8 target[] = {10, 0, 2, host};
    u64 end = deadline();
    do {
        if (e1000_receive(response, sizeof(response)) >= ARP_BYTES &&
            same(response, mac, 6) && same(response + 12, arp_header, sizeof(arp_header)) &&
            response[21] == 2 && same(response + 6, response + 22, 6) &&
            !same(response + 6, mac, 6) && !(response[6] & 1) &&
            same(response + 28, gateway, sizeof(gateway)) && same(response + 32, mac, 6) &&
            same(response + 38, target, sizeof(target))) return true;
        __asm__ volatile("pause");
    } while (tsc() < end);
    serial("e1000 test: no matching ARP reply\n");
    return false;
}

bool e1000_check(void) {
    if (!e1000_init()) {
        serial("e1000 test: controller initialization failed\n");
        return false;
    }
    u8 mac[6];
    e1000_mac(mac);
    serial("e1000 test: controller initialized\n");
    if (!wait_link(false)) return false;
    serial("e1000 test: initial link down\n");
    if (!wait_link(true)) return false;
    serial("e1000 test: exchanging frames\n");
    for (unsigned i = 0; i < EXCHANGE_COUNT; ++i) {
        if (!exchange(mac, FIRST_HOST + i)) return false;
        if (i == 0) serial("e1000 test: first ARP reply\n");
    }
    serial("e1000 test: exchanged 40 ARP replies\n");
    if (!wait_link(false)) return false;
    u8 response[2048];
    if (send_request(mac, DOWN_HOST) || e1000_receive(response, sizeof(response))) {
        serial("e1000 test: unexpected traffic with link down\n");
        return false;
    }
    serial("e1000 test: traffic blocked with link down\n");
    if (!wait_link(true) || !exchange(mac, RECOVERY_HOST)) return false;
    serial("e1000 test: ARP recovered\n");
    return true;
}
