#include "../kernel/x86_64/e1000.h"
#include "../kernel/x86_64/net.h"

extern void kernel64_serial_char(char ch);

#define IPV4(a, b, c, d) (((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | (d))
enum { ICMP = 1, TEST_PROTOCOL = 253 };
static const u32 address = IPV4(10, 0, 2, 15), gateway = IPV4(10, 0, 2, 2);
static const u32 outside = IPV4(192, 0, 2, 7), no_route = IPV4(192, 0, 2, 8);
static const u32 on_link = IPV4(10, 0, 2, 3);
static const u8 route_payload[] = {0x4d, 0x79, 0x4f, 0x53, 0x93, 0xa7};
static const u8 echo_fields[] = {0x39, 0x17, 0xa2, 0x65, 0xf2, 0x44, 0x12, 0x84, 0xbb, 0xde, 0x51};

/* Таймер ARP в этой проверке не истекает, а ожидание устройства ограничено TSC. */
static const u64 now_ns = 1;

static bool stage(bool result, const char *message) {
    while (*message) kernel64_serial_char(*message++);
    kernel64_serial_char('\n');
    return result;
}

static u64 tsc(void) {
    u32 low, high;
    __asm__ volatile("lfence; rdtsc" : "=a"(low), "=d"(high) : : "memory");
    return (u64)high << 32 | low;
}

static u64 deadline(void) {
    return tsc() + 30000000000ul;
}

static void receive(void *context, u32 source, u32 destination, u8 protocol, const u8 *data, u32 length) {
    if (source != gateway || destination != address || protocol != ICMP ||
        length != 4 + sizeof(echo_fields) || data[0] != 0 || data[1] != 0 ||
        net64_checksum(data, length, 0) != 0) return;
    for (unsigned i = 0; i < sizeof(echo_fields); ++i)
        if (data[4 + i] != echo_fields[i]) return;
    *(bool *)context = true;
}

static bool send_after_arp(u32 destination, bool *reply) {
    if (net64_send(now_ns, destination, TEST_PROTOCOL, route_payload, sizeof(route_payload)) != NET64_RETRY)
        return stage(false, "IPv4 test: unresolved next hop did not request ARP");

    u64 end = deadline();
    do {
        net64_poll(now_ns, receive, reply);
        enum net64_tx result = net64_send(now_ns, destination, TEST_PROTOCOL, route_payload, sizeof(route_payload));
        if (result == NET64_SENT) return true;
        if (result != NET64_RETRY) return stage(false, "IPv4 test: pending send failed");
        __asm__ volatile("pause");
    } while (tsc() < end);
    return stage(false, "IPv4 test: ARP resolution timed out");
}

static bool check_echo(bool *reply) {
    u8 request[4 + sizeof(echo_fields)] = {8};
    for (unsigned i = 0; i < sizeof(echo_fields); ++i) request[4 + i] = echo_fields[i];
    u16 checksum = net64_checksum(request, sizeof(request), 0);
    request[2] = checksum >> 8;
    request[3] = checksum;
    if (net64_send(now_ns, gateway, ICMP, request, sizeof(request)) != NET64_SENT)
        return stage(false, "IPv4 test: ICMP echo send failed");

    u64 end = deadline();
    do {
        net64_poll(now_ns, receive, reply);
        if (*reply) return true;
        __asm__ volatile("pause");
    } while (tsc() < end);
    return stage(false, "IPv4 test: matching ICMP echo reply timed out");
}

bool net64_check(void) {
    struct net64_config config = {.address = address, .mask = IPV4(255, 255, 255, 0), .gateway = gateway};
    if (!e1000_init() || !net64_configure(config)) return stage(false, "IPv4 test: initialization failed");
    stage(true, "IPv4 test: waiting for link");
    u64 end = deadline();
    while (!e1000_link()) {
        if (tsc() >= end) return stage(false, "IPv4 test: link timed out");
        __asm__ volatile("pause");
    }

    bool reply = false;
    if (!send_after_arp(outside, &reply)) return false;
    stage(true, "IPv4 test: off-link packet sent");
    if (!check_echo(&reply)) return false;
    stage(true, "IPv4 test: ICMP echo reply received");

    config.gateway = 0;
    if (!net64_configure(config)) return stage(false, "IPv4 test: could not clear gateway");
    if (net64_send(now_ns, no_route, TEST_PROTOCOL, route_payload, sizeof(route_payload)) != NET64_NO_ROUTE)
        return stage(false, "IPv4 test: missing gateway accepted an off-link packet");
    if (!send_after_arp(on_link, &reply)) return false;
    return stage(true, "IPv4 test: on-link packet sent without a gateway");
}
