#include "../kernel/x86_64/ethernet.h"
#include "../kernel/x86_64/net.h"

#define SECOND 1000000000ull

enum { MAC_BYTES = 6, ETH_HEADER = 14, IPV4_HEADER = 20, ARP_FRAME = 42 };
static const struct net64_config settings = {0x0a00020f, 0xffffff00u, 0x0a000202};
static const u32 remote = 0xc6336407u;
static const u8 guest_mac[MAC_BYTES] = {0x52, 0x54, 0, 0x12, 0x34, 0x56};
static const u8 gateway_mac[MAC_BYTES] = {0x52, 0x55, 0x0a, 0, 2, 2};
static const u8 other_mac[MAC_BYTES] = {0x52, 0x55, 0x0a, 0, 2, 3};
static const u8 payload[] = {0xa5, 0x5a, 0x11};
static bool link_up = true;
static u8 rx[64], tx[64];
static u32 rx_size, tx_size, tx_count;
static unsigned init_count, failed_init_count;

extern int puts(const char *text);

static void copy(u8 *dst, const u8 *src, u32 size) {
    for (u32 i = 0; i < size; ++i) dst[i] = src[i];
}

static bool equal(const u8 *a, const u8 *b, u32 size) {
    for (u32 i = 0; i < size; ++i) if (a[i] != b[i]) return false;
    return true;
}

static bool fake_init(void) {
    ++init_count;
    return true;
}

static bool failed_init(void) {
    ++failed_init_count;
    return false;
}

static bool fake_link(void) {
    return link_up;
}

static void fake_mac(u8 out[MAC_BYTES]) {
    copy(out, guest_mac, MAC_BYTES);
}

static bool fake_send(const void *frame, u32 size) {
    if (!link_up || size > sizeof(tx)) return false;
    copy(tx, frame, size);
    tx_size = size;
    ++tx_count;
    return true;
}

static u32 fake_receive(void *frame, u32 capacity) {
    if (rx_size > capacity) return 0;
    u32 size = rx_size;
    copy(frame, rx, size);
    rx_size = 0;
    return size;
}

static const struct ethernet64_driver driver = {
    .name = "IPv4 fixture", .init = fake_init, .link = fake_link,
    .mac = fake_mac, .send = fake_send, .receive = fake_receive,
};

static bool absent_driver(void) {
    static const u8 zeros[MAC_BYTES] = {0};
    u8 mac[MAC_BYTES] = {1, 2, 3, 4, 5, 6}, frame[ETH_HEADER] = {0x5a};
    ethernet64_mac(mac);
    return !ethernet64_name() && !ethernet64_link() && equal(mac, zeros, sizeof(mac)) &&
           !ethernet64_send(frame, sizeof(frame)) &&
           !ethernet64_receive(frame, sizeof(frame)) && frame[0] == 0x5a;
}

static bool check_driver(void) {
    struct ethernet64_driver failed = driver;
    failed.init = NULL;
    if (!absent_driver() || ethernet64_attach(NULL) || ethernet64_attach(&failed)) return false;
    failed.init = failed_init;
    if (ethernet64_attach(&failed) || failed_init_count != 1 || !absent_driver()) return false;

    if (!ethernet64_attach(&driver) || ethernet64_name() != driver.name ||
        !ethernet64_link() || init_count != 1) return false;
    link_up = false;
    bool kept = ethernet64_attach(&driver) && !ethernet64_attach(&failed) &&
                !ethernet64_link() && ethernet64_name() == driver.name &&
                init_count == 1 && failed_init_count == 1;
    link_up = true;
    return kept;
}

static void queue_arp_reply(const u8 mac[MAC_BYTES]) {
    static const u8 arp[] = {
        0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 2,
        0, 0, 0, 0, 0, 0, 10, 0, 2, 2,
        0, 0, 0, 0, 0, 0, 10, 0, 2, 15,
    };
    copy(rx, guest_mac, MAC_BYTES);
    copy(rx + MAC_BYTES, mac, MAC_BYTES);
    copy(rx + 2 * MAC_BYTES, arp, sizeof(arp));
    copy(rx + 22, mac, MAC_BYTES);
    copy(rx + 32, guest_mac, MAC_BYTES);
    rx_size = ARP_FRAME;
}

static bool gateway_probe(void) {
    static const u8 gateway[] = {10, 0, 2, 2};
    return tx_size == ARP_FRAME && tx[12] == 0x08 && tx[13] == 0x06 && tx[21] == 1 &&
           equal(tx + 38, gateway, sizeof(gateway));
}

static enum net64_tx send_remote(u64 now) {
    return net64_send(now, remote, 17, payload, sizeof(payload));
}

static bool check_retries(void) {
    if (!net64_configure(settings) || send_remote(0) != NET64_RETRY || tx_count != 1 || !gateway_probe())
        return false;
    if (send_remote(SECOND - 1) != NET64_RETRY || tx_count != 1) return false;
    net64_poll(SECOND, NULL, NULL);
    if (tx_count != 2 || !gateway_probe()) return false;
    net64_poll(2 * SECOND, NULL, NULL);
    if (tx_count != 3 || !gateway_probe() || send_remote(3 * SECOND - 1) != NET64_RETRY ||
        tx_count != 3 || send_remote(3 * SECOND) != NET64_UNREACHABLE) return false;

    queue_arp_reply(gateway_mac);
    net64_poll(3 * SECOND + 1, NULL, NULL);
    if (send_remote(6 * SECOND - 1) != NET64_UNREACHABLE || tx_count != 3) return false;
    return send_remote(6 * SECOND) == NET64_RETRY && tx_count == 4 && gateway_probe();
}

static bool check_arp(void) {
    const u64 now = 10 * SECOND;
    if (!net64_configure(settings)) return false;
    tx_count = 0;
    queue_arp_reply(gateway_mac);
    net64_poll(now, NULL, NULL);
    if (send_remote(now) != NET64_RETRY || tx_count != 1 || !gateway_probe()) return false;

    /* Длина адреса, MAC отправителя, MAC и IP получателя, IP ответившего и Ethernet-адрес получателя. */
    static const u8 invalid_fields[] = {18, 23, 32, 41, 31, 5};
    for (unsigned i = 0; i < sizeof(invalid_fields); ++i) {
        queue_arp_reply(gateway_mac);
        rx[invalid_fields[i]] ^= 1;
        net64_poll(now + 1, NULL, NULL);
        if (send_remote(now + 1) != NET64_RETRY || tx_count != 1) return false;
    }

    queue_arp_reply(gateway_mac);
    net64_poll(now + 2, NULL, NULL);
    queue_arp_reply(other_mac);
    net64_poll(now + 3, NULL, NULL);
    static const u8 destination[] = {198, 51, 100, 7};
    if (send_remote(now + 3) != NET64_SENT || tx_count != 2 || tx_size != ETH_HEADER + IPV4_HEADER + sizeof(payload) ||
        !equal(tx, gateway_mac, MAC_BYTES) || tx[12] != 8 || tx[13] ||
        !equal(tx + ETH_HEADER + 16, destination, sizeof(destination))) return false;

    link_up = false;
    net64_poll(now + 4, NULL, NULL);
    link_up = true;
    if (send_remote(now + 5) != NET64_RETRY || tx_count != 3 || !gateway_probe()) return false;

    static const u8 broadcast[MAC_BYTES] = {255, 255, 255, 255, 255, 255};
    static const u8 zero_addresses[4 + MAC_BYTES] = {0};
    queue_arp_reply(other_mac);
    copy(rx, broadcast, sizeof(broadcast));
    rx[21] = 1;
    copy(rx + 28, zero_addresses, sizeof(zero_addresses));
    net64_poll(now + 6, NULL, NULL);
    return tx_count == 4 && tx_size == ARP_FRAME && tx[12] == 8 && tx[13] == 6 && tx[21] == 2 &&
           equal(tx, other_mac, MAC_BYTES) && equal(tx + 22, guest_mac, MAC_BYTES) &&
           equal(tx + 32, other_mac, MAC_BYTES) && equal(tx + 38, zero_addresses, 4);
}

struct received {
    unsigned count;
    bool matches;
};

static void record_ipv4(void *context, u32 source, u32 destination, u8 protocol, const u8 *data, u32 length) {
    struct received *received = context;
    ++received->count;
    received->matches = source == remote && destination == settings.address && protocol == 17 &&
                        length == sizeof(payload) && equal(data, payload, length);
}

static void queue_ipv4(u16 flags, u16 checksum, u8 length) {
    u8 ip[IPV4_HEADER] = {
        0x45, 0, 0, length, 0, 0x12, (u8)(flags >> 8), (u8)flags,
        64, 17, (u8)(checksum >> 8), (u8)checksum, 198, 51, 100, 7, 10, 0, 2, 15,
    };
    copy(rx, guest_mac, MAC_BYTES);
    copy(rx + MAC_BYTES, gateway_mac, MAC_BYTES);
    rx[12] = 8;
    rx[13] = 0;
    copy(rx + ETH_HEADER, ip, sizeof(ip));
    copy(rx + ETH_HEADER + IPV4_HEADER, payload, sizeof(payload));
    rx_size = 60; /* Ethernet дополняет короткие кадры. */
}

static bool check_ipv4(void) {
    const u64 now = 11 * SECOND;
    if (!net64_configure(settings)) return false;
    struct received received = {0};
    queue_ipv4(0x4000, 0x047a, 23); /* Ошибка в контрольной сумме. */
    net64_poll(now, record_ipv4, &received);
    queue_ipv4(0x2000, 0x2476, 28); /* Восемь байт и корректная контрольная сумма первого фрагмента. */
    net64_poll(now + 1, record_ipv4, &received);
    queue_ipv4(0x0001, 0x447a, 23); /* Ненулевое смещение фрагмента. */
    net64_poll(now + 2, record_ipv4, &received);
    if (received.count) return false;
    queue_ipv4(0x4000, 0x047b, 23);
    net64_poll(now + 3, record_ipv4, &received);
    return received.count == 1 && received.matches;
}

int main(void) {
    if (!check_driver()) { puts("Ethernet: driver attachment FAIL"); return 4; }
    if (!check_retries()) { puts("IPv4: ARP retries/negative cache FAIL"); return 1; }
    if (!check_arp()) { puts("IPv4: ARP replies/link reset FAIL"); return 2; }
    if (!check_ipv4()) { puts("IPv4: packet validation/dispatch FAIL"); return 3; }
    puts("IPv4: ARP retries, replies, link reset and IPv4 dispatch PASS");
    return 0;
}
