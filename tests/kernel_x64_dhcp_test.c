#include "../kernel/x86_64/dhcp.h"
#include "../kernel/x86_64/ethernet.h"
#include "../kernel/x86_64/net_bytes.h"

#define SECOND 1000000000ull
#define BROADCAST 0xffffffffu

enum { UDP_HEADER = 8, BOOTP_OPTIONS = UDP_HEADER + 240, DISCOVER = 1, OFFER = 2, REQUEST = 3, ACK = 5, NAK = 6 };
static const u8 mac[] = {0x52, 0x54, 0, 0x12, 0x34, 0x56};
static const u32 address = 0x0a2c0014, mask = 0xffffff00u, gateway = 0x0a2c0005, dns = 0x0a2c0035;
static const u64 request_time = SECOND + 3;
static u8 tx[320], rx[320];
static u32 tx_size, rx_size, tx_src, tx_dst, rx_server;
static unsigned tx_count, configured, cleared;
static bool link_up;
static struct net64_config active;
static net64_receiver dhcp_receive;

extern int puts(const char *text);

static bool fake_init(void) { return true; }
static bool fake_link(void) { return link_up; }

static void fake_mac(u8 out[6]) {
    for (unsigned i = 0; i < sizeof(mac); ++i) out[i] = mac[i];
}

static bool fake_send(const void *frame, u32 length) {
    (void)frame;
    (void)length;
    return false;
}

static u32 fake_receive(void *frame, u32 capacity) {
    (void)frame;
    (void)capacity;
    return 0;
}

static const struct ethernet64_driver driver = {
    .name = "DHCP fixture", .init = fake_init, .link = fake_link,
    .mac = fake_mac, .send = fake_send, .receive = fake_receive,
};

bool net64_enable_dhcp(net64_receiver receive) {
    dhcp_receive = receive;
    return receive != NULL;
}

void net64_poll(u64 now, net64_receiver receive, void *context) {
    (void)receive;
    (void)context;
    if (!rx_size) return;
    u32 size = rx_size;
    rx_size = 0;
    dhcp_receive(&now, rx_server, BROADCAST, 17, rx, size);
}

static bool transmit(u32 source, u32 dest, const void *data, u32 length) {
    ++tx_count;
    if (!link_up || length > sizeof(tx)) return false;
    const u8 *bytes = data;
    for (u32 i = 0; i < length; ++i) tx[i] = bytes[i];
    tx_size = length;
    tx_src = source;
    tx_dst = dest;
    return true;
}

bool net64_dhcp_broadcast(u32 source, const u8 *datagram, u32 length) {
    return transmit(source, BROADCAST, datagram, length);
}

enum net64_tx net64_send(u64 now, u32 dest, u8 protocol, const void *data, u32 length) {
    (void)now;
    return protocol == 17 && transmit(active.address, dest, data, length) ? NET64_SENT : NET64_INVALID;
}

bool net64_configure(struct net64_config config) {
    active = config;
    ++configured;
    return true;
}

void net64_clear_config(void) {
    active = (struct net64_config){0};
    ++cleared;
}

u16 net64_checksum(const void *data, u32 length, u32 sum) {
    const u8 *bytes = data;
    for (u32 i = 0; i < length; ++i) sum += (u32)bytes[i] << (i % 2 ? 0 : 8);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (u16)~sum;
}

static u8 *option32(u8 *p, u8 code, u32 value) {
    *p++ = code;
    *p++ = 4;
    net_write32(p, value);
    return p + 4;
}

static u8 *begin_reply(u8 type, u32 xid, u32 server) {
    for (unsigned i = 0; i < sizeof(rx); ++i) rx[i] = 0;
    u8 *bootp = rx + UDP_HEADER;
    bootp[0] = 2;
    bootp[1] = 1;
    bootp[2] = sizeof(mac);
    net_write32(bootp + 4, xid);
    net_write32(bootp + 16, type == NAK ? 0 : address);
    fake_mac(bootp + 28);
    net_write32(bootp + 236, 0x63825363);
    u8 *p = rx + BOOTP_OPTIONS;
    *p++ = 53;
    *p++ = 1;
    *p++ = type;
    rx_server = server;
    return option32(p, 54, server);
}

static void finish_reply(u8 *p) {
    *p++ = 255;
    rx_size = (u32)(p - rx);
    net_write16(rx, 67);
    net_write16(rx + 2, 68);
    net_write16(rx + 4, (u16)rx_size);
}

static void reply(u8 type, u32 xid, u32 server) {
    u8 *p = begin_reply(type, xid, server);
    if (type == ACK) {
        p = option32(p, 1, mask);
        p = option32(p, 3, gateway);
        p = option32(p, 6, dns);
        p = option32(p, 51, 8);
        p = option32(p, 58, 2);
        p = option32(p, 59, 5);
    }
    finish_reply(p);
}

static const u8 *find_option(u8 code, u8 size) {
    for (u32 i = BOOTP_OPTIONS; i < tx_size;) {
        u8 found = tx[i++];
        if (found == 255) return NULL;
        if (!found) continue;
        if (i == tx_size) return NULL;
        u8 length = tx[i++];
        if (length > tx_size - i) return NULL;
        if (found == code && length == size) return tx + i;
        i += length;
    }
    return NULL;
}

static u32 xid(void) { return net_read32(tx + UDP_HEADER + 4); }

static bool request_is(u8 type, u32 dest, u32 source) {
    const u8 *option = find_option(53, 1);
    if (!option || *option != type || tx_src != source || tx_dst != dest ||
        net_read32(tx + UDP_HEADER + 12) != source ||
        net_read16(tx) != 68 || net_read16(tx + 2) != 67 || net_read16(tx + 4) != tx_size ||
        net_read16(tx + UDP_HEADER + 10) != (dest == BROADCAST ? 0x8000 : 0)) return false;
    u32 pseudo = (source >> 16) + (source & 0xffffu) + (dest >> 16) + (dest & 0xffffu) + 17 + tx_size;
    return net_read16(tx + 6) && !net64_checksum(tx, tx_size, pseudo);
}

static bool check_dora(void) {
    if (!dhcp64_start(0x12fe8349) || dhcp64_poll(0, NULL) || tx_count || configured) return false;
    link_up = true;
    dhcp64_poll(SECOND, NULL);
    if (tx_count != 1 || !request_is(DISCOVER, BROADCAST, 0) || !xid()) return false;
    u32 first = xid();
    reply(OFFER, first ^ 1u, gateway);
    dhcp64_poll(SECOND + 1, NULL);
    if (tx_count != 1) return false;
    reply(OFFER, first, gateway);
    rx[UDP_HEADER + 28] ^= 1;
    dhcp64_poll(SECOND + 2, NULL);
    if (tx_count != 1) return false;
    reply(OFFER, first, gateway);
    dhcp64_poll(request_time, NULL);
    const u8 *want = find_option(50, 4), *server = find_option(54, 4);
    if (configured || tx_count != 2 || !request_is(REQUEST, BROADCAST, 0) || xid() != first ||
        !want || net_read32(want) != address || !server || net_read32(server) != gateway) return false;

    reply(ACK, first, gateway ^ 1u);
    dhcp64_poll(SECOND + 4, NULL);
    if (configured) return false;
    reply(ACK, first, gateway);
    dhcp64_poll(2 * SECOND, NULL);
    struct dhcp64_lease lease;
    return configured == 1 && tx_count == 2 && dhcp64_get_lease(&lease) && active.address == address &&
           active.mask == mask && active.gateway == gateway && lease.network.address == address &&
           lease.network.mask == mask && lease.network.gateway == gateway && lease.dns == dns && lease.seconds == 8;
}

static bool check_renewal(void) {
    const u64 t1 = request_time + 2 * SECOND, t2 = request_time + 5 * SECOND;
    const u64 nak_time = t2 + 1, restart = nak_time + 4 * SECOND;
    u32 initial = xid();
    dhcp64_poll(t1 - 1, NULL);
    if (tx_count != 2) return false;
    dhcp64_poll(t1, NULL);
    if (tx_count != 3 || !request_is(REQUEST, gateway, address) || xid() == initial || find_option(50, 4) ||
        find_option(54, 4)) return false;
    u32 renewal = xid();
    dhcp64_poll(t2 - 1, NULL);
    if (tx_count != 3) return false;
    dhcp64_poll(t2, NULL);
    if (tx_count != 4 || !request_is(REQUEST, BROADCAST, address) || xid() != renewal ||
        find_option(50, 4) || find_option(54, 4)) return false;

    reply(NAK, renewal, gateway ^ 1u);
    dhcp64_poll(nak_time, NULL);
    struct dhcp64_lease lease;
    if (cleared != 1 || active.address || dhcp64_get_lease(&lease) || tx_count != 4) return false;
    dhcp64_poll(restart - 1, NULL);
    if (tx_count != 4) return false;
    dhcp64_poll(restart, NULL);
    if (tx_count != 5 || !request_is(DISCOVER, BROADCAST, 0) || xid() == renewal) return false;

    const u64 new_request = restart + 1, renew = new_request + 2 * SECOND;
    const u32 new_gateway = gateway + 1;
    reply(OFFER, xid(), gateway);
    dhcp64_poll(new_request, NULL);
    if (tx_count != 6 || !request_is(REQUEST, BROADCAST, 0)) return false;
    reply(ACK, xid(), gateway);
    dhcp64_poll(new_request + 1, NULL);
    if (configured != 2 || active.mask != mask || active.gateway != gateway) return false;

    dhcp64_poll(renew, NULL);
    if (tx_count != 7 || !request_is(REQUEST, gateway, address)) return false;
    u8 *p = begin_reply(ACK, xid(), gateway);
    p = option32(p, 3, new_gateway);
    p = option32(p, 51, 8);
    finish_reply(p);
    dhcp64_poll(renew + SECOND, NULL);
    if (configured != 3 || active.address != address || active.mask != mask || active.gateway != new_gateway ||
        !dhcp64_get_lease(&lease) || lease.network.mask != mask || lease.network.gateway != new_gateway ||
        lease.dns != dns) return false;

    /* Срок аренды отсчитывается от отправленного REQUEST, хотя ACK пришёл секундой позже. */
    const u64 expiry = renew + 8 * SECOND;
    dhcp64_poll(expiry - 1, NULL);
    if (cleared != 1 || !dhcp64_get_lease(&lease)) return false;
    unsigned before = tx_count;
    dhcp64_poll(expiry, NULL);
    if (cleared != 2 || active.address || dhcp64_get_lease(&lease) || tx_count != before + 1 ||
        !request_is(DISCOVER, BROADCAST, 0)) return false;

    link_up = false;
    return !dhcp64_poll(expiry + SECOND, NULL) && !dhcp64_poll(60 * SECOND, NULL) && tx_count == before + 1;
}

int main(void) {
    if (!ethernet64_attach(&driver)) { puts("DHCPv4: Ethernet attachment FAIL"); return 3; }
    if (!check_dora()) { puts("DHCPv4: DORA or reply validation FAIL"); return 1; }
    if (!check_renewal()) { puts("DHCPv4: renewal, rebinding or restart FAIL"); return 2; }
    puts("DHCPv4: DORA, T1/T2, partial ACK, expiry, NAK and link down PASS");
    return 0;
}
