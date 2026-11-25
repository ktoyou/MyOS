#include "net.h"
#include "e1000.h"

#define NS_PER_SECOND 1000000000ull

enum {
    MAC_BYTES = 6, ETH_HEADER = 14, ARP_BYTES = 28, IP_HEADER = 20, IP_MTU = 1500,
    ETH_IPV4 = 0x0800, ETH_ARP = 0x0806, ARP_REQUEST = 1, ARP_REPLY = 2,
    IP_DONT_FRAGMENT = 0x4000, NEIGHBOR_COUNT = 16, PROBE_LIMIT = 3, RX_BUDGET = 32,
};

enum neighbor_state { NEIGHBOR_EMPTY, NEIGHBOR_PENDING, NEIGHBOR_REACHABLE, NEIGHBOR_FAILED };

struct neighbor {
    u32 address;
    u8 mac[MAC_BYTES], probes;
    enum neighbor_state state;
    u64 until, next_probe;
};

static struct net64_config config;
static struct neighbor neighbors[NEIGHBOR_COUNT];
static u8 local_mac[MAC_BYTES];
static u8 tx_frame[ETH_HEADER + IP_MTU], rx_frame[2048];
static const u8 broadcast_mac[MAC_BYTES] = {255, 255, 255, 255, 255, 255};
static u16 ip_id;

static u16 read16(const u8 *p) {
    return (u16)((u16)p[0] << 8 | p[1]);
}

static u32 read32(const u8 *p) {
    return (u32)read16(p) << 16 | read16(p + 2);
}

static void write16(u8 *p, u16 value) {
    p[0] = (u8)(value >> 8);
    p[1] = (u8)value;
}

static void write32(u8 *p, u32 value) {
    write16(p, (u16)(value >> 16));
    write16(p + 2, (u16)value);
}

static void copy_bytes(u8 *destination, const u8 *source, u32 length) {
    for (u32 i = 0; i < length; ++i) destination[i] = source[i];
}

static bool equal_mac(const u8 *a, const u8 *b) {
    for (unsigned i = 0; i < MAC_BYTES; ++i)
        if (a[i] != b[i]) return false;
    return true;
}

static bool unicast_mac(const u8 *mac) {
    if (mac[0] & 1) return false;
    for (unsigned i = 0; i < MAC_BYTES; ++i)
        if (mac[i]) return true;
    return false;
}

u16 net64_checksum(const void *data, u32 length, u32 sum) {
    const u8 *p = data;
    u64 total = sum;
    for (; length >= 2; length -= 2, p += 2) total += read16(p);
    if (length) total += (u16)p[0] << 8;
    while (total >> 16) total = (total & 0xffffu) + (total >> 16);
    return (u16)~total;
}

static bool unicast_ip(u32 address) {
    u8 first = (u8)(address >> 24);
    return first && first != 127 && first < 224;
}

static bool subnet_host(u32 address, u32 mask) {
    u32 host_mask = ~mask, host = address & host_mask;
    return unicast_ip(address) && (host_mask <= 1 || (host && host != host_mask));
}

static bool same_subnet(const struct net64_config *settings, u32 address) {
    return ((address ^ settings->address) & settings->mask) == 0;
}

static void clear_neighbors(void) {
    for (unsigned i = 0; i < NEIGHBOR_COUNT; ++i) neighbors[i].state = NEIGHBOR_EMPTY;
}

bool net64_configure(struct net64_config settings) {
    u32 host_mask = ~settings.mask;
    if (!settings.mask || (host_mask & (host_mask + 1)) || !subnet_host(settings.address, settings.mask))
        return false;
    if (settings.gateway && (settings.gateway == settings.address ||
        !same_subnet(&settings, settings.gateway) || !subnet_host(settings.gateway, settings.mask))) return false;
    u8 mac[MAC_BYTES];
    e1000_mac(mac);
    if (!unicast_mac(mac)) return false;
    config = settings;
    copy_bytes(local_mac, mac, MAC_BYTES);
    clear_neighbors();
    return true;
}

static u32 next_hop(u32 dst) {
    if (!config.address || dst == config.address || !unicast_ip(dst)) return 0;
    if (same_subnet(&config, dst)) return subnet_host(dst, config.mask) ? dst : 0;
    return config.gateway;
}

static bool ethernet_send(const u8 *mac, u16 type, u32 size) {
    copy_bytes(tx_frame, mac, MAC_BYTES);
    copy_bytes(tx_frame + MAC_BYTES, local_mac, MAC_BYTES);
    write16(tx_frame + 2 * MAC_BYTES, type);
    return e1000_send(tx_frame, ETH_HEADER + size);
}

static bool arp_send(u16 opcode, const u8 *mac, u32 address) {
    u8 *arp = tx_frame + ETH_HEADER;
    static const u8 zero_mac[MAC_BYTES] = {0};
    write16(arp, 1);
    write16(arp + 2, ETH_IPV4);
    arp[4] = MAC_BYTES;
    arp[5] = 4;
    write16(arp + 6, opcode);
    copy_bytes(arp + 8, local_mac, MAC_BYTES);
    write32(arp + 14, config.address);
    copy_bytes(arp + 18, opcode == ARP_REQUEST ? zero_mac : mac, MAC_BYTES);
    write32(arp + 24, address);
    return ethernet_send(mac, ETH_ARP, ARP_BYTES);
}

static void expire_neighbor(struct neighbor *entry, u64 now) {
    if (entry->state == NEIGHBOR_EMPTY) return;
    if (entry->state != NEIGHBOR_PENDING) {
        if (now >= entry->until) entry->state = NEIGHBOR_EMPTY;
        return;
    }
    if (now >= entry->until || (entry->probes == PROBE_LIMIT && now >= entry->next_probe)) {
        entry->state = NEIGHBOR_FAILED;
        entry->until = now + 3 * NS_PER_SECOND;
    }
}

static void advance_neighbor(struct neighbor *entry, u64 now) {
    expire_neighbor(entry, now);
    if (entry->state == NEIGHBOR_PENDING && now >= entry->next_probe) {
        if (arp_send(ARP_REQUEST, broadcast_mac, entry->address)) {
            ++entry->probes;
            entry->next_probe = now + NS_PER_SECOND;
        } else {
            entry->next_probe = now + NS_PER_SECOND / 100;
        }
    }
}

static struct neighbor *find_neighbor(u32 ip, u64 now) {
    struct neighbor *empty = NULL, *oldest = NULL;
    for (unsigned i = 0; i < NEIGHBOR_COUNT; ++i) {
        struct neighbor *entry = &neighbors[i];
        expire_neighbor(entry, now);
        if (entry->state != NEIGHBOR_EMPTY && entry->address == ip) return entry;
        if (entry->state == NEIGHBOR_EMPTY) empty = entry;
        else if (entry->state != NEIGHBOR_PENDING && (!oldest || entry->until < oldest->until)) oldest = entry;
    }
    struct neighbor *entry = empty ? empty : oldest;
    if (entry) *entry = (struct neighbor){.address = ip, .state = NEIGHBOR_PENDING,
                                        .until = now + 4 * NS_PER_SECOND, .next_probe = now};
    return entry;
}

static void arp_receive(const u8 *frame, u32 length, u64 now) {
    if (length < ARP_BYTES) return;
    const u8 *arp = frame + ETH_HEADER;
    if (read16(arp) != 1 || read16(arp + 2) != ETH_IPV4 || arp[4] != MAC_BYTES || arp[5] != 4 ||
        !equal_mac(frame + MAC_BYTES, arp + 8) || read32(arp + 24) != config.address) return;
    u16 opcode = read16(arp + 6);
    u32 sender = read32(arp + 14);
    if (opcode == ARP_REQUEST) {
        /* ARP Probe при проверке конфликта адреса имеет нулевой IP отправителя. */
        bool broadcast = equal_mac(frame, broadcast_mac);
        if ((!sender && broadcast) || (sender != config.address && unicast_ip(sender) &&
                                      (broadcast || equal_mac(frame, local_mac))))
            arp_send(ARP_REPLY, arp + 8, sender);
    } else if (opcode == ARP_REPLY && equal_mac(frame, local_mac) && equal_mac(arp + 18, local_mac) &&
               same_subnet(&config, sender) && sender != config.address && subnet_host(sender, config.mask)) {
        /* Незапрошенный ответ не меняет привязку соседнего узла. */
        for (unsigned i = 0; i < NEIGHBOR_COUNT; ++i) {
            struct neighbor *entry = &neighbors[i];
            if (entry->address != sender) continue;
            expire_neighbor(entry, now);
            if (entry->state != NEIGHBOR_PENDING || !entry->probes) continue;
            copy_bytes(entry->mac, arp + 8, MAC_BYTES);
            entry->until = now + 60 * NS_PER_SECOND;
            entry->state = NEIGHBOR_REACHABLE;
            break;
        }
    }
}

enum net64_tx net64_send(u64 now, u32 dst, u8 protocol, const void *data, u32 length) {
    if (!protocol || (length && !data) || length > IP_MTU - IP_HEADER) return NET64_INVALID;
    u32 hop = next_hop(dst);
    if (!hop) return NET64_NO_ROUTE;
    if (!e1000_link()) {
        clear_neighbors();
        return NET64_LINK_DOWN;
    }
    struct neighbor *entry = find_neighbor(hop, now);
    if (!entry) return NET64_RETRY;
    advance_neighbor(entry, now);
    if (entry->state == NEIGHBOR_FAILED) return NET64_UNREACHABLE;
    if (entry->state != NEIGHBOR_REACHABLE) return NET64_RETRY;

    u8 *ip = tx_frame + ETH_HEADER;
    ip[0] = 0x45;
    ip[1] = 0;
    write16(ip + 2, (u16)(IP_HEADER + length));
    write16(ip + 4, ip_id++);
    write16(ip + 6, IP_DONT_FRAGMENT);
    ip[8] = 64;
    ip[9] = protocol;
    write16(ip + 10, 0);
    write32(ip + 12, config.address);
    write32(ip + 16, dst);
    write16(ip + 10, net64_checksum(ip, IP_HEADER, 0));
    copy_bytes(ip + IP_HEADER, data, length);
    return ethernet_send(entry->mac, ETH_IPV4, IP_HEADER + length) ? NET64_SENT : NET64_RETRY;
}

static void ipv4_receive(const u8 *ip, u32 length, net64_receiver receive, void *context) {
    if (!receive || length < IP_HEADER || ip[0] >> 4 != 4) return;
    u32 header = (ip[0] & 15u) * 4, packet = read16(ip + 2);
    if (header < IP_HEADER || packet < header || packet > length || packet > IP_MTU ||
        (read16(ip + 6) & ~IP_DONT_FRAGMENT) || !ip[8] || !ip[9] || net64_checksum(ip, header, 0)) return;
    u32 src = read32(ip + 12), dst = read32(ip + 16);
    if (!unicast_ip(src) || dst != config.address) return;
    receive(context, src, dst, ip[9], ip + header, packet - header);
}

void net64_poll(u64 now, net64_receiver receive, void *context) {
    if (!config.address) return;
    if (!e1000_link()) {
        clear_neighbors();
        return;
    }
    for (unsigned i = 0; i < RX_BUDGET; ++i) {
        u32 length = e1000_receive(rx_frame, sizeof(rx_frame));
        if (!length) break;
        if (length < ETH_HEADER || !unicast_mac(rx_frame + MAC_BYTES)) continue;
        u16 type = read16(rx_frame + 2 * MAC_BYTES);
        if (type == ETH_ARP) arp_receive(rx_frame, length - ETH_HEADER, now);
        else if (type == ETH_IPV4 && equal_mac(rx_frame, local_mac))
            ipv4_receive(rx_frame + ETH_HEADER, length - ETH_HEADER, receive, context);
    }
    for (unsigned i = 0; i < NEIGHBOR_COUNT; ++i) advance_neighbor(&neighbors[i], now);
}
