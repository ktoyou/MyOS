#include "dhcp.h"
#include "e1000.h"
#include "net_bytes.h"

#define SECOND 1000000000ull
#define BROADCAST 0xffffffffu

enum {
    UDP = 17, SERVER_PORT = 67, CLIENT_PORT = 68, UDP_BYTES = 8,
    BOOTP_BYTES = 240, DHCP_BYTES = 300, COOKIE = 0x63825363,
    DISCOVER = 1, OFFER = 2, REQUEST = 3, ACK = 5, NAK = 6,
    SUBNET = 1, ROUTER = 3, DNS = 6, REQUESTED_IP = 50, LEASE_TIME = 51, MESSAGE_TYPE = 53,
    SERVER_ID = 54, PARAMS = 55, RENEWAL_TIME = 58, REBIND_TIME = 59, CLIENT_ID = 61, END = 255,
};

enum dhcp_state { OFF, WAIT_LINK, SELECTING, REQUESTING, BOUND, RENEWING, REBINDING, COOLDOWN };

static struct {
    enum dhcp_state state;
    struct dhcp64_lease lease;
    u8 mac[6], attempts;
    u32 random, xid, selected_ip, server;
    u64 start, next, deadline, request_sent, renewal, rebind, expires;
} client;

static u32 random_word(void) {
    u32 value = client.random;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return client.random = value;
}

static u32 udp_sum(u32 source, u32 dest, u32 length) {
    return (source >> 16) + (source & 0xffffu) + (dest >> 16) + (dest & 0xffffu) + UDP + length;
}

static u8 *address_option(u8 *option, u8 type, u32 value) {
    *option++ = type;
    *option++ = 4;
    net_write32(option, value);
    return option + 4;
}

static bool send_message(u64 now) {
    u8 packet[UDP_BYTES + DHCP_BYTES] = {0};
    u8 *bootp = packet + UDP_BYTES;
    bool renewal = client.state == RENEWING || client.state == REBINDING;
    bool broadcast = client.state != RENEWING;
    u32 src = renewal ? client.lease.network.address : 0;
    u32 dest = broadcast ? BROADCAST : client.server;
    u64 seconds = (now - client.start) / SECOND;
    bootp[0] = bootp[1] = 1;
    bootp[2] = sizeof(client.mac);
    net_write32(bootp + 4, client.xid);
    net_write16(bootp + 8, seconds > 65535 ? 65535 : (u16)seconds);
    if (broadcast) net_write16(bootp + 10, 0x8000);
    net_write32(bootp + 12, src);
    for (unsigned i = 0; i < sizeof(client.mac); ++i) bootp[28 + i] = client.mac[i];
    net_write32(bootp + 236, COOKIE);

    u8 *option = bootp + BOOTP_BYTES;
    *option++ = MESSAGE_TYPE;
    *option++ = 1;
    *option++ = client.state == SELECTING ? DISCOVER : REQUEST;
    *option++ = CLIENT_ID;
    *option++ = 1 + sizeof(client.mac);
    *option++ = 1;
    for (unsigned i = 0; i < sizeof(client.mac); ++i) *option++ = client.mac[i];
    if (client.state == REQUESTING) {
        option = address_option(option, REQUESTED_IP, client.selected_ip);
        option = address_option(option, SERVER_ID, client.server);
    }
    *option++ = PARAMS;
    *option++ = 6;
    *option++ = SUBNET;
    *option++ = ROUTER;
    *option++ = DNS;
    *option++ = LEASE_TIME;
    *option++ = RENEWAL_TIME;
    *option++ = REBIND_TIME;
    *option = END;
    net_write16(packet, CLIENT_PORT);
    net_write16(packet + 2, SERVER_PORT);
    net_write16(packet + 4, sizeof(packet));
    u16 checksum = net64_checksum(packet, sizeof(packet), udp_sum(src, dest, sizeof(packet)));
    net_write16(packet + 6, checksum ? checksum : 0xffffu);
    if (broadcast) return net64_dhcp_broadcast(src, packet, sizeof(packet));
    return net64_send(now, dest, UDP, packet, sizeof(packet)) == NET64_SENT;
}

struct dhcp_options {
    u32 mask, router, dns, server, lease, renewal, rebind;
    u8 type;
    bool has_router, has_dns;
};

static bool parse_options(const u8 *packet, u32 length, struct dhcp_options *options) {
    unsigned seen = 0;
    for (u32 i = 0; i < length;) {
        u8 code = packet[i++];
        if (code == END) return (seen & 1u) != 0;
        if (!code) continue;
        if (i == length) return false;
        u8 size = packet[i++];
        if (size > length - i) return false;
        const u8 *value = packet + i;
        i += size;
        if (code == MESSAGE_TYPE) {
            if (size != 1 || (seen & 1u)) return false;
            seen |= 1u;
            options->type = value[0];
            continue;
        }
        u32 *field;
        unsigned bit;
        switch (code) {
        case SUBNET: field = &options->mask; bit = 1u << 1; break;
        case ROUTER: field = &options->router; bit = 1u << 2; options->has_router = true; break;
        case DNS: field = &options->dns; bit = 1u << 3; options->has_dns = true; break;
        case SERVER_ID: field = &options->server; bit = 1u << 4; break;
        case LEASE_TIME: field = &options->lease; bit = 1u << 5; break;
        case RENEWAL_TIME: field = &options->renewal; bit = 1u << 6; break;
        case REBIND_TIME: field = &options->rebind; bit = 1u << 7; break;
        default: continue;
        }
        bool list = code == ROUTER || code == DNS;
        if ((seen & bit) || size < 4 || (list ? size % 4 : size != 4)) return false;
        seen |= bit;
        *field = net_read32(value);
        if (code == SUBNET && !*field) return false;
    }
    return false;
}

static bool unicast(u32 address) {
    u32 first = address >> 24;
    return first && first != 127 && first < 224;
}

static void clear_lease(void) {
    if (client.lease.network.address) net64_clear_config();
    client.lease = (struct dhcp64_lease){0};
}

static void cooldown(u64 now) {
    client.state = COOLDOWN;
    client.next = now + 4 * SECOND;
}

static void begin(u64 now, enum dhcp_state state) {
    client.state = state;
    client.xid = random_word();
    client.start = client.next = now;
    client.deadline = now + 31 * SECOND;
    client.attempts = 0;
}

static bool install_lease(const struct dhcp_options *opt, u32 address, u64 now) {
    struct net64_config previous = client.lease.network;
    struct net64_config network = {
        .address = address,
        .mask = opt->mask ? opt->mask : previous.mask,
        .gateway = opt->has_router ? opt->router : previous.gateway,
    };
    if (!opt->lease || !network.mask) return false;
    u64 length = (u64)opt->lease * SECOND;
    if (opt->lease != BROADCAST && now - client.request_sent >= length) return false;
    if ((network.address != previous.address || network.mask != previous.mask || network.gateway != previous.gateway) &&
        !net64_configure(network)) return false;
    client.lease = (struct dhcp64_lease){network, opt->has_dns ? opt->dns : client.lease.dns, opt->lease};
    client.server = opt->server;
    client.state = BOUND;
    if (opt->lease == 0xffffffffu) {
        client.renewal = client.rebind = client.expires = (u64)-1;
        return true;
    }
    u64 renewal = (u64)opt->renewal * SECOND, rebind = (u64)opt->rebind * SECOND;
    if (!renewal || renewal >= length) renewal = length / 2;
    if (rebind <= renewal || rebind >= length) rebind = length - length / 8;
    if (renewal >= rebind) renewal = length / 2;
    client.renewal = client.request_sent + renewal;
    client.rebind = client.request_sent + rebind;
    client.expires = client.request_sent + length;
    return true;
}

static void receive(void *context, u32 source, u32 dest, u8 protocol, const u8 *packet, u32 length) {
    (void)protocol;
    if (!client.attempts || (client.state != SELECTING && client.state != REQUESTING &&
        client.state != RENEWING && client.state != REBINDING)) return;
    u32 udp_length = net_read16(packet + 4);
    if (udp_length > length || udp_length < UDP_BYTES + BOOTP_BYTES + 1 ||
        (net_read16(packet + 6) && net64_checksum(packet, udp_length, udp_sum(source, dest, udp_length)))) return;
    const u8 *bootp = packet + UDP_BYTES;
    if (bootp[0] != 2 || bootp[1] != 1 || bootp[2] != sizeof(client.mac) ||
        net_read32(bootp + 4) != client.xid || net_read32(bootp + 236) != COOKIE) return;
    for (unsigned i = 0; i < sizeof(client.mac); ++i)
        if (bootp[28 + i] != client.mac[i]) return;
    struct dhcp_options options = {0};
    if (!parse_options(bootp + BOOTP_BYTES, udp_length - UDP_BYTES - BOOTP_BYTES, &options) ||
        !unicast(options.server)) return;
    u32 address = net_read32(bootp + 16);
    u64 now = *(const u64 *)context;
    if (client.state == SELECTING) {
        if (options.type != OFFER || !unicast(address) || (dest != BROADCAST && dest != address)) return;
        client.selected_ip = address;
        client.server = options.server;
        client.state = REQUESTING;
        client.attempts = 0;
        client.next = now;
        client.deadline = now + 31 * SECOND;
        return;
    }
    if (client.state != REBINDING && options.server != client.server) return;
    if (options.type == NAK && dest == BROADCAST) {
        clear_lease();
        cooldown(now);
        return;
    }
    u32 expected = client.state == REQUESTING ? client.selected_ip : client.lease.network.address;
    if (options.type == ACK && address == expected && (dest == BROADCAST || dest == address))
        install_lease(&options, address, now);
}

bool dhcp64_start(u32 seed) {
    if (client.state != OFF) return true;
    if (!net64_enable_dhcp(receive)) return false;
    e1000_mac(client.mac);
    client.random = seed ? seed : 1;
    client.state = WAIT_LINK;
    return true;
}

bool dhcp64_poll(u64 now, net64_receiver receiver) {
    if (client.state == OFF) return false;
    if (!e1000_link()) {
        clear_lease();
        client.state = WAIT_LINK;
        return false;
    }
    if (client.state == WAIT_LINK || (client.state == COOLDOWN && now >= client.next)) {
        begin(now, SELECTING);
    } else if (client.lease.network.address && now >= client.expires) {
        clear_lease();
        begin(now, SELECTING);
    } else if (client.state == BOUND && now >= client.renewal) {
        begin(now, RENEWING);
    }
    if (client.state == RENEWING && now >= client.rebind) {
        client.state = REBINDING;
        client.next = now;
    }
    bool acquiring = client.state == SELECTING || client.state == REQUESTING;
    if (acquiring && (now >= client.deadline || (client.attempts >= 3 && now >= client.next))) {
        cooldown(now);
        return false;
    }
    net64_poll(now, receiver, NULL);
    acquiring = client.state == SELECTING || client.state == REQUESTING;
    if ((acquiring || client.state == RENEWING || client.state == REBINDING) && now >= client.next) {
        if (send_message(now)) {
            if (client.state != SELECTING) client.request_sent = now;
            unsigned shift = client.attempts < 2 ? client.attempts : 2;
            client.next = now + (4ull << shift) * SECOND + random_word() % (SECOND / 2);
            if (client.attempts < 3) ++client.attempts;
        } else {
            client.next = now + SECOND / 10;
        }
    }
    return acquiring;
}

bool dhcp64_get_lease(struct dhcp64_lease *result) {
    if (!client.lease.network.address) return false;
    *result = client.lease;
    return true;
}
