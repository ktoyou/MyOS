#include "linux.h"
#include "dhcp.h"
#include "ethernet.h"
#include "net_bytes.h"
#include "tcp.h"

enum { ICMP = 1, TCP = 6, UDP = 17, IPV4_DONT_FRAGMENT = 0x4000 };

static bool started, waiting;
static u64 next_poll;
static struct dhcp64_lease reported;

bool linux64_net_init(void) {
    if (!ethernet64_name()) return false;
    u32 seed;
    if (linux64_random_bytes(&seed, sizeof(seed)) == sizeof(seed))
        started = dhcp64_start(seed);
    return true;
}

static void print_text(const char *text) {
    while (*text) kernel64_serial_char(*text++);
}

static char *format_address(u32 address, char *buffer) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        unsigned octet = (address >> shift) & 255;
        if (octet >= 100) *buffer++ = '0' + octet / 100;
        if (octet >= 10) *buffer++ = '0' + octet / 10 % 10;
        *buffer++ = '0' + octet % 10;
        if (shift) *buffer++ = '.';
    }
    return buffer;
}

static void print_address(u32 address) {
    char buffer[16];
    *format_address(address, buffer) = 0;
    print_text(buffer);
}

u32 linux64_net_dns_server(void) {
    struct dhcp64_lease lease;
    return dhcp64_get_lease(&lease) ? lease.dns : 0;
}

uptr linux64_net_resolver_config(u32 server, char *buffer) {
    static const char nameserver[] = "nameserver ";
    /* glibc иначе объединяет запросы A и AAAA в sendmmsg, которого пока нет. */
    static const char options[] = "\noptions single-request\n";
    _Static_assert(sizeof(nameserver) - 1 + 15 + sizeof(options) - 1 <= LINUX64_RESOLVER_CONFIG_MAX,
                   "Linux x86-64 resolver config");
    char *next = buffer;
    for (unsigned i = 0; i < sizeof(nameserver) - 1; ++i) *next++ = nameserver[i];
    next = format_address(server, next);
    for (unsigned i = 0; i < sizeof(options) - 1; ++i) *next++ = options[i];
    return (uptr)(next - buffer);
}

static void report_lease(void) {
    struct dhcp64_lease lease;
    if (!dhcp64_get_lease(&lease)) {
        if (reported.network.address) print_text("MyOS x86-64: DHCP lease lost\n");
        reported = (struct dhcp64_lease){0};
        return;
    }
    if (lease.network.address == reported.network.address && lease.network.mask == reported.network.mask &&
        lease.network.gateway == reported.network.gateway && lease.dns == reported.dns) return;
    reported = lease;
    print_text("MyOS x86-64: DHCP address=");
    print_address(lease.network.address);
    print_text(" mask=");
    print_address(lease.network.mask);
    print_text(" gateway=");
    print_address(lease.network.gateway);
    print_text(" dns=");
    print_address(lease.dns);
    print_text("\n");
}

static void receive_icmp(u32 source, u32 destination, const u8 *icmp, u32 length) {
    enum { ICMP_HEADER = 8, UDP_HEADER = 8, IPV4_HEADER = 20 };
    if (length < ICMP_HEADER + IPV4_HEADER + UDP_HEADER ||
        (icmp[0] != 3 && icmp[0] != 11 && icmp[0] != 12) || net64_checksum(icmp, length, 0)) return;

    const u8 *quoted = icmp + ICMP_HEADER;
    u32 available = length - ICMP_HEADER;
    u32 header = (quoted[0] & 15u) * 4, total = net_read16(quoted + 2);
    if (quoted[0] >> 4 != 4 || header < IPV4_HEADER ||
        available < header + UDP_HEADER || total < header + UDP_HEADER ||
        (net_read16(quoted + 6) & ~IPV4_DONT_FRAGMENT) || quoted[9] != UDP ||
        net_read32(quoted + 12) != destination || net64_checksum(quoted, header, 0)) return;

    /* RFC 4884 отделяет расширения ICMP от процитированного пакета. */
    if (icmp[5]) {
        u32 quote_length = (u32)icmp[5] * 4;
        if (quote_length < header + UDP_HEADER || quote_length > available) return;
        available = quote_length;
    }
    const u8 *udp = quoted + header;
    u32 udp_length = net_read16(udp + 4);
    if (udp_length < UDP_HEADER || udp_length > total - header) return;
    u32 present = available - header;
    if (present > udp_length) present = udp_length;
    u32 info = icmp[0] == 3 && icmp[1] == 4 ? net_read16(icmp + 6) : 0;
    linux64_udp_icmp_error(source, destination, net_read32(quoted + 16),
                          net_read16(udp), net_read16(udp + 2), icmp[0], icmp[1], info,
                          udp + UDP_HEADER, present - UDP_HEADER);
}

static void receive(void *context, u32 source, u32 destination, u8 protocol, const u8 *data, u32 length) {
    if (protocol == ICMP) receive_icmp(source, destination, data, length);
    else if (protocol == TCP) tcp64_input(*(const u64 *)context, source, destination, data, length);
    else if (protocol == UDP) linux64_udp_receive(context, source, destination, protocol, data, length);
}

bool linux64_net_poll(void) {
    u64 now;
    if (!started || !linux64_monotonic_ns(&now)) return false;
    if (now >= next_poll) {
        next_poll = now + 10000000ull;
        bool dhcp_waiting = dhcp64_poll(now, receive);
        bool udp_waiting = linux64_udp_flush(now);
        waiting = tcp64_tick(now) || udp_waiting || dhcp_waiting;
        report_lease();
    }
    return waiting;
}
