#include "linux.h"
#include "dhcp.h"
#include "e1000.h"

static bool started, waiting;
static u64 next_poll;
static struct dhcp64_lease reported;

bool linux64_net_init(void) {
    if (!e1000_init()) return false;
    u32 seed;
    if (linux64_random_bytes(&seed, sizeof(seed)) == sizeof(seed))
        started = dhcp64_start(seed);
    return true;
}

static void print_text(const char *text) {
    while (*text) kernel64_serial_char(*text++);
}

static void print_address(u32 address) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        unsigned octet = (address >> shift) & 255;
        if (octet >= 100) kernel64_serial_char('0' + octet / 100);
        if (octet >= 10) kernel64_serial_char('0' + octet / 10 % 10);
        kernel64_serial_char('0' + octet % 10);
        if (shift) kernel64_serial_char('.');
    }
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

bool linux64_net_poll(void) {
    u64 now;
    if (!started || !linux64_monotonic_ns(&now)) return false;
    if (now >= next_poll) {
        next_poll = now + 10000000ull;
        waiting = dhcp64_poll(now);
        report_lease();
    }
    return waiting;
}
