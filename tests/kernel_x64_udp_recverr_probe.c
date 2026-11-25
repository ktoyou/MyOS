typedef unsigned long word;
typedef unsigned int u32;
typedef unsigned short u16;

enum { INET = 2, DGRAM = 2, IPPROTO_IP = 0, IP_RECVERR = 11, SOL_SOCKET = 1, SO_ERROR = 4,
       ENETUNREACH = 101, ECONNREFUSED = 111, EAGAIN = 11, POLLERR = 8,
       MSG_DONTWAIT = 0x40, MSG_ERRQUEUE = 0x2000, SO_EE_ORIGIN_ICMP = 2 };
enum { ENABLED_PORT = 42003, DISABLED_PORT = 42004, REMOTE_PORT = 42005 };

struct address {
    u16 family, port;
    u32 ip;
    unsigned char padding[8];
};
struct poll_entry { int fd; short events, revents; };
struct vector { void *base; word length; };
struct message {
    struct address *name;
    u32 name_length;
    struct vector *vectors;
    word vector_count;
    void *control;
    word control_length;
    u32 flags;
};
struct error_control {
    word length;
    int level, type;
    u32 error;
    unsigned char origin, icmp_type, icmp_code, padding;
    u32 info, data;
    struct address offender;
};

static const char enabled_data[] = "myos-recverr:enabled\xd1", disabled_data[] = "myos-recverr:disabled\xd2";

static long call6(word number, word a, word b, word c, word d, word e, word f) {
    register word arg4 __asm__("r10") = d;
    register word arg5 __asm__("r8") = e;
    register word arg6 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c), "r"(arg4), "r"(arg5), "r"(arg6)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long call(word number, word a, word b, word c) {
    return call6(number, a, b, c, 0, 0, 0);
}

static struct address address(u32 ip, u16 port) {
    return (struct address){.family = INET, .port = __builtin_bswap16(port), .ip = __builtin_bswap32(ip)};
}

static int equal(const char *a, const char *b, word length) {
    for (word i = 0; i < length; ++i)
        if (a[i] != b[i]) return 0;
    return 1;
}

static int same_address(const struct address *a, const struct address *b) {
    return a->family == b->family && a->ip == b->ip && a->port == b->port;
}

static int option_is(long fd, word level, word name, int expected) {
    int value = -1;
    u32 size = sizeof(value);
    return !call6(55, fd, level, name, (word)&value, (word)&size, 0) && value == expected && size == sizeof(value);
}

static int set_recverr(long fd, int value) {
    return !call6(54, fd, IPPROTO_IP, IP_RECVERR, (word)&value, sizeof(value), 0);
}

static int marker(const char *message, word length) {
    return call(1, 1, (word)message, length) == (long)length;
}

static long open_bound(u16 port) {
    struct address local = address(0, port);
    long fd = call(41, INET, DGRAM, 0);
    return fd < 0 || call(49, fd, (word)&local, sizeof(local)) ? -1 : fd;
}

static int check_recverr(void) {
    const struct address remote = address(0x0a2c0051u, REMOTE_PORT), offender = address(0x0a2c0052u, 0);
    long enabled = open_bound(ENABLED_PORT), disabled = open_bound(DISABLED_PORT);
    static const char ready[] = "UDP RECVERR guest ready\n", sent[] = "UDP RECVERR probes sent\n";
    if (enabled < 0 || disabled < 0 || !option_is(enabled, IPPROTO_IP, IP_RECVERR, 0) ||
        !set_recverr(enabled, 1) || !option_is(enabled, IPPROTO_IP, IP_RECVERR, 1) ||
        !set_recverr(disabled, 1) || !set_recverr(disabled, 0) || !option_is(disabled, IPPROTO_IP, IP_RECVERR, 0) ||
        !marker(ready, sizeof(ready) - 1)) return 1;

    long result = -ENETUNREACH;
    for (unsigned i = 0; i < 240 && result == -ENETUNREACH; ++i) {
        if (call(7, 0, 0, 50)) return 2;
        result = call(42, enabled, (word)&remote, sizeof(remote));
    }
    if (result || call(1, enabled, (word)enabled_data, sizeof(enabled_data) - 1) != (long)(sizeof(enabled_data) - 1) ||
        call6(44, disabled, (word)disabled_data, sizeof(disabled_data) - 1, 0, (word)&remote, sizeof(remote)) !=
        (long)(sizeof(disabled_data) - 1) || !marker(sent, sizeof(sent) - 1)) return 2;

    struct poll_entry poll[] = {{.fd = (int)enabled}, {.fd = (int)disabled}};
    if (call(7, (word)poll, 2, (word)-1) != 1 || poll[0].revents != POLLERR || poll[1].revents ||
        !option_is(enabled, SOL_SOCKET, SO_ERROR, ECONNREFUSED) ||
        !option_is(enabled, SOL_SOCKET, SO_ERROR, 0) || !option_is(disabled, SOL_SOCKET, SO_ERROR, 0) ||
        call(7, (word)poll, 2, 0) != 1 || poll[0].revents != POLLERR || poll[1].revents) return 3;

    char bytes[64];
    struct address name = {0};
    struct vector vector = {.base = bytes, .length = sizeof(bytes)};
    struct error_control control = {0};
    struct message message = {.name = &name, .name_length = sizeof(name), .vectors = &vector, .vector_count = 1,
                              .control = &control, .control_length = sizeof(control)};
    if (call(47, enabled, (word)&message, MSG_ERRQUEUE) != (long)(sizeof(enabled_data) - 1) ||
        !equal(bytes, enabled_data, sizeof(enabled_data) - 1) || message.flags != MSG_ERRQUEUE ||
        message.name_length != sizeof(name) || !same_address(&name, &remote) ||
        message.control_length != sizeof(control) || control.length != sizeof(control) ||
        control.level != IPPROTO_IP || control.type != IP_RECVERR || control.error != ECONNREFUSED ||
        control.origin != SO_EE_ORIGIN_ICMP || control.icmp_type != 3 || control.icmp_code != 3 ||
        control.padding || control.info || control.data || !same_address(&control.offender, &offender)) return 4;

    if (call(47, enabled, (word)&message, MSG_ERRQUEUE | MSG_DONTWAIT) != -EAGAIN ||
        call(47, disabled, (word)&message, MSG_ERRQUEUE | MSG_DONTWAIT) != -EAGAIN ||
        call(7, (word)poll, 2, 0) || poll[0].revents || poll[1].revents ||
        !option_is(enabled, SOL_SOCKET, SO_ERROR, 0) || call(3, enabled, 0, 0) || call(3, disabled, 0, 0)) return 5;
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    int result = check_recverr();
    if (!result) {
        static const char passed[] = "UDP RECVERR guest PASS\n";
        if (!marker(passed, sizeof(passed) - 1)) result = 6;
    }
    call(60, result, 0, 0);
    __builtin_trap();
}
