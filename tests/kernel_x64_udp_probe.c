typedef unsigned long word;
typedef unsigned int u32;
typedef unsigned short u16;

enum { INET = 2, DGRAM = 2, EADDRINUSE = 98, ENETUNREACH = 101, ECONNREFUSED = 111, EAGAIN = 11,
       MSG_PEEK = 2, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40, EPOLLIN = 1 };
enum { LOCAL_PORT = 41993, PEER_PORT = 41994, LOOP_PORT = 41995, CLOSE_PORT = 41996 };

struct address {
    u16 family, port;
    u32 ip;
    unsigned char padding[8];
};
struct epoll_event { u32 events; word data; } __attribute__((packed));
struct pollfd { int fd; short events, revents; };
struct vector { const void *base; word length; };
struct message {
    struct address *name;
    u32 name_length;
    struct vector *vectors;
    word vector_count;
    void *control;
    word control_length;
    u32 flags;
};

static const char first[] = "myos-udp:sendto\x91", first_reply[] = "myos-udp:peek\x94",
                  second_reply[] = "myos-udp:next\x95", connected[] = "myos-udp:sendmsg\x96",
                  connected_reply[] = "myos-udp:recvmsg\x97";

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

static int equal(const char *a, const char *b, word size) {
    for (word i = 0; i < size; ++i)
        if (a[i] != b[i]) return 0;
    return 1;
}

static int same_address(const struct address *a, const struct address *b) {
    return a->family == b->family && a->port == b->port && a->ip == b->ip;
}

static long send_to(long fd, const char *data, word bytes, const struct address *peer) {
    return call6(44, fd, (word)data, bytes, 0, (word)peer, sizeof(*peer));
}

static int receive_from(long fd, char *data, word bytes, word flags, const struct address *peer, word expected) {
    struct address source = {0};
    u32 size = sizeof(source);
    return call6(45, fd, (word)data, bytes, flags, (word)&source, (word)&size) == (long)expected &&
           size == sizeof(source) && same_address(&source, peer);
}

static int wait_input(long epoll) {
    struct epoll_event event;
    return call6(232, epoll, (word)&event, 1, (word)-1, 0, 0) == 1 && event.events == EPOLLIN && event.data == 0x199;
}

static int poll_epoll(long epoll) {
    struct pollfd fd = {(int)epoll, EPOLLIN, 0};
    return call(7, (word)&fd, 1, (word)-1) == 1 && fd.revents == EPOLLIN;
}

static int check_loopback(void) {
    const struct address target = address(0x7f000001u, LOOP_PORT);
    long sender = call(41, INET, DGRAM, 0), listener = call(41, INET, DGRAM, 0);
    if (sender < 0 || listener < 0 || call(49, listener, (word)&target, sizeof(target)) ||
        send_to(sender, "loopback", 8, &target) != 8) return 0;
    struct address source = {0};
    u32 size = sizeof(source);
    if (call(51, sender, (word)&source, (word)&size) || size != sizeof(source) ||
        source.family != INET || !source.port) return 0;
    source.ip = target.ip;
    char data[8];
    if (!receive_from(listener, data, sizeof(data), MSG_DONTWAIT, &source, sizeof(data)) ||
        !equal(data, "loopback", sizeof(data)) || call(42, listener, (word)&source, sizeof(source))) return 0;
    long other = call(41, INET, DGRAM, 0);
    if (other < 0 || send_to(other, "wrong peer", 10, &target) != 10 ||
        call6(45, listener, (word)data, sizeof(data), MSG_DONTWAIT, 0, 0) != -EAGAIN) return 0;
    if (send_to(sender, "", 0, &target) || call(0, listener, (word)data, 0) ||
        !receive_from(listener, data, sizeof(data), MSG_DONTWAIT, &source, 0)) return 0;
    if (call(42, sender, (word)&target, sizeof(target)) || call(3, listener, 0, 0) ||
        call(1, sender, (word)"closed", 6) != 6 ||
        call(0, sender, (word)data, sizeof(data)) != -ECONNREFUSED) return 0;
    return !call(3, other, 0, 0) && !call(3, sender, 0, 0);
}

static int check_udp(void) {
    const struct address local = address(0, LOCAL_PORT), peer = address(0x0a2c0051u, PEER_PORT);
    long fd = call(41, INET, DGRAM, 0), conflict = call(41, INET, DGRAM, 0);
    long epoll = call(291, 0, 0, 0);
    struct epoll_event event = {.events = EPOLLIN, .data = 0x199};
    static const char ready[] = "UDP guest ready\n";
    if (fd < 0 || conflict < 0 || epoll < 0 || call(49, fd, (word)&local, sizeof(local)) ||
        call(49, conflict, (word)&local, sizeof(local)) != -EADDRINUSE ||
        send_to(fd, first, sizeof(first) - 1, &peer) != -ENETUNREACH ||
        call6(233, epoll, 1, fd, (word)&event, 0, 0) ||
        call(1, 1, (word)ready, sizeof(ready) - 1) != sizeof(ready) - 1) return 1;

    long result = -ENETUNREACH;
    for (unsigned i = 0; i < 240 && (result == -ENETUNREACH || result == -EAGAIN); ++i) {
        if (call(7, 0, 0, 50)) return 2;
        result = send_to(fd, first, sizeof(first) - 1, &peer);
    }
    char data[64];
    if (result != sizeof(first) - 1 || !poll_epoll(epoll) || !wait_input(epoll) ||
        !receive_from(fd, data, 3, MSG_PEEK | MSG_TRUNC, &peer, sizeof(first_reply) - 1) ||
        !equal(data, first_reply, 3) || !receive_from(fd, data, 4, 0, &peer, 4) ||
        !equal(data, first_reply, 4) || !wait_input(epoll) ||
        !receive_from(fd, data, sizeof(data), 0, &peer, sizeof(second_reply) - 1) ||
        !equal(data, second_reply, sizeof(second_reply) - 1) ||
        call6(45, fd, (word)data, sizeof(data), MSG_DONTWAIT, 0, 0) != -EAGAIN) return 3;

    struct vector send[] = {{connected, 5}, {connected + 5, sizeof(connected) - 6}};
    struct message outgoing = {.vectors = send, .vector_count = 2};
    struct address source = {0};
    struct vector recv[] = {{data, 3}, {data + 3, sizeof(data) - 3}};
    struct message incoming = {.name = &source, .name_length = sizeof(source), .vectors = recv, .vector_count = 2};
    if (call(42, fd, (word)&peer, sizeof(peer)) ||
        call(46, fd, (word)&outgoing, 0) != sizeof(connected) - 1 || !wait_input(epoll) ||
        call(47, fd, (word)&incoming, 0) != sizeof(connected_reply) - 1 || incoming.flags ||
        incoming.name_length != sizeof(source) || !same_address(&source, &peer) ||
        !equal(data, connected_reply, sizeof(connected_reply) - 1)) return 4;

    if (call(3, fd, 0, 0) || call(49, conflict, (word)&local, sizeof(local)) ||
        call(3, conflict, 0, 0) || call(3, epoll, 0, 0) || !check_loopback()) return 5;
    return 0;
}

static int check_close_queue(void) {
    const struct address local = address(0, CLOSE_PORT), peer = address(0x0a2c0052u, PEER_PORT);
    static const char queued[] = "myos-udp:closed\x98", marker[] = "UDP close queued\n";
    long fd = call(41, INET, DGRAM, 0);
    if (fd < 0 || call(49, fd, (word)&local, sizeof(local)) ||
        send_to(fd, queued, sizeof(queued) - 1, &peer) != (long)(sizeof(queued) - 1) ||
        call(3, fd, 0, 0) || call(1, 1, (word)marker, sizeof(marker) - 1) != (long)(sizeof(marker) - 1))
        return 0;
    return !call(7, 0, 0, 2000);
}

__attribute__((noreturn)) void _start(void) {
    int status = check_udp();
    if (!status && !check_close_queue()) status = 7;
    if (!status) {
        static const char passed[] = "UDP guest PASS\n";
        if (call(1, 1, (word)passed, sizeof(passed) - 1) != sizeof(passed) - 1) status = 6;
    }
    call(60, status, 0, 0);
    __builtin_trap();
}
