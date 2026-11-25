typedef unsigned long word;
typedef unsigned int u32;
typedef unsigned short u16;

enum { INET = 2, STREAM = 1, NONBLOCK = 0x800, EAGAIN = 11, EINPROGRESS = 115,
       ENETUNREACH = 101, EPOLLIN = 1, EPOLLOUT = 4, SOL_SOCKET = 1, SO_ERROR = 4,
       LOCAL_PORT = 41997, SERVER_PORT = 41998, TX_BYTES = 5003, RX_BYTES = 7001 };

struct address {
    u16 family, port;
    u32 ip;
    unsigned char padding[8];
};
struct epoll_event { u32 events; word data; } __attribute__((packed));

static long call(word number, word a, word b, word c, word d, word e) {
    register word arg4 __asm__("r10") = d;
    register word arg5 __asm__("r8") = e;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c), "r"(arg4), "r"(arg5)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static struct address address(u32 ip, u16 port) {
    return (struct address){.family = INET, .port = __builtin_bswap16(port), .ip = __builtin_bswap32(ip)};
}

static int mark(const char *message, word length) {
    return call(1, 1, (word)message, length, 0, 0) == (long)length;
}

static int watch(long epoll, long fd, u32 events, word operation) {
    struct epoll_event event = {.events = events, .data = 0x201};
    return !call(233, epoll, operation, fd, (word)&event, 0);
}

static int wait_for(long epoll, u32 mask) {
    struct epoll_event event;
    return call(232, epoll, (word)&event, 1, 5000, 0) == 1 &&
           (event.events & mask) && event.data == 0x201;
}

static int write_all(long fd, long epoll, const void *buffer, word length) {
    const unsigned char *data = buffer;
    for (word sent = 0; sent < length;) {
        long result = call(1, fd, (word)(data + sent), length - sent, 0, 0);
        if (result > 0) sent += (word)result;
        else if (result != -EAGAIN || !wait_for(epoll, EPOLLOUT)) return 0;
    }
    return 1;
}

static int check_tcp(void) {
    const struct address local = address(0, LOCAL_PORT), remote = address(0x0a2c0051u, SERVER_PORT);
    long fd = call(41, INET, STREAM | NONBLOCK, 0, 0, 0);
    long epoll = call(291, 0, 0, 0, 0, 0);
    static const char ready[] = "TCP guest ready\n", established[] = "TCP guest connected\n";
    static const char peer_eof[] = "TCP guest received EOF\n", trailer[] = "myos-tcp:after-peer-fin\xa1";
    if (fd < 0 || epoll < 0 || call(49, fd, (word)&local, sizeof(local), 0, 0) ||
        !mark(ready, sizeof(ready) - 1)) return 1;

    long result = -ENETUNREACH;
    for (unsigned i = 0; i < 240 && result == -ENETUNREACH; ++i) {
        if (call(7, 0, 0, 50, 0, 0)) return 2;
        result = call(42, fd, (word)&remote, sizeof(remote), 0, 0);
    }
    int error = -1;
    u32 size = sizeof(error);
    if (result != -EINPROGRESS || !watch(epoll, fd, EPOLLOUT, 1) || !wait_for(epoll, EPOLLOUT) ||
        call(55, fd, SOL_SOCKET, SO_ERROR, (word)&error, (word)&size) || error || size != sizeof(error) ||
        !mark(established, sizeof(established) - 1)) return 3;

    unsigned char data[RX_BYTES];
    for (word i = 0; i < TX_BYTES; ++i) data[i] = (unsigned char)(i * 17 + 0x39);
    if (!write_all(fd, epoll, data, TX_BYTES) || !watch(epoll, fd, EPOLLIN, 3)) return 4;

    word received = 0;
    for (;;) {
        long count = call(0, fd, (word)data, sizeof(data), 0, 0);
        if (!count) break;
        if (count == -EAGAIN && wait_for(epoll, EPOLLIN)) continue;
        if (count < 0 || (word)count > RX_BYTES - received) return 5;
        for (word i = 0; i < (word)count; ++i)
            if (data[i] != (unsigned char)((received + i) * 29 + 0x71)) return 5;
        received += (word)count;
    }

    if (received != RX_BYTES || !mark(peer_eof, sizeof(peer_eof) - 1) ||
        !watch(epoll, fd, EPOLLOUT, 3) || !write_all(fd, epoll, trailer, sizeof(trailer) - 1) ||
        call(48, fd, 1, 0, 0, 0) || call(3, fd, 0, 0, 0, 0) || call(3, epoll, 0, 0, 0, 0)) return 6;
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    int status = check_tcp();
    if (!status) {
        static const char passed[] = "TCP guest PASS\n";
        if (!mark(passed, sizeof(passed) - 1)) status = 7;
        /* Завершение PID 1 останавливает ядро, а закрытый TCP ещё ждёт ACK и FIN. */
        else call(7, 0, 0, 20000, 0, 0);
    }
    call(60, status, 0, 0, 0, 0);
    __builtin_trap();
}
