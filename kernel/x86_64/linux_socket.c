#include "linux_task.h"
#include "paging.h"
#include "net.h"
#include "net_bytes.h"
#include "tcp.h"

enum {
    EBADF = 9, EAGAIN = 11, ENOMEM = 12, EFAULT = 14, EINVAL = 22, ENFILE = 23, EPIPE = 32,
    EMSGSIZE = 90, EPROTONOSUPPORT = 93, ESOCKTNOSUPPORT = 94, EOPNOTSUPP = 95,
    EAFNOSUPPORT = 97, ENOPROTOOPT = 92, ECONNRESET = 104, EISCONN = 106, ENOTCONN = 107,
    ECONNREFUSED = 111, EALREADY = 114, EINPROGRESS = 115,
    EDESTADDRREQ = 89, EADDRINUSE = 98, EADDRNOTAVAIL = 99, ENETDOWN = 100,
    ENETUNREACH = 101, EHOSTUNREACH = 113,
    AF_UNIX = 1, AF_INET = 2, SOCK_STREAM = 1, SOCK_DGRAM = 2, SOCK_SEQPACKET = 5,
    SOCK_MAX = 11, SOCK_TYPE_MASK = 0xf, IPPROTO_TCP = 6, IPPROTO_UDP = 17, TCP_NODELAY = 1,
    SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000,
    SHUT_RD = 0, SHUT_WR = 1, SHUT_RDWR = 2,
    SOL_SOCKET = 1, SO_TYPE = 3, SO_ERROR = 4, SO_PASSCRED = 16, SO_PEERCRED = 17,
    SO_PROTOCOL = 38, SO_DOMAIN = 39,
    SCM_RIGHTS = 1, SCM_CREDENTIALS = 2,
    MSG_OOB = 1, MSG_PEEK = 2, MSG_CTRUNC = 8, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40,
    MSG_EOR = 0x80, MSG_NOSIGNAL = 0x4000, MSG_CMSG_CLOEXEC = 0x40000000,
    MAX_IOV = 64, MAX_QUEUED = 32, MAX_BACKLOG = 31, SCM_MAX_FD = 253,
    UDP_HEADER = 8, UDP_MAX = 1472, UDP_TX_LIMIT = 4, UDP_FIRST_PORT = 49152,
};

_Static_assert(__builtin_offsetof(struct linux64_sockaddr, path) == 2, "Linux sockaddr_un path");

struct iovec {
    uptr base, length;
};

struct msghdr {
    uptr name;
    u32 name_length, name_padding;
    uptr iov, iov_count, control, control_length;
    u32 flags, flags_padding;
};

struct identity {
    i32 pid;
    u32 uid, gid;
};

struct cmsghdr {
    uptr length;
    i32 level, type;
};

struct credentials {
    uptr length;
    i32 level, type;
    struct identity sender;
};

#define CRED_LENGTH (__builtin_offsetof(struct credentials, sender) + sizeof(struct identity))
_Static_assert(sizeof(struct msghdr) == 56 && sizeof(struct iovec) == 16, "Linux x86-64 msghdr");
_Static_assert(CRED_LENGTH == 28 && sizeof(struct credentials) == 32, "Linux x86-64 credentials");
_Static_assert(sizeof(struct cmsghdr) == 16, "Linux x86-64 cmsghdr");

struct linux64_scm_rights {
    struct linux64_scm_rights *next;
    unsigned count;
    bool queued;
    struct file_handle *files[SCM_MAX_FD];
};

_Static_assert(sizeof(struct linux64_scm_rights) <= PMM_PAGE_SIZE, "SCM rights page");

struct packet {
    struct packet *next;
    struct linux64_pid *sender;
    u32 length, rights_phys;
    union {
        struct { u32 uid, gid; };
        struct { u32 ip; u16 port, source_port; } datagram;
    };
    u8 bytes[];
};

#define MAX_PACKET (PMM_PAGE_SIZE - sizeof(struct packet))

struct peer_snapshot {
    struct linux64_pid *pid;
    u32 uid, gid;
};

struct linux64_socket {
    struct tcp64_connection *tcp;
    struct linux64_socket *peer;
    struct linux64_socket *accept_head, *accept_tail, *accept_next;
    struct packet *head, *tail;
    struct packet *udp_tx_head, *udp_tx_tail;
    struct linux64_udp_address local, remote;
    struct peer_snapshot peer_credentials;
    u64 inode;
    unsigned queued, head_offset, backlog, pending;
    unsigned udp_tx_count;
    u32 udp_tx_source, tcp_source;
    i32 udp_error;
    u8 type;
    bool open, passcred, reset, read_shutdown, write_shutdown, listening, scm_marked, inet, inet_bound;
    char name[LINUX64_UNIX_PATH_LIMIT + 1];
};

/* Один конец может оставаться открытым после закрытия его пары. */
static struct linux64_socket pairs[LINUX64_OPEN_FILE_COUNT][2];
static struct linux64_socket *scm_mark_queue[sizeof(pairs) / sizeof(pairs[0][0])];
static unsigned scm_mark_count;

static struct peer_snapshot current_credentials(void) {
    return (struct peer_snapshot){linux64_current->process->pid_identity, LINUX64_UID, LINUX64_GID};
}

static void store_credentials(struct linux64_socket *socket, struct peer_snapshot snapshot) {
    linux64_pid_retain(snapshot.pid);
    linux64_pid_release(socket->peer_credentials.pid);
    socket->peer_credentials = snapshot;
}

static struct linux64_socket *free_pair(void) {
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i)
        if (!pairs[i][0].open && !pairs[i][1].open && !pairs[i][0].udp_tx_head) return pairs[i];
    return NULL;
}

long linux64_socket_create(i32 domain, u32 type, i32 protocol, struct linux64_socket **socket) {
    u32 base = type & SOCK_TYPE_MASK;
    if (type & ~(SOCK_TYPE_MASK | SOCK_CLOEXEC | SOCK_NONBLOCK)) return -EINVAL;
    if (domain != AF_UNIX && domain != AF_INET) return -EAFNOSUPPORT;
    if (base >= SOCK_MAX) return -EINVAL;
    if (domain == AF_INET) {
        if (base != SOCK_DGRAM && base != SOCK_STREAM) return -ESOCKTNOSUPPORT;
        if (protocol && protocol != (base == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP)) return -EPROTONOSUPPORT;
    } else {
        if (protocol && protocol != AF_UNIX) return -EPROTONOSUPPORT;
        if (base != SOCK_STREAM) return -ESOCKTNOSUPPORT;
    }
    struct linux64_socket *slot = free_pair();
    if (!slot) return -ENFILE;
    *slot = (struct linux64_socket){.type = (u8)base, .open = true, .inet = domain == AF_INET};
    *socket = slot;
    return 0;
}

long linux64_socket_pair(i32 domain, u32 type, i32 protocol, struct linux64_socket *ends[2]) {
    if (domain != AF_UNIX) return -EAFNOSUPPORT;
    if (type != SOCK_STREAM && type != SOCK_SEQPACKET) return -ESOCKTNOSUPPORT;
    if (protocol != 0 && protocol != AF_UNIX) return -EPROTONOSUPPORT;
    struct linux64_socket *pair = free_pair();
    if (!pair) return -ENFILE;
    pair[0] = (struct linux64_socket){.peer = &pair[1], .type = type, .open = true};
    pair[1] = (struct linux64_socket){.peer = &pair[0], .type = type, .open = true};
    struct peer_snapshot creator = current_credentials();
    store_credentials(&pair[0], creator);
    store_credentials(&pair[1], creator);
    ends[0] = &pair[0];
    ends[1] = &pair[1];
    return 0;
}

bool linux64_socket_is_stream(const struct linux64_socket *socket) {
    return socket->type == SOCK_STREAM;
}

bool linux64_socket_is_udp(const struct linux64_socket *socket) {
    return linux64_socket_is_inet(socket) && socket->type == SOCK_DGRAM;
}

bool linux64_socket_is_inet(const struct linux64_socket *socket) {
    return socket && socket->inet;
}

bool linux64_socket_is_tcp(const struct linux64_socket *socket) {
    return linux64_socket_is_inet(socket) && socket->type == SOCK_STREAM;
}

static bool loopback(u32 ip) {
    return (ip >> 24) == 127;
}

struct ipv4_sockaddr { u16 family; u8 port[2], ip[4], padding[8]; };
_Static_assert(sizeof(struct ipv4_sockaddr) == 16, "Linux sockaddr_in");

long linux64_udp_address(uptr address, u32 length, struct linux64_udp_address *result, bool disconnect) {
    struct ipv4_sockaddr name;
    if (length < sizeof(name.family)) return -EINVAL;
    if (paging64_copy_from_user(&name.family, address, sizeof(name.family)) != sizeof(name.family)) return -EFAULT;
    if (!name.family && disconnect) {
        *result = (struct linux64_udp_address){0};
        return 0;
    }
    if (name.family != AF_INET) return -EAFNOSUPPORT;
    if (length < sizeof(name)) return -EINVAL;
    if (paging64_copy_from_user(&name, address, sizeof(name)) != sizeof(name)) return -EFAULT;
    *result = (struct linux64_udp_address){net_read32(name.ip), net_read16(name.port)};
    return 0;
}

static long put_udp_address(uptr address, u32 available, struct linux64_udp_address endpoint) {
    struct ipv4_sockaddr name = {.family = AF_INET};
    net_write32(name.ip, endpoint.ip);
    net_write16(name.port, endpoint.port);
    uptr bytes = available < sizeof(name) ? available : sizeof(name);
    return paging64_copy_to_user(address, &name, bytes) == bytes ? 0 : -EFAULT;
}

static long put_udp_name(uptr address, uptr length, struct linux64_udp_address endpoint) {
    i32 available;
    if (paging64_copy_from_user(&available, length, sizeof(available)) != sizeof(available)) return -EFAULT;
    if (available < 0) return -EINVAL;
    long error = put_udp_address(address, (u32)available, endpoint);
    if (error) return error;
    return paging64_put_user_u32(length, sizeof(struct ipv4_sockaddr)) ? 0 : -EFAULT;
}

static bool port_used(const struct linux64_socket *self, struct linux64_udp_address endpoint) {
    if (linux64_socket_is_tcp(self) && tcp64_port_used(endpoint.port)) return true;
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i) {
        const struct linux64_socket *socket = pairs[i];
        if (socket != self && socket->open && socket->inet && socket->type == self->type &&
            socket->local.port == endpoint.port &&
            (!socket->local.ip || !endpoint.ip || socket->local.ip == endpoint.ip)) return true;
    }
    return false;
}

static long inet_bind(struct linux64_socket *socket, struct linux64_udp_address endpoint) {
    if (socket->local.port) return -EINVAL;
    if (endpoint.ip && endpoint.ip != net64_address() &&
        !(linux64_socket_is_udp(socket) && loopback(endpoint.ip))) return -EADDRNOTAVAIL;
    if (!endpoint.port) {
        static u16 udp_next = UDP_FIRST_PORT, tcp_next = UDP_FIRST_PORT;
        u16 *next = linux64_socket_is_tcp(socket) ? &tcp_next : &udp_next;
        for (unsigned i = UDP_FIRST_PORT; i <= 65535u; ++i) {
            endpoint.port = *next;
            *next = *next == 65535u ? UDP_FIRST_PORT : *next + 1;
            if (!port_used(socket, endpoint)) {
                socket->local = endpoint;
                return 0;
            }
        }
        return -EADDRINUSE;
    }
    if (port_used(socket, endpoint)) return -EADDRINUSE;
    socket->local = endpoint;
    return 0;
}

static u32 udp_source(const struct linux64_socket *socket, u32 destination) {
    if (socket->local.ip) return socket->local.ip;
    return loopback(destination) ? 0x7f000001u : net64_address();
}

static long udp_route(const struct linux64_socket *socket, u32 dest, u32 *source, bool *local) {
    u32 interface = net64_address();
    *source = udp_source(socket, dest);
    *local = loopback(dest) || (interface && dest == interface);
    if (!*source) return -ENETUNREACH;
    if (loopback(*source) != loopback(dest) || (!loopback(*source) && *source != interface)) return -EADDRNOTAVAIL;
    return *local || net64_has_route(dest) ? 0 : -ENETUNREACH;
}

long linux64_udp_path(struct linux64_socket *socket, bool bind, uptr address, u32 length) {
    struct linux64_udp_address name;
    long result = linux64_udp_address(address, length, &name, !bind);
    if (result) return result;
    if (bind) {
        result = inet_bind(socket, name);
        if (!result) socket->inet_bound = true;
        return result;
    }
    if (!name.ip && !name.port) {
        socket->remote = name;
        if (!socket->inet_bound) socket->local = (struct linux64_udp_address){0};
        return 0;
    }
    if (!name.port) return -EINVAL;
    if (!name.ip) name.ip = 0x7f000001u;
    u32 source;
    bool local;
    result = udp_route(socket, name.ip, &source, &local);
    if (result) return result;
    if (!socket->local.port) {
        result = inet_bind(socket, (struct linux64_udp_address){0});
        if (result) return result;
    }
    socket->remote = name;
    return 0;
}

long linux64_tcp_connect_result(const struct linux64_socket *socket) {
    return socket->tcp ? tcp64_connect_result(socket->tcp) : -ENOTCONN;
}

long linux64_tcp_connect_complete(struct linux64_socket *socket) {
    long result = linux64_tcp_connect_result(socket);
    if (result == -EINPROGRESS) return -EAGAIN;
    if (result < 0 && socket->tcp) tcp64_error(socket->tcp, true);
    return result;
}

long linux64_tcp_path(struct linux64_socket *socket, bool bind, uptr address, u32 length) {
    struct linux64_udp_address name;
    long result = linux64_udp_address(address, length, &name, false);
    if (result) return result;
    if (bind) {
        result = inet_bind(socket, name);
        if (!result) socket->inet_bound = true;
        return result;
    }

    if (!name.port) return -EINVAL;
    u64 now;
    if (!linux64_monotonic_ns(&now)) return -ENETDOWN;
    if (socket->tcp) {
        result = linux64_tcp_connect_result(socket);
        if (result == -EINPROGRESS) return -EALREADY;
        if (!result) return -EISCONN;
        tcp64_close(socket->tcp, now);
        socket->tcp = NULL;
        socket->tcp_source = 0;
        socket->remote = (struct linux64_udp_address){0};
        if (!socket->inet_bound) socket->local = (struct linux64_udp_address){0};
    }
    u32 source = net64_address();
    if (socket->local.ip && socket->local.ip != source) return -EADDRNOTAVAIL;
    if (!source || !net64_has_route(name.ip)) return -ENETUNREACH;
    if (!socket->local.port) {
        result = inet_bind(socket, (struct linux64_udp_address){0});
        if (result) return result;
    }
    result = tcp64_open(now, source, socket->local.port, name.ip, name.port, &socket->tcp);
    if (result) {
        if (!socket->inet_bound) socket->local = (struct linux64_udp_address){0};
        return result;
    }
    socket->tcp_source = source;
    socket->remote = name;
    return -EINPROGRESS;
}

bool linux64_socket_can_bind(const struct linux64_socket *socket) {
    return linux64_socket_is_stream(socket) && !socket->inode && !socket->peer;
}

void linux64_socket_bind(struct linux64_socket *socket, u64 inode, const char *name) {
    socket->inode = inode;
    for (unsigned i = 0; (socket->name[i] = name[i]); ++i) {}
}

long linux64_socket_listen(struct linux64_socket *socket, u32 backlog) {
    if (linux64_socket_is_inet(socket)) return -EOPNOTSUPP;
    if (!linux64_socket_is_stream(socket) || !socket->inode || socket->peer) return -EINVAL;
    socket->backlog = backlog > MAX_BACKLOG ? MAX_BACKLOG : backlog;
    socket->listening = true;
    store_credentials(socket, current_credentials());
    return 0;
}

static struct linux64_socket *find_listener(u64 inode) {
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i) {
        struct linux64_socket *socket = pairs[i];
        if (socket->open && socket->listening && socket->inode == inode) return socket;
    }
    return NULL;
}

bool linux64_socket_connect_ready(const struct linux64_socket *socket, u64 inode) {
    const struct linux64_socket *listener = find_listener(inode);
    return socket->peer || socket->listening || !listener || listener->read_shutdown ||
           listener->pending <= listener->backlog;
}

long linux64_socket_connect(struct linux64_socket *socket, u64 inode) {
    if (!linux64_socket_is_stream(socket) || socket->listening) return -EINVAL;
    if (socket->peer) return -EISCONN;
    struct linux64_socket *listener = find_listener(inode);
    if (!listener || listener->read_shutdown) return -ECONNREFUSED;
    if (listener->pending > listener->backlog) return -EAGAIN;
    /* Клиент занимает первый элемент пары, второй остаётся за очередью accept. */
    struct linux64_socket *accepted = socket + 1;
    *accepted = (struct linux64_socket){.peer = socket, .type = SOCK_STREAM, .open = true,
                                       .passcred = listener->passcred};
    /* accept может выполняться другой задачей, поэтому снимки берём здесь. */
    store_credentials(socket, listener->peer_credentials);
    store_credentials(accepted, current_credentials());
    for (unsigned i = 0; (accepted->name[i] = listener->name[i]); ++i) {}
    socket->peer = accepted;
    if (listener->accept_tail) listener->accept_tail->accept_next = accepted;
    else listener->accept_head = accepted;
    listener->accept_tail = accepted;
    ++listener->pending;
    return 0;
}

long linux64_socket_pending(struct linux64_socket *socket, bool blocking, struct linux64_socket **accepted) {
    if (linux64_socket_is_inet(socket)) return -EOPNOTSUPP;
    if (!socket->listening) return -EINVAL;
    if (!socket->accept_head) return blocking && socket->read_shutdown ? -EINVAL : -EAGAIN;
    *accepted = socket->accept_head;
    return 0;
}

bool linux64_socket_accept_ready(const struct linux64_socket *socket) {
    return socket->accept_head || socket->read_shutdown;
}

bool linux64_socket_io_ready(const struct linux64_socket *socket, bool receive) {
    if (linux64_socket_is_tcp(socket)) {
        u16 mask = receive ? LINUX64_POLL_READ | LINUX64_POLLRDHUP : LINUX64_POLL_WRITE;
        return (linux64_socket_poll(socket) & (mask | LINUX64_POLLERR | LINUX64_POLLHUP)) != 0;
    }
    if (linux64_socket_is_udp(socket))
        return receive ? socket->head || socket->udp_error || socket->read_shutdown :
                         socket->udp_error || socket->write_shutdown || socket->udp_tx_count < UDP_TX_LIMIT;
    if (!socket->peer) return true;
    if (receive) return socket->head || socket->reset || socket->read_shutdown || !socket->peer->open;
    return socket->write_shutdown || !socket->peer->open || socket->peer->queued < MAX_QUEUED;
}

void linux64_socket_dequeue(struct linux64_socket *socket) {
    struct linux64_socket *accepted = socket->accept_head;
    socket->accept_head = accepted->accept_next;
    if (!socket->accept_head) socket->accept_tail = NULL;
    accepted->accept_next = NULL;
    --socket->pending;
}

long linux64_socket_check_sendto(const struct linux64_socket *socket, u32 flags, uptr address, i32 length) {
    if (address) {
        u8 name[128];
        if (length < 0 || (uptr)length > sizeof(name)) return -EINVAL;
        if (paging64_copy_from_user(name, address, (uptr)length) != (uptr)length) return -EFAULT;
        if (length && linux64_socket_is_stream(socket))
            return socket->peer || (socket->tcp && !linux64_tcp_connect_result(socket)) ?
                   -EISCONN : -EOPNOTSUPP;
    }
    if (flags & MSG_OOB) return -EOPNOTSUPP;
    return 0;
}

long linux64_socket_name(const struct linux64_socket *socket, bool peer, uptr address, uptr length) {
    if (linux64_socket_is_tcp(socket)) {
        if (peer && linux64_tcp_connect_result(socket)) return -ENOTCONN;
        struct linux64_udp_address endpoint = peer ? socket->remote : socket->local;
        if (!peer && socket->tcp_source) endpoint.ip = socket->tcp_source;
        return put_udp_name(address, length, endpoint);
    }
    if (linux64_socket_is_udp(socket)) {
        if (peer && !socket->remote.port) return -ENOTCONN;
        struct linux64_udp_address endpoint = peer ? socket->remote : socket->local;
        if (!peer && socket->remote.port) endpoint.ip = udp_source(socket, socket->remote.ip);
        return put_udp_name(address, length, endpoint);
    }
    if (peer) {
        if (!socket->peer) return -ENOTCONN;
        socket = socket->peer;
    }
    i32 available;
    if (paging64_copy_from_user(&available, length, sizeof(available)) != sizeof(available)) return -EFAULT;
    if (available < 0) return -EINVAL;
    struct linux64_sockaddr name = {.family = AF_UNIX};
    i32 size = __builtin_offsetof(struct linux64_sockaddr, path);
    if (socket->name[0]) {
        unsigned i = 0;
        do { name.path[i] = socket->name[i]; } while (socket->name[i++]);
        size += (i32)i;
    }
    if (available > size) available = size;
    if (!paging64_put_user_u32(length, (u32)size) ||
        paging64_copy_to_user(address, &name, (uptr)available) != (uptr)available) return -EFAULT;
    return 0;
}

static void rights_queued(struct linux64_scm_rights *rights, bool queued) {
    if (!rights) return;
    for (unsigned i = 0; i < rights->count; ++i) linux64_scm_set_inflight(rights->files[i], queued);
    rights->queued = queued;
}

static struct linux64_scm_rights *packet_rights(const struct packet *packet) {
    return packet->rights_phys ? pmm64_pointer(packet->rights_phys) : NULL;
}

void linux64_scm_release(struct linux64_scm_rights *rights) {
    if (!rights) return;
    if (rights->queued) rights_queued(rights, false);
    for (unsigned i = 0; i < rights->count; ++i) linux64_scm_put_file(rights->files[i]);
    pmm64_free((uptr)rights - (uptr)pmm64_pointer(0));
}

void linux64_scm_mark_socket(struct linux64_socket *socket) {
    if (!socket || socket->scm_marked) return;
    socket->scm_marked = true;
    scm_mark_queue[scm_mark_count++] = socket;
}

void linux64_scm_collect_sockets(void) {
    scm_mark_count = 0;
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i)
        for (unsigned end = 0; end < 2; ++end) pairs[i][end].scm_marked = false;
    linux64_scm_mark_roots();
    for (unsigned i = 0; i < scm_mark_count; ++i) {
        const struct linux64_socket *socket = scm_mark_queue[i];
        for (struct linux64_socket *pending = socket->accept_head; pending; pending = pending->accept_next)
            linux64_scm_mark_socket(pending);
        for (const struct packet *packet = socket->head; packet; packet = packet->next) {
            const struct linux64_scm_rights *rights = packet_rights(packet);
            if (!rights) continue;
            for (unsigned j = 0; j < rights->count; ++j)
                linux64_scm_mark_socket(linux64_scm_file_socket(rights->files[j]));
        }
    }
    struct linux64_scm_rights *garbage = NULL;
    /* Сначала разрываем рёбра: освобождение ссылки может закрыть целую очередь. */
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i) {
        for (unsigned end = 0; end < 2; ++end) {
            struct linux64_socket *socket = &pairs[i][end];
            if (socket->scm_marked) continue;
            for (struct packet *packet = socket->head; packet; packet = packet->next) {
                struct linux64_scm_rights *rights = packet_rights(packet);
                if (!rights) continue;
                rights->next = garbage;
                garbage = rights;
                packet->rights_phys = 0;
            }
        }
    }
    while (garbage) {
        struct linux64_scm_rights *next = garbage->next;
        linux64_scm_release(garbage);
        garbage = next;
    }
}

static void free_packet(struct packet *packet) {
    linux64_pid_release(packet->sender);
    linux64_scm_release(packet_rights(packet));
    pmm64_free((uptr)packet - (uptr)pmm64_pointer(0));
}

static void drop_udp_tx(struct linux64_socket *socket) {
    struct packet *packet = socket->udp_tx_head;
    socket->udp_tx_head = packet->next;
    if (!socket->udp_tx_head) socket->udp_tx_tail = NULL;
    --socket->udp_tx_count;
    free_packet(packet);
}

static void drop_packet(struct linux64_socket *socket) {
    struct packet *packet = socket->head;
    socket->head = packet->next;
    if (!socket->head) socket->tail = NULL;
    --socket->queued;
    socket->head_offset = 0;
    free_packet(packet);
}

static void close_endpoint(struct linux64_socket *socket) {
    socket->open = false;
    store_credentials(socket, (struct peer_snapshot){0});
    const struct packet *unread = socket->head;
    if (unread && !unread->length) unread = unread->next;
    if (unread && socket->peer && socket->peer->open) socket->peer->reset = true;
    while (socket->head) drop_packet(socket);
}

void linux64_socket_close(struct linux64_socket *socket) {
    if (socket->tcp) {
        u64 now = 0;
        linux64_monotonic_ns(&now);
        tcp64_close(socket->tcp, now);
        socket->tcp = NULL;
    }
    while (socket->accept_head) {
        struct linux64_socket *accepted = socket->accept_head;
        linux64_socket_dequeue(socket);
        if (accepted->peer->open) accepted->peer->reset = true;
        close_endpoint(accepted);
    }
    close_endpoint(socket);
}

long linux64_socket_shutdown(struct linux64_socket *socket, i32 how) {
    if (how < SHUT_RD || how > SHUT_RDWR) return -EINVAL;
    if (linux64_socket_is_tcp(socket)) {
        if (linux64_tcp_connect_result(socket)) return -ENOTCONN;
        tcp64_shutdown(socket->tcp, how);
        return 0;
    }
    if (linux64_socket_is_udp(socket) && !socket->remote.port) return -ENOTCONN;
    struct linux64_socket *peer = socket->peer;
    /* Закрытие направления останавливает новые записи, но сохраняет очередь. */
    if (how != SHUT_WR) {
        socket->read_shutdown = true;
        if (peer && peer->open) peer->write_shutdown = true;
    }
    if (how != SHUT_RD) {
        socket->write_shutdown = true;
        if (peer && peer->open) peer->read_shutdown = true;
    }
    return 0;
}

u16 linux64_socket_poll(const struct linux64_socket *socket) {
    if (linux64_socket_is_tcp(socket))
        return socket->tcp ? tcp64_events(socket->tcp) : LINUX64_POLLHUP | LINUX64_POLL_WRITE;
    if (linux64_socket_is_udp(socket)) {
        u16 ready = 0;
        if (socket->head || socket->read_shutdown) ready |= LINUX64_POLL_READ;
        if (socket->read_shutdown) ready |= LINUX64_POLLRDHUP;
        if (socket->udp_tx_count < UDP_TX_LIMIT) ready |= LINUX64_POLL_WRITE;
        if (socket->udp_error) ready |= LINUX64_POLLERR;
        return ready;
    }
    if (socket->listening) {
        u16 ready = socket->accept_head || socket->read_shutdown ? LINUX64_POLL_READ : 0;
        if (socket->read_shutdown) ready |= LINUX64_POLLRDHUP;
        if (socket->read_shutdown && socket->write_shutdown) ready |= LINUX64_POLLHUP;
        return ready;
    }
    if (!socket->peer) {
        u16 ready = LINUX64_POLLHUP | LINUX64_POLL_WRITE | LINUX64_POLLWRBAND;
        if (socket->read_shutdown) ready |= LINUX64_POLLRDHUP | LINUX64_POLL_READ;
        return ready;
    }
    bool read_closed = socket->read_shutdown || !socket->peer->open;
    u16 ready = socket->reset ? LINUX64_POLLERR : 0;
    if (read_closed) ready |= LINUX64_POLLRDHUP;
    if (read_closed && (socket->write_shutdown || !socket->peer->open)) ready |= LINUX64_POLLHUP;
    if (socket->head || read_closed) ready |= LINUX64_POLL_READ;
    if (socket->peer->queued < MAX_QUEUED) ready |= LINUX64_POLL_WRITE | LINUX64_POLLWRBAND;
    return ready;
}

long linux64_socket_option(struct linux64_socket *socket, bool get, i32 level, i32 option,
                           uptr value, uptr length) {
    bool tcp = linux64_socket_is_tcp(socket);
    bool nodelay = tcp && level == IPPROTO_TCP && option == TCP_NODELAY;
    if (!nodelay && level != SOL_SOCKET) return -ENOPROTOOPT;
    bool udp = linux64_socket_is_udp(socket);
    if (!nodelay && (socket->inet ?
        !(get && (option == SO_TYPE || option == SO_ERROR || option == SO_DOMAIN || option == SO_PROTOCOL)) :
        (option != SO_PASSCRED && !(get && (option == SO_TYPE || option == SO_PEERCRED))))) return -ENOPROTOOPT;
    if (!get) {
        i32 enabled;
        if ((i32)length < (i32)sizeof(enabled)) return -EINVAL;
        if (paging64_copy_from_user(&enabled, value, sizeof(enabled)) != sizeof(enabled))
            return -EFAULT;
        /* Стек отправляет короткие записи без задержки Нейгла. */
        if (nodelay) return enabled ? 0 : -EOPNOTSUPP;
        socket->passcred = enabled != 0;
        return 0;
    }
    i32 count;
    if (paging64_copy_from_user(&count, length, sizeof(count)) != sizeof(count)) return -EFAULT;
    if (count < 0) return -EINVAL;
    i32 result = option == SO_TYPE ? socket->type : socket->passcred;
    if (nodelay) result = 1;
    else if (socket->inet) {
        if (option == SO_ERROR) result = udp ? socket->udp_error : socket->tcp ? tcp64_error(socket->tcp, false) : 0;
        if (option == SO_DOMAIN) result = AF_INET;
        if (option == SO_PROTOCOL) result = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    }
    struct identity credentials = {.uid = (u32)-1, .gid = (u32)-1};
    const void *data = &result;
    i32 size = sizeof(result);
    if (option == SO_PEERCRED) {
        const struct peer_snapshot *peer = &socket->peer_credentials;
        const struct linux64_process *process = linux64_current->process;
        if (peer->pid) {
            credentials.pid = linux64_pid_number(peer->pid, process->pid_ns);
            credentials.uid = linux64_visible_id(process->userns, false, peer->uid);
            credentials.gid = linux64_visible_id(process->userns, true, peer->gid);
        }
        data = &credentials;
        size = sizeof(credentials);
    }
    if (count > size) count = size;
    if (paging64_copy_to_user(value, data, (uptr)count) != (uptr)count ||
        paging64_copy_to_user(length, &count, sizeof(count)) != sizeof(count)) return -EFAULT;
    if (udp && option == SO_ERROR) socket->udp_error = 0;
    if (tcp && !nodelay && option == SO_ERROR && socket->tcp) tcp64_error(socket->tcp, true);
    return 0;
}

static struct packet *allocate_packet(void) {
    uptr physical = pmm64_alloc();
    return physical ? pmm64_pointer(physical) : NULL;
}

static struct packet *new_packet(const struct linux64_socket *socket) {
    struct packet *packet = allocate_packet();
    if (!packet) return NULL;
    if (socket->passcred || socket->peer->passcred) {
        packet->sender = linux64_current->process->pid_identity;
        linux64_pid_retain(packet->sender);
        packet->uid = LINUX64_UID;
        packet->gid = LINUX64_GID;
    } else {
        packet->uid = packet->gid = 65534;
    }
    return packet;
}

static void enqueue(struct linux64_socket *peer, struct packet *packet) {
    if (peer->tail) peer->tail->next = packet;
    else peer->head = packet;
    peer->tail = packet;
    ++peer->queued;
}

static bool udp_deliver(struct linux64_udp_address source, struct linux64_udp_address dest,
                        const u8 *data, u32 length) {
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i) {
        struct linux64_socket *socket = pairs[i];
        if (!socket->open || !linux64_socket_is_udp(socket) || socket->local.port != dest.port ||
            (socket->local.ip && socket->local.ip != dest.ip) ||
            (socket->remote.port && (socket->remote.ip != source.ip || socket->remote.port != source.port)))
            continue;
        if (socket->read_shutdown || socket->queued >= MAX_QUEUED) return true;
        struct packet *packet = allocate_packet();
        if (!packet) return true;
        packet->datagram.ip = source.ip;
        packet->datagram.port = source.port;
        packet->length = length;
        for (u32 j = 0; j < length; ++j) packet->bytes[j] = data[j];
        enqueue(socket, packet);
        return true;
    }
    return false;
}

static u32 udp_checksum_seed(u32 source, u32 dest, u32 length) {
    return (source >> 16) + (source & 0xffffu) + (dest >> 16) + (dest & 0xffffu) + IPPROTO_UDP + length;
}

void linux64_udp_receive(void *context, u32 source, u32 destination, u8 protocol, const u8 *data, u32 length) {
    (void)context;
    if (protocol != IPPROTO_UDP || length < UDP_HEADER) return;
    u32 size = net_read16(data + 4);
    u16 source_port = net_read16(data), dest_port = net_read16(data + 2);
    if (!dest_port || size < UDP_HEADER || size > length ||
        (net_read16(data + 6) && net64_checksum(data, size, udp_checksum_seed(source, destination, size)))) return;
    udp_deliver((struct linux64_udp_address){source, source_port},
                (struct linux64_udp_address){destination, dest_port}, data + UDP_HEADER, size - UDP_HEADER);
}

static long udp_transmit(const struct packet *packet, u64 now, u32 source) {
    u8 wire[UDP_HEADER + UDP_MAX];
    u32 size = UDP_HEADER + packet->length;
    net_write16(wire, packet->datagram.source_port);
    net_write16(wire + 2, packet->datagram.port);
    net_write16(wire + 4, (u16)size);
    net_write16(wire + 6, 0);
    for (u32 i = 0; i < packet->length; ++i) wire[UDP_HEADER + i] = packet->bytes[i];
    u16 checksum = net64_checksum(wire, size, udp_checksum_seed(source, packet->datagram.ip, size));
    net_write16(wire + 6, checksum ? checksum : 0xffffu);
    switch (net64_send(now, packet->datagram.ip, IPPROTO_UDP, wire, size)) {
    case NET64_SENT: return 0;
    case NET64_RETRY: return -EAGAIN;
    case NET64_NO_ROUTE: return -ENETUNREACH;
    case NET64_LINK_DOWN: return -ENETDOWN;
    case NET64_UNREACHABLE: return -EHOSTUNREACH;
    default: return -EINVAL;
    }
}

bool linux64_udp_flush(u64 now) {
    bool pending = false;
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i) {
        struct linux64_socket *socket = pairs[i];
        /* Уже принятые датаграммы переживают последний close до отправки или сетевой ошибки. */
        while (socket->udp_tx_head) {
            u32 source = net64_address();
            long result = source && source == socket->udp_tx_source ?
                          udp_transmit(socket->udp_tx_head, now, source) : -ENETDOWN;
            if (result == -EAGAIN) {
                pending = true;
                break;
            }
            if (result < 0 && socket->open && !socket->udp_error) socket->udp_error = (i32)-result;
            drop_udp_tx(socket);
        }
    }
    return pending;
}

static long udp_pending_error(struct linux64_socket *socket) {
    long error = -socket->udp_error;
    socket->udp_error = 0;
    return error;
}

static long udp_send(struct linux64_socket *socket, const struct iovec *iov, uptr count,
                     struct linux64_udp_address dest) {
    if (socket->udp_error) return udp_pending_error(socket);
    if (socket->write_shutdown) return -EPIPE;
    if (!dest.port) return -EDESTADDRREQ;
    if (!dest.ip) dest.ip = 0x7f000001u;
    u32 source;
    bool local;
    long result = udp_route(socket, dest.ip, &source, &local);
    if (result) return result;
    uptr length = 0;
    for (uptr i = 0; i < count; ++i) {
        if (iov[i].length > UDP_MAX - length) return -EMSGSIZE;
        length += iov[i].length;
    }
    if (!local && socket->udp_tx_count >= UDP_TX_LIMIT) return -EAGAIN;
    struct packet *packet = allocate_packet();
    if (!packet) return -ENOMEM;
    packet->datagram.ip = dest.ip;
    packet->datagram.port = dest.port;
    packet->length = (u32)length;
    uptr copied = 0;
    for (uptr i = 0; i < count; ++i) {
        uptr size = iov[i].length;
        if (paging64_copy_from_user(packet->bytes + copied, iov[i].base, size) != size) {
            free_packet(packet);
            return -EFAULT;
        }
        copied += size;
    }
    result = socket->local.port ? 0 : inet_bind(socket, (struct linux64_udp_address){0});
    packet->datagram.source_port = socket->local.port;
    if (!result && local) {
        bool delivered = udp_deliver((struct linux64_udp_address){source, socket->local.port},
                                     dest, packet->bytes, packet->length);
        if (!delivered && socket->remote.port == dest.port && socket->remote.ip == dest.ip)
            socket->udp_error = ECONNREFUSED;
    } else if (!result) {
        u64 now;
        if (!linux64_monotonic_ns(&now)) result = -ENETDOWN;
        else if (socket->udp_tx_head)
            result = socket->udp_tx_source == source ? -EAGAIN : -ENETDOWN;
        else result = udp_transmit(packet, now, source);
        if (result == -EAGAIN) {
            if (socket->udp_tx_tail) socket->udp_tx_tail->next = packet;
            else socket->udp_tx_head = packet;
            socket->udp_tx_tail = packet;
            socket->udp_tx_source = source;
            ++socket->udp_tx_count;
            return (long)length;
        }
    }
    free_packet(packet);
    return result ? result : (long)length;
}

static long udp_receive(struct linux64_socket *socket, const struct iovec *iov, uptr count, u32 flags,
                        struct msghdr *message, uptr name, uptr name_length) {
    if (socket->udp_error) return udp_pending_error(socket);
    struct packet *packet = socket->head;
    if (!packet) return socket->read_shutdown ? 0 : -EAGAIN;
    struct linux64_udp_address source = {packet->datagram.ip, packet->datagram.port};
    uptr copied = 0;
    for (uptr i = 0; i < count && copied < packet->length; ++i) {
        uptr size = packet->length - copied;
        if (size > iov[i].length) size = iov[i].length;
        if (paging64_copy_to_user(iov[i].base, packet->bytes + copied, size) != size) return -EFAULT;
        copied += size;
    }
    if (name) {
        long result = put_udp_name(name, name_length, source);
        if (result) return result;
    }
    if (message) {
        if (message->name) {
            long result = put_udp_address(message->name, message->name_length, source);
            if (result) return result;
            message->name_length = sizeof(struct ipv4_sockaddr);
        } else message->name_length = 0;
        message->flags = copied < packet->length ? MSG_TRUNC : 0;
        message->control_length = 0;
    }
    long result = (long)(flags & MSG_TRUNC ? packet->length : copied);
    if (!(flags & MSG_PEEK)) drop_packet(socket);
    return result;
}

long linux64_udp_io(struct linux64_socket *socket, bool receive, struct linux64_socket_wait *wait) {
    u32 allowed = receive ? MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT : MSG_DONTWAIT | MSG_NOSIGNAL;
    if (wait->flags & ~allowed) return -EOPNOTSUPP;
    if (wait->length && (wait->address >= X64_USER_TOP || wait->length > X64_USER_TOP - wait->address)) return -EFAULT;
    const struct iovec iov = {wait->address, wait->length};
    if (receive) {
        if (wait->operation == SOCKET_READ && !wait->length) return 0;
        return udp_receive(socket, &iov, 1, wait->flags, NULL, wait->name, wait->name_length);
    }
    struct linux64_udp_address dest = wait->name ? wait->destination : socket->remote;
    return udp_send(socket, &iov, 1, dest);
}

static void attach_rights(struct packet *packet, struct linux64_scm_rights **rights) {
    if (!rights || !*rights) return;
    packet->rights_phys = (u32)((uptr)*rights - (uptr)pmm64_pointer(0));
    rights_queued(*rights, true);
    *rights = NULL;
}

static struct linux64_scm_rights *take_rights(struct packet *packet, bool peek) {
    struct linux64_scm_rights *rights = packet_rights(packet);
    if (!peek && rights) {
        packet->rights_phys = 0;
        rights_queued(rights, false);
    }
    return rights;
}

static long send_packet(struct linux64_socket *socket, const struct iovec *iov, uptr count,
                        struct linux64_scm_rights **rights) {
    if (socket->reset) {
        socket->reset = false;
        return -ECONNRESET;
    }
    struct linux64_socket *peer = socket->peer;
    if (!peer) return -ENOTCONN;
    if (!peer->open || socket->write_shutdown) return -EPIPE;
    uptr length = 0;
    for (uptr i = 0; i < count; ++i) {
        if (iov[i].length > MAX_PACKET - length) return -EMSGSIZE;
        length += iov[i].length;
    }
    if (peer->queued == MAX_QUEUED) return -EAGAIN;
    struct packet *packet = new_packet(socket);
    if (!packet) return -ENOMEM;
    packet->length = (u32)length;
    uptr copied = 0;
    for (uptr i = 0; i < count; ++i) {
        uptr size = iov[i].length;
        if (paging64_copy_from_user(packet->bytes + copied, iov[i].base, size) != size) {
            free_packet(packet);
            return -EFAULT;
        }
        copied += size;
    }
    attach_rights(packet, rights);
    enqueue(peer, packet);
    return (long)length;
}

static struct identity packet_identity(const struct packet *packet) {
    return (struct identity){
        .pid = linux64_pid_number(packet->sender, linux64_current->process->pid_ns),
        .uid = packet->uid, .gid = packet->gid,
    };
}

struct received_ancillary {
    struct identity sender;
    struct linux64_scm_rights *rights;
    bool credentials;
};

static void receive_credentials(struct identity sender, struct msghdr *message) {
    uptr available = message->control ? message->control_length : 0;
    message->control_length = 0;
    if (available < CRED_LENGTH) message->flags |= MSG_CTRUNC;
    if (available < __builtin_offsetof(struct credentials, sender)) return;
    uptr length = available < CRED_LENGTH ? available : CRED_LENGTH;
    const struct linux64_userns *ns = linux64_current->process->userns;
    struct credentials control = {
        .length = length, .level = SOL_SOCKET, .type = SCM_CREDENTIALS,
        .sender = sender,
    };
    control.sender.uid = linux64_visible_id(ns, false, control.sender.uid);
    control.sender.gid = linux64_visible_id(ns, true, control.sender.gid);
    if (paging64_copy_to_user(message->control, &control, length) != length) return;
    message->control_length = available < sizeof(control) ? available : sizeof(control);
}

static long receive_packet(struct linux64_socket *socket, const struct iovec *iov, uptr count,
                           struct msghdr *message, u32 flags, struct received_ancillary *ancillary) {
    if (!socket->peer) return -EINVAL;
    if (socket->reset) {
        socket->reset = false;
        return -ECONNRESET;
    }
    struct packet *packet = socket->head;
    if (!packet) {
        if (message) message->control_length = 0;
        return socket->peer->open && !socket->read_shutdown ? -EAGAIN : 0;
    }
    uptr copied = 0;
    long result = 0;
    for (uptr i = 0; i < count && copied < packet->length; ++i) {
        uptr size = packet->length - copied;
        if (size > iov[i].length) size = iov[i].length;
        if (paging64_copy_to_user(iov[i].base, packet->bytes + copied, size) != size) {
            result = -EFAULT;
            break;
        }
        copied += size;
    }
    if (!result) {
        if (message) {
            if (copied < packet->length) message->flags |= MSG_TRUNC;
            ancillary->credentials = socket->passcred;
            if (ancillary->credentials) ancillary->sender = packet_identity(packet);
            ancillary->rights = take_rights(packet, (flags & MSG_PEEK) != 0);
        }
        result = (long)(flags & MSG_TRUNC ? packet->length : copied);
    }
    if (!(flags & MSG_PEEK)) drop_packet(socket);
    return result;
}

struct iov_cursor {
    const struct iovec *entry, *end;
    uptr offset;
};

static bool iov_remaining(struct iov_cursor *cursor) {
    while (cursor->entry < cursor->end && cursor->offset == cursor->entry->length) {
        ++cursor->entry;
        cursor->offset = 0;
    }
    return cursor->entry < cursor->end;
}

static uptr stream_copy(struct iov_cursor *cursor, u8 *bytes, uptr length, bool receive, bool *fault) {
    uptr copied = 0;
    while (copied < length && iov_remaining(cursor)) {
        uptr user = cursor->entry->base + cursor->offset;
        uptr chunk = cursor->entry->length - cursor->offset;
        if (chunk > length - copied) chunk = length - copied;
        uptr done = receive ? paging64_copy_to_user(user, bytes + copied, chunk) :
                              paging64_copy_from_user(bytes + copied, user, chunk);
        cursor->offset += done;
        copied += done;
        if (done != chunk) {
            *fault = true;
            break;
        }
    }
    return copied;
}

static long tcp_io(struct linux64_socket *socket, const struct iovec *iov, uptr count, bool receive, u32 flags) {
    u8 bytes[PMM_PAGE_SIZE];
    uptr length = 0;
    for (uptr i = 0; i < count && length < sizeof(bytes); ++i) {
        uptr room = sizeof(bytes) - length;
        length += iov[i].length < room ? iov[i].length : room;
    }
    if (!length && receive) return 0;
    if (!socket->tcp) return -ENOTCONN;

    bool fault = false;
    struct iov_cursor cursor = {iov, iov + count, 0};
    if (!receive) {
        uptr copied = stream_copy(&cursor, bytes, length, false, &fault);
        if (fault && !copied) return -EFAULT;
        return tcp64_write(socket->tcp, bytes, (u32)copied);
    }

    long result = tcp64_read(socket->tcp, bytes, (u32)length);
    if (result <= 0) return result;
    uptr copied = flags & MSG_TRUNC ? (uptr)result : stream_copy(&cursor, bytes, (uptr)result, true, &fault);
    if (fault && !copied) return -EFAULT;
    if (!(flags & MSG_PEEK)) tcp64_consume(socket->tcp, (u32)copied);
    return (long)copied;
}

long linux64_tcp_recvfrom(struct linux64_socket *socket, struct linux64_socket_wait *wait) {
    if (wait->flags & ~(MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC)) return -EOPNOTSUPP;
    if (wait->length && (wait->address >= X64_USER_TOP || wait->length > X64_USER_TOP - wait->address))
        return -EFAULT;
    const struct iovec iov = {wait->address, wait->length};
    long result = tcp_io(socket, &iov, 1, true, wait->flags | MSG_PEEK);
    if (result < 0) return result;
    if (wait->name) {
        i32 available;
        if (paging64_copy_from_user(&available, wait->name_length, sizeof(available)) != sizeof(available))
            return -EFAULT;
        if (available < 0) return -EINVAL;
        if (!paging64_put_user_u32(wait->name_length, 0)) return -EFAULT;
    }
    if (result && !(wait->flags & MSG_PEEK)) tcp64_consume(socket->tcp, (u32)result);
    return result;
}

static long send_stream(struct linux64_socket *socket, const struct iovec *iov, uptr count,
                        struct linux64_scm_rights **rights) {
    struct linux64_socket *peer = socket->peer;
    if (!peer) return -ENOTCONN;
    if (!peer->open || socket->write_shutdown) return -EPIPE;
    struct iov_cursor cursor = {iov, iov + count, 0};
    uptr done = 0;
    while (iov_remaining(&cursor)) {
        if (peer->queued == MAX_QUEUED) return done ? (long)done : -EAGAIN;
        struct packet *packet = new_packet(socket);
        if (!packet) return done ? (long)done : -ENOMEM;
        bool fault = false;
        packet->length = (u32)stream_copy(&cursor, packet->bytes, MAX_PACKET, false, &fault);
        if (packet->length) {
            done += packet->length;
            attach_rights(packet, rights);
            enqueue(peer, packet);
        } else free_packet(packet);
        if (fault) return done ? (long)done : -EFAULT;
    }
    return (long)done;
}

static long receive_stream(struct linux64_socket *socket, const struct iovec *iov, uptr count,
                           u32 flags, struct received_ancillary *ancillary) {
    if (!socket->peer) return -EINVAL;
    struct iov_cursor cursor = {iov, iov + count, 0};
    struct packet *packet = socket->head;
    if (!packet) {
        if (socket->reset) {
            socket->reset = false;
            return -ECONNRESET;
        }
        return socket->peer->open && !socket->read_shutdown ? -EAGAIN : 0;
    }
    struct identity sender = packet_identity(packet);
    struct linux64_pid *first_sender = packet->sender;
    linux64_pid_retain(first_sender);
    bool fault = false;
    uptr done = 0;
    while (packet && iov_remaining(&cursor)) {
        if (socket->passcred && (first_sender != packet->sender || sender.uid != packet->uid ||
                                 sender.gid != packet->gid)) break;
        unsigned offset = packet == socket->head ? socket->head_offset : 0;
        uptr available = packet->length - offset;
        uptr copied = stream_copy(&cursor, packet->bytes + offset, available, true, &fault);
        done += copied;
        struct linux64_scm_rights *rights = copied ? take_rights(packet, (flags & MSG_PEEK) != 0) : NULL;
        if (flags & MSG_PEEK) packet = packet->next;
        else {
            socket->head_offset += (unsigned)copied;
            if (copied == available) drop_packet(socket);
            packet = socket->head;
        }
        if (rights) {
            if (ancillary) ancillary->rights = rights;
            else linux64_scm_release(rights);
            break;
        }
        if (fault) break;
    }
    linux64_pid_release(first_sender);
    if (fault && !done) return -EFAULT;
    if (ancillary && socket->passcred && done) {
        ancillary->credentials = true;
        ancillary->sender = sender;
    }
    return (long)done;
}

long linux64_socket_io(struct linux64_socket *socket, bool receive, uptr buffer, uptr length) {
    if (buffer >= X64_USER_TOP || length > X64_USER_TOP - buffer) return -EFAULT;
    const struct iovec iov = {buffer, length};
    if (linux64_socket_is_tcp(socket)) return tcp_io(socket, &iov, 1, receive, 0);
    if (linux64_socket_is_stream(socket)) {
        if (!receive) return send_stream(socket, &iov, 1, NULL);
        return length ? receive_stream(socket, &iov, 1, 0, NULL) : 0;
    }
    if (!receive) return send_packet(socket, &iov, 1, NULL);
    return length ? receive_packet(socket, &iov, 1, NULL, 0, NULL) : 0;
}

static uptr control_align(uptr length) {
    return (length + 7) & ~7ul;
}

static long parse_rights(uptr control, uptr size, struct linux64_scm_rights **out) {
    if (!size) return 0;
    if (control >= X64_USER_TOP || size > X64_USER_TOP - control) return -EFAULT;
    if (size > 0x7fffffffu) return -EINVAL;
    while (size >= sizeof(struct cmsghdr)) {
        struct cmsghdr header;
        if (paging64_copy_from_user(&header, control, sizeof(header)) != sizeof(header)) return -EFAULT;
        if (header.length < sizeof(header) || header.length > size) return -EINVAL;
        if (header.level == SOL_SOCKET) {
            if (header.type != SCM_RIGHTS) return -EINVAL;
            uptr count = (header.length - sizeof(header)) / sizeof(i32);
            if (count > SCM_MAX_FD - (*out ? (*out)->count : 0)) return -EINVAL;
            if (count && !*out) {
                uptr page = pmm64_alloc();
                if (!page) return -ENOMEM;
                *out = pmm64_pointer(page);
            }
            for (uptr i = 0; i < count; ++i) {
                i32 fd;
                if (paging64_copy_from_user(&fd, control + sizeof(header) + i * sizeof(fd), sizeof(fd)) !=
                    sizeof(fd)) return -EFAULT;
                struct file_handle *file = linux64_scm_get_file(fd);
                if (!file) return -EBADF;
                (*out)->files[(*out)->count++] = file;
            }
        }
        uptr step = control_align(header.length);
        if (step >= size) break;
        control += step;
        size -= step;
    }
    return 0;
}

long linux64_socket_prepare_rights(uptr address, u32 flags, struct linux64_scm_rights **rights) {
    if (flags & ~(MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL)) return -EOPNOTSUPP;
    struct msghdr message;
    if (paging64_copy_from_user(&message, address, sizeof(message)) != sizeof(message)) return -EFAULT;
    long result = parse_rights(message.control, message.control_length, rights);
    if (result) {
        linux64_scm_release(*rights);
        *rights = NULL;
    }
    return result;
}

struct received_fds {
    struct cmsghdr header;
    i32 descriptors[SCM_MAX_FD];
    unsigned count;
};
_Static_assert(__builtin_offsetof(struct received_fds, descriptors) == sizeof(struct cmsghdr),
               "SCM_RIGHTS descriptor alignment");

static void close_received(struct received_fds *fds) {
    while (fds->count) linux64_scm_close(fds->descriptors[--fds->count]);
}

static void receive_ancillary(struct msghdr *message, const struct received_ancillary *ancillary,
                              struct received_fds *fds) {
    uptr capacity = message->control ? message->control_length : 0;
    if (ancillary->credentials) receive_credentials(ancillary->sender, message);
    else message->control_length = 0;
    const struct linux64_scm_rights *rights = ancillary->rights;
    if (!rights) return;
    uptr available = capacity - message->control_length;
    uptr slots = available >= sizeof(fds->header) ? (available - sizeof(fds->header)) / sizeof(i32) : 0;
    while (fds->count < rights->count && fds->count < slots) {
        long fd = linux64_scm_install(rights->files[fds->count], (message->flags & MSG_CMSG_CLOEXEC) != 0);
        if (fd < 0) break;
        fds->descriptors[fds->count++] = (i32)fd;
    }
    if (fds->count) {
        uptr length = sizeof(fds->header) + fds->count * sizeof(i32);
        fds->header = (struct cmsghdr){length, SOL_SOCKET, SCM_RIGHTS};
        uptr address = message->control + message->control_length;
        if (paging64_copy_to_user(address, fds, length) == length) {
            uptr padded = control_align(length);
            message->control_length += available < padded ? available : padded;
        } else close_received(fds);
    }
    if (fds->count < rights->count) message->flags |= MSG_CTRUNC;
}

long linux64_socket_message(struct linux64_socket *socket, struct linux64_socket_wait *wait) {
    bool receive = wait->operation == SOCKET_RECVMSG;
    uptr address = wait->address;
    u32 flags = wait->flags;
    u32 allowed = receive ? MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT | MSG_CMSG_CLOEXEC
                          : MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL;
    if (flags & ~allowed) return -EOPNOTSUPP;
    struct msghdr message;
    if (paging64_copy_from_user(&message, address, sizeof(message)) != sizeof(message))
        return -EFAULT;
    if (message.iov_count > MAX_IOV) return -EMSGSIZE;
    struct iovec iov[MAX_IOV];
    uptr size = message.iov_count * sizeof(*iov);
    if (paging64_copy_from_user(iov, message.iov, size) != size) return -EFAULT;
    for (uptr i = 0; i < message.iov_count; ++i)
        if (iov[i].length &&
            (iov[i].base >= X64_USER_TOP || iov[i].length > X64_USER_TOP - iov[i].base))
            return -EFAULT;
    if (linux64_socket_is_tcp(socket)) {
        if (!receive) {
            if (message.control_length) return -EOPNOTSUPP;
            if (message.name && message.name_length) {
                long result = linux64_socket_check_sendto(socket, flags, message.name, (i32)message.name_length);
                if (result) return result;
            }
            return tcp_io(socket, iov, message.iov_count, false, flags);
        }
        long result = tcp_io(socket, iov, message.iov_count, true, flags | MSG_PEEK);
        if (result < 0) return result;
        if (!paging64_put_user_u32(address + __builtin_offsetof(struct msghdr, name_length), 0) ||
            !paging64_put_user_u32(address + __builtin_offsetof(struct msghdr, flags), 0) ||
            !paging64_put_user_u64(address + __builtin_offsetof(struct msghdr, control_length), 0)) return -EFAULT;
        if (result && !(flags & MSG_PEEK)) tcp64_consume(socket->tcp, (u32)result);
        return result;
    }
    if (linux64_socket_is_udp(socket)) {
        if (!receive) {
            if (message.control_length) return -EOPNOTSUPP;
            struct linux64_udp_address dest = socket->remote;
            if (message.name) {
                long error = linux64_udp_address(message.name, message.name_length, &dest, false);
                if (error) return error;
            }
            return udp_send(socket, iov, message.iov_count, dest);
        }
        message.flags = 0;
        message.control_length = 0;
        message.name_length = message.name ? message.name_length : 0;
        long result = udp_receive(socket, iov, message.iov_count, flags, &message, 0, 0);
        if (result < 0) return result;
        if (!paging64_put_user_u32(address + __builtin_offsetof(struct msghdr, name_length), message.name_length) ||
            !paging64_put_user_u32(address + __builtin_offsetof(struct msghdr, flags), message.flags) ||
            !paging64_put_user_u64(address + __builtin_offsetof(struct msghdr, control_length), 0)) return -EFAULT;
        return result;
    }
    if (!receive) {
        return linux64_socket_is_stream(socket) ? send_stream(socket, iov, message.iov_count, &wait->rights) :
                                                  send_packet(socket, iov, message.iov_count, &wait->rights);
    }
    message.flags = flags & MSG_CMSG_CLOEXEC;
    if (message.control && message.control_length &&
        (message.control >= X64_USER_TOP || message.control_length > X64_USER_TOP - message.control))
        return -EFAULT;
    struct received_ancillary ancillary = {0};
    long result = linux64_socket_is_stream(socket) ? receive_stream(socket, iov, message.iov_count, flags, &ancillary) :
                                                    receive_packet(socket, iov, message.iov_count, &message, flags, &ancillary);
    if (result < 0) return result;
    struct received_fds fds = {0};
    receive_ancillary(&message, &ancillary, &fds);
    if (!(flags & MSG_PEEK)) linux64_scm_release(ancillary.rights);
    message.name_length = 0;
    if ((message.name && paging64_copy_to_user(address + __builtin_offsetof(struct msghdr, name_length),
                                              &message.name_length, sizeof(message.name_length)) !=
                         sizeof(message.name_length)) ||
        paging64_copy_to_user(address + __builtin_offsetof(struct msghdr, flags),
                              &message.flags, sizeof(message.flags)) != sizeof(message.flags) ||
        !paging64_put_user_u64(address + __builtin_offsetof(struct msghdr, control_length),
                               message.control_length)) {
        close_received(&fds);
        return -EFAULT;
    }
    return result;
}
