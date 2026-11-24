#include "linux_task.h"
#include "paging.h"

enum {
    EAGAIN = 11, ENOMEM = 12, EFAULT = 14, EINVAL = 22, EMFILE = 24, EPIPE = 32,
    EMSGSIZE = 90, EPROTONOSUPPORT = 93, ESOCKTNOSUPPORT = 94, EOPNOTSUPP = 95,
    EAFNOSUPPORT = 97, ENOPROTOOPT = 92, ECONNRESET = 104, EISCONN = 106, ENOTCONN = 107,
    ECONNREFUSED = 111,
    AF_UNIX = 1, SOCK_STREAM = 1, SOCK_SEQPACKET = 5, SOCK_MAX = 11, SOCK_TYPE_MASK = 0xf,
    SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000,
    SHUT_RD = 0, SHUT_WR = 1, SHUT_RDWR = 2,
    SOL_SOCKET = 1, SO_TYPE = 3, SO_PASSCRED = 16, SCM_CREDENTIALS = 2,
    MSG_PEEK = 2, MSG_CTRUNC = 8, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40,
    MSG_EOR = 0x80, MSG_NOSIGNAL = 0x4000, MSG_CMSG_CLOEXEC = 0x40000000,
    MAX_IOV = 64, MAX_QUEUED = 32, MAX_BACKLOG = 31,
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

struct credentials {
    uptr length;
    i32 level, type;
    struct identity sender;
};

#define CRED_LENGTH (__builtin_offsetof(struct credentials, sender) + sizeof(struct identity))
_Static_assert(sizeof(struct msghdr) == 56 && sizeof(struct iovec) == 16, "Linux x86-64 msghdr");
_Static_assert(CRED_LENGTH == 28 && sizeof(struct credentials) == 32, "Linux x86-64 credentials");

struct packet {
    struct packet *next;
    struct linux64_pid *sender;
    u32 length, uid, gid;
    u8 bytes[];
};

#define MAX_PACKET (PMM_PAGE_SIZE - sizeof(struct packet))

struct linux64_socket {
    struct linux64_socket *peer;
    struct linux64_socket *accept_head, *accept_tail, *accept_next;
    struct packet *head, *tail;
    u64 inode;
    unsigned queued, head_offset, backlog, pending;
    u8 type;
    bool open, passcred, reset, read_shutdown, write_shutdown, listening;
    char name[LINUX64_UNIX_PATH_LIMIT + 1];
};

/* Один конец может оставаться открытым после закрытия его пары. */
static struct linux64_socket pairs[LINUX64_TASK_COUNT * LINUX64_FD_COUNT][2];

static struct linux64_socket *free_pair(void) {
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i)
        if (!pairs[i][0].open && !pairs[i][1].open) return pairs[i];
    return NULL;
}

long linux64_socket_create(i32 domain, u32 type, i32 protocol, struct linux64_socket **socket) {
    u32 base = type & SOCK_TYPE_MASK;
    if (type & ~(SOCK_TYPE_MASK | SOCK_CLOEXEC | SOCK_NONBLOCK)) return -EINVAL;
    if (domain != AF_UNIX) return -EAFNOSUPPORT;
    if (base >= SOCK_MAX) return -EINVAL;
    if (protocol != 0 && protocol != AF_UNIX) return -EPROTONOSUPPORT;
    if (base != SOCK_STREAM) return -ESOCKTNOSUPPORT;
    struct linux64_socket *slot = free_pair();
    if (!slot) return -EMFILE;
    *slot = (struct linux64_socket){.type = SOCK_STREAM, .open = true};
    *socket = slot;
    return 0;
}

long linux64_socket_pair(i32 domain, u32 type, i32 protocol, struct linux64_socket *ends[2]) {
    if (type & ~(SOCK_TYPE_MASK | SOCK_CLOEXEC | SOCK_NONBLOCK)) return -EINVAL;
    if (domain != AF_UNIX) return -EAFNOSUPPORT;
    if ((type & SOCK_TYPE_MASK) != SOCK_SEQPACKET) return -ESOCKTNOSUPPORT;
    if (protocol != 0 && protocol != AF_UNIX) return -EPROTONOSUPPORT;
    struct linux64_socket *pair = free_pair();
    if (!pair) return -EMFILE;
    pair[0] = (struct linux64_socket){.peer = &pair[1], .type = SOCK_SEQPACKET, .open = true};
    pair[1] = (struct linux64_socket){.peer = &pair[0], .type = SOCK_SEQPACKET, .open = true};
    ends[0] = &pair[0];
    ends[1] = &pair[1];
    return 0;
}

bool linux64_socket_is_stream(const struct linux64_socket *socket) {
    return socket->type == SOCK_STREAM;
}

bool linux64_socket_can_bind(const struct linux64_socket *socket) {
    return linux64_socket_is_stream(socket) && !socket->inode && !socket->peer;
}

void linux64_socket_bind(struct linux64_socket *socket, u64 inode, const char *name) {
    socket->inode = inode;
    for (unsigned i = 0; (socket->name[i] = name[i]); ++i) {}
}

long linux64_socket_listen(struct linux64_socket *socket, u32 backlog) {
    if (!linux64_socket_is_stream(socket) || !socket->inode || socket->peer) return -EINVAL;
    socket->backlog = backlog > MAX_BACKLOG ? MAX_BACKLOG : backlog;
    socket->listening = true;
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
    for (unsigned i = 0; (accepted->name[i] = listener->name[i]); ++i) {}
    socket->peer = accepted;
    if (listener->accept_tail) listener->accept_tail->accept_next = accepted;
    else listener->accept_head = accepted;
    listener->accept_tail = accepted;
    ++listener->pending;
    return 0;
}

long linux64_socket_pending(struct linux64_socket *socket, bool blocking, struct linux64_socket **accepted) {
    if (!socket->listening) return -EINVAL;
    if (!socket->accept_head) return blocking && socket->read_shutdown ? -EINVAL : -EAGAIN;
    *accepted = socket->accept_head;
    return 0;
}

bool linux64_socket_accept_ready(const struct linux64_socket *socket) {
    return socket->accept_head || socket->read_shutdown;
}

bool linux64_socket_io_ready(const struct linux64_socket *socket, bool receive) {
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

long linux64_socket_name(const struct linux64_socket *socket, bool peer, uptr address, uptr length) {
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

static void free_packet(struct packet *packet) {
    linux64_pid_release(packet->sender);
    pmm64_free((uptr)packet - (uptr)pmm64_pointer(0));
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
    const struct packet *unread = socket->head;
    if (unread && !unread->length) unread = unread->next;
    if (unread && socket->peer && socket->peer->open) socket->peer->reset = true;
    while (socket->head) drop_packet(socket);
}

void linux64_socket_close(struct linux64_socket *socket) {
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
    if (level != SOL_SOCKET || (option != SO_PASSCRED && !(get && option == SO_TYPE)))
        return -ENOPROTOOPT;
    if (!get) {
        i32 enabled;
        if ((i32)length < (i32)sizeof(enabled)) return -EINVAL;
        if (paging64_copy_from_user(&enabled, value, sizeof(enabled)) != sizeof(enabled))
            return -EFAULT;
        socket->passcred = enabled != 0;
        return 0;
    }
    i32 count;
    if (paging64_copy_from_user(&count, length, sizeof(count)) != sizeof(count)) return -EFAULT;
    if (count < 0) return -EINVAL;
    i32 result = option == SO_TYPE ? socket->type : socket->passcred;
    if (count > (i32)sizeof(result)) count = sizeof(result);
    if (paging64_copy_to_user(value, &result, (uptr)count) != (uptr)count ||
        paging64_copy_to_user(length, &count, sizeof(count)) != sizeof(count)) return -EFAULT;
    return 0;
}

static struct packet *new_packet(const struct linux64_socket *socket) {
    uptr physical = pmm64_alloc();
    if (!physical) return NULL;
    struct packet *packet = pmm64_pointer(physical);
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

static long send_packet(struct linux64_socket *socket, const struct iovec *iov, uptr count) {
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
    enqueue(peer, packet);
    return (long)length;
}

static struct identity packet_identity(const struct packet *packet) {
    return (struct identity){
        .pid = linux64_pid_number(packet->sender, linux64_current->process->pid_ns),
        .uid = packet->uid, .gid = packet->gid,
    };
}

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
                           struct msghdr *message, u32 flags) {
    if (!socket->peer) return -EINVAL;
    if (socket->reset) {
        socket->reset = false;
        return -ECONNRESET;
    }
    const struct packet *packet = socket->head;
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
            if (socket->passcred) receive_credentials(packet_identity(packet), message);
            else message->control_length = 0;
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

static long send_stream(struct linux64_socket *socket, const struct iovec *iov, uptr count) {
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
            enqueue(peer, packet);
        } else free_packet(packet);
        if (fault) return done ? (long)done : -EFAULT;
    }
    return (long)done;
}

static long receive_stream(struct linux64_socket *socket, const struct iovec *iov, uptr count,
                           struct msghdr *message, u32 flags) {
    if (!socket->peer) return -EINVAL;
    struct iov_cursor cursor = {iov, iov + count, 0};
    struct packet *packet = socket->head;
    if (!packet) {
        if (message) message->control_length = 0;
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
        if (flags & MSG_PEEK) packet = packet->next;
        else {
            socket->head_offset += (unsigned)copied;
            if (copied == available) drop_packet(socket);
            packet = socket->head;
        }
        if (fault) break;
    }
    linux64_pid_release(first_sender);
    if (fault && !done) return -EFAULT;
    if (message) {
        if (socket->passcred && done) receive_credentials(sender, message);
        else message->control_length = 0;
    }
    return (long)done;
}

long linux64_socket_io(struct linux64_socket *socket, bool receive, uptr buffer, uptr length) {
    if (buffer >= X64_USER_TOP || length > X64_USER_TOP - buffer) return -EFAULT;
    const struct iovec iov = {buffer, length};
    if (linux64_socket_is_stream(socket)) {
        if (!receive) return send_stream(socket, &iov, 1);
        return length ? receive_stream(socket, &iov, 1, NULL, 0) : 0;
    }
    if (!receive) return send_packet(socket, &iov, 1);
    return length ? receive_packet(socket, &iov, 1, NULL, 0) : 0;
}

long linux64_socket_message(struct linux64_socket *socket, bool receive, uptr address, u32 flags) {
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
    if (!receive) {
        if (message.control_length) return -EOPNOTSUPP;
        return linux64_socket_is_stream(socket) ? send_stream(socket, iov, message.iov_count) :
                                                  send_packet(socket, iov, message.iov_count);
    }
    message.flags = flags & MSG_CMSG_CLOEXEC;
    long result = linux64_socket_is_stream(socket) ? receive_stream(socket, iov, message.iov_count, &message, flags) :
                                                    receive_packet(socket, iov, message.iov_count, &message, flags);
    if (result < 0) return result;
    message.name_length = 0;
    if ((message.name && paging64_copy_to_user(address + __builtin_offsetof(struct msghdr, name_length),
                                              &message.name_length, sizeof(message.name_length)) !=
                         sizeof(message.name_length)) ||
        paging64_copy_to_user(address + __builtin_offsetof(struct msghdr, flags),
                              &message.flags, sizeof(message.flags)) != sizeof(message.flags) ||
        !paging64_put_user_u64(address + __builtin_offsetof(struct msghdr, control_length),
                               message.control_length))
        return -EFAULT;
    return result;
}
