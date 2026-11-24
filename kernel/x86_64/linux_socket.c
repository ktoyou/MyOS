#include "linux_task.h"
#include "paging.h"

enum {
    EAGAIN = 11, ENOMEM = 12, EFAULT = 14, EINVAL = 22, EMFILE = 24, EPIPE = 32,
    EMSGSIZE = 90, EPROTONOSUPPORT = 93, ESOCKTNOSUPPORT = 94, EOPNOTSUPP = 95,
    EAFNOSUPPORT = 97, ENOPROTOOPT = 92, ECONNRESET = 104,
    AF_UNIX = 1, SOCK_SEQPACKET = 5, SOCK_TYPE_MASK = 0xf,
    SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000,
    SHUT_RD = 0, SHUT_WR = 1, SHUT_RDWR = 2,
    SOL_SOCKET = 1, SO_TYPE = 3, SO_PASSCRED = 16, SCM_CREDENTIALS = 2,
    MSG_PEEK = 2, MSG_CTRUNC = 8, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40,
    MSG_EOR = 0x80, MSG_NOSIGNAL = 0x4000, MSG_CMSG_CLOEXEC = 0x40000000,
    MAX_IOV = 64, MAX_QUEUED = 32,
};

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
    uptr physical;
    u32 length;
    struct identity sender;
    u8 bytes[];
};

#define MAX_PACKET (PMM_PAGE_SIZE - sizeof(struct packet))

struct linux64_socket {
    struct linux64_socket *peer;
    struct packet *head, *tail;
    unsigned queued;
    bool open, passcred, reset, read_shutdown, write_shutdown;
};

/* Один конец может оставаться открытым после закрытия его пары. */
static struct linux64_socket pairs[LINUX64_TASK_COUNT * LINUX64_FD_COUNT][2];

long linux64_socket_pair(i32 domain, u32 type, i32 protocol, struct linux64_socket *ends[2]) {
    if (type & ~(SOCK_TYPE_MASK | SOCK_CLOEXEC | SOCK_NONBLOCK)) return -EINVAL;
    if (domain != AF_UNIX) return -EAFNOSUPPORT;
    if ((type & SOCK_TYPE_MASK) != SOCK_SEQPACKET) return -ESOCKTNOSUPPORT;
    if (protocol != 0 && protocol != AF_UNIX) return -EPROTONOSUPPORT;
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i) {
        struct linux64_socket *pair = pairs[i];
        if (pair[0].open || pair[1].open) continue;
        pair[0] = (struct linux64_socket){.peer = &pair[1], .open = true};
        pair[1] = (struct linux64_socket){.peer = &pair[0], .open = true};
        ends[0] = &pair[0];
        ends[1] = &pair[1];
        return 0;
    }
    return -EMFILE;
}

static void drop_packet(struct linux64_socket *socket) {
    struct packet *packet = socket->head;
    socket->head = packet->next;
    if (!socket->head) socket->tail = NULL;
    --socket->queued;
    pmm64_free(packet->physical);
}

void linux64_socket_close(struct linux64_socket *socket) {
    socket->open = false;
    const struct packet *unread = socket->head;
    if (unread && !unread->length) unread = unread->next;
    if (socket->peer->open && unread) socket->peer->reset = true;
    while (socket->head) drop_packet(socket);
}

long linux64_socket_shutdown(struct linux64_socket *socket, i32 how) {
    if (how < SHUT_RD || how > SHUT_RDWR) return -EINVAL;
    /* Закрытие направления останавливает новые записи, но сохраняет очередь. */
    if (how != SHUT_WR) {
        socket->read_shutdown = true;
        if (socket->peer->open) socket->peer->write_shutdown = true;
    }
    if (how != SHUT_RD) {
        socket->write_shutdown = true;
        if (socket->peer->open) socket->peer->read_shutdown = true;
    }
    return 0;
}

u16 linux64_socket_poll(const struct linux64_socket *socket) {
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
    i32 result = option == SO_TYPE ? SOCK_SEQPACKET : socket->passcred;
    if (count > (i32)sizeof(result)) count = sizeof(result);
    if (paging64_copy_to_user(value, &result, (uptr)count) != (uptr)count ||
        paging64_copy_to_user(length, &count, sizeof(count)) != sizeof(count)) return -EFAULT;
    return 0;
}

static long send_packet(struct linux64_socket *socket, const struct iovec *iov, uptr count) {
    if (socket->reset) {
        socket->reset = false;
        return -ECONNRESET;
    }
    struct linux64_socket *peer = socket->peer;
    if (!peer->open || socket->write_shutdown) return -EPIPE;
    uptr length = 0;
    for (uptr i = 0; i < count; ++i) {
        if (iov[i].length > MAX_PACKET - length) return -EMSGSIZE;
        length += iov[i].length;
    }
    if (peer->queued == MAX_QUEUED) return -EAGAIN;
    uptr physical = pmm64_alloc();
    if (!physical) return -ENOMEM;
    struct packet *packet = pmm64_pointer(physical);
    packet->physical = physical;
    packet->length = (u32)length;
    if (socket->passcred || peer->passcred)
        packet->sender = (struct identity){linux64_current->process->pid, LINUX64_UID, LINUX64_GID};
    else
        packet->sender = (struct identity){0, 65534, 65534};
    uptr copied = 0;
    for (uptr i = 0; i < count; ++i) {
        uptr size = iov[i].length;
        if (paging64_copy_from_user(packet->bytes + copied, iov[i].base, size) != size) {
            pmm64_free(physical);
            return -EFAULT;
        }
        copied += size;
    }
    if (peer->tail) peer->tail->next = packet;
    else peer->head = packet;
    peer->tail = packet;
    ++peer->queued;
    return (long)length;
}

static void receive_credentials(const struct packet *packet, struct msghdr *message) {
    uptr available = message->control ? message->control_length : 0;
    message->control_length = 0;
    if (available < CRED_LENGTH) message->flags |= MSG_CTRUNC;
    if (available < __builtin_offsetof(struct credentials, sender)) return;
    uptr length = available < CRED_LENGTH ? available : CRED_LENGTH;
    const struct linux64_userns *ns = linux64_current->process->userns;
    struct credentials control = {
        .length = length, .level = SOL_SOCKET, .type = SCM_CREDENTIALS,
        .sender = packet->sender,
    };
    control.sender.uid = linux64_visible_id(ns, false, control.sender.uid);
    control.sender.gid = linux64_visible_id(ns, true, control.sender.gid);
    if (paging64_copy_to_user(message->control, &control, length) != length) return;
    message->control_length = available < sizeof(control) ? available : sizeof(control);
}

static long receive_packet(struct linux64_socket *socket, const struct iovec *iov, uptr count,
                           struct msghdr *message, u32 flags) {
    if (socket->reset) {
        socket->reset = false;
        return -ECONNRESET;
    }
    const struct packet *packet = socket->head;
    if (!packet) {
        if (message) message->control_length = 0;
        /* Ожидание записи другого процесса ещё не связано с планировщиком. */
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
            if (socket->passcred) receive_credentials(packet, message);
            else message->control_length = 0;
        }
        result = (long)(flags & MSG_TRUNC ? packet->length : copied);
    }
    if (!(flags & MSG_PEEK)) drop_packet(socket);
    return result;
}

long linux64_socket_io(struct linux64_socket *socket, bool receive, uptr buffer, uptr length) {
    const struct iovec iov = {buffer, length};
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
        return send_packet(socket, iov, message.iov_count);
    }
    message.flags = flags & MSG_CMSG_CLOEXEC;
    long result = receive_packet(socket, iov, message.iov_count, &message, flags);
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
