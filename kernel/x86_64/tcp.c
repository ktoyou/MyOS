#include "tcp.h"
#include "linux.h"
#include "net.h"
#include "net_bytes.h"
#include "pmm.h"

#define SECOND 1000000000ull

enum {
    TCP = 6, HEADER = 20, MSS = 1460, BUFFER = 2 * PMM_PAGE_SIZE, CONNECTIONS = 64,
    FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16, RETRIES = 6,
    EAGAIN = 11, ENOMEM = 12, EINVAL = 22, ENFILE = 23, EPIPE = 32, EADDRINUSE = 98,
    ENETDOWN = 100, ENETUNREACH = 101, ECONNRESET = 104, ENOTCONN = 107,
    ETIMEDOUT = 110, ECONNREFUSED = 111, EHOSTUNREACH = 113, EINPROGRESS = 115,
};

enum tcp_state { FREE, SYN_SENT, CONNECTED, TIME_WAIT, CLOSED };

struct tcp64_connection {
    enum tcp_state state;
    bool established, detached, shut_rx, shut_tx, fin_sent, fin_acked, peer_fin, ack_pending;
    u8 retries;
    u16 local_port, remote_port, mss;
    u32 source, destination, snd_una, snd_nxt, rcv_nxt;
    u32 snd_window, wnd_seq, wnd_ack, congestion, slow_threshold, congestion_credit;
    u32 tx_length, rx_head, rx_length;
    i32 error, connect_error;
    uptr storage;
    u64 retransmit, rto, connect_until, close_until, probe_at, stalled_until;
};

static struct tcp64_connection connections[CONNECTIONS];

static bool before(u32 a, u32 b) {
    return (i32)(a - b) < 0;
}

static u32 min(u32 a, u32 b) {
    return a < b ? a : b;
}

static u8 *tx_buffer(const struct tcp64_connection *c) {
    return pmm64_pointer(c->storage);
}

static u8 *rx_buffer(const struct tcp64_connection *c) {
    return (u8 *)pmm64_pointer(c->storage) + BUFFER;
}

static void release(struct tcp64_connection *c) {
    for (uptr offset = 0; offset < 2 * BUFFER; offset += PMM_PAGE_SIZE)
        pmm64_free(c->storage + offset);
    *c = (struct tcp64_connection){0};
}

static void finish(struct tcp64_connection *c, i32 error) {
    if (c->detached) {
        release(c);
        return;
    }
    c->state = CLOSED;
    c->error = error;
    if (!c->established) c->connect_error = error;
    c->tx_length = 0;
}

static i32 route_error(enum net64_tx result) {
    switch (result) {
    case NET64_NO_ROUTE: return ENETUNREACH;
    case NET64_LINK_DOWN: return ENETDOWN;
    case NET64_UNREACHABLE: return EHOSTUNREACH;
    case NET64_INVALID: return EINVAL;
    default: return 0;
    }
}

static u32 checksum_seed(u32 source, u32 dest, u32 length) {
    return (source >> 16) + (source & 0xffffu) + (dest >> 16) + (dest & 0xffffu) + TCP + length;
}

static u32 receive_window(const struct tcp64_connection *c) {
    return BUFFER - c->rx_length;
}

static enum net64_tx segment(const struct tcp64_connection *c, u64 now, u8 flags,
                             u32 sequence, u32 offset, u32 bytes) {
    u8 wire[HEADER + MSS];
    unsigned header = HEADER;
    net_write16(wire, c->local_port);
    net_write16(wire + 2, c->remote_port);
    net_write32(wire + 4, sequence);
    net_write32(wire + 8, flags & ACK ? c->rcv_nxt : 0);
    wire[13] = flags;
    net_write16(wire + 14, (u16)receive_window(c));
    net_write16(wire + 16, 0);
    net_write16(wire + 18, 0);
    if (flags & SYN) {
        wire[20] = 2;
        wire[21] = 4;
        net_write16(wire + 22, MSS);
        header += 4;
    }
    wire[12] = (u8)((header / 4) << 4);
    if (bytes) {
        const u8 *data = tx_buffer(c) + offset;
        for (u32 i = 0; i < bytes; ++i) wire[header + i] = data[i];
    }
    u32 length = header + bytes;
    net_write16(wire + 16, net64_checksum(wire, length, checksum_seed(c->source, c->destination, length)));
    return net64_send(now, c->destination, TCP, wire, length);
}

static bool sent(struct tcp64_connection *c, u64 now, u8 flags, u32 sequence, u32 offset, u32 bytes) {
    enum net64_tx result = segment(c, now, flags, sequence, offset, bytes);
    if (result == NET64_SENT) {
        if (flags & ACK) c->ack_pending = false;
        return true;
    }
    i32 error = route_error(result);
    if (error) finish(c, error);
    return false;
}

bool tcp64_port_used(u16 port) {
    for (unsigned i = 0; i < CONNECTIONS; ++i)
        if (connections[i].state != FREE && connections[i].state != CLOSED && connections[i].local_port == port)
            return true;
    return false;
}

long tcp64_open(u64 now, u32 source, u16 local_port, u32 destination, u16 remote_port,
                struct tcp64_connection **out) {
    if (!source || !local_port || !remote_port) return -EINVAL;
    if (source != net64_address() || !net64_has_route(destination)) return -ENETUNREACH;
    if (tcp64_port_used(local_port)) return -EADDRINUSE;
    struct tcp64_connection *c = NULL;
    for (unsigned i = 0; i < CONNECTIONS; ++i) {
        if (connections[i].state != FREE) continue;
        c = &connections[i];
        break;
    }
    if (!c) return -ENFILE;
    u32 initial;
    if (linux64_random_bytes(&initial, sizeof(initial)) != sizeof(initial)) return -EAGAIN;
    uptr storage = pmm64_alloc_contiguous(2 * BUFFER / PMM_PAGE_SIZE);
    if (!storage) return -ENOMEM;
    *c = (struct tcp64_connection){
        .state = SYN_SENT, .source = source, .destination = destination,
        .local_port = local_port, .remote_port = remote_port, .snd_una = initial, .snd_nxt = initial,
        .storage = storage, .connect_until = now + 32 * SECOND, .rto = SECOND,
    };
    *out = c;
    return 0;
}

long tcp64_connect_result(const struct tcp64_connection *c) {
    if (!c) return -ENOTCONN;
    if (c->established) return 0;
    if (c->state == SYN_SENT) return -EINPROGRESS;
    return c->connect_error ? -c->connect_error : -ENOTCONN;
}

i32 tcp64_error(struct tcp64_connection *c, bool clear) {
    if (!c) return 0;
    i32 error = c->error;
    if (clear) c->error = 0;
    return error;
}

u16 tcp64_events(const struct tcp64_connection *c) {
    if (!c) return LINUX64_POLLHUP | LINUX64_POLL_WRITE;
    if (c->state == SYN_SENT) return 0;
    u16 ready = c->error ? LINUX64_POLLERR : 0;
    bool eof = c->peer_fin || c->shut_rx || c->state == CLOSED || c->state == TIME_WAIT;
    if (eof) ready |= LINUX64_POLLRDHUP;
    if (c->rx_length || eof) ready |= LINUX64_POLL_READ;
    if (c->tx_length < BUFFER || c->shut_tx || c->error) ready |= LINUX64_POLL_WRITE;
    if (c->state == CLOSED || c->state == TIME_WAIT || (eof && c->shut_tx)) ready |= LINUX64_POLLHUP;
    return ready;
}

long tcp64_read(struct tcp64_connection *c, void *buffer, u32 length) {
    if (!c) return -ENOTCONN;
    if (!length) return 0;
    if (c->rx_length) {
        u8 *destination = buffer, *rx = rx_buffer(c);
        u32 copied = min(c->rx_length, length);
        for (u32 i = 0; i < copied; ++i) destination[i] = rx[(c->rx_head + i) % BUFFER];
        return copied;
    }
    if (c->error) return -tcp64_error(c, true);
    if (c->state == SYN_SENT) return -EAGAIN;
    if (!c->established) return -ENOTCONN;
    return c->peer_fin || c->shut_rx || c->state == CLOSED ? 0 : -EAGAIN;
}

void tcp64_consume(struct tcp64_connection *c, u32 bytes) {
    bytes = min(bytes, c->rx_length);
    c->rx_head = (c->rx_head + bytes) % BUFFER;
    c->rx_length -= bytes;
    if (bytes && !c->peer_fin && c->state == CONNECTED) c->ack_pending = true;
}

long tcp64_write(struct tcp64_connection *c, const void *buffer, u32 length) {
    if (!c) return -ENOTCONN;
    if (c->error) return -tcp64_error(c, true);
    if (c->state == SYN_SENT) return -EAGAIN;
    if (!c->established) return -ENOTCONN;
    if (c->shut_tx || c->state != CONNECTED) return -EPIPE;
    if (!length) return 0;
    u32 bytes = min(BUFFER - c->tx_length, length);
    if (!bytes) return -EAGAIN;
    u8 *tx = tx_buffer(c) + c->tx_length;
    const u8 *source = buffer;
    for (u32 i = 0; i < bytes; ++i) tx[i] = source[i];
    c->tx_length += bytes;
    return bytes;
}

void tcp64_shutdown(struct tcp64_connection *c, i32 how) {
    if (how != 1) {
        c->shut_rx = true;
        tcp64_consume(c, c->rx_length);
    }
    if (how != 0) c->shut_tx = true;
}

void tcp64_close(struct tcp64_connection *c, u64 now) {
    if (!c) return;
    if (c->state == CLOSED || !c->established) {
        release(c);
        return;
    }
    tcp64_shutdown(c, 2);
    c->detached = true;
    if (c->state != TIME_WAIT) c->close_until = now + 30 * SECOND;
}

static u16 peer_mss(const u8 *opt, u32 size) {
    while (size && opt[0]) {
        if (opt[0] == 1) {
            ++opt;
            --size;
            continue;
        }
        if (size < 2 || opt[1] < 2 || opt[1] > size) break;
        if (opt[0] == 2 && opt[1] == 4 && net_read16(opt + 2))
            return (u16)min(MSS, net_read16(opt + 2));
        u32 length = opt[1];
        opt += length;
        size -= length;
    }
    return 536;
}

static void syn_input(struct tcp64_connection *c, u8 flags, u32 seq, u32 ack, u32 window,
                      const u8 *options, u32 length) {
    if (!(flags & ACK) || c->snd_una == c->snd_nxt || ack != c->snd_nxt) return;
    if (flags & RST) {
        finish(c, ECONNREFUSED);
        return;
    }
    if (!(flags & SYN) || (flags & FIN)) return;
    c->state = CONNECTED;
    c->established = true;
    c->snd_una = ack;
    c->rcv_nxt = seq + 1;
    c->snd_window = window;
    c->wnd_seq = seq;
    c->wnd_ack = ack;
    c->mss = peer_mss(options, length);
    c->congestion = 2u * c->mss;
    c->slow_threshold = BUFFER;
    c->retransmit = 0;
    c->rto = SECOND;
    c->retries = 0;
    c->ack_pending = true;
}

static void acknowledge(struct tcp64_connection *c, u64 now, u32 ack) {
    u32 confirmed = ack - c->snd_una;
    u32 data = min(confirmed, c->tx_length);
    u8 *bytes = tx_buffer(c);
    for (u32 i = data; i < c->tx_length; ++i) bytes[i - data] = bytes[i];
    c->tx_length -= data;
    c->snd_una = ack;
    c->retries = 0;
    c->rto = SECOND;
    c->retransmit = c->snd_una != c->snd_nxt ? now + c->rto : 0;
    c->stalled_until = 0;
    if (c->congestion < c->slow_threshold)
        c->congestion += min(data, c->mss);
    else if ((c->congestion_credit += data) >= c->congestion) {
        c->congestion_credit -= c->congestion;
        c->congestion += c->mss;
    }
    c->congestion = min(c->congestion, BUFFER);
    if (c->fin_sent && ack == c->snd_nxt) c->fin_acked = true;
}

static void time_wait(struct tcp64_connection *c, u64 now) {
    if (c->fin_acked && c->peer_fin) {
        c->state = TIME_WAIT;
        c->close_until = now + 60 * SECOND;
    }
}

void tcp64_input(u64 now, u32 source, u32 destination, const u8 *wire, u32 length) {
    if (length < HEADER) return;
    u32 header = (wire[12] >> 4) * 4;
    if (header < HEADER || header > length || net64_checksum(wire, length, checksum_seed(source, destination, length)))
        return;
    u16 remote_port = net_read16(wire), local_port = net_read16(wire + 2);
    struct tcp64_connection *c = NULL;
    for (unsigned i = 0; i < CONNECTIONS; ++i) {
        struct tcp64_connection *entry = &connections[i];
        if (entry->state == FREE || entry->state == CLOSED || entry->local_port != local_port ||
            entry->remote_port != remote_port || entry->source != destination || entry->destination != source) continue;
        c = entry;
        break;
    }
    if (!c) return;
    u32 seq = net_read32(wire + 4), ack = net_read32(wire + 8), window = net_read16(wire + 14);
    u8 flags = wire[13];
    if (c->state == SYN_SENT) {
        syn_input(c, flags, seq, ack, window, wire + HEADER, header - HEADER);
        return;
    }
    u32 size = length - header;
    if (c->state == TIME_WAIT) {
        if ((flags & FIN) && seq + size + 1 == c->rcv_nxt) {
            c->ack_pending = true;
            c->close_until = now + 60 * SECOND;
        }
        return;
    }
    if (flags & RST) {
        if (seq == c->rcv_nxt) finish(c, ECONNRESET);
        else if (!before(seq, c->rcv_nxt) && before(seq, c->rcv_nxt + receive_window(c))) c->ack_pending = true;
        return;
    }
    if (!(flags & ACK) || (flags & SYN) || before(c->snd_nxt, ack) || before(c->rcv_nxt, seq)) {
        c->ack_pending = true;
        return;
    }
    u32 skip = c->rcv_nxt - seq;
    if (skip > size || (skip && skip == size && !(flags & FIN))) {
        if (size || (flags & FIN) || skip == 1) c->ack_pending = true;
        return;
    }
    if (!before(ack, c->snd_una)) {
        if (before(c->snd_una, ack)) acknowledge(c, now, ack);
        if (before(c->wnd_seq, seq) || (c->wnd_seq == seq && !before(ack, c->wnd_ack))) {
            c->snd_window = window;
            c->wnd_seq = seq;
            c->wnd_ack = ack;
        }
    }
    if (!c->peer_fin) {
        u32 bytes = min(size - skip, receive_window(c));
        if (bytes && !c->shut_rx) {
            const u8 *data = wire + header + skip;
            u8 *rx = rx_buffer(c);
            for (u32 i = 0; i < bytes; ++i) rx[(c->rx_head + c->rx_length + i) % BUFFER] = data[i];
            c->rx_length += bytes;
        }
        c->rcv_nxt += bytes;
        if ((flags & FIN) && seq + size == c->rcv_nxt) {
            ++c->rcv_nxt;
            c->peer_fin = true;
        }
    }
    if (size || (flags & FIN)) c->ack_pending = true;
    time_wait(c, now);
}

static void retry_timer(struct tcp64_connection *c, u64 now) {
    ++c->retries;
    if (c->rto < 8 * SECOND) c->rto *= 2;
    c->retransmit = now + c->rto;
}

static void transmit_syn(struct tcp64_connection *c, u64 now) {
    if (now >= c->connect_until) {
        finish(c, ETIMEDOUT);
        return;
    }
    if (c->snd_nxt == c->snd_una) {
        if (sent(c, now, SYN, c->snd_una, 0, 0)) {
            ++c->snd_nxt;
            c->retransmit = now + c->rto;
        }
    } else if (now >= c->retransmit && sent(c, now, SYN, c->snd_una, 0, 0)) retry_timer(c, now);
}

static void retransmit(struct tcp64_connection *c, u64 now) {
    if (c->retries == RETRIES) {
        finish(c, ETIMEDOUT);
        return;
    }
    u32 flight = min(c->tx_length, c->snd_nxt - c->snd_una);
    u32 bytes = min(c->mss, flight);
    if (!sent(c, now, bytes ? ACK | PSH : ACK | FIN, c->snd_una, 0, bytes)) return;
    if (!c->retries) {
        u32 minimum = 2u * c->mss;
        c->slow_threshold = flight / 2 > minimum ? flight / 2 : minimum;
    }
    c->congestion = c->mss;
    c->congestion_credit = 0;
    retry_timer(c, now);
}

static void transmit_stream(struct tcp64_connection *c, u64 now) {
    if (c->retransmit && now >= c->retransmit) {
        retransmit(c, now);
        return;
    }
    u32 window = min(c->snd_window, c->congestion);
    for (unsigned budget = 0; budget < 6; ++budget) {
        u32 unacked = c->snd_nxt - c->snd_una;
        if (unacked >= c->tx_length || unacked >= window) break;
        u32 bytes = min(c->mss, min(c->tx_length - unacked, window - unacked));
        if (!sent(c, now, ACK | PSH, c->snd_nxt, unacked, bytes)) return;
        c->snd_nxt += bytes;
        if (!unacked) c->retransmit = now + c->rto;
    }
    if (c->shut_tx && !c->fin_sent && !c->tx_length && window) {
        if (sent(c, now, ACK | FIN, c->snd_nxt, 0, 0)) {
            c->fin_sent = true;
            ++c->snd_nxt;
            c->retransmit = now + c->rto;
        }
    }
}

static bool tick_connection(struct tcp64_connection *c, u64 now) {
    if (c->state == FREE || c->state == CLOSED) return false;
    if (((c->detached || c->state == TIME_WAIT) && now >= c->close_until)) {
        finish(c, 0);
        return false;
    }
    if (c->source != net64_address()) {
        finish(c, ENETDOWN);
        return false;
    }
    if (c->state == SYN_SENT) {
        transmit_syn(c, now);
        return c->state == SYN_SENT;
    }
    if (c->state == CONNECTED) transmit_stream(c, now);
    if (c->state == FREE || c->state == CLOSED) return false;
    if (c->ack_pending) sent(c, now, ACK, c->snd_nxt, 0, 0);
    if (c->state == FREE || c->state == CLOSED) return false;
    if (c->state == TIME_WAIT) return c->ack_pending;
    bool blocked = c->state == CONNECTED && !c->snd_window && !c->retransmit &&
                   (c->tx_length || (c->shut_tx && !c->fin_sent));
    if (blocked) {
        if (!c->stalled_until) c->stalled_until = now + 60 * SECOND;
        if (now >= c->stalled_until) finish(c, ETIMEDOUT);
        else if (now >= c->probe_at && sent(c, now, ACK, c->snd_nxt - 1, 0, 0))
            c->probe_at = now + SECOND;
    } else c->stalled_until = 0;
    return c->state != FREE && c->state != CLOSED &&
           (c->tx_length || c->ack_pending || (c->shut_tx && !c->fin_acked) || c->detached);
}

bool tcp64_tick(u64 now) {
    bool waiting = false;
    for (unsigned i = 0; i < CONNECTIONS; ++i)
        if (tick_connection(&connections[i], now)) waiting = true;
    return waiting;
}
