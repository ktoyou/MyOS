#include "../kernel/x86_64/linux.h"
#include "../kernel/x86_64/net.h"
#include "../kernel/x86_64/net_bytes.h"
#include "../kernel/x86_64/pmm.h"
#include "../kernel/x86_64/tcp.h"

#define SECOND 1000000000ull
#define STEP (SECOND / 20)

enum {
    TCP = 6, TCP_HEADER = 20, FIN = 1, SYN = 2, RST = 4, ACK = 16,
    EINPROGRESS = 115, ECONNREFUSED = 111, EAGAIN = 11,
    LOCAL_PORT = 43001, REMOTE_PORT = 443, MOCK_PAGES = 128,
};

static const u32 local = 0x0a2c0014, remote = 0x0a2c0051;
static const u32 peer_iss = 0x94fea781;
static const u8 outgoing[] = {0x4d, 0x79, 0x4f, 0x53, 0x98};
static const u8 incoming[] = {0x11, 0x5a, 0xa5};

struct transmission {
    u8 bytes[1500];
    u32 size;
    u64 time;
    unsigned count;
};

static struct transmission syn, data, fin;
static enum net64_tx route_result = NET64_SENT;
static unsigned attempts;
static bool malformed;
static u8 memory[MOCK_PAGES * PMM_PAGE_SIZE] __attribute__((aligned(PMM_PAGE_SIZE)));
static bool allocated[MOCK_PAGES];

extern int puts(const char *text);

static void copy(u8 *dst, const u8 *src, u32 size) {
    for (u32 i = 0; i < size; ++i) dst[i] = src[i];
}

static bool equal(const u8 *a, const u8 *b, u32 size) {
    for (u32 i = 0; i < size; ++i)
        if (a[i] != b[i]) return false;
    return true;
}

uptr pmm64_alloc_contiguous(u32 count) {
    if (!count || count >= MOCK_PAGES) return 0;
    for (u32 first = 1; first <= MOCK_PAGES - count; ++first) {
        u32 end = first;
        while (end < first + count && !allocated[end]) ++end;
        if (end != first + count) {
            first = end;
            continue;
        }
        for (u32 page = first; page < end; ++page) {
            allocated[page] = true;
            u8 *bytes = memory + page * PMM_PAGE_SIZE;
            for (u32 i = 0; i < PMM_PAGE_SIZE; ++i) bytes[i] = 0;
        }
        return (uptr)first * PMM_PAGE_SIZE;
    }
    return 0;
}

uptr pmm64_alloc(void) {
    return pmm64_alloc_contiguous(1);
}

void *pmm64_pointer(uptr physical) {
    return physical < sizeof(memory) ? memory + physical : NULL;
}

bool pmm64_free(uptr physical) {
    if (!physical || physical % PMM_PAGE_SIZE || physical >= sizeof(memory)) return false;
    u32 page = (u32)(physical / PMM_PAGE_SIZE);
    if (!allocated[page]) return false;
    allocated[page] = false;
    return true;
}

uptr linux64_random_bytes(void *buffer, uptr length) {
    static u8 entropy = 0x60;
    u8 *bytes = buffer;
    for (uptr i = 0; i < length; ++i) bytes[i] = ++entropy;
    return length;
}

u32 net64_address(void) {
    return local;
}

bool net64_has_route(u32 destination) {
    return destination == remote;
}

u16 net64_checksum(const void *buffer, u32 length, u32 sum) {
    const u8 *bytes = buffer;
    for (u32 i = 0; i < length; ++i) sum += (u32)bytes[i] << (i % 2 ? 0 : 8);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (u16)~sum;
}

static u32 pseudo_header(u32 source, u32 destination, u32 length) {
    return (source >> 16) + (source & 0xffffu) + (destination >> 16) +
           (destination & 0xffffu) + TCP + length;
}

static void record(struct transmission *tx, const u8 *segment, u32 length, u64 now) {
    copy(tx->bytes, segment, length);
    tx->size = length;
    tx->time = now;
    ++tx->count;
}

enum net64_tx net64_send(u64 now, u32 destination, u8 protocol, const void *buffer, u32 length) {
    const u8 *segment = buffer;
    ++attempts;
    if (protocol != TCP || destination != remote || length < TCP_HEADER || length > sizeof(syn.bytes)) {
        malformed = true;
        return NET64_INVALID;
    }
    u32 header = (segment[12] >> 4) * 4;
    if (header < TCP_HEADER || header > length || net_read16(segment + 2) != REMOTE_PORT ||
        net64_checksum(segment, length, pseudo_header(local, remote, length))) {
        malformed = true;
        return NET64_INVALID;
    }
    if (route_result != NET64_SENT) return route_result;
    if (segment[13] & SYN) record(&syn, segment, length, now);
    if (header < length) record(&data, segment, length, now);
    if (segment[13] & FIN) record(&fin, segment, length, now);
    return NET64_SENT;
}

static void inject(u64 now, u16 port, u32 seq, u32 ack, u8 flags, const u8 *payload, u32 length) {
    u8 packet[TCP_HEADER + sizeof(incoming)] = {0};
    u32 size = TCP_HEADER + length;
    net_write16(packet, REMOTE_PORT);
    net_write16(packet + 2, port);
    net_write32(packet + 4, seq);
    net_write32(packet + 8, ack);
    packet[12] = 5u << 4;
    packet[13] = flags;
    net_write16(packet + 14, 4096);
    copy(packet + TCP_HEADER, payload, length);
    net_write16(packet + 16, net64_checksum(packet, size, pseudo_header(remote, local, size)));
    tcp64_input(now, remote, local, packet, size);
}

static bool check_syn_retry(void) {
    const u64 start = SECOND;
    struct tcp64_connection *connection = NULL;
    route_result = NET64_RETRY;
    if (tcp64_open(start, local, LOCAL_PORT, remote, REMOTE_PORT, &connection) || !connection ||
        !tcp64_port_used(LOCAL_PORT)) return false;
    /* Пока ARP не завершён, попытки передачи не запускают таймер SYN. */
    for (u64 time = start; time < start + 3 * SECOND; time += STEP) tcp64_tick(time);
    if (!attempts || syn.count || tcp64_connect_result(connection) != -EINPROGRESS) return false;

    route_result = NET64_SENT;
    for (u64 time = start + 3 * SECOND; !syn.count && time <= start + 4 * SECOND; time += STEP)
        tcp64_tick(time);
    if (syn.count != 1 || syn.bytes[13] != SYN || net_read16(syn.bytes) != LOCAL_PORT) return false;
    u64 first_send = syn.time;
    u32 iss = net_read32(syn.bytes + 4);

    tcp64_tick(first_send + SECOND - 1);
    if (syn.count != 1) return false;
    tcp64_tick(first_send + SECOND);
    if (syn.count != 2 || syn.bytes[13] != SYN || net_read32(syn.bytes + 4) != iss) return false;

    inject(first_send + SECOND + 1, LOCAL_PORT, 0, iss + 2, RST | ACK, NULL, 0);
    if (tcp64_connect_result(connection) != -EINPROGRESS) return false;
    inject(first_send + SECOND + 2, LOCAL_PORT, 0, iss + 1, RST | ACK, NULL, 0);
    if (tcp64_connect_result(connection) != -ECONNREFUSED) return false;
    tcp64_close(connection, first_send + SECOND + 3);
    return !tcp64_port_used(LOCAL_PORT);
}

static bool check_data(void) {
    const u64 start = 40 * SECOND;
    const u16 port = LOCAL_PORT + 1;
    struct tcp64_connection *connection = NULL;
    syn.count = 0;
    if (tcp64_open(start, local, port, remote, REMOTE_PORT, &connection) || !connection) return false;
    tcp64_tick(start);
    if (syn.count != 1 || net_read16(syn.bytes) != port) return false;
    u32 seq = net_read32(syn.bytes + 4) + 1;

    inject(start + 1, port, peer_iss, seq, SYN | ACK, NULL, 0);
    u8 buffer[sizeof(incoming)];
    if (tcp64_connect_result(connection) || tcp64_read(connection, buffer, sizeof(buffer)) != -EAGAIN ||
        tcp64_write(connection, outgoing, sizeof(outgoing)) != sizeof(outgoing)) return false;
    tcp64_tick(start + 2);
    u32 header = (data.bytes[12] >> 4) * 4;
    if (data.count != 1 || data.size != header + sizeof(outgoing) || net_read32(data.bytes + 4) != seq ||
        net_read32(data.bytes + 8) != peer_iss + 1 || !(data.bytes[13] & ACK) ||
        !equal(data.bytes + header, outgoing, sizeof(outgoing))) return false;

    u64 first_send = data.time;
    tcp64_tick(first_send + SECOND - 1);
    if (data.count != 1) return false;
    tcp64_tick(first_send + SECOND);
    header = (data.bytes[12] >> 4) * 4;
    if (data.count != 2 || data.size != header + sizeof(outgoing) || net_read32(data.bytes + 4) != seq ||
        !equal(data.bytes + header, outgoing, sizeof(outgoing))) return false;

    u32 after_data = seq + sizeof(outgoing);
    u64 peer_data = first_send + SECOND + 1;
    inject(peer_data, port, peer_iss + 1, after_data, ACK, incoming, sizeof(incoming));
    if (tcp64_read(connection, buffer, sizeof(buffer)) != sizeof(buffer) || !equal(buffer, incoming, sizeof(buffer)) ||
        tcp64_read(connection, buffer, sizeof(buffer)) != sizeof(buffer)) return false;
    tcp64_consume(connection, 1);
    if (tcp64_read(connection, buffer, sizeof(buffer)) != sizeof(buffer) - 1 ||
        !equal(buffer, incoming + 1, sizeof(buffer) - 1)) return false;
    tcp64_consume(connection, sizeof(buffer) - 1);
    if (tcp64_read(connection, buffer, sizeof(buffer)) != -EAGAIN) return false;
    tcp64_tick(peer_data + 3 * SECOND);
    if (data.count != 2) return false;

    u64 finish = peer_data + 3 * SECOND + 1;
    u32 peer_end = peer_iss + 1 + sizeof(incoming);
    inject(finish, port, peer_end, after_data, FIN | ACK, NULL, 0);
    if (tcp64_read(connection, buffer, sizeof(buffer)) != 0) return false;
    tcp64_shutdown(connection, 1);
    tcp64_tick(finish + 1);
    if (fin.count != 1 || !(fin.bytes[13] & ACK) || net_read32(fin.bytes + 4) != after_data ||
        net_read32(fin.bytes + 8) != peer_end + 1) return false;
    inject(finish + 2, port, peer_end + 1, after_data + 1, ACK, NULL, 0);
    tcp64_close(connection, finish + 3);
    return true;
}

int main(void) {
    if (!check_syn_retry()) { puts("TCP: ARP, SYN retransmission or RST validation FAIL"); return 1; }
    if (!check_data()) { puts("TCP: data retransmission, receive queue or FIN FAIL"); return 2; }
    if (malformed) { puts("TCP: outgoing header/checksum FAIL"); return 3; }
    puts("TCP: ARP wait, SYN and data retransmission, validated RST, receive and FIN PASS");
    return 0;
}
