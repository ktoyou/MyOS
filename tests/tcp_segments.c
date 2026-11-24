#define HOST_TEST
#include "../kernel/tcp.c"

extern int printf(const char *, ...);
extern void exit(int);
#define CHECK(x) do { if (!(x)) { printf("TCP test failed at %d: %s\n", __LINE__, #x); exit(1); } } while (0)

struct sock *socks[MAX_SOCKS];
static struct sock client, child;
static u8 tx[SOCK_TXBUF], rx[SOCK_RXBUF];
static u32 now, segments, bytes, limit;

void task_wakeup(void *p) { (void)p; }
u32 timer_ticks(void) { return now; }
u32 net_src_ip(u32 dst) { (void)dst; return 1; }
struct sock *sock_alloc(int type) { child.type = type; socks[1] = &child; return &child; }
/* Проверяем границы сегментов и порядок потока, контрольную сумму моделирует канал. */
u16 net_checksum(const void *p, u32 len, u32 sum) { (void)p; (void)len; (void)sum; return 0; }
int ip_send(u32 dst, u8 proto, const void *pkt, u32 len) {
    (void)dst;
    CHECK(proto == PROTO_TCP);
    const struct tcp_hdr *h = pkt;
    u32 payload = len - (h->off >> 4) * 4;
    if (payload) {
        CHECK(payload <= limit);
        segments++;
        bytes += payload;
    }
    return 0;
}

static void receive(u8 flags, u32 seq, const u8 *options, u32 optlen,
                    const char *data, u32 length) {
    u8 pkt[80] = {0};
    struct tcp_hdr *h = (struct tcp_hdr *)pkt;
    h->dport = htons(1234); h->sport = htons(443);
    h->flags = flags; h->seq = htonl(seq); h->ack = htonl(1);
    h->win = htons(8000); h->off = ((sizeof(*h) + optlen) / 4) << 4;
    if (optlen) memcpy(pkt + sizeof(*h), options, optlen);
    if (length) memcpy(pkt + sizeof(*h) + optlen, data, length);
    tcp_input(2, 1, pkt, sizeof(*h) + optlen + length);
}

int main(void) {
    const u8 options[] = {1, 1, 2, 4, 2, 0, 0, 0};
    const u8 invalid[] = {2, 9, 0, 0};
    CHECK(peer_mss(NULL, 0) == 536);
    CHECK(peer_mss(invalid, sizeof(invalid)) == 536);
    socks[0] = &client;
    client = (struct sock){.type=SOCK_TCP, .state=TCP_SYN_SENT, .lport=1234,
        .rport=443, .rip=2, .snd_nxt=1, .txbuf=tx, .rxbuf=rx, .rto=RTO_MIN};
    receive(F_SYN | F_ACK, 17, options, sizeof(options), NULL, 0);
    CHECK(client.state == TCP_ESTABLISHED && client.snd_mss == 512);
    limit = 512;
    char request[1300] = {0};
    CHECK(tcp_write(&client, request, sizeof(request)) == sizeof(request));
    CHECK(segments == 3 && bytes == sizeof(request));
    now = client.rtx_deadline;
    tcp_timer();
    CHECK(segments == 6 && bytes == 2 * sizeof(request));
    receive(F_ACK, 18, NULL, 0, "abc", 3);
    receive(F_ACK, 18, NULL, 0, "ab", 2);
    receive(F_ACK | F_FIN, 19, NULL, 0, "bcdef", 5);
    CHECK(client.peer_fin && client.rx_len == 6 && client.rcv_nxt == 25);
    CHECK(memcmp(rx, "abcdef", 6) == 0);
    client.state = TCP_LISTEN;
    client.backlog = 1;
    receive(F_SYN, 42, options, sizeof(options), NULL, 0);
    CHECK(child.state == TCP_SYN_RCVD && child.snd_mss == 512);
    printf("TCP MSS, retransmission and overlapping receive: PASS\n");
    return 0;
}
