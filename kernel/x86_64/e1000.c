#include "e1000.h"
#include "paging.h"
#include "pci.h"

enum {
    BAR_BYTES = 0x20000, RING_COUNT = 32, BUFFER_BYTES = 2048, DMA_PAGES = 2 + RING_COUNT,
    PCI_MEMORY = 1 << 1, PCI_MASTER = 1 << 2,
    REG_CTRL = 0x0000, REG_STATUS = 0x0008, REG_ICR = 0x00c0, REG_IMC = 0x00d8,
    REG_RCTL = 0x0100, REG_TCTL = 0x0400, REG_TIPG = 0x0410,
    REG_RDBAL = 0x2800, REG_RDBAH = 0x2804, REG_RDLEN = 0x2808, REG_RDH = 0x2810, REG_RDT = 0x2818,
    REG_TDBAL = 0x3800, REG_TDBAH = 0x3804, REG_TDLEN = 0x3808, REG_TDH = 0x3810, REG_TDT = 0x3818,
    REG_MTA = 0x5200, REG_RAL = 0x5400, REG_RAH = 0x5404,
    CTRL_LINK_RESET = 1 << 3, CTRL_LINK_UP = 1 << 6,
    CTRL_FORCE_SPEED = 1 << 11, CTRL_FORCE_DUPLEX = 1 << 12,
    CTRL_VLAN = 1u << 30, CTRL_PHY_RESET = 1u << 31, STATUS_LINK = 1 << 1,
    RX_ENABLE = 1 << 1, RX_BROADCAST = 1 << 15, RX_STRIP_CRC = 1 << 26,
    TX_ENABLE = 1 << 1, TX_PAD = 1 << 3, TX_EOP = 1 << 0, TX_FCS = 1 << 1, TX_REPORT = 1 << 3,
    DESC_DONE = 1, RX_EOP = 2, RX_FRAME_ERRORS = 0x97,
    MIN_FRAME = 14, MIN_WIRE_FRAME = 60,
};

struct rx_desc {
    u64 address;
    u16 length, checksum;
    u8 status, errors;
    u16 special;
};

struct tx_desc {
    u64 address;
    u16 length;
    u8 checksum_offset, command, status, checksum_start;
    u16 special;
};

_Static_assert(sizeof(struct rx_desc) == 16 && sizeof(struct tx_desc) == 16, "82540EM descriptor ABI");
_Static_assert(PMM_PAGE_SIZE == 2 * BUFFER_BYTES, "82540EM buffers per DMA page");
_Static_assert(RING_COUNT * sizeof(struct rx_desc) <= PMM_PAGE_SIZE &&
               (RING_COUNT * sizeof(struct rx_desc)) % 128 == 0, "82540EM ring size");

static volatile u32 *mmio;
static volatile struct rx_desc *rx;
static volatile struct tx_desc *tx;
static u8 *rx_buffer[RING_COUNT], *tx_buffer[RING_COUNT];
static uptr pages[DMA_PAGES];
static unsigned page_count, rx_next, tx_next;
static bool ready, partial_frame;
static u8 mac[6];

static u32 read_reg(unsigned offset) {
    return mmio[offset / sizeof(*mmio)];
}

static void write_reg(unsigned offset, u32 value) {
    mmio[offset / sizeof(*mmio)] = value;
}

static void copy_bytes(void *destination, const void *source, u32 bytes) {
    u8 *out = destination;
    const u8 *in = source;
    for (u32 i = 0; i < bytes; ++i) out[i] = in[i];
}

static uptr dma_page(void) {
    uptr physical = pmm64_alloc();
    if (physical) pages[page_count++] = physical;
    return physical;
}

static bool allocate_dma(uptr *rx_ring, uptr *tx_ring) {
    *rx_ring = dma_page();
    *tx_ring = dma_page();
    if (!*rx_ring || !*tx_ring) return false;
    rx = pmm64_pointer(*rx_ring);
    tx = pmm64_pointer(*tx_ring);
    for (unsigned i = 0; i < RING_COUNT; i += 2) {
        uptr rx_page = dma_page(), tx_page = dma_page();
        if (!rx_page || !tx_page) return false;
        for (unsigned half = 0; half < 2; ++half) {
            uptr offset = half * BUFFER_BYTES;
            unsigned slot = i + half;
            rx[slot].address = rx_page + offset;
            tx[slot].address = tx_page + offset;
            tx[slot].status = DESC_DONE;
            rx_buffer[slot] = pmm64_pointer(rx_page + offset);
            tx_buffer[slot] = pmm64_pointer(tx_page + offset);
        }
    }
    return true;
}

static void stop_queues(void) {
    write_reg(REG_IMC, 0xffffffffu);
    write_reg(REG_RCTL, 0);
    write_reg(REG_TCTL, 0);
    (void)read_reg(REG_ICR);
}

static bool read_mac(void) {
    u32 low = read_reg(REG_RAL), high = read_reg(REG_RAH);
    if (!(high & (1u << 31)) || (low & 1u) || !(low | (high & 0xffffu))) return false;
    for (unsigned i = 0; i < 4; ++i) mac[i] = (u8)(low >> (i * 8));
    mac[4] = (u8)high;
    mac[5] = (u8)(high >> 8);
    return true;
}

static void program_queues(uptr rx_ring, uptr tx_ring) {
    write_reg(REG_RDBAL, (u32)rx_ring);
    write_reg(REG_RDBAH, (u32)(rx_ring >> 32));
    write_reg(REG_RDLEN, RING_COUNT * sizeof(*rx));
    write_reg(REG_RDH, 0);
    write_reg(REG_RDT, 0);

    write_reg(REG_TDBAL, (u32)tx_ring);
    write_reg(REG_TDBAH, (u32)(tx_ring >> 32));
    write_reg(REG_TDLEN, RING_COUNT * sizeof(*tx));
    write_reg(REG_TDH, 0);
    write_reg(REG_TDT, 0);
}

bool e1000_init(void) {
    if (ready) return true;
    struct pci64_device device;
    if (!pci64_find(0x8086, 0x100e, 0x0200, &device)) return false;
    uptr bar = pci64_mmio_bar0(device);
    if (!bar || (bar & (BAR_BYTES - 1))) return false;
    mmio = paging64_map_mmio(bar, BAR_BYTES);
    if (!mmio) return false;

    u16 command = pci64_command(device) & ~PCI_MASTER;
    pci64_set_command(device, command | PCI_MEMORY);
    if ((pci64_command(device) & (PCI_MEMORY | PCI_MASTER)) != PCI_MEMORY) goto fail;
    /* QEMU уже сбрасывает устройство при старте. Останавливаем очереди прошивки перед заменой колец. */
    stop_queues();
    if (!read_mac()) goto fail;
    uptr rx_ring, tx_ring;
    if (!allocate_dma(&rx_ring, &tx_ring)) goto fail;
    for (unsigned i = 0; i < 128; ++i) write_reg(REG_MTA + i * sizeof(u32), 0);
    program_queues(rx_ring, tx_ring);
    /* Адреса колец и дескрипторы уже видны устройству при включении DMA. */
    __sync_synchronize();
    pci64_set_command(device, command | PCI_MEMORY | PCI_MASTER);
    if ((pci64_command(device) & (PCI_MEMORY | PCI_MASTER)) != (PCI_MEMORY | PCI_MASTER)) goto fail;
    u32 control = read_reg(REG_CTRL) & ~(CTRL_PHY_RESET | CTRL_VLAN | CTRL_FORCE_DUPLEX |
                                        CTRL_FORCE_SPEED | CTRL_LINK_RESET);
    write_reg(REG_CTRL, control | CTRL_LINK_UP);
    write_reg(REG_TIPG, 0x0060200au);
    write_reg(REG_TCTL, TX_ENABLE | TX_PAD | (0x10u << 4) | (0x40u << 12));
    write_reg(REG_RCTL, RX_ENABLE | RX_BROADCAST | RX_STRIP_CRC);
    write_reg(REG_RDT, RING_COUNT - 1);
    (void)read_reg(REG_STATUS);
    rx_next = tx_next = 0;
    partial_frame = false;
    ready = true;
    return true;

fail:
    if (pci64_command(device) & PCI_MEMORY) stop_queues();
    pci64_set_command(device, command);
    (void)pci64_command(device);
    while (page_count) pmm64_free(pages[--page_count]);
    paging64_unmap_mmio(mmio, BAR_BYTES);
    mmio = NULL;
    return false;
}

bool e1000_link(void) {
    return ready && (read_reg(REG_STATUS) & STATUS_LINK);
}

void e1000_mac(u8 out[6]) {
    copy_bytes(out, mac, sizeof(mac));
}

bool e1000_send(const void *frame, u32 size) {
    if (!frame || size < MIN_FRAME || size > BUFFER_BYTES || !e1000_link()) return false;
    volatile struct tx_desc *desc = &tx[tx_next];
    unsigned next = (tx_next + 1) % RING_COUNT;
    /* Одинаковые head и tail означают пустое, а не заполненное кольцо. */
    if (next == read_reg(REG_TDH) || !(desc->status & DESC_DONE)) return false;
    __sync_synchronize();
    u8 *buffer = tx_buffer[tx_next];
    copy_bytes(buffer, frame, size);
    while (size < MIN_WIRE_FRAME) buffer[size++] = 0;
    desc->length = (u16)size;
    desc->command = TX_EOP | TX_FCS | TX_REPORT;
    desc->status = 0;
    __sync_synchronize();
    tx_next = next;
    write_reg(REG_TDT, next);
    return true;
}

u32 e1000_receive(void *frame, u32 capacity) {
    if (!ready || !frame) return 0;
    for (unsigned inspected = 0; inspected < RING_COUNT; ++inspected) {
        volatile struct rx_desc *desc = &rx[rx_next];
        u8 status = desc->status;
        if (!(status & DESC_DONE)) return 0;
        __sync_synchronize();
        u32 length = desc->length;
        bool valid = !partial_frame && (status & RX_EOP) && !(desc->errors & RX_FRAME_ERRORS) &&
                     length >= MIN_FRAME && length <= BUFFER_BYTES && length <= capacity;
        if (valid) copy_bytes(frame, rx_buffer[rx_next], length);
        partial_frame = !(status & RX_EOP);
        desc->status = 0;
        __sync_synchronize();
        write_reg(REG_RDT, rx_next);
        rx_next = (rx_next + 1) % RING_COUNT;
        if (valid) return length;
    }
    return 0;
}

const struct ethernet64_driver e1000_driver = {
    .name = "e1000",
    .init = e1000_init,
    .link = e1000_link,
    .mac = e1000_mac,
    .send = e1000_send,
    .receive = e1000_receive,
};
