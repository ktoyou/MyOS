#include "rtl8125_probe.h"

enum {
    PCI_ID = 0x00, PCI_COMMAND = 0x04, PCI_CLASS_REVISION = 0x08,
    PCI_HEADER_TYPE = 0x0c, PCI_BAR0 = 0x10, PCI_CAPABILITIES = 0x34,
    PCI_MEMORY_ENABLE = 0x2, PCI_STATUS_CAP_LIST = 0x00100000,
    PCI_ETHERNET = 0x0200, PCI_MEMORY_BAR64 = 0x4, PCI_PM_CAP = 1,
    RTL8125_REGISTER_BAR = 2, RTL8125_TX_CONFIG = 0x40,
};

static bool base64(uint32_t bar) {
    return (bar & 7) == PCI_MEMORY_BAR64;
}

static bool powered_on(const struct rtl8125_probe_io *io, uint32_t command) {
    uint32_t link;
    if (!(command & PCI_STATUS_CAP_LIST) || !io->config32(io->context, PCI_CAPABILITIES, &link))
        return false;
    unsigned offset = link & 0xff;
    uint64_t visited = 0;
    while (offset >= 0x40 && offset <= 0xfc && !(offset & 3)) {
        uint64_t bit = UINT64_C(1) << (offset / 4);
        if (visited & bit || !io->config32(io->context, offset, &link)) return false;
        visited |= bit;
        if ((link & 0xff) == PCI_PM_CAP) {
            uint32_t state;
            return offset <= 0xf8 && io->config32(io->context, offset + 4, &state) &&
                   state != UINT32_MAX && !(state & 3);
        }
        offset = (link >> 8) & 0xff;
    }
    return false;
}

enum rtl8125_probe_status rtl8125_probe(const struct rtl8125_probe_io *io,
                                       struct rtl8125_probe_result *result) {
    *result = (struct rtl8125_probe_result){0};
    uint32_t id, class, header, command;
    if (!io->config32(io->context, PCI_ID, &id)) return RTL8125_PROBE_CONFIG_READ;
    if (id != 0x812510ecu) return RTL8125_PROBE_NOT_DEVICE;
    if (!io->config32(io->context, PCI_CLASS_REVISION, &class) ||
        !io->config32(io->context, PCI_HEADER_TYPE, &header) ||
        !io->config32(io->context, PCI_COMMAND, &command)) return RTL8125_PROBE_CONFIG_READ;
    if (class >> 16 != PCI_ETHERNET || ((header >> 16) & 0x7f)) return RTL8125_PROBE_CLASS;
    if (command == UINT32_MAX) return RTL8125_PROBE_CONFIG_READ;
    if (!(command & PCI_MEMORY_ENABLE)) return RTL8125_PROBE_MEMORY_DISABLED;

    uint32_t bar0, bar1, bar2;
    if (!io->config32(io->context, PCI_BAR0, &bar0) ||
        !io->config32(io->context, PCI_BAR0 + 4, &bar1) ||
        !io->config32(io->context, PCI_BAR0 + 8, &bar2)) return RTL8125_PROBE_CONFIG_READ;
    /* RTL8125 использует BAR2. Старшее слово BAR1 не является самостоятельным BAR. */
    if ((!base64(bar0) && base64(bar1)) || ((bar2 & 7) != 0 && !base64(bar2)))
        return RTL8125_PROBE_BAR;
    uint64_t base = bar2 & ~UINT32_C(15);
    bool wide = base64(bar2);
    if (wide) {
        uint32_t high;
        if (!io->config32(io->context, PCI_BAR0 + 12, &high)) return RTL8125_PROBE_CONFIG_READ;
        base |= (uint64_t)high << 32;
    }
    uint64_t bytes, limit = wide ? UINT64_MAX : UINT32_MAX;
    if (!base || !io->memory_bar(io->context, RTL8125_REGISTER_BAR, base, wide, &bytes) ||
        bytes < RTL8125_TX_CONFIG + sizeof(uint32_t) || bytes - 1 > limit - base)
        return RTL8125_PROBE_BAR;
    result->bar_base = base;
    result->bar_size = bytes;

    if (!powered_on(io, command)) return RTL8125_PROBE_POWER;
    if (!io->config32(io->context, PCI_COMMAND, &command) || command == UINT32_MAX)
        return RTL8125_PROBE_CONFIG_READ;
    if (!(command & PCI_MEMORY_ENABLE)) return RTL8125_PROBE_MEMORY_DISABLED;
    if (!io->mmio32(io->context, RTL8125_REGISTER_BAR, RTL8125_TX_CONFIG, &result->tx_config))
        return RTL8125_PROBE_MMIO_READ;
    if (result->tx_config == UINT32_MAX) return RTL8125_PROBE_INVALID_TX_CONFIG;
    result->xid = (result->tx_config >> 20) & 0xfcf;
    return RTL8125_PROBE_OK;
}
