#ifndef RTL8125_PROBE_H
#define RTL8125_PROBE_H

#include <stdbool.h>
#include <stdint.h>

enum rtl8125_probe_status {
    RTL8125_PROBE_OK,
    RTL8125_PROBE_CONFIG_READ,
    RTL8125_PROBE_NOT_DEVICE,
    RTL8125_PROBE_CLASS,
    RTL8125_PROBE_BAR,
    RTL8125_PROBE_MEMORY_DISABLED,
    RTL8125_PROBE_POWER,
    RTL8125_PROBE_MMIO_READ,
    RTL8125_PROBE_INVALID_TX_CONFIG,
};

struct rtl8125_probe_io {
    void *context;
    bool (*config32)(void *context, unsigned offset, uint32_t *value);
    bool (*memory_bar)(void *context, unsigned index, uint64_t base, bool wide, uint64_t *bytes);
    bool (*mmio32)(void *context, unsigned index, unsigned offset, uint32_t *value);
};

struct rtl8125_probe_result {
    uint64_t bar_base, bar_size;
    uint32_t tx_config, xid;
};

enum rtl8125_probe_status rtl8125_probe(const struct rtl8125_probe_io *io,
                                       struct rtl8125_probe_result *result);

#endif
