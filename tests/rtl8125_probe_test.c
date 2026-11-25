#include "../tools/rtl8125_probe.h"

#include <stdio.h>
#include <stdlib.h>

enum {
    PCI_ID = 0x00, PCI_COMMAND = 0x04, PCI_CLASS_REVISION = 0x08,
    PCI_HEADER = 0x0c, PCI_BAR0 = 0x10, PCI_BAR1 = 0x14, PCI_BAR2 = 0x18,
    PCI_BAR3 = 0x1c, PCI_CAPABILITIES = 0x34, CAP_PM = 0x50,
    CAP_PCIE = 0x60, PCI_MEMORY_ENABLE = 0x02, REGISTER_BAR = 2, TX_CONFIG = 0x40,
};

#define BAR_BASE UINT64_C(0x1234560000)
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

struct mock_pci {
    uint32_t config[64], command_after, tx_config;
    uint64_t bar_base, bar_size;
    unsigned fail_config, config_reads[64], bar_reads, mmio_reads;
    bool bar_wide, bar_ok, mmio_ok;
};

static struct mock_pci make_device(void) {
    return (struct mock_pci){
        .config = {
            [PCI_ID / 4] = 0x812510ec,
            [PCI_COMMAND / 4] = 0x00100006,
            [PCI_CLASS_REVISION / 4] = 0x0200000c,
            [PCI_BAR0 / 4] = 0x9001,
            [PCI_BAR2 / 4] = 0x34560004,
            [PCI_BAR3 / 4] = 0x12,
            [PCI_CAPABILITIES / 4] = CAP_PCIE,
            [CAP_PCIE / 4] = (CAP_PM << 8) | 0x10,
            [CAP_PM / 4] = 1,
            [(CAP_PM + 4) / 4] = 0x100,
        },
        .command_after = 0x00100006, .tx_config = 0x6b802345,
        .bar_base = BAR_BASE, .bar_size = 0x10000, .fail_config = 0x100,
        .bar_wide = true, .bar_ok = true, .mmio_ok = true,
    };
}

static bool config_read(void *context, unsigned offset, uint32_t *value) {
    struct mock_pci *pci = context;
    CHECK(offset < sizeof(pci->config) && !(offset & 3));
    unsigned index = offset / 4;
    unsigned count = ++pci->config_reads[index];
    CHECK(count <= (offset == PCI_COMMAND ? 2u : 1u));
    if (offset == pci->fail_config) return false;
    *value = offset == PCI_COMMAND && count == 2 ? pci->command_after : pci->config[index];
    return true;
}

static bool describe_bar(void *context, unsigned index, uint64_t base, bool wide, uint64_t *bytes) {
    struct mock_pci *pci = context;
    CHECK(index == REGISTER_BAR && base == pci->bar_base && wide == pci->bar_wide);
    CHECK(++pci->bar_reads == 1);
    if (!pci->bar_ok) return false;
    *bytes = pci->bar_size;
    return true;
}

static bool mmio_read(void *context, unsigned index, unsigned offset, uint32_t *value) {
    struct mock_pci *pci = context;
    CHECK(index == REGISTER_BAR && offset == TX_CONFIG);
    CHECK(pci->config_reads[PCI_COMMAND / 4] == 2);
    CHECK(++pci->mmio_reads == 1);
    if (!pci->mmio_ok) return false;
    *value = pci->tx_config;
    return true;
}

static struct rtl8125_probe_result run(const char *name, struct mock_pci *pci,
                                       enum rtl8125_probe_status expected,
                                       unsigned bar_reads, unsigned mmio_reads) {
    const struct rtl8125_probe_io io = {pci, config_read, describe_bar, mmio_read};
    struct rtl8125_probe_result result = {UINT64_MAX, UINT64_MAX, UINT32_MAX, UINT32_MAX};
    enum rtl8125_probe_status status = rtl8125_probe(&io, &result);
    if (status != expected || pci->bar_reads != bar_reads || pci->mmio_reads != mmio_reads) {
        fprintf(stderr, "%s: status %d, BAR %u, MMIO %u (expected %d, %u, %u)\n", name,
                status, pci->bar_reads, pci->mmio_reads, expected, bar_reads, mmio_reads);
        exit(EXIT_FAILURE);
    }
    if (status != RTL8125_PROBE_OK) CHECK(!result.xid);
    return result;
}

static void check_valid_probes(void) {
    struct mock_pci pci = make_device();
    struct rtl8125_probe_result result = run("64-bit BAR2, XID 688", &pci, RTL8125_PROBE_OK, 1, 1);
    CHECK(result.bar_base == BAR_BASE && result.bar_size == 0x10000);
    CHECK(result.tx_config == 0x6b802345 && result.xid == 0x688);
    CHECK(pci.config_reads[CAP_PCIE / 4] == 1 && pci.config_reads[(CAP_PM + 4) / 4] == 1);

    pci = make_device();
    pci.tx_config = 0x6b902345;
    result = run("64-bit BAR2, XID 689", &pci, RTL8125_PROBE_OK, 1, 1);
    CHECK(result.tx_config == 0x6b902345 && result.xid == 0x689);

    pci = make_device();
    pci.config[PCI_BAR0 / 4] = 0xf0000004;
    pci.config[PCI_BAR1 / 4] = 0x4;
    pci.config[PCI_BAR2 / 4] = 0x34560000;
    pci.bar_base = 0x34560000;
    pci.bar_wide = false;
    result = run("32-bit BAR2 after 64-bit BAR0", &pci, RTL8125_PROBE_OK, 1, 1);
    CHECK(result.bar_base == pci.bar_base && !pci.config_reads[PCI_BAR3 / 4]);
}

static void check_pci_and_bars(void) {
    struct mock_pci pci = make_device();
    pci.config[PCI_ID / 4] = 0x100e8086;
    struct rtl8125_probe_result result = run("Intel 82540", &pci, RTL8125_PROBE_NOT_DEVICE, 0, 0);
    CHECK(!pci.config_reads[PCI_CLASS_REVISION / 4] && !result.bar_base && !result.tx_config);

    pci = make_device();
    pci.config[PCI_CLASS_REVISION / 4] = 0x0280000c;
    run("non-Ethernet class", &pci, RTL8125_PROBE_CLASS, 0, 0);

    pci = make_device();
    pci.config[PCI_HEADER / 4] = 1u << 16;
    run("PCI bridge header", &pci, RTL8125_PROBE_CLASS, 0, 0);

    pci = make_device();
    pci.fail_config = PCI_BAR3;
    run("BAR2 high word read fails", &pci, RTL8125_PROBE_CONFIG_READ, 0, 0);

    pci = make_device();
    pci.config[PCI_BAR1 / 4] = 0xabcd0004;
    run("BAR2 is upper half of BAR1", &pci, RTL8125_PROBE_BAR, 0, 0);

    pci = make_device();
    pci.config[PCI_BAR2 / 4] = 0x4;
    pci.config[PCI_BAR3 / 4] = 0;
    run("unassigned BAR2", &pci, RTL8125_PROBE_BAR, 0, 0);

    pci = make_device();
    pci.config[PCI_BAR2 / 4] = 0x9001;
    run("BAR2 is an I/O port", &pci, RTL8125_PROBE_BAR, 0, 0);

    pci = make_device();
    pci.bar_size = TX_CONFIG + 3;
    run("BAR2 too short", &pci, RTL8125_PROBE_BAR, 1, 0);

    pci = make_device();
    pci.bar_size = UINT64_MAX;
    run("BAR2 range overflows", &pci, RTL8125_PROBE_BAR, 1, 0);

    pci = make_device();
    pci.config[PCI_BAR2 / 4] = 0xfffff000;
    pci.bar_base = 0xfffff000;
    pci.bar_wide = false;
    run("32-bit BAR2 range exceeds 4 GiB", &pci, RTL8125_PROBE_BAR, 1, 0);

    pci = make_device();
    pci.bar_ok = false;
    run("BAR2 metadata unavailable", &pci, RTL8125_PROBE_BAR, 1, 0);
}

static void check_decode_and_power(void) {
    struct mock_pci pci = make_device();
    pci.config[PCI_COMMAND / 4] &= ~PCI_MEMORY_ENABLE;
    run("memory decode initially disabled", &pci, RTL8125_PROBE_MEMORY_DISABLED, 0, 0);
    CHECK(pci.config_reads[PCI_COMMAND / 4] == 1);

    pci = make_device();
    pci.command_after &= ~PCI_MEMORY_ENABLE;
    run("memory decode disabled before MMIO", &pci, RTL8125_PROBE_MEMORY_DISABLED, 1, 0);
    CHECK(pci.config_reads[PCI_COMMAND / 4] == 2);

    pci = make_device();
    pci.command_after = UINT32_MAX;
    run("device disappeared before MMIO", &pci, RTL8125_PROBE_CONFIG_READ, 1, 0);

    pci = make_device();
    pci.config[(CAP_PM + 4) / 4] |= 3;
    run("PCI power D3hot", &pci, RTL8125_PROBE_POWER, 1, 0);

    pci = make_device();
    pci.config[CAP_PM / 4] = (CAP_PCIE << 8) | 0x05;
    run("capability cycle", &pci, RTL8125_PROBE_POWER, 1, 0);
    CHECK(pci.config_reads[CAP_PCIE / 4] == 1 && pci.config_reads[CAP_PM / 4] == 1);

    pci = make_device();
    pci.config[CAP_PCIE / 4] = 0x10;
    run("PCI power capability absent", &pci, RTL8125_PROBE_POWER, 1, 0);

    pci = make_device();
    pci.config[PCI_CAPABILITIES / 4] = CAP_PM + 1;
    run("unaligned capability pointer", &pci, RTL8125_PROBE_POWER, 1, 0);

    pci = make_device();
    pci.config[PCI_CAPABILITIES / 4] = 0xfc;
    pci.config[0xfc / 4] = 1;
    run("power capability truncated at end of config space", &pci, RTL8125_PROBE_POWER, 1, 0);

    pci = make_device();
    pci.fail_config = CAP_PM + 4;
    run("power status read fails", &pci, RTL8125_PROBE_POWER, 1, 0);
}

static void check_mmio_failures(void) {
    struct mock_pci pci = make_device();
    pci.mmio_ok = false;
    run("failed MMIO transaction", &pci, RTL8125_PROBE_MMIO_READ, 1, 1);

    pci = make_device();
    pci.tx_config = UINT32_MAX;
    struct rtl8125_probe_result result = run("all-ones TxConfig", &pci, RTL8125_PROBE_INVALID_TX_CONFIG, 1, 1);
    CHECK(result.tx_config == UINT32_MAX);
}

int main(void) {
    check_valid_probes();
    check_pci_and_bars();
    check_decode_and_power();
    check_mmio_failures();
    puts("RTL8125 read-only probe unit tests: PASS");
    return 0;
}
