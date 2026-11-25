#include "../kernel/nvme.h"
#include "../kernel/x86_64/pmm.h"

extern void kernel64_serial_char(char ch);

enum { SECTOR = 512, DATA_SECTORS = 8192, FIRST = 32, COUNT = 19, UNIT = 3 };
static const char live_magic[] = "MYOSNVME";
static const char data_magic[] = "MYOSDATA";
static const u8 seeds[] = {0x37, 0x58, 0xa9};
static u8 write_buffer[COUNT * SECTOR] __attribute__((aligned(PMM_PAGE_SIZE)));
static u8 sector[SECTOR];

static bool matches(const u8 *bytes, const char *magic, unsigned length) {
    for (unsigned i = 0; i < length; ++i)
        if (bytes[i] != (u8)magic[i]) return false;
    return true;
}

static bool failure(const char *stage) {
    static const char prefix[] = "NVMe data check: ";
    for (unsigned i = 0; prefix[i]; ++i) kernel64_serial_char(prefix[i]);
    while (*stage) kernel64_serial_char(*stage++);
    kernel64_serial_char('\r');
    kernel64_serial_char('\n');
    return false;
}

static u8 pattern(u8 seed, unsigned index) {
    return (u8)(seed + index * 13 + (index / 256) * 29);
}

static bool check_payload(u8 seed) {
    for (unsigned block = 0; block < COUNT; ++block) {
        if (nvme_read(UNIT, FIRST + block, sector)) return false;
        for (unsigned i = 0; i < SECTOR; ++i)
            if (sector[i] != pattern(seed, block * SECTOR + i)) return false;
    }
    return true;
}

static bool check_guard(u32 lba, u8 value) {
    if (nvme_read(UNIT, lba, sector)) return false;
    for (unsigned i = 0; i < SECTOR; ++i)
        if (sector[i] != value) return false;
    return true;
}

bool nvme64_check(const struct boot_info *boot) {
    if (!boot_root_valid(boot) || boot_disk_root(boot)) return failure("expected Live boot");
    const u8 *live = pmm64_pointer(boot->root_phys);
    unsigned phase = live[sizeof(live_magic) - 1];
    if (!matches(live, live_magic, sizeof(live_magic) - 1) || phase > 1) return failure("invalid test phase");

    if (!nvme64_probe_live(boot) || nvme_present(0) || !nvme_present(UNIT) || nvme_present(4) ||
        nvme_sectors(UNIT) != DATA_SECTORS) return failure("wrong namespace selection");
    if (nvme_read(UNIT, 0, sector) || !matches(sector, data_magic, sizeof(data_magic) - 1))
        return failure("wrong data disk identity");
    if (!check_payload(seeds[phase])) return failure("initial or persisted payload mismatch");

    if (!nvme_read(UNIT, DATA_SECTORS, sector) || !nvme_write(UNIT, DATA_SECTORS, write_buffer, 1) ||
        !nvme_write(UNIT, DATA_SECTORS - 1, write_buffer, 2) || !nvme_write(UNIT, FIRST, write_buffer, 0))
        return failure("accepted invalid LBA or count");

    /* Первая команда пересекает границу страницы, весь запрос занимает 19 секторов. */
    for (unsigned i = 0; i < sizeof(write_buffer); ++i) write_buffer[i] = pattern(seeds[phase + 1], i);
    if (nvme_write(UNIT, FIRST, write_buffer, COUNT) || nvme_flush(UNIT)) return failure("write or flush failed");
    if (!check_payload(seeds[phase + 1]) || !check_guard(FIRST - 1, 0x19) ||
        !check_guard(FIRST + COUNT, 0x32) || !check_guard(DATA_SECTORS - 1, 0xc7))
        return failure("payload or guard sector changed unexpectedly");
    return true;
}
