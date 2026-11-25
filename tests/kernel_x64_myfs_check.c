#include "../kernel/block.h"
#include "../kernel/myfs.h"
#include "../kernel/nvme.h"
#include "../kernel/x86_64/pmm.h"

extern void kernel64_serial_char(char ch);

enum {
    SECTOR = 512, VOLUME_SECTORS = 32768, PAYLOAD_BYTES = 19 * SECTOR, DISK = 3, DEVICE = DISK * 5,
    INJECT_ERROR = 2, CHECK_RECOVERY = 3,
};
static const char live_magic[] = "MYOSMYFS";
static const char volume_marker[] = "MYOSX64MYFSDATA!";
static const char staging[] = "/pending";
static const char persisted[] = "/persisted";
static const char rolled_back[] = "/rolled-back";
static const u8 seeds[] = {0x39, 0x91};
static u8 bytes[PAYLOAD_BYTES + 1];

static void report(const char *stage) {
    static const char prefix[] = "MyFS data check: ";
    for (unsigned i = 0; prefix[i]; ++i) kernel64_serial_char(prefix[i]);
    while (*stage) kernel64_serial_char(*stage++);
    kernel64_serial_char('\r');
    kernel64_serial_char('\n');
}

static bool failure(const char *stage) {
    report(stage);
    return false;
}

static bool matches(const u8 *data, const char *text, unsigned size) {
    for (unsigned i = 0; i < size; ++i)
        if (data[i] != (u8)text[i]) return false;
    return true;
}

static u32 read_le32(const u8 *data) {
    return (u32)data[0] | (u32)data[1] << 8 | (u32)data[2] << 16 | (u32)data[3] << 24;
}

static u8 pattern(u8 seed, unsigned index) {
    return (u8)(seed + index * 13 + (index / 256) * 29);
}

static bool absent(const char *path) {
    u32 ino;
    return myfs_resolve(FS_ROOT, path, &ino) == FS_ENOENT;
}

static bool check_file(u32 ino, u8 seed) {
    struct fs_stat st;
    if (myfs_stat(ino, &st) || st.type != FS_TYPE_FILE || st.size != PAYLOAD_BYTES ||
        myfs_read(ino, 0, bytes, sizeof(bytes)) != PAYLOAD_BYTES) return false;
    for (unsigned i = 0; i < PAYLOAD_BYTES; ++i)
        if (bytes[i] != pattern(seed, i)) return false;
    return true;
}

static bool check_rollback(u32 ino) {
    if (myfs_transaction_begin()) return false;
    u32 actual;
    bool moved = !myfs_rename(FS_ROOT, persisted, rolled_back) && absent(persisted) &&
                 !myfs_resolve(FS_ROOT, rolled_back, &actual) && actual == ino;
    /* Откатываем сделанное переименование, а не ошибку предварительной валидации. */
    return myfs_transaction_end(FS_EINVAL) == FS_EINVAL && moved && absent(rolled_back) &&
           !myfs_resolve(FS_ROOT, persisted, &actual) && actual == ino;
}

static bool check_failed_sync(unsigned phase) {
    u32 ino;
    if (myfs_resolve(FS_ROOT, persisted, &ino) || !check_file(ino, seeds[0]) ||
        !absent(staging) || !absent(rolled_back)) return failure("missing baseline content for journal error");
    if (phase == CHECK_RECOVERY) {
        report("old file readable after failed commit");
        return true;
    }

    /* Только перезапись существующих блоков должна попасть в redo до commit. */
    for (unsigned i = 0; i < PAYLOAD_BYTES; ++i) bytes[i] = pattern(seeds[1], i);
    if (myfs_write(ino, 0, bytes, PAYLOAD_BYTES) != PAYLOAD_BYTES || !check_file(ino, seeds[1]))
        return failure("journal overwrite before fault did not succeed");
    if (myfs_sync() != FS_EIO || myfs_ready() || myfs_sync() != FS_EIO)
        return failure("journal header fault did not disable volume");
    report("journal commit returned FS_EIO and disabled volume");
    return true;
}

bool myfs64_check(const struct boot_info *boot) {
    if (!boot_root_valid(boot) || boot_disk_root(boot)) return failure("expected Live boot");
    const u8 *live = pmm64_pointer(boot->root_phys);
    unsigned phase = live[sizeof(live_magic) - 1];
    if (!matches(live, live_magic, sizeof(live_magic) - 1) || phase > CHECK_RECOVERY)
        return failure("invalid test phase");

    u8 sector[SECTOR];
    if (!nvme64_probe_live(boot) || !nvme_present(DISK) || nvme_present(0) || nvme_present(4) ||
        nvme_sectors(DISK) != VOLUME_SECTORS + 1 || nvme_read(DISK, VOLUME_SECTORS, sector) ||
        !matches(sector, volume_marker, sizeof(volume_marker) - 1)) return failure("wrong NVMe data disk");
    if (nvme_read(DISK, 0, sector) || !matches(sector, "MYFS", 4) || read_le32(sector + 4) != 5 ||
        read_le32(sector + 8) != VOLUME_SECTORS) return failure("wrong raw MyFS v5 geometry");
    if (block_rescan(DISK) || block_disk_partitioned(DISK)) return failure("could not select raw disk");
    const struct block_device *device = block_get(DEVICE);
    if (!device || device->partition || device->start || device->sectors != VOLUME_SECTORS + 1)
        return failure("wrong block device");
    myfs_select(0, DEVICE);
    bool formatted;
    if (myfs_init(&formatted, false) || formatted || !myfs_ready()) return failure("mount preformatted volume");
    if (phase >= INJECT_ERROR) return check_failed_sync(phase);

    u32 previous = 0;
    if (!phase && !absent(persisted)) return failure("unexpected persisted file on first boot");
    if (phase && (myfs_resolve(FS_ROOT, persisted, &previous) || !check_file(previous, seeds[0])))
        return failure("missing or invalid file from first boot");
    if (!absent(staging) || !absent(rolled_back)) return failure("unexpected staging file after mount");

    for (unsigned i = 0; i < PAYLOAD_BYTES; ++i) bytes[i] = pattern(seeds[phase], i);
    u32 ino, actual;
    if (myfs_create(FS_ROOT, staging, FS_TYPE_FILE, &ino) || ino == previous ||
        myfs_write(ino, 0, bytes, PAYLOAD_BYTES) != PAYLOAD_BYTES ||
        myfs_rename(FS_ROOT, staging, persisted) || !absent(staging) ||
        myfs_resolve(FS_ROOT, persisted, &actual) || actual != ino || myfs_sync())
        return failure("write, rename and sync");
    if (!check_rollback(ino) || !check_file(ino, seeds[phase]) || myfs_sync() || myfs_unmount())
        return failure("rollback or unmount");
    return true;
}
