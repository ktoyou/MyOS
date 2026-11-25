#include "linux_myfs.h"
#include "linux_task.h"
#include "../block.h"
#include "../myfs.h"
#include "../nvme.h"

enum {
    PROFILE_TOKEN_SIZE = 16, PROFILE_SECTOR_SIZE = 512,
    MYFS_PIN_COUNT = LINUX64_OPEN_FILE_COUNT + 2 * LINUX64_PROCESS_COUNT + 1,
};

static bool mounted;
static struct myfs_pin {
    u32 ino, references;
    struct linux64_inode_locks locks;
    bool orphan;
} pins[MYFS_PIN_COUNT];

static long error(int result) {
    switch (result) {
    case FS_OK: return 0;
    case FS_ENOENT: return -2;
    case FS_EEXIST: return -17;
    case FS_ENOTDIR: return -20;
    case FS_EISDIR: return -21;
    case FS_ENOSPC: return -28;
    case FS_ENOTEMPTY: return -39;
    case FS_EINVAL: return -22;
    case FS_ENODEV: return -19;
    case FS_EFBIG: return -27;
    case FS_ENAMETOOLONG: return -36;
    case FS_EROFS: return -30;
    case FS_EBUSY: return -16;
    case FS_EXDEV: return -18;
    case FS_ELOOP: return -40;
    case FS_EACCES: return -13;
    case FS_EPERM: return -1;
    default: return -5;
    }
}

static bool bytes_equal(const u8 *left, const u8 *right, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        if (left[i] != right[i]) return false;
    return true;
}

static u32 le32(const u8 *bytes) {
    return (u32)bytes[0] | (u32)bytes[1] << 8 | (u32)bytes[2] << 16 | (u32)bytes[3] << 24;
}

void linux64_myfs_mount(const struct boot_info *boot, const struct linux64_file_source *source) {
    struct linux64_file selector;
    if (!source->lookup || !source->lookup(source->context, "/myos/myfs-volume", &selector) ||
        selector.size != PROFILE_TOKEN_SIZE || !selector.bytes) return;

    bool nonzero = false;
    for (unsigned i = 0; i < PROFILE_TOKEN_SIZE; ++i) nonzero |= selector.bytes[i] != 0;
    if (!nonzero || !nvme64_probe_live(boot)) return;
    int selected = -1;
    u8 sector[PROFILE_SECTOR_SIZE];
    for (int unit = 3; unit < BLOCK_UNITS; ++unit) {
        u32 sectors = nvme_sectors(unit);
        if (sectors < 2 || nvme_read(unit, sectors - 1, sector) ||
            !bytes_equal(sector, (const u8 *)"MYOSPROF", 8) ||
            !bytes_equal(sector + 8, selector.bytes, PROFILE_TOKEN_SIZE)) continue;
        if (selected >= 0) return;
        selected = unit;
    }
    if (selected < 0 || nvme_read(selected, 0, sector)) return;
    u32 version = le32(sector + 4);
    if (!bytes_equal(sector, (const u8 *)"MYFS", 4) ||
        (version != MYFS_SECONDS_VERSION && version != MYFS_PRECISE_TIME_VERSION) ||
        le32(sector + 8) != nvme_sectors(selected) - 1 ||
        block_rescan(selected) || block_disk_partitioned(selected)) return;
    myfs_select(0, selected * 5);
    bool formatted;
    mounted = !myfs_init(&formatted, false);
}

bool linux64_myfs_mounted(void) {
    return mounted;
}

long linux64_myfs_stat(u32 ino, struct linux64_file *file) {
    struct fs_stat stat;
    u32 nanos;
    int result = myfs_stat_precise(ino, &stat, &nanos);
    if (result) return error(result);
    u32 type;
    switch (stat.type) {
    case FS_TYPE_FILE: type = LINUX64_S_IFREG; break;
    case FS_TYPE_DIR: type = LINUX64_S_IFDIR; break;
    case FS_TYPE_LINK: type = LINUX64_S_IFLNK; break;
    default: return -2;
    }
    *file = (struct linux64_file){
        .size = stat.size, .inode = (1ull << 40) | ino, .mode = type | stat.mode,
        .uid = stat.uid, .gid = stat.gid, .writable_directory = stat.type == FS_TYPE_DIR,
        .myfs_ino = ino, .myfs_links = stat.links, .myfs_blocks = stat.blocks,
        .myfs_times = {stat.atime, stat.mtime, stat.ctime}, .myfs_time_nsec = nanos,
    };
    return 0;
}

long linux64_myfs_lookup(u32 parent, const char *name, struct linux64_file *file) {
    u32 ino;
    int result = myfs_lookup_child(parent, name, &ino);
    return result ? error(result) : linux64_myfs_stat(ino, file);
}

long linux64_myfs_next(u32 ino, uptr *position, char name[256], struct linux64_file *file) {
    if (*position > (u32)-1) return -22;
    u32 cursor = (u32)*position;
    struct fs_dirent entry;
    int result = myfs_readdir(ino, &cursor, &entry);
    if (result <= 0) return error(result);
    long status = linux64_myfs_stat(entry.ino, file);
    if (status) return status;
    for (unsigned i = 0; (name[i] = entry.name[i]); ++i) {}
    *position = cursor;
    return 1;
}

long linux64_myfs_create(u32 parent, const char *name, const struct linux64_file *requested,
                         struct linux64_file *file) {
    int type;
    switch (requested->mode & LINUX64_S_IFMT) {
    case LINUX64_S_IFREG: type = FS_TYPE_FILE; break;
    case LINUX64_S_IFDIR: type = FS_TYPE_DIR; break;
    case LINUX64_S_IFLNK: type = FS_TYPE_LINK; break;
    default: return -95;
    }
    int result = myfs_enable_precise_time();
    if (!result) result = myfs_transaction_begin();
    if (result) return error(result);
    u32 ino = 0;
    result = myfs_create(parent, name, type, &ino);
    if (!result) result = myfs_setattr(ino, requested->mode & 07777, LINUX64_UID, LINUX64_GID);
    if (!result && type == FS_TYPE_LINK) {
        int written = myfs_write(ino, 0, requested->bytes, (u32)requested->size);
        if (written < 0) result = written;
        else if ((uptr)written != requested->size) result = FS_EIO;
    }
    result = myfs_transaction_end(result);
    return result ? error(result) : linux64_myfs_stat(ino, file);
}

static struct myfs_pin *find_pin(u32 ino) {
    for (unsigned i = 0; i < MYFS_PIN_COUNT; ++i)
        if (pins[i].ino == ino) return &pins[i];
    return NULL;
}

struct linux64_inode_locks *linux64_myfs_lock_state(u32 ino) {
    struct myfs_pin *pin = ino ? find_pin(ino) : NULL;
    return pin ? &pin->locks : NULL;
}

long linux64_myfs_retain(u32 ino) {
    if (!ino) return 0;
    struct myfs_pin *pin = find_pin(ino);
    if (!pin) {
        pin = find_pin(0);
        if (!pin) return -23;
        pin->ino = ino;
    }
    ++pin->references;
    return 0;
}

void linux64_myfs_release(u32 ino) {
    if (!ino) return;
    struct myfs_pin *pin = find_pin(ino);
    if (!pin || --pin->references) return;
    if (pin->orphan) myfs_reap_orphan(ino);
    *pin = (struct myfs_pin){0};
}

long linux64_myfs_remove(u32 parent, const char *name, u32 ino) {
    struct myfs_pin *pin = find_pin(ino);
    int result = myfs_enable_precise_time();
    if (!result) result = myfs_remove_keep(parent, name, pin != NULL);
    if (!result && pin) pin->orphan = true;
    return error(result);
}

long linux64_myfs_rename(u32 old_parent, const char *old_name, u32 new_parent, const char *new_name,
                         u32 victim) {
    struct myfs_pin *pin = victim ? find_pin(victim) : NULL;
    int result = myfs_enable_precise_time();
    if (!result) result = myfs_rename_at(old_parent, old_name, new_parent, new_name, pin != NULL);
    if (!result && pin) pin->orphan = true;
    return error(result);
}

long linux64_myfs_path(u32 ino, char *path) {
    static const char mount[] = LINUX64_MYFS_MOUNT;
    unsigned prefix = sizeof(mount) - 1;
    for (unsigned i = 0; i <= prefix; ++i) path[i] = mount[i];
    if (ino == LINUX64_MYFS_ROOT) return 0;
    return error(myfs_getpath(ino, path + prefix, LINUX64_PATH_LIMIT - prefix));
}

long linux64_myfs_read(u32 ino, uptr offset, void *buffer, uptr length) {
    if (offset > (u32)-1) return 0;
    if (length > (u32)-1 || length > (u32)-1 - offset) length = (u32)-1 - offset;
    int result = myfs_read(ino, (u32)offset, buffer, (u32)length);
    return result < 0 ? error(result) : result;
}

long linux64_myfs_write(u32 ino, uptr offset, const void *buffer, uptr length) {
    if (offset > (u32)-1 || length > (u32)-1 - offset) return -27;
    if (!length) return 0;
    int result = myfs_enable_precise_time();
    if (result) return error(result);
    result = myfs_write(ino, (u32)offset, buffer, (u32)length);
    if (result > 0) linux64_myfs_map_update(ino, offset, buffer, (uptr)result);
    return result < 0 ? error(result) : result;
}

long linux64_myfs_truncate(u32 ino, uptr size) {
    if (size > 0xfffffffful) return -27;
    struct linux64_file file;
    long result = linux64_myfs_stat(ino, &file);
    if (result) return result;
    if (size && size == file.size) return 0;
    if (linux64_myfs_has_mapping(ino)) return -16;
    int upgrade = myfs_enable_precise_time();
    return error(upgrade ? upgrade : myfs_resize(ino, (u32)size));
}

long linux64_myfs_sync(void) {
    return error(myfs_sync());
}
