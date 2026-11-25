typedef unsigned long word;

enum {
    SYS_READ = 0, SYS_WRITE = 1, SYS_CLOSE = 3, SYS_FSTAT = 5, SYS_MMAP = 9, SYS_MPROTECT = 10, SYS_MUNMAP = 11,
    SYS_PREAD = 17, SYS_PWRITE = 18,
    SYS_PIPE = 22, SYS_DUP = 32, SYS_GETPID = 39, SYS_FORK = 57, SYS_EXIT = 60, SYS_WAIT4 = 61,
    SYS_FCNTL = 72, SYS_FLOCK = 73, SYS_FSYNC = 74, SYS_FDATASYNC = 75, SYS_FTRUNCATE = 77,
    SYS_GETCWD = 79, SYS_CHDIR = 80, SYS_CREAT = 85, SYS_UMASK = 95,
    SYS_STATFS = 137, SYS_FSTATFS = 138,
    SYS_GETDENTS64 = 217, SYS_OPENAT = 257, SYS_MKDIRAT = 258, SYS_STATAT = 262, SYS_UNLINKAT = 263, SYS_RENAMEAT = 264,
    SYS_SYMLINKAT = 266, SYS_READLINKAT = 267,
    AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0, O_RDWR = 2,
    O_CREAT = 0100, O_EXCL = 0200, O_DIRECTORY = 0200000, O_NOFOLLOW = 0400000,
    ENOENT = 2, EAGAIN = 11, EACCES = 13, EBUSY = 16, EEXIST = 17, EXDEV = 18,
    ENOTDIR = 20, EISDIR = 21, EINVAL = 22, ELOOP = 40,
    DT_DIR = 4, DT_REG = 8, DT_LNK = 10, PAYLOAD_BYTES = 9728, PATH_LIMIT = 4096, DEEP_LEVELS = 36,
    F_GETLK = 5, F_SETLK = 6, F_RDLCK = 0, F_WRLCK = 1, F_UNLCK = 2, LOCK_EX = 2, LOCK_NB = 4, SEEK_END = 2,
    PAGE_BYTES = 4096, MAP_BYTES = 2 * PAGE_BYTES, PATCH_OFFSET = 2 * PAGE_BYTES - 2, PATCH_BYTES = 4,
    PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_SHARED = 1, MAP_PRIVATE = 2, MAP_FIXED = 0x10,
};

struct file_time {
    long seconds, nanos;
};

struct file_stat {
    word device, inode, links;
    unsigned mode, uid, gid, padding;
    word rdev;
    long size, block_size, blocks;
    struct file_time accessed, modified, changed;
    word reserved[3];
};

struct filesystem_info {
    word type, block_size, blocks, free_blocks, available_blocks, inodes, free_inodes;
    unsigned fsid[2];
    word name_max, fragment_size, flags, reserved[4];
};

_Static_assert(sizeof(struct filesystem_info) == 120, "Linux x86-64 statfs ABI");

struct directory_entry {
    word inode, offset;
    unsigned short size;
    unsigned char type;
    char name[];
};

struct file_lock {
    short type, whence;
    long start, length;
    int pid;
};

_Static_assert(sizeof(struct file_stat) == 144 && __builtin_offsetof(struct file_stat, size) == 48 &&
               __builtin_offsetof(struct file_stat, modified) == 88,
               "Linux x86-64 stat ABI");
_Static_assert(__builtin_offsetof(struct directory_entry, name) == 19, "Linux x86-64 linux_dirent64 ABI");
_Static_assert(sizeof(struct file_lock) == 32 && __builtin_offsetof(struct file_lock, pid) == 24,
               "Linux x86-64 flock ABI");

static const char draft[] = "draft", final_dir[] = "Default";
static const char current[] = "Preferences", temporary[] = "Preferences.tmp";
static const char old_contents[] = "old settings";
static const char link_name[] = "PreferenceAlias";
static const char long_link[] = "LongAlias";
static const char lock_name[] = "SingletonLock", lock_target[] = "myos-test-host-1234";
static unsigned char buffer[PAYLOAD_BYTES + 1];
static char long_target[PATH_LIMIT];

static long call(word number, word a0, word a1, word a2, word a3) {
    register word fourth __asm__("r10") = a3;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a0), "S"(a1), "d"(a2), "r"(fourth)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long map_file(long fd, word address, word length, word protection, word mode, word offset) {
    word number = SYS_MMAP;
    register word flags __asm__("r10") = mode;
    register word file __asm__("r8") = fd;
    register word position __asm__("r9") = offset;
    __asm__ volatile("syscall" : "+a"(number) : "D"(address), "S"(length), "d"(protection), "r"(flags), "r"(file), "r"(position)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long map_shared(long fd, word length, word protection, word offset) {
    return map_file(fd, 0, length, protection, MAP_SHARED, offset);
}

static long open_at(long directory, const char *name, word flags, word mode) {
    return call(SYS_OPENAT, directory, (word)name, flags, mode);
}

static long stat_at(long directory, const char *name, struct file_stat *info, word flags) {
    return call(SYS_STATAT, directory, (word)name, (word)info, flags);
}

static long stat_fd(long fd, struct file_stat *info) {
    return call(SYS_FSTAT, fd, (word)info, 0, 0);
}

static long close_fd(long fd) {
    return call(SYS_CLOSE, fd, 0, 0, 0);
}

static __attribute__((noreturn)) void finish(int status) {
    call(SYS_EXIT, status, 0, 0, 0);
    __builtin_trap();
}

static int child_passed(long child) {
    int status;
    return child > 0 && call(SYS_WAIT4, child, (word)&status, 0, 0) == child && !status;
}

static long set_record_at(long fd, short type, short whence, long start, long length) {
    struct file_lock lock = {.type = type, .whence = whence, .start = start, .length = length};
    return call(SYS_FCNTL, fd, F_SETLK, (word)&lock, 0);
}

static long set_record(long fd, short type, long start, long length) {
    return set_record_at(fd, type, 0, start, length);
}

static long get_record(long fd, long start, long length, struct file_lock *lock) {
    *lock = (struct file_lock){.type = F_WRLCK, .start = start, .length = length};
    return call(SYS_FCNTL, fd, F_GETLK, (word)lock, 0);
}

static int record_matches(long fd, long start, long length, short type, long owner) {
    struct file_lock lock;
    if (get_record(fd, start, length, &lock) || lock.type != type) return 0;
    return type == F_UNLCK || (!lock.whence && lock.start == 4 && lock.length == 8 && lock.pid == owner);
}

static long flock_exclusive(long fd) {
    return call(SYS_FLOCK, fd, LOCK_EX | LOCK_NB, 0, 0);
}

static int same_bytes(const void *data, const void *expected, word size) {
    const unsigned char *left = data, *right = expected;
    for (word i = 0; i < size; ++i)
        if (left[i] != right[i]) return 0;
    return 1;
}

static int valid_stat(const struct file_stat *info, unsigned mode, unsigned uid, unsigned gid) {
    return info->mode == mode && info->uid == uid && info->gid == gid;
}

static unsigned char pattern(unsigned index) {
    return (unsigned char)(0xa7 + index * 13 + (index / 256) * 29);
}

static int contents_match(long fd) {
    if (call(SYS_PREAD, fd, (word)buffer, sizeof(buffer), 0) != PAYLOAD_BYTES) return 0;
    for (unsigned i = 0; i < PAYLOAD_BYTES; ++i)
        if (buffer[i] != pattern(i)) return 0;
    return 1;
}

static int mapped_contents(const volatile unsigned char *mapping, const unsigned char *patch) {
    for (unsigned i = 0; i < MAP_BYTES; ++i) {
        unsigned offset = PAGE_BYTES + i;
        unsigned char expected = offset < PAYLOAD_BYTES ? pattern(offset) : 0;
        if (patch && offset >= PATCH_OFFSET && offset < PATCH_OFFSET + PATCH_BYTES)
            expected = patch[offset - PATCH_OFFSET];
        if (mapping[i] != expected) return 0;
    }
    return 1;
}

static int patch_mapped_file(long directory, const volatile unsigned char *mapping) {
    static const char moved[] = "Preferences.moved";
    struct file_stat info;
    if (call(SYS_RENAMEAT, directory, (word)current, directory, (word)moved) ||
        stat_at(directory, current, &info, 0) != -ENOENT || !mapped_contents(mapping, 0)) return 50;

    unsigned char original[PATCH_BYTES], patch[PATCH_BYTES];
    for (unsigned i = 0; i < PATCH_BYTES; ++i) {
        original[i] = pattern(PATCH_OFFSET + i);
        patch[i] = (unsigned char)~original[i];
    }
    long writer = open_at(directory, moved, O_RDWR, 0);
    if (writer < 0 || call(SYS_PWRITE, writer, (word)patch, sizeof(patch), PATCH_OFFSET) != sizeof(patch) ||
        close_fd(writer) || !mapped_contents(mapping, patch)) return 51;

    /* У потомка есть общее отображение, а дескрипторы файла уже закрыты. */
    long child = call(SYS_FORK, 0, 0, 0, 0);
    if (!child) finish(!mapped_contents(mapping, patch));
    if (!child_passed(child)) return 52;

    writer = open_at(directory, moved, O_RDWR, 0);
    if (writer < 0 || call(SYS_PWRITE, writer, (word)original, sizeof(original), PATCH_OFFSET) != sizeof(original) ||
        call(SYS_FDATASYNC, writer, 0, 0, 0) || close_fd(writer) || !mapped_contents(mapping, 0) ||
        call(SYS_RENAMEAT, directory, (word)moved, directory, (word)current) || call(SYS_FSYNC, directory, 0, 0, 0))
        return 53;
    return 0;
}

static int check_fixed_replacement(long directory, long address) {
    long fd = open_at(directory, current, O_RDONLY, 0);
    if (fd < 0 || map_file(fd, address, MAP_BYTES, PROT_READ, MAP_FIXED | MAP_PRIVATE, PAGE_BYTES) != address ||
        !mapped_contents((const void *)address, 0)) return 58;
    if (call(SYS_MPROTECT, address, MAP_BYTES, PROT_READ | PROT_WRITE, 0)) return 59;
    volatile unsigned char *snapshot = (void *)address;
    unsigned char first = (unsigned char)~pattern(PAGE_BYTES), second = (unsigned char)~pattern(2 * PAGE_BYTES);
    snapshot[0] = first;
    snapshot[PAGE_BYTES] = second;
    if (snapshot[0] != first || snapshot[PAGE_BYTES] != second || !contents_match(fd) || close_fd(fd)) return 60;
    return 0;
}

static int check_map_reclamation(long directory) {
    static const char name[] = "mapping-reclaim";
    long fd = open_at(directory, name, O_CREAT | O_EXCL | O_RDWR, 0600);
    for (unsigned i = 0; i < MAP_BYTES; ++i) buffer[i] = pattern(i);
    if (fd < 0 || call(SYS_WRITE, fd, (word)buffer, MAP_BYTES, 0) != MAP_BYTES) return 61;
    long address = map_shared(fd, MAP_BYTES, PROT_READ, 0);
    if (address < 0 || call(SYS_FTRUNCATE, fd, 0, 0, 0) != -EBUSY) return 62;
    struct file_stat info;
    if (call(SYS_MUNMAP, address, MAP_BYTES, 0, 0) || call(SYS_FTRUNCATE, fd, 0, 0, 0) ||
        stat_fd(fd, &info) || info.size || call(SYS_PREAD, fd, (word)buffer, 1, 0) || close_fd(fd) ||
        call(SYS_UNLINKAT, directory, (word)name, 0, 0) || call(SYS_FSYNC, directory, 0, 0, 0)) return 63;
    return 0;
}

static int check_profile_mmap(long parent, int first_boot) {
    long directory = open_at(parent, final_dir, O_RDONLY | O_DIRECTORY, 0);
    long fd = directory < 0 ? directory : open_at(directory, current, first_boot ? O_RDWR : O_RDONLY, 0);
    if (fd < 0 || map_shared(fd, PAGE_BYTES, PROT_READ, 3 * PAGE_BYTES) != -EINVAL ||
        map_shared(fd, PAGE_BYTES, PROT_READ | PROT_EXEC, PAGE_BYTES) != -EACCES ||
        (first_boot && map_shared(fd, PAGE_BYTES, PROT_READ | PROT_WRITE, PAGE_BYTES) != -EACCES)) return 47;

    long address = map_shared(fd, MAP_BYTES, PROT_READ, PAGE_BYTES);
    const volatile unsigned char *mapping = (const void *)address;
    if (address < 0 || close_fd(fd) || !mapped_contents(mapping, 0)) return 48;
    if (call(SYS_MPROTECT, address, MAP_BYTES, PROT_READ | PROT_WRITE, 0) != -EACCES) return 49;
    if (first_boot) {
        int status = patch_mapped_file(directory, mapping);
        if (status) return status;
    } else {
        long child = call(SYS_FORK, 0, 0, 0, 0);
        if (!child) finish(!mapped_contents(mapping, 0));
        if (!child_passed(child)) return 54;
    }

    if (!mapped_contents(mapping, 0)) return 55;
    int fixed = check_fixed_replacement(directory, address);
    if (fixed) return fixed;
    if (call(SYS_MUNMAP, address, MAP_BYTES, 0, 0)) return 55;
    fd = open_at(directory, current, O_RDONLY, 0);
    if (fd < 0) return 56;
    address = map_shared(fd, MAP_BYTES, PROT_READ, PAGE_BYTES);
    if (address < 0 || close_fd(fd) || !mapped_contents((const void *)address, 0) ||
        call(SYS_MUNMAP, address, MAP_BYTES, 0, 0)) return 57;
    if (first_boot) {
        int reclaimed = check_map_reclamation(directory);
        if (reclaimed) return reclaimed;
    }
    return close_fd(directory) ? 64 : 0;
}

static int check_permissions(long parent) {
    struct file_stat info;
    if (stat_fd(parent, &info) || !valid_stat(&info, 0040700, 1000, 1000)) return 4;
    long group = open_at(parent, "group", O_RDONLY, 0);
    if (group < 0 || stat_fd(group, &info) || !valid_stat(&info, 0100640, 1001, 1000) ||
        call(SYS_READ, group, (word)buffer, 1, 0) != 1 || buffer[0] != 'g' || close_fd(group)) return 5;
    if (open_at(parent, "group", O_RDWR, 0) != -EACCES || open_at(parent, "private", O_RDONLY, 0) != -EACCES ||
        open_at(parent, "sealed/inside", O_RDONLY, 0) != -EACCES) return 6;
    return 0;
}

static int link_matches(long directory, const char *name, const char *target, word size) {
    struct file_stat info;
    buffer[size] = 0xff;
    return !stat_at(directory, name, &info, AT_SYMLINK_NOFOLLOW) && (info.mode & 0170000) == 0120000 &&
           info.size == (long)size && open_at(directory, name, O_RDONLY | O_NOFOLLOW, 0) == -ELOOP &&
           call(SYS_READLINKAT, directory, (word)name, (word)buffer, size + 1) == (long)size &&
           same_bytes(buffer, target, size) && buffer[size] == 0xff;
}

static void prepare_long_target(void) {
    /* Вместе с суффиксом развёрнутая строка длиннее страницы, а реальный путь короткий. */
    for (unsigned i = 0; i < sizeof(long_target) - 2; i += 2) {
        long_target[i] = '.';
        long_target[i + 1] = '/';
    }
    long_target[sizeof(long_target) - 2] = '.';
}

static int check_deep_path(long parent, int create) {
    static const char prefix[] = "/profile/owned";
    static const char marker[] = "leaf";
    char path[sizeof(prefix) + DEEP_LEVELS * 2];
    unsigned length = sizeof(prefix) - 1;
    for (unsigned i = 0; i < length; ++i) path[i] = prefix[i];
    long directory = parent;
    for (unsigned i = 0; i < DEEP_LEVELS; ++i) {
        if (create && call(SYS_MKDIRAT, directory, (word)"d", 0700, 0)) return 29;
        long child = open_at(directory, "d", O_RDONLY | O_DIRECTORY, 0);
        if (child < 0 || (directory != parent && close_fd(directory))) return 30;
        directory = child;
        path[length++] = '/';
        path[length++] = 'd';
    }
    path[length++] = 0;
    long fd = open_at(directory, marker, create ? O_CREAT | O_EXCL | O_RDWR : O_RDONLY, 0600);
    if (fd < 0 || (create && (call(SYS_WRITE, fd, (word)marker, sizeof(marker) - 1, 0) != sizeof(marker) - 1 ||
                            call(SYS_FSYNC, fd, 0, 0, 0))) ||
        call(SYS_PREAD, fd, (word)buffer, sizeof(buffer), 0) != sizeof(marker) - 1 ||
        !same_bytes(buffer, marker, sizeof(marker) - 1) || close_fd(fd)) return 31;
    struct file_stat held, cwd;
    if (stat_fd(directory, &held) || call(SYS_CHDIR, (word)path, 0, 0, 0) ||
        call(SYS_GETCWD, (word)buffer, sizeof(buffer), 0, 0) != (long)length || !same_bytes(buffer, path, length) ||
        stat_at(AT_FDCWD, ".", &cwd, 0) || held.inode != cwd.inode || held.device != cwd.device ||
        call(SYS_CHDIR, (word)"/", 0, 0, 0) || close_fd(directory)) return 32;
    return 0;
}

static int check_live_locks(long directory) {
    long posix = open_at(directory, current, O_RDWR, 0);
    long bsd = open_at(directory, current, O_RDWR, 0);
    long alias = open_at(directory, link_name, O_RDWR, 0);
    long owner = call(SYS_GETPID, 0, 0, 0, 0);
    if (posix < 0 || bsd < 0 || alias < 0 || owner <= 0 || set_record(posix, F_WRLCK, 4, 8) ||
        flock_exclusive(bsd) || flock_exclusive(alias) != -EAGAIN) return 34;

    long child = call(SYS_FORK, 0, 0, 0, 0);
    if (!child) {
        finish(!record_matches(alias, 8, 1, F_WRLCK, owner) || !record_matches(alias, 12, 1, F_UNLCK, 0) ||
               set_record(alias, F_WRLCK, 11, 2) != -EAGAIN || set_record(alias, F_WRLCK, 12, 1) ||
               set_record(alias, F_UNLCK, 12, 1) || flock_exclusive(bsd) || flock_exclusive(alias) != -EAGAIN);
    }
    if (!child_passed(child) || close_fd(alias)) return 35;

    long duplicate = call(SYS_DUP, bsd, 0, 0, 0);
    if (duplicate < 0 || close_fd(bsd) || flock_exclusive(posix) != -EAGAIN) return 36;
    int gate[2];
    if (call(SYS_PIPE, (word)gate, 0, 0, 0)) return 37;
    child = call(SYS_FORK, 0, 0, 0, 0);
    if (!child) {
        char ready;
        if (close_fd(gate[1]) || call(SYS_READ, gate[0], (word)&ready, 1, 0) != 1 || ready != 'g' ||
            !record_matches(posix, 4, 8, F_UNLCK, 0) || set_record(posix, F_WRLCK, 4, 8) ||
            flock_exclusive(posix) != -EAGAIN || close_fd(duplicate)) finish(1);
        long reopened = open_at(directory, current, O_RDWR, 0);
        finish(reopened < 0 || flock_exclusive(reopened));
    }
    /* Родитель закрыл все ссылки на flock; последняя копия остаётся у потомка до сигнала. */
    if (child < 0 || close_fd(gate[0]) || close_fd(duplicate) || flock_exclusive(posix) != -EAGAIN ||
        call(SYS_WRITE, gate[1], (word)"g", 1, 0) != 1 || close_fd(gate[1]) || !child_passed(child)) return 38;

    /* Выход процесса освобождает обе блокировки; второй запуск открывает тот же inode. */
    if (flock_exclusive(posix) || set_record(posix, F_WRLCK, 4, 8)) return 39;
    return 0;
}

static int check_profile_locks(long parent, int first_boot) {
    long directory = open_at(parent, final_dir, O_RDONLY | O_DIRECTORY, 0);
    if (directory < 0) return 40;
    if (first_boot) {
        int status = check_live_locks(directory);
        if (status) return status;
    } else {
        long fd = open_at(directory, current, O_RDONLY, 0);
        if (fd < 0 || !record_matches(fd, 4, 8, F_UNLCK, 0) || set_record(fd, F_RDLCK, 4, 8) ||
            flock_exclusive(fd) || close_fd(fd)) return 41;
    }
    return close_fd(directory) ? 42 : 0;
}

static int directory_entries_match(long directory) {
    static const struct { const char *name; word size; unsigned char type; } expected[] = {
        {".", sizeof("."), DT_DIR}, {"..", sizeof(".."), DT_DIR},
        {current, sizeof(current), DT_REG}, {link_name, sizeof(link_name), DT_LNK}, {lock_name, sizeof(lock_name), DT_LNK},
        {long_link, sizeof(long_link), DT_LNK},
    };
    unsigned seen = 0;
    for (;;) {
        unsigned char raw[48] __attribute__((aligned(8)));
        long count = call(SYS_GETDENTS64, directory, (word)raw, sizeof(raw), 0);
        if (count < 0 || (word)count > sizeof(raw)) return 0;
        if (!count) break;
        for (word offset = 0; offset < (word)count;) {
            word remaining = (word)count - offset;
            if (remaining < 20) return 0;
            const struct directory_entry *entry = (const void *)(raw + offset);
            if (entry->size < 20 || (entry->size & 7) || entry->size > remaining) return 0;
            unsigned i = 0;
            while (i < sizeof(expected) / sizeof(expected[0])) {
                if (entry->size >= 19 + expected[i].size && same_bytes(entry->name, expected[i].name, expected[i].size))
                    break;
                ++i;
            }
            struct file_stat info;
            if (i == sizeof(expected) / sizeof(expected[0]) || (seen & (1u << i)) || entry->type != expected[i].type ||
                stat_at(directory, expected[i].name, &info, AT_SYMLINK_NOFOLLOW) || entry->inode != info.inode) return 0;
            seen |= 1u << i;
            offset += entry->size;
        }
    }
    return seen == (1u << (sizeof(expected) / sizeof(expected[0]))) - 1;
}

static int invalid_renames(long parent, long directory) {
    const char ram_file[] = "/tmp/myfs-profile-boundary";
    long ram = open_at(AT_FDCWD, ram_file, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (ram < 0 || close_fd(ram)) return 26;
    struct file_stat info;
    if (call(SYS_RENAMEAT, directory, (word)current, parent, (word)final_dir) != -EISDIR ||
        call(SYS_RENAMEAT, parent, (word)final_dir, parent, (word)"group") != -ENOTDIR ||
        call(SYS_RENAMEAT, directory, (word)current, AT_FDCWD, (word)ram_file) != -EXDEV ||
        call(SYS_RENAMEAT, AT_FDCWD, (word)ram_file, directory, (word)"incoming") != -EXDEV ||
        stat_at(directory, "incoming", &info, 0) != -ENOENT ||
        call(SYS_UNLINKAT, AT_FDCWD, (word)ram_file, 0, 0)) return 27;
    return 0;
}

static int check_replaced_locks(long directory, long previous, long old_observer, long replacement) {
    long fresh = open_at(directory, current, O_RDONLY, 0);
    if (fresh < 0 || flock_exclusive(old_observer) != -EAGAIN || flock_exclusive(fresh) ||
        flock_exclusive(replacement) != -EAGAIN) return 44;

    long owner = call(SYS_GETPID, 0, 0, 0, 0);
    long child = call(SYS_FORK, 0, 0, 0, 0);
    if (!child) {
        const long start = sizeof(old_contents) - 3;
        struct file_lock lock;
        finish(get_record(old_observer, start, 1, &lock) || lock.type != F_WRLCK || lock.whence ||
               lock.start != start || lock.length != 1 || lock.pid != owner);
    }
    if (owner <= 0 || !child_passed(child)) return 45;

    /* Освобождение последней ссылки на старый flock не затрагивает новый inode. */
    if (close_fd(previous) || flock_exclusive(old_observer) || close_fd(old_observer) ||
        flock_exclusive(replacement) != -EAGAIN || close_fd(fresh)) return 46;
    return 0;
}

static int verify_profile(long parent) {
    long directory = open_at(parent, final_dir, O_RDONLY | O_DIRECTORY, 0);
    struct file_stat info, alias;
    if (directory < 0 || stat_fd(directory, &info) || !valid_stat(&info, 0040700, 1000, 1000) ||
        stat_at(parent, draft, &info, 0) != -ENOENT || stat_at(directory, temporary, &info, 0) != -ENOENT)
        return 20;
    long fd = open_at(directory, current, O_RDONLY, 0);
    if (fd < 0 || stat_fd(fd, &info) || !valid_stat(&info, 0100600, 1000, 1000) || info.links != 1 ||
        info.size != PAYLOAD_BYTES || !contents_match(fd) || close_fd(fd)) return 21;
    if (!link_matches(directory, lock_name, lock_target, sizeof(lock_target) - 1) ||
        stat_at(directory, lock_name, &alias, 0) != -ENOENT ||
        !link_matches(directory, link_name, current, sizeof(current) - 1) ||
        stat_at(directory, link_name, &alias, 0) || alias.inode != info.inode || alias.device != info.device)
        return 22;
    long through_link = open_at(directory, "LongAlias/Preferences", O_RDONLY, 0);
    if (through_link < 0 || !link_matches(directory, long_link, long_target, sizeof(long_target) - 1) ||
        stat_fd(through_link, &alias) || alias.inode != info.inode || alias.device != info.device ||
        !contents_match(through_link) || close_fd(through_link)) return 33;
    if (!directory_entries_match(directory)) return 28;
    return close_fd(directory) ? 23 : 0;
}

static int write_profile(long parent) {
    const word create = O_CREAT | O_EXCL | O_RDWR;
    struct file_stat info, old, next;
    long mask = call(SYS_UMASK, 0077, 0, 0, 0);
    if (mask < 0 || stat_at(parent, final_dir, &info, 0) != -ENOENT ||
        call(SYS_MKDIRAT, parent, (word)draft, 0777, 0)) return 7;
    long directory = open_at(parent, draft, O_RDONLY | O_DIRECTORY, 0);
    if (directory < 0 || stat_fd(directory, &old) || call(SYS_CHDIR, (word)"/profile/owned/draft", 0, 0, 0) ||
        call(SYS_RENAMEAT, parent, (word)draft, parent, (word)final_dir) ||
        stat_at(parent, draft, &info, 0) != -ENOENT || stat_at(parent, final_dir, &info, 0) ||
        old.inode != info.inode || old.device != info.device) return 8;
    static const char moved_path[] = "/profile/owned/Default";
    if (call(SYS_GETCWD, (word)buffer, sizeof(buffer), 0, 0) != sizeof(moved_path) ||
        !same_bytes(buffer, moved_path, sizeof(moved_path)) || stat_at(AT_FDCWD, ".", &info, 0) ||
        old.inode != info.inode || old.device != info.device || call(SYS_CHDIR, (word)"/", 0, 0, 0)) return 25;

    /* Новый файл создаётся через дескриптор каталога, открытый до rename. */
    long previous = open_at(directory, current, create, 0666);
    long old_observer = open_at(directory, current, O_RDWR, 0);
    long replacement = open_at(directory, temporary, create, 0666);
    if (previous < 0 || old_observer < 0 || replacement < 0 || call(SYS_UMASK, mask, 0, 0, 0) != 0077 ||
        call(SYS_WRITE, previous, (word)old_contents, sizeof(old_contents) - 1, 0) != sizeof(old_contents) - 1 ||
        call(SYS_FSYNC, previous, 0, 0, 0) || stat_fd(previous, &old) || stat_fd(replacement, &next)) return 9;
    if (flock_exclusive(previous) || flock_exclusive(old_observer) != -EAGAIN ||
        set_record_at(old_observer, F_WRLCK, SEEK_END, -2, 1)) return 43;
    for (unsigned i = 0; i < PAYLOAD_BYTES; ++i) buffer[i] = pattern(i);
    if (call(SYS_WRITE, replacement, (word)buffer, PAYLOAD_BYTES, 0) != PAYLOAD_BYTES ||
        call(SYS_FDATASYNC, replacement, 0, 0, 0) || !contents_match(replacement) ||
        call(SYS_RENAMEAT, directory, (word)temporary, directory, (word)current)) return 10;

    if (stat_fd(previous, &info) || info.inode != old.inode || info.device != old.device || info.links ||
        call(SYS_PREAD, previous, (word)buffer, sizeof(buffer), 0) != sizeof(old_contents) - 1 ||
        !same_bytes(buffer, old_contents, sizeof(old_contents) - 1) ||
        stat_at(directory, current, &info, 0) || info.inode != next.inode || info.device != next.device ||
        info.inode == old.inode || info.links != 1 || !contents_match(replacement)) return 11;
    if (call(SYS_SYMLINKAT, (word)current, directory, (word)link_name, 0) ||
        call(SYS_SYMLINKAT, (word)lock_target, directory, (word)lock_name, 0) ||
        call(SYS_SYMLINKAT, (word)long_target, directory, (word)long_link, 0) ||
        call(SYS_SYMLINKAT, (word)"different", directory, (word)lock_name, 0) != -EEXIST) return 12;
    int invalid = invalid_renames(parent, directory);
    if (invalid) return invalid;
    int locks = check_replaced_locks(directory, previous, old_observer, replacement);
    if (locks) return locks;
    if (close_fd(replacement) || call(SYS_FSYNC, directory, 0, 0, 0) ||
        call(SYS_FSYNC, parent, 0, 0, 0) || close_fd(directory)) return 13;
    return 0;
}

static int check_filesystem_space(long parent) {
    static const char profile[] = "/profile/owned";
    static const char probe[] = "statfs-probe";
    static const char data[512] = "statfs";
    struct filesystem_info before, allocated, after, ram;
    if (call(SYS_STATFS, (word)profile, (word)&before, 0, 0) ||
        call(SYS_FSTATFS, parent, (word)&after, 0, 0) ||
        !same_bytes(&before, &after, sizeof(before)) ||
        before.type != 0x5346594d || before.block_size != sizeof(data) ||
        before.fragment_size != sizeof(data) || before.name_max != 255 ||
        !before.blocks || before.blocks < before.free_blocks ||
        before.free_blocks != before.available_blocks ||
        !before.inodes || before.inodes < before.free_inodes ||
        !(before.flags & 0x20) || (before.flags & 1)) return 71;
    if (call(SYS_STATFS, (word)"/tmp", (word)&ram, 0, 0) ||
        ram.type != 0x01021994 || ram.fragment_size != PAGE_BYTES ||
        !ram.blocks || !ram.free_blocks || ram.blocks < ram.free_blocks ||
        !ram.inodes || ram.inodes < ram.free_inodes ||
        call(SYS_STATFS, (word)"/profile/owned/statfs-missing", (word)&after, 0, 0) != -ENOENT ||
        call(SYS_STATFS, (word)profile, 1, 0, 0) != -14 ||
        call(SYS_FSTATFS, -1, (word)&after, 0, 0) != -9) return 72;
    long fd = open_at(parent, probe, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0 || call(SYS_WRITE, fd, (word)data, sizeof(data), 0) != sizeof(data) ||
        call(SYS_FSTATFS, fd, (word)&allocated, 0, 0) ||
        allocated.blocks != before.blocks || allocated.free_blocks >= before.free_blocks ||
        allocated.free_inodes + 1 != before.free_inodes || close_fd(fd) ||
        call(SYS_UNLINKAT, parent, (word)probe, 0, 0) ||
        call(SYS_FSTATFS, parent, (word)&after, 0, 0) ||
        !same_bytes(&before, &after, sizeof(before))) return 73;
    return 0;
}

static int check_creat(long parent) {
    static const char path[] = "/profile/owned/creat-probe";
    static const char payload[] = "CacheStorage index";
    struct file_stat info;
    long fd = call(SYS_CREAT, (word)path, 0640, 0, 0);
    if (fd < 0 || call(SYS_READ, fd, (word)buffer, 1, 0) != -9 ||
        call(SYS_WRITE, fd, (word)payload, sizeof(payload), 0) != sizeof(payload) ||
        stat_fd(fd, &info) || info.size != sizeof(payload) || (info.mode & 0777) != 0640 ||
        close_fd(fd)) return 78;

    fd = call(SYS_CREAT, (word)path, 0600, 0, 0);
    if (fd < 0 || stat_fd(fd, &info) || info.size || (info.mode & 0777) != 0640 ||
        close_fd(fd) || call(SYS_UNLINKAT, parent, (word)"creat-probe", 0, 0)) return 79;
    return 0;
}

static int check_resize(long parent) {
    enum { SECTOR = 512 };
    static const char name[] = "resize-probe";
    static const unsigned offsets[] = {
        0, 12 * SECTOR, 145 * SECTOR, (12 + 128 + 128 * 128 + 1) * SECTOR,
    };
    static const char payload[] = "MyFS resize";
    static const unsigned short_length = 5;
    struct file_stat info;
    struct filesystem_info before, sparse, after;
    if (call(SYS_FSTATFS, parent, (word)&before, 0, 0)) return 74;
    long fd = open_at(parent, name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) return 74;
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(*offsets); ++i)
        if (call(SYS_PWRITE, fd, (word)payload, sizeof(payload), offsets[i]) != sizeof(payload)) return 74;

    const word maximum_offset = offsets[sizeof(offsets) / sizeof(*offsets) - 1];
    const word large_size = maximum_offset + sizeof(payload) + SECTOR;
    if (call(SYS_FSTATFS, fd, (word)&sparse, 0, 0) ||
        call(SYS_FTRUNCATE, fd, large_size, 0, 0) || stat_fd(fd, &info) || info.size != (long)large_size ||
        call(SYS_FSTATFS, fd, (word)&after, 0, 0) || sparse.free_blocks != after.free_blocks ||
        call(SYS_PREAD, fd, (word)buffer, 1, maximum_offset + sizeof(payload)) != 1 || buffer[0] ||
        call(SYS_FTRUNCATE, fd, (word)-1, 0, 0) != -EINVAL ||
        call(SYS_FTRUNCATE, fd, 1ul << 32, 0, 0) != -27 ||
        call(SYS_FTRUNCATE, fd, 1ul << 31, 0, 0) != -27) return 75;

    long mapping = map_shared(fd, PAGE_BYTES, PROT_READ, 0);
    if (mapping < 0 || call(SYS_FTRUNCATE, fd, large_size, 0, 0) ||
        call(SYS_FTRUNCATE, fd, short_length, 0, 0) != -EBUSY ||
        call(SYS_MUNMAP, mapping, PAGE_BYTES, 0, 0)) return 75;

    if (call(SYS_FTRUNCATE, fd, short_length, 0, 0) || stat_fd(fd, &info) || info.size != short_length ||
        call(SYS_PREAD, fd, (word)buffer, sizeof(payload), 0) != short_length ||
        !same_bytes(buffer, payload, short_length) ||
        call(SYS_FSTATFS, fd, (word)&after, 0, 0) || after.free_blocks <= sparse.free_blocks ||
        call(SYS_FTRUNCATE, fd, large_size, 0, 0) ||
        call(SYS_PREAD, fd, (word)buffer, sizeof(payload), 0) != sizeof(payload) ||
        !same_bytes(buffer, payload, short_length)) return 76;
    for (unsigned i = short_length; i < sizeof(payload); ++i)
        if (buffer[i]) return 76;
    for (unsigned i = 1; i < sizeof(offsets) / sizeof(*offsets); ++i) {
        if (call(SYS_PREAD, fd, (word)buffer, sizeof(payload), offsets[i]) != sizeof(payload)) return 76;
        for (unsigned j = 0; j < sizeof(payload); ++j)
            if (buffer[j]) return 76;
    }
    if (call(SYS_FSYNC, fd, 0, 0, 0) || close_fd(fd) || call(SYS_UNLINKAT, parent, (word)name, 0, 0) ||
        call(SYS_FSTATFS, parent, (word)&after, 0, 0) || after.free_blocks != before.free_blocks ||
        after.free_inodes != before.free_inodes) return 77;
    return 0;
}

static void hex_word(char *out, word number) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 16; i; --i) {
        out[i - 1] = digits[number & 15];
        number >>= 4;
    }
}

static int change_directory_mtime(long directory) {
    static const char before[] = "pending", after[] = "indexed";
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        struct file_stat created, renamed;
        long file = open_at(directory, before, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (file < 0 || close_fd(file) || stat_fd(directory, &created) ||
            call(SYS_FSYNC, directory, 0, 0, 0) ||
            call(SYS_RENAMEAT, directory, (word)before, directory, (word)after) ||
            stat_fd(directory, &renamed)) return 81;
        if (created.modified.seconds == renamed.modified.seconds) {
            if (created.modified.seconds <= 0 || created.modified.nanos < 0 ||
                renamed.modified.nanos >= 1000000000 ||
                renamed.modified.nanos - created.modified.nanos < 1000) return 82;
            return call(SYS_FSYNC, directory, 0, 0, 0) ? 83 : 0;
        }
        /* Переход через границу секунды не проверяет дробную часть времени. */
        if (call(SYS_UNLINKAT, directory, (word)after, 0, 0)) return 81;
    }
    return 82;
}

static int check_precise_mtime(long parent, int first_boot) {
    static const char name[] = "precise-mtime";
    if (first_boot && call(SYS_MKDIRAT, parent, (word)name, 0700, 0)) return 80;
    long directory = open_at(parent, name, O_RDONLY | O_DIRECTORY, 0);
    if (directory < 0) return 80;
    if (first_boot) {
        int result = change_directory_mtime(directory);
        if (result) return result;
    }
    struct file_stat by_fd, by_path;
    if (stat_fd(directory, &by_fd) || stat_at(parent, name, &by_path, 0) ||
        !same_bytes(&by_fd.modified, &by_path.modified, sizeof(by_fd.modified)) ||
        by_fd.modified.seconds <= 0 || by_fd.modified.nanos <= 0 || by_fd.modified.nanos >= 1000000000 ||
        stat_at(directory, "indexed", &by_path, 0) || close_fd(directory)) return 84;

    static const char prefix[] = "Linux MyFS directory mtime ";
    char report[] = "Linux MyFS directory mtime 0000000000000000 0000000000000000\n";
    hex_word(report + sizeof(prefix) - 1, (word)by_fd.modified.seconds);
    hex_word(report + sizeof(prefix) + 16, (word)by_fd.modified.nanos);
    return call(SYS_WRITE, 1, (word)report, sizeof(report) - 1, 0) == sizeof(report) - 1 ? 0 : 85;
}

static int check_legacy_profile(long parent) {
    static const char seed[] = "group can read\n";
    struct file_stat directory, by_path, by_fd;
    struct filesystem_info fs;
    if (stat_fd(parent, &directory) || !valid_stat(&directory, 0040700, 1000, 1000) ||
        directory.modified.seconds <= 0 || directory.modified.nanos ||
        call(SYS_FSTATFS, parent, (word)&fs, 0, 0) || fs.type != 0x5346594d ||
        stat_at(parent, "group", &by_path, 0) || !valid_stat(&by_path, 0100640, 1001, 1000) ||
        by_path.modified.seconds <= 0 || by_path.modified.nanos) return 86;
    long file = open_at(parent, "group", O_RDONLY, 0);
    if (file < 0 || stat_fd(file, &by_fd) || by_fd.inode != by_path.inode ||
        !same_bytes(&by_fd.modified, &by_path.modified, sizeof(by_fd.modified)) ||
        call(SYS_PREAD, file, (word)buffer, sizeof(seed), 0) != sizeof(seed) - 1 ||
        !same_bytes(buffer, seed, sizeof(seed) - 1) || close_fd(file)) return 87;
    return 0;
}

void _start(void) {
    int status = 1;
    char phase;
    long phase_fd = open_at(AT_FDCWD, "/myos/myfs-test-phase", O_RDONLY, 0);
    if (phase_fd >= 0 && call(SYS_READ, phase_fd, (word)&phase, 1, 0) == 1 && !close_fd(phase_fd) &&
        (phase == '0' || phase == '1' || phase == '2')) {
        long parent = open_at(AT_FDCWD, "/profile/owned", O_RDONLY | O_DIRECTORY, 0);
        if (phase == '0') {
            status = parent < 0 ? 2 : check_legacy_profile(parent);
            if (!status && close_fd(parent)) status = 3;
            static const char marker[] = "Linux MyFS guest read v5 profile PASS\n";
            if (!status && call(SYS_WRITE, 1, (word)marker, sizeof(marker) - 1, 0) != sizeof(marker) - 1)
                status = 24;
            finish(status);
        }
        prepare_long_target();
        status = parent < 0 ? 2 : check_permissions(parent);
        if (!status) status = check_precise_mtime(parent, phase == '1');
        if (!status) status = check_filesystem_space(parent);
        if (!status && phase == '1') status = check_creat(parent);
        if (!status && phase == '1') status = check_resize(parent);
        if (!status && phase == '1') status = write_profile(parent);
        if (!status) status = verify_profile(parent);
        if (!status) status = check_deep_path(parent, phase == '1');
        if (!status) status = check_profile_mmap(parent, phase == '1');
        if (!status) status = check_profile_locks(parent, phase == '1');
        if (!status && close_fd(parent)) status = 3;
        if (!status) {
            static const char wrote[] = "Linux MyFS guest wrote profile PASS\n";
            static const char reopened[] = "Linux MyFS guest reopened profile PASS\n";
            const char *message = phase == '1' ? wrote : reopened;
            word length = phase == '1' ? sizeof(wrote) - 1 : sizeof(reopened) - 1;
            if (call(SYS_WRITE, 1, (word)message, length, 0) != (long)length) status = 24;
        }
    }
    finish(status);
}
