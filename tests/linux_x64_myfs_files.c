typedef unsigned long word;

enum {
    SYS_READ = 0, SYS_WRITE = 1, SYS_CLOSE = 3, SYS_FSTAT = 5, SYS_PREAD = 17,
    SYS_EXIT = 60, SYS_FSYNC = 74, SYS_FDATASYNC = 75, SYS_GETCWD = 79, SYS_CHDIR = 80, SYS_UMASK = 95,
    SYS_GETDENTS64 = 217, SYS_OPENAT = 257, SYS_MKDIRAT = 258, SYS_STATAT = 262, SYS_UNLINKAT = 263, SYS_RENAMEAT = 264,
    SYS_SYMLINKAT = 266, SYS_READLINKAT = 267,
    AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0, O_RDWR = 2,
    O_CREAT = 0100, O_EXCL = 0200, O_DIRECTORY = 0200000, O_NOFOLLOW = 0400000,
    EACCES = 13, ENOENT = 2, EEXIST = 17, EXDEV = 18, ENOTDIR = 20, EISDIR = 21, ELOOP = 40,
    DT_DIR = 4, DT_REG = 8, DT_LNK = 10, PAYLOAD_BYTES = 9728, PATH_LIMIT = 4096, DEEP_LEVELS = 36,
};

struct file_stat {
    word device, inode, links;
    unsigned mode, uid, gid, padding;
    word rdev;
    long size;
    word remaining[11];
};

struct directory_entry {
    word inode, offset;
    unsigned short size;
    unsigned char type;
    char name[];
};

_Static_assert(sizeof(struct file_stat) == 144 && __builtin_offsetof(struct file_stat, size) == 48,
               "Linux x86-64 stat ABI");
_Static_assert(__builtin_offsetof(struct directory_entry, name) == 19, "Linux x86-64 linux_dirent64 ABI");

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
    long replacement = open_at(directory, temporary, create, 0666);
    if (previous < 0 || replacement < 0 || call(SYS_UMASK, mask, 0, 0, 0) != 0077 ||
        call(SYS_WRITE, previous, (word)old_contents, sizeof(old_contents) - 1, 0) != sizeof(old_contents) - 1 ||
        call(SYS_FSYNC, previous, 0, 0, 0) || stat_fd(previous, &old) || stat_fd(replacement, &next)) return 9;
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
    if (close_fd(previous) || close_fd(replacement) || call(SYS_FSYNC, directory, 0, 0, 0) ||
        call(SYS_FSYNC, parent, 0, 0, 0) || close_fd(directory)) return 13;
    return 0;
}

void _start(void) {
    int status = 1;
    char phase;
    long phase_fd = open_at(AT_FDCWD, "/myos/myfs-test-phase", O_RDONLY, 0);
    if (phase_fd >= 0 && call(SYS_READ, phase_fd, (word)&phase, 1, 0) == 1 && !close_fd(phase_fd) &&
        (phase == '1' || phase == '2')) {
        long parent = open_at(AT_FDCWD, "/profile/owned", O_RDONLY | O_DIRECTORY, 0);
        prepare_long_target();
        status = parent < 0 ? 2 : check_permissions(parent);
        if (!status && phase == '1') status = write_profile(parent);
        if (!status) status = verify_profile(parent);
        if (!status) status = check_deep_path(parent, phase == '1');
        if (!status && close_fd(parent)) status = 3;
        if (!status) {
            static const char wrote[] = "Linux MyFS guest wrote profile PASS\n";
            static const char reopened[] = "Linux MyFS guest reopened profile PASS\n";
            const char *message = phase == '1' ? wrote : reopened;
            word length = phase == '1' ? sizeof(wrote) - 1 : sizeof(reopened) - 1;
            if (call(SYS_WRITE, 1, (word)message, length, 0) != (long)length) status = 24;
        }
    }
    call(SYS_EXIT, status, 0, 0, 0);
    __builtin_trap();
}
