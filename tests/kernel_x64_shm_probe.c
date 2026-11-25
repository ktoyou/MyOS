typedef unsigned long word;

enum {
    SYS_WRITE = 1, SYS_CLOSE = 3, SYS_STAT = 4, SYS_FSTAT = 5,
    SYS_MMAP = 9, SYS_MUNMAP = 11, SYS_PREAD = 17, SYS_FORK = 57, SYS_EXIT = 60, SYS_WAIT4 = 61,
    SYS_FTRUNCATE = 77, SYS_CHDIR = 80, SYS_UNLINK = 87,
    SYS_CHROOT = 161, SYS_GETDENTS64 = 217, SYS_OPENAT = 257, SYS_UNSHARE = 272,
    AT_FDCWD = -100, O_RDONLY = 0, O_RDWR = 2, O_CREAT = 0100, O_EXCL = 0200,
    O_DIRECTORY = 0200000, O_CLOEXEC = 02000000, PROT_READ = 1, PROT_WRITE = 2, MAP_SHARED = 1,
    CLONE_NEWUSER = 0x10000000, EEXIST = 17, ENOENT = 2, DT_DIR = 4,
    SHM_SIZE = 8192, PARENT_OFFSET = 11, CHILD_OFFSET = 4097, PARENT_VALUE = 0x52, CHILD_VALUE = 0xa3,
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
    unsigned short length;
    unsigned char type;
    char name[];
};

_Static_assert(sizeof(struct file_stat) == 144 && __builtin_offsetof(struct file_stat, mode) == 24 &&
               __builtin_offsetof(struct file_stat, size) == 48, "Linux x86-64 stat ABI");
_Static_assert(__builtin_offsetof(struct directory_entry, name) == 19, "Linux x86-64 linux_dirent64 ABI");

static const char shm_directory[] = "/dev/shm";
static const char shm_path[] = "/dev/shm/myos-shm-probe";

static long syscall6(word number, word a0, word a1, word a2, word a3, word a4, word a5) {
    register word fourth __asm__("r10") = a3;
    register word fifth __asm__("r8") = a4;
    register word sixth __asm__("r9") = a5;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a0), "S"(a1), "d"(a2), "r"(fourth), "r"(fifth), "r"(sixth) : "rcx", "r11", "memory");
    return (long)number;
}

static long call(word number, word a0, word a1, word a2) {
    return syscall6(number, a0, a1, a2, 0, 0, 0);
}

static long open_path(const char *path, word flags, word mode) {
    return syscall6(SYS_OPENAT, AT_FDCWD, (word)path, flags | O_CLOEXEC, mode, 0, 0);
}

static long read_byte(long fd, unsigned char *value, word offset) {
    return syscall6(SYS_PREAD, fd, (word)value, 1, offset, 0, 0);
}

static __attribute__((noreturn)) void finish(int status) {
    call(SYS_EXIT, status, 0, 0);
    __builtin_trap();
}

static int child_passed(long pid) {
    int status = -1;
    return pid > 0 && call(SYS_WAIT4, pid, (word)&status, 0) == pid && status == 0;
}

static int dev_lists_shm(word inode) {
    long fd = open_path("/dev", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return 0;
    unsigned found = 0;
    for (;;) {
        unsigned char buffer[256] __attribute__((aligned(8)));
        long size = call(SYS_GETDENTS64, fd, (word)buffer, sizeof(buffer));
        if (size < 0 || (word)size > sizeof(buffer)) return 0;
        if (!size) break;
        for (word offset = 0; offset < (word)size;) {
            word remaining = (word)size - offset;
            if (remaining < 20) return 0;
            const struct directory_entry *entry = (const void *)(buffer + offset);
            if (entry->length < 20 || (entry->length & 7) || entry->length > remaining) return 0;
            if (entry->length >= 23 && entry->name[0] == 's' && entry->name[1] == 'h' &&
                entry->name[2] == 'm' && entry->name[3] == '\0') {
                if (entry->type != DT_DIR || entry->inode != inode) return 0;
                ++found;
            }
            offset += entry->length;
        }
    }
    return call(SYS_CLOSE, fd, 0, 0) == 0 && found == 1;
}

static void check_jail(void) {
    long child = call(SYS_FORK, 0, 0, 0);
    if (child < 0) finish(6);
    if (!child) {
        if (call(SYS_UNSHARE, CLONE_NEWUSER, 0, 0) || call(SYS_CHROOT, (word)"/tmp", 0, 0) ||
            call(SYS_CHDIR, (word)"/", 0, 0)) finish(1);
        if (open_path(shm_directory, O_RDONLY | O_DIRECTORY, 0) != -ENOENT ||
            open_path(shm_path, O_RDONLY, 0) != -ENOENT ||
            open_path("../../dev/shm/myos-shm-probe", O_RDWR | O_CREAT | O_EXCL, 0600) != -ENOENT) finish(2);
        finish(0);
    }
    if (!child_passed(child)) finish(7);
}

static long map_shared(long fd, word protection) {
    return syscall6(SYS_MMAP, 0, SHM_SIZE, protection, MAP_SHARED, fd, 0);
}

void _start(void) {
    struct file_stat directory, old, current;
    if (call(SYS_STAT, (word)shm_directory, (word)&directory, 0) || directory.mode != 041777) finish(1);
    if (!dev_lists_shm(directory.inode)) finish(2);

    const word create = O_RDWR | O_CREAT | O_EXCL;
    long fd = open_path(shm_path, create, 0600);
    if (fd < 0 || open_path(shm_path, create, 0600) != -EEXIST) finish(3);
    if (call(SYS_FTRUNCATE, fd, SHM_SIZE, 0) || call(SYS_FSTAT, fd, (word)&old, 0) || old.size != SHM_SIZE)
        finish(4);
    long readonly = open_path(shm_path, O_RDONLY, 0);
    if (readonly < 0 || call(SYS_FSTAT, readonly, (word)&current, 0) || current.inode != old.inode)
        finish(5);
    check_jail();

    long address = map_shared(fd, PROT_READ | PROT_WRITE);
    if (address < 0) finish(8);
    volatile unsigned char *mapping = (void *)address;
    if (mapping[PARENT_OFFSET] || mapping[CHILD_OFFSET]) finish(9);
    mapping[PARENT_OFFSET] = PARENT_VALUE;
    long child = call(SYS_FORK, 0, 0, 0);
    if (!child) {
        if (mapping[PARENT_OFFSET] != PARENT_VALUE) finish(1);
        mapping[CHILD_OFFSET] = CHILD_VALUE;
        finish(0);
    }
    if (!child_passed(child) || mapping[CHILD_OFFSET] != CHILD_VALUE) finish(10);

    if (call(SYS_UNLINK, (word)shm_path, 0, 0) || open_path(shm_path, O_RDONLY, 0) != -ENOENT) finish(11);
    long replacement = open_path(shm_path, create, 0600);
    if (replacement < 0 || call(SYS_FSTAT, replacement, (word)&current, 0) ||
        current.inode == old.inode || current.size != 0 || call(SYS_FTRUNCATE, replacement, SHM_SIZE, 0)) finish(12);
    unsigned char value;
    if (read_byte(readonly, &value, CHILD_OFFSET) != 1 || value != CHILD_VALUE ||
        read_byte(replacement, &value, CHILD_OFFSET) != 1 || value != 0) finish(13);
    long old_alias = map_shared(readonly, PROT_READ);
    if (old_alias < 0 || call(SYS_CLOSE, readonly, 0, 0) || call(SYS_CLOSE, fd, 0, 0)) finish(14);
    const volatile unsigned char *alias = (const void *)old_alias;
    if (alias[CHILD_OFFSET] != CHILD_VALUE || mapping[PARENT_OFFSET] != PARENT_VALUE) finish(15);
    mapping[CHILD_OFFSET] = PARENT_VALUE;
    if (alias[CHILD_OFFSET] != PARENT_VALUE || read_byte(replacement, &value, CHILD_OFFSET) != 1 || value != 0)
        finish(16);

    if (call(SYS_MUNMAP, old_alias, SHM_SIZE, 0) || call(SYS_MUNMAP, address, SHM_SIZE, 0) ||
        call(SYS_CLOSE, replacement, 0, 0) || call(SYS_UNLINK, (word)shm_path, 0, 0)) finish(17);
    static const char passed[] = "SHM guest PASS\n";
    finish(call(SYS_WRITE, 1, (word)passed, sizeof(passed) - 1) == sizeof(passed) - 1 ? 0 : 18);
}
