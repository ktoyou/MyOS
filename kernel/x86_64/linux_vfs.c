#include "linux_task.h"
#include "pmm.h"

enum {
    ENOENT = 2, EACCES = 13, EEXIST = 17, ENOTDIR = 20, ENOSPC = 28, EROFS = 30,
    ENAMETOOLONG = 36, NAME_LIMIT = 255, TEMP_DIRECTORIES = 256,
};

static struct {
    const char *path;
    struct linux64_file file;
} temporary[TEMP_DIRECTORIES];
static unsigned temporary_count;

static bool same_path(const char *left, const char *right) {
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}

static bool find_node(const struct linux64_file_source *source, const char *path,
                      struct linux64_file *file) {
    if (linux64_special_node(path, file)) return true;
    if (same_path(path, "/")) {
        *file = (struct linux64_file){.mode = LINUX64_S_IFDIR | 0555, .inode = 1};
        return true;
    }
    if (same_path(path, "/tmp")) {
        *file = (struct linux64_file){
            .mode = LINUX64_S_IFDIR | 01777, .inode = 2, .writable_directory = true,
        };
        return true;
    }
    for (unsigned i = 0; i < temporary_count; ++i) {
        if (!same_path(path, temporary[i].path)) continue;
        *file = temporary[i].file;
        return true;
    }
    if (source->lookup && source->lookup(source->context, path, file)) return true;
    u64 inode = source->directory ? source->directory(source->context, path) : 0;
    if (!inode) return false;
    *file = (struct linux64_file){.mode = LINUX64_S_IFDIR | 0555, .inode = inode};
    return true;
}

u32 linux64_directory_permissions(const struct linux64_file *file) {
    unsigned shift = file->uid == LINUX64_UID ? 6 : file->gid == LINUX64_GID ? 3 : 0;
    return (file->mode >> shift) & 7u;
}

static long create_directory(const struct linux64_file *parent, const char *path,
                             uptr length, u32 mode) {
    if (!parent->writable_directory) return -EROFS;
    if (!(linux64_directory_permissions(parent) & 2u)) return -EACCES;
    if (temporary_count == TEMP_DIRECTORIES) return -ENOSPC;
    uptr physical = pmm64_alloc();
    if (!physical) return -ENOSPC;
    char *name = pmm64_pointer(physical);
    for (uptr i = 0; i <= length; ++i) name[i] = path[i];
    unsigned slot = temporary_count++;
    temporary[slot].path = name;
    temporary[slot].file = (struct linux64_file){
        .mode = mode, .uid = LINUX64_UID, .gid = LINUX64_GID,
        .inode = (1ull << 32) + slot, .writable_directory = true,
    };
    return 0;
}

long linux64_vfs_walk(const struct linux64_file_source *source, const char *absolute,
                      struct linux64_file *file, char *resolved, u32 create_mode) {
    char path[LINUX64_PATH_LIMIT] = "/";
    uptr length = 1;
    find_node(source, path, file);
    if (*absolute++ != '/') return -ENOENT;
    while (*absolute) {
        if (*absolute == '/') { ++absolute; continue; }
        if (!(file->mode & LINUX64_S_IFDIR)) return -ENOTDIR;
        if (!(linux64_directory_permissions(file) & 1u)) return -EACCES;
        const char *start = absolute;
        while (*absolute && *absolute != '/') ++absolute;
        uptr count = (uptr)(absolute - start);
        bool trailing = *absolute == '/';
        while (*absolute == '/') ++absolute;
        if (count > NAME_LIMIT) return -ENAMETOOLONG;
        if (count == 1 && start[0] == '.') continue;
        if (count == 2 && start[0] == '.' && start[1] == '.') {
            while (length > 1 && path[--length] != '/') {}
            path[length] = 0;
            find_node(source, path, file);
            continue;
        }
        if (length > 1) path[length++] = '/';
        if (count >= sizeof(path) - length) return -ENAMETOOLONG;
        for (uptr i = 0; i < count; ++i) path[length++] = start[i];
        path[length] = 0;
        struct linux64_file child;
        if (!find_node(source, path, &child)) {
            if (create_mode && !*absolute) return create_directory(file, path, length, create_mode);
            return -ENOENT;
        }
        if (trailing && !(child.mode & LINUX64_S_IFDIR)) return -ENOTDIR;
        *file = child;
    }
    if (create_mode) return -EEXIST;
    if (resolved)
        for (uptr i = 0; i <= length; ++i) resolved[i] = path[i];
    return 0;
}
