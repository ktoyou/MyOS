#include "linux_task.h"
#include "pmm.h"

enum {
    EPERM = 1, ENOENT = 2, EACCES = 13, EEXIST = 17, ENOTDIR = 20, EISDIR = 21,
    ENOSPC = 28, EROFS = 30, ENAMETOOLONG = 36, ELOOP = 40,
    NAME_LIMIT = 255, LINK_LIMIT = 40, TEMP_NODES = 256,
};

enum walk_action { WALK_FOLLOW, WALK_NOFOLLOW, WALK_CREATE, WALK_UNLINK };

struct temporary_node {
    const char *path;
    struct linux64_file file;
    uptr name_page, target_page;
};

static struct temporary_node temporary[TEMP_NODES];
static u64 next_inode = 1ull << 32;

static bool same_path(const char *left, const char *right) {
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}

static struct temporary_node *temporary_node(const char *path) {
    for (unsigned i = 0; i < TEMP_NODES; ++i)
        if (temporary[i].path && same_path(path, temporary[i].path)) return &temporary[i];
    return NULL;
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
    const struct temporary_node *node = temporary_node(path);
    if (node) {
        *file = node->file;
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

static long create_node(const char *path, uptr length, struct linux64_file file) {
    unsigned slot = 0;
    while (slot < TEMP_NODES && temporary[slot].path) ++slot;
    if (slot == TEMP_NODES) return -ENOSPC;
    uptr name_page = pmm64_alloc(), target_page = 0;
    if (!name_page) return -ENOSPC;
    if (file.bytes) {
        target_page = pmm64_alloc();
        if (!target_page) {
            pmm64_free(name_page);
            return -ENOSPC;
        }
        u8 *target = pmm64_pointer(target_page);
        for (uptr i = 0; i <= file.size; ++i) target[i] = file.bytes[i];
        file.bytes = target;
    }
    char *name = pmm64_pointer(name_page);
    for (uptr i = 0; i <= length; ++i) name[i] = path[i];
    file.inode = next_inode++;
    file.uid = LINUX64_UID;
    file.gid = LINUX64_GID;
    temporary[slot] = (struct temporary_node){
        .path = name, .file = file, .name_page = name_page, .target_page = target_page,
    };
    return 0;
}

static long unlink_node(const struct linux64_file *parent, const struct linux64_file *child,
                        const char *path, bool trailing) {
    if ((child->mode & LINUX64_S_IFMT) == LINUX64_S_IFDIR) return -EISDIR;
    if (trailing) return -ENOTDIR;
    if (!(linux64_directory_permissions(parent) & 2u)) return -EACCES;
    if ((parent->mode & 01000u) && parent->uid != LINUX64_UID && child->uid != LINUX64_UID)
        return -EPERM;
    struct temporary_node *node = temporary_node(path);
    if (!node) return -EROFS;
    if (node->target_page) pmm64_free(node->target_page);
    pmm64_free(node->name_page);
    *node = (struct temporary_node){0};
    return 0;
}

static long walk(const struct linux64_file_source *source, const char *absolute,
                 struct linux64_file *file, char *resolved, enum walk_action action,
                 const struct linux64_file *create) {
    char path[LINUX64_PATH_LIMIT] = "/";
    uptr length = 1;
    /* Обход не уступает CPU, поэтому указатели на цели действуют до его конца. */
    const char *suffixes[LINK_LIMIT];
    unsigned depth = 0, links = 0;
    find_node(source, path, file);
    if (*absolute++ != '/') return -ENOENT;
    for (;;) {
        while (*absolute == '/') ++absolute;
        if (!*absolute) {
            if (!depth) break;
            absolute = suffixes[--depth];
            continue;
        }
        if ((file->mode & LINUX64_S_IFMT) != LINUX64_S_IFDIR) return -ENOTDIR;
        if (!(linux64_directory_permissions(file) & 1u)) return -EACCES;
        const char *start = absolute;
        while (*absolute && *absolute != '/') ++absolute;
        uptr count = (uptr)(absolute - start);
        bool trailing = *absolute == '/';
        while (*absolute == '/') ++absolute;
        while (!*absolute && depth) {
            trailing = true;
            absolute = suffixes[--depth];
        }
        bool final = !*absolute;
        if (count > NAME_LIMIT) return -ENAMETOOLONG;
        if (count == 1 && start[0] == '.') continue;
        if (count == 2 && start[0] == '.' && start[1] == '.') {
            while (length > 1 && path[--length] != '/') {}
            path[length] = 0;
            find_node(source, path, file);
            continue;
        }
        uptr parent_length = length;
        if (length > 1) path[length++] = '/';
        if (count >= sizeof(path) - length) return -ENAMETOOLONG;
        for (uptr i = 0; i < count; ++i) path[length++] = start[i];
        path[length] = 0;
        if (final && action == WALK_UNLINK && !file->writable_directory) return -EROFS;
        struct linux64_file child;
        if (!find_node(source, path, &child)) {
            if (!final || action != WALK_CREATE || (trailing && create->bytes)) return -ENOENT;
            if (!file->writable_directory) return -EROFS;
            if (!(linux64_directory_permissions(file) & 2u)) return -EACCES;
            return create_node(path, length, *create);
        }
        if (final && action == WALK_CREATE) return -EEXIST;
        if (final && action == WALK_UNLINK) return unlink_node(file, &child, path, trailing);
        u32 type = child.mode & LINUX64_S_IFMT;
        if (type == LINUX64_S_IFLNK && (trailing || action == WALK_FOLLOW)) {
            if (++links > LINK_LIMIT) return -ELOOP;
            /* Пустой хвост сохраняет завершающий '/', который требует каталог. */
            if (trailing) suffixes[depth++] = absolute;
            absolute = (const char *)child.bytes;
            if (*absolute == '/') {
                length = 1;
                path[length] = 0;
                find_node(source, path, file);
            } else {
                length = parent_length;
                path[length] = 0;
            }
            continue;
        }
        if (trailing && type != LINUX64_S_IFDIR) return -ENOTDIR;
        *file = child;
    }
    if (action == WALK_CREATE) return -EEXIST;
    if (action == WALK_UNLINK) return -EISDIR;
    if (resolved)
        for (uptr i = 0; i <= length; ++i) resolved[i] = path[i];
    return 0;
}

long linux64_vfs_walk(const struct linux64_file_source *source, const char *absolute,
                      struct linux64_file *file, char *resolved, bool follow_final) {
    return walk(source, absolute, file, resolved, follow_final ? WALK_FOLLOW : WALK_NOFOLLOW, NULL);
}

long linux64_vfs_mkdir(const struct linux64_file_source *source, const char *absolute, u32 mode) {
    const struct linux64_file node = {.mode = mode, .writable_directory = true};
    struct linux64_file file;
    return walk(source, absolute, &file, NULL, WALK_CREATE, &node);
}

long linux64_vfs_symlink(const struct linux64_file_source *source, const char *absolute,
                        const char *target, uptr length) {
    const struct linux64_file node = {
        .bytes = (const u8 *)target, .size = length, .mode = LINUX64_S_IFLNK | 0777,
    };
    struct linux64_file file;
    return walk(source, absolute, &file, NULL, WALK_CREATE, &node);
}

long linux64_vfs_unlink(const struct linux64_file_source *source, const char *absolute) {
    struct linux64_file file;
    return walk(source, absolute, &file, NULL, WALK_UNLINK, NULL);
}
