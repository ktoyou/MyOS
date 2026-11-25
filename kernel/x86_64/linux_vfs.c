#include "linux_task.h"
#include "pmm.h"
#include "linux_myfs.h"

enum {
    EPERM = 1, ENOENT = 2, EIO = 5, ENOMEM = 12, EACCES = 13, EBUSY = 16, EEXIST = 17, EXDEV = 18, ENOTDIR = 20, EISDIR = 21,
    ENOSPC = 28, EROFS = 30, ENAMETOOLONG = 36, ELOOP = 40, EOPNOTSUPP = 95,
    NAME_LIMIT = 255, LINK_LIMIT = 40,
    SYNTHETIC_ENTRY_OFFSET = 1u << 30, PROFILE_ENTRY_OFFSET, LIVE_ENTRY_OFFSET,
};

enum walk_action { WALK_FOLLOW, WALK_NOFOLLOW, WALK_CREATE, WALK_CREATE_FOLLOW, WALK_UNLINK, WALK_RENAME };

struct temporary_node {
    const char *path;
    struct linux64_file file;
    uptr name_page, target_page;
};

struct rename_entry {
    struct linux64_file parent, child;
    struct temporary_node *node;
    char leaf[NAME_LIMIT + 1];
    bool found, trailing;
};

#define TEMP_NODES_PER_PAGE ((PMM_PAGE_SIZE - sizeof(void *)) / sizeof(struct temporary_node))

struct temporary_page {
    struct temporary_page *next;
    struct temporary_node nodes[TEMP_NODES_PER_PAGE];
};

_Static_assert(sizeof(struct temporary_page) <= PMM_PAGE_SIZE &&
               SYNTHETIC_ENTRY_OFFSET > BOOT_MEMORY_LIMIT / PMM_PAGE_SIZE + 2,
               "Temporary VFS page and directory offsets");

/* Свободные ячейки переиспользуются без сдвига каталожных смещений. */
static struct temporary_page *temporary;
static u32 temporary_slots, temporary_used;
static u64 next_inode = 1ull << 32;
static const u64 etc_inode = 1ull << 36;
static const u64 shm_inode = 1ull << 37;

struct linux64_fs *linux64_initial_fs(void) {
    static struct linux64_fs initial = {
        .root = {.path = "/", .file = {.mode = LINUX64_S_IFDIR | 0555, .inode = 1}},
        .cwd = {.path = "/", .file = {.mode = LINUX64_S_IFDIR | 0555, .inode = 1}},
        .references = 1, .umask = 022,
    };
    return &initial;
}

struct linux64_fs *linux64_fs_copy(const struct linux64_fs *source) {
    uptr page = pmm64_alloc();
    if (!page) return NULL;
    struct linux64_fs *fs = pmm64_pointer(page);
    *fs = *source;
    fs->page = page;
    fs->references = 1;
    if (linux64_myfs_retain(fs->root.file.myfs_ino)) {
        pmm64_free(page);
        return NULL;
    }
    if (linux64_myfs_retain(fs->cwd.file.myfs_ino)) {
        linux64_myfs_release(fs->root.file.myfs_ino);
        pmm64_free(page);
        return NULL;
    }
    if (fs->root.page) pmm64_retain(fs->root.page);
    if (fs->cwd.page) pmm64_retain(fs->cwd.page);
    return fs;
}

void linux64_fs_retain(struct linux64_fs *fs) {
    ++fs->references;
}

void linux64_fs_release(struct linux64_fs *fs) {
    if (!fs || --fs->references) return;
    linux64_myfs_release(fs->root.file.myfs_ino);
    linux64_myfs_release(fs->cwd.file.myfs_ino);
    if (fs->root.page) pmm64_free(fs->root.page);
    if (fs->cwd.page) pmm64_free(fs->cwd.page);
    if (fs->page) pmm64_free(fs->page);
}

static bool same_path(const char *left, const char *right) {
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}

void linux64_vfs_temporary_counts(u32 *total, u32 *free) {
    u32 pages, available;
    pmm64_page_counts(&pages, &available);
    /* На имя узла нужна одна страница, плюс страница метаданных на каждую новую группу. */
    u32 spare = temporary_slots - temporary_used;
    u32 names = available;
    if (available > spare) {
        u32 unallocated = available - spare;
        names = spare + unallocated - (unallocated + TEMP_NODES_PER_PAGE) / (TEMP_NODES_PER_PAGE + 1);
    }
    *free = names;
    *total = pages - (pages + TEMP_NODES_PER_PAGE) / (TEMP_NODES_PER_PAGE + 1);
}

static struct temporary_node *temporary_node(const char *path) {
    for (struct temporary_page *page = temporary; page; page = page->next)
        for (unsigned i = 0; i < TEMP_NODES_PER_PAGE; ++i) {
            struct temporary_node *node = &page->nodes[i];
            if (node->path && same_path(path, node->path)) return node;
        }
    return NULL;
}

static struct temporary_node *vacant_node(void) {
    struct temporary_page **link = &temporary;
    for (; *link; link = &(*link)->next)
        for (unsigned i = 0; i < TEMP_NODES_PER_PAGE; ++i)
            if (!(*link)->nodes[i].path) return &(*link)->nodes[i];
    uptr physical = pmm64_alloc();
    if (!physical) return NULL;
    *link = pmm64_pointer(physical);
    temporary_slots += TEMP_NODES_PER_PAGE;
    return &(*link)->nodes[0];
}

static bool find_node(const struct linux64_file_source *source, const char *path,
                      struct linux64_file *file) {
    if (linux64_myfs_mounted() && same_path(path, LINUX64_MYFS_MOUNT))
        return !linux64_myfs_stat(LINUX64_MYFS_ROOT, file);
    if (linux64_special_node(path, file)) return true;
    if (same_path(path, "/")) {
        *file = (struct linux64_file){.mode = LINUX64_S_IFDIR | 0555, .inode = 1};
        return true;
    }
    bool temporary_root = same_path(path, "/tmp");
    if (temporary_root || same_path(path, "/dev/shm")) {
        *file = (struct linux64_file){
            .mode = LINUX64_S_IFDIR | 01777, .inode = temporary_root ? 2 : shm_inode,
            .writable_directory = true,
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
    if (inode || same_path(path, "/etc")) {
        *file = (struct linux64_file){.mode = LINUX64_S_IFDIR | 0555, .inode = inode ? inode : etc_inode};
        return true;
    }
    if (!same_path(path, "/etc/resolv.conf")) return false;
    u32 server = linux64_net_dns_server();
    if (!server) return false;
    char config[LINUX64_RESOLVER_CONFIG_MAX];
    *file = (struct linux64_file){
        .size = linux64_net_resolver_config(server, config),
        /* libc перечитывает resolv.conf, когда по этому пути появился другой inode. */
        .inode = etc_inode | server, .mode = LINUX64_S_IFREG | 0444, .dns_server = server,
    };
    return true;
}

static const char *child_name(const char *entry, const char *parent, uptr *length) {
    while (*parent && *entry == *parent) { ++entry; ++parent; }
    if (*parent) return NULL;
    if (entry[-1] != '/') {
        if (*entry != '/') return NULL;
        ++entry;
    }
    uptr size = 0;
    while (entry[size] && entry[size] != '/') ++size;
    if (!size || size > NAME_LIMIT ||
        (entry[0] == '.' && (size == 1 || (size == 2 && entry[1] == '.')))) return NULL;
    *length = size;
    return entry;
}

static bool same_child(const char *parent, const char *entry, const char *name, uptr length) {
    uptr candidate_length;
    const char *candidate = child_name(entry, parent, &candidate_length);
    if (!candidate || candidate_length != length) return false;
    for (uptr i = 0; i < length; ++i) {
        if (candidate[i] != name[i]) return false;
    }
    return true;
}

static bool live_child(const struct linux64_file_source *source, const char *parent,
                       uptr *index, const char **name, uptr *length) {
    const char *path;
    while ((path = source->entry_path(source->context, *index))) {
        uptr current = (*index)++;
        const char *child = child_name(path, parent, length);
        if (!child) continue;
        /* Один каталог Live-образа может быть префиксом нескольких записей. */
        uptr earlier = 0;
        while (earlier < current &&
               !same_child(parent, source->entry_path(source->context, earlier), child, *length))
            ++earlier;
        if (earlier != current) continue;
        *name = child;
        return true;
    }
    return false;
}

long linux64_vfs_next_entry(const struct linux64_directory *dir, uptr *position,
                            char name[256], struct linux64_file *file) {
    const struct linux64_file_source *source = linux64_file_source();
    const struct linux64_directory *root = &linux64_current->process->fs->root;
    if (dir->file.myfs_ino) {
        if (*position < 2) {
            bool parent = *position == 1;
            u32 ino = dir->file.myfs_ino;
            if (parent && ino != root->file.myfs_ino) {
                if (ino == LINUX64_MYFS_ROOT) find_node(source, "/", file);
                else {
                    long result = linux64_myfs_lookup(ino, "..", file);
                    if (result) return result;
                }
            } else {
                long result = linux64_myfs_stat(ino, file);
                if (result) return result;
            }
            name[0] = '.';
            name[1] = parent ? '.' : 0;
            name[2] = 0;
            ++*position;
            return 1;
        }
        uptr cursor = *position - 2;
        long result = linux64_myfs_next(dir->file.myfs_ino, &cursor, name, file);
        if (result > 0) *position = cursor + 2;
        return result;
    }
    char path[LINUX64_PATH_LIMIT];
    uptr length = 0;
    while ((path[length] = dir->path[length])) ++length;
    if (*position < 2) {
        bool parent = (*position)++ != 0;
        name[0] = '.';
        name[1] = parent ? '.' : 0;
        name[2] = 0;
        *file = dir->file;
        if (parent && length > 1 && !same_path(path, root->path)) {
            while (length > 1 && path[--length] != '/') {}
            path[length] = 0;
            find_node(source, path, file);
        }
        return true;
    }
    if (dir->file.private_directory) return false;

    const char *child = NULL;
    uptr size;
    /* Смещения временных узлов остаются неизменными при добавлении соседей. */
    if (*position < SYNTHETIC_ENTRY_OFFSET) {
        uptr index = *position - 2;
        const struct temporary_page *page = temporary;
        while (page && index >= TEMP_NODES_PER_PAGE) {
            index -= TEMP_NODES_PER_PAGE;
            page = page->next;
        }
        for (; page && !child; page = page->next, index = 0) {
            for (; index < TEMP_NODES_PER_PAGE; ++index) {
                const struct temporary_node *node = &page->nodes[index];
                ++*position;
                if (!node->path) continue;
                child = child_name(node->path, dir->path, &size);
                if (child && !child[size]) {
                    *file = node->file;
                    break;
                }
                child = NULL;
            }
        }
        if (!child) *position = SYNTHETIC_ENTRY_OFFSET;
    }
    if (!child && *position == SYNTHETIC_ENTRY_OFFSET) {
        ++*position;
        if (same_path(dir->path, "/") && find_node(source, "/etc", file) && file->inode == etc_inode) {
            child = "etc";
            size = sizeof("etc") - 1;
        } else if (same_path(dir->path, "/etc") && find_node(source, "/etc/resolv.conf", file) &&
                   file->dns_server) {
            child = "resolv.conf";
            size = sizeof("resolv.conf") - 1;
        } else if (same_path(dir->path, "/dev") && find_node(source, "/dev/shm", file)) {
            child = "shm";
            size = sizeof("shm") - 1;
        }
    }
    if (!child && *position == PROFILE_ENTRY_OFFSET) {
        ++*position;
        if (linux64_myfs_mounted() && same_path(dir->path, "/") &&
            find_node(source, LINUX64_MYFS_MOUNT, file)) {
            child = LINUX64_MYFS_MOUNT + 1;
            size = sizeof(LINUX64_MYFS_MOUNT) - 2;
        }
    }
    if (!child) {
        if (!source->entry_path) return false;
        uptr index = *position - LIVE_ENTRY_OFFSET;
        if (length > 1) path[length++] = '/';
        while (live_child(source, dir->path, &index, &child, &size)) {
            for (uptr i = 0; i < size; ++i) path[length + i] = child[i];
            path[length + size] = 0;
            /* /dev/shm уже перечислен в зарезервированной позиции. */
            if (!same_path(path, "/dev/shm") &&
                !(linux64_myfs_mounted() && same_path(path, LINUX64_MYFS_MOUNT)) &&
                find_node(source, path, file)) break;
            child = NULL;
        }
        if (!child) return false;
        *position = index + LIVE_ENTRY_OFFSET;
    }
    for (uptr i = 0; i < size; ++i) name[i] = child[i];
    name[size] = 0;
    return true;
}

u32 linux64_file_permissions(const struct linux64_file *file) {
    unsigned shift = file->uid == LINUX64_UID ? 6 : file->gid == LINUX64_GID ? 3 : 0;
    return (file->mode >> shift) & 7u;
}

static long create_node(const char *path, uptr length, struct linux64_file file,
                        struct linux64_file *created) {
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
    if ((file.mode & LINUX64_S_IFMT) == LINUX64_S_IFREG) {
        file.backing = linux64_tmp_alloc();
        if (!file.backing) {
            if (target_page) pmm64_free(target_page);
            pmm64_free(name_page);
            return -ENOSPC;
        }
    }
    struct temporary_node *node = vacant_node();
    if (!node) {
        if (file.backing) linux64_tmp_unlink(file.backing);
        if (target_page) pmm64_free(target_page);
        pmm64_free(name_page);
        return -ENOSPC;
    }
    char *name = pmm64_pointer(name_page);
    for (uptr i = 0; i <= length; ++i) name[i] = path[i];
    file.inode = next_inode++;
    file.uid = LINUX64_UID;
    file.gid = LINUX64_GID;
    *node = (struct temporary_node){
        .path = name, .file = file, .name_page = name_page, .target_page = target_page,
    };
    ++temporary_used;
    *created = file;
    return 0;
}

static long may_remove(const struct linux64_file *parent, const struct linux64_file *child) {
    if (!(linux64_file_permissions(parent) & 2u)) return -EACCES;
    if ((parent->mode & 01000u) && parent->uid != LINUX64_UID && child->uid != LINUX64_UID)
        return -EPERM;
    return 0;
}

static void remove_temporary_node(struct temporary_node *node) {
    if (node->file.backing) linux64_tmp_unlink(node->file.backing);
    if (node->target_page) pmm64_free(node->target_page);
    pmm64_free(node->name_page);
    *node = (struct temporary_node){0};
    --temporary_used;
}

static long unlink_node(const struct linux64_file *parent, const struct linux64_file *child,
                        const char *path, bool trailing) {
    if ((child->mode & LINUX64_S_IFMT) == LINUX64_S_IFDIR) return -EISDIR;
    if (trailing) return -ENOTDIR;
    long result = may_remove(parent, child);
    if (result) return result;
    struct temporary_node *node = temporary_node(path);
    if (!node) return -EROFS;
    remove_temporary_node(node);
    return 0;
}

static uptr path_length(const char *path) {
    uptr length = 0;
    while (path[length]) ++length;
    return length;
}

static long start_at(char *path, const struct linux64_directory *anchor, struct linux64_file *file) {
    *file = anchor->file;
    if (file->myfs_ino) {
        long result = linux64_myfs_stat(file->myfs_ino, file);
        if (result) return result;
        result = linux64_myfs_path(file->myfs_ino, path);
        if (!result) return (long)path_length(path);
        if (result != -ENOENT) return result;
    }
    uptr length = 0;
    while ((path[length] = anchor->path[length])) ++length;
    return (long)length;
}

struct link_scratch {
    uptr pages[LINK_LIMIT];
    unsigned count;
};

static long read_link(struct link_scratch *scratch, const struct linux64_file *link,
                      const char **absolute) {
    if (!link->size) return -ENOENT;
    if (link->size >= LINUX64_PATH_LIMIT) return -ENAMETOOLONG;
    uptr page = pmm64_alloc();
    if (!page) return -ENOMEM;
    scratch->pages[scratch->count++] = page;
    char *target = pmm64_pointer(page);
    long count = linux64_myfs_read(link->myfs_ino, 0, target, link->size);
    if (count < 0) return count;
    if ((uptr)count != link->size) return -EIO;
    for (uptr i = 0; i < link->size; ++i) if (!target[i]) return -EIO;
    target[link->size] = 0;
    *absolute = target;
    return 0;
}

static long walk_inner(const struct linux64_directory *base, const char *input,
                       struct linux64_file *file, char *resolved, enum walk_action action,
                       const struct linux64_file *create, struct rename_entry *entry,
                       struct link_scratch *scratch) {
    const struct linux64_fs *fs = linux64_current->process->fs;
    const struct linux64_directory *root = &fs->root;
    const struct linux64_file_source *source = linux64_file_source();
    const char *absolute = input;
    bool creating = action == WALK_CREATE || action == WALK_CREATE_FOLLOW;
    char path[LINUX64_PATH_LIMIT];
    long position = start_at(path, *input == '/' ? root : base ? base : &fs->cwd, file);
    if (position < 0) return position;
    uptr length = (uptr)position;
    /* Обход не уступает CPU, поэтому указатели на цели действуют до его конца. */
    const char *suffixes[LINK_LIMIT];
    unsigned depth = 0, links = 0;
    for (;;) {
        while (*absolute == '/') ++absolute;
        if (!*absolute) {
            if (!depth) break;
            absolute = suffixes[--depth];
            continue;
        }
        if ((file->mode & LINUX64_S_IFMT) != LINUX64_S_IFDIR) return -ENOTDIR;
        if (!(linux64_file_permissions(file) & 1u)) return -EACCES;
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
        if (count == 1 && start[0] == '.') {
            if (entry && final) return -EBUSY;
            continue;
        }
        if (count == 2 && start[0] == '.' && start[1] == '.') {
            if (entry && final) return -EBUSY;
            if (file->myfs_ino) {
                if (file->myfs_ino == root->file.myfs_ino) continue;
                if (file->myfs_ino == LINUX64_MYFS_ROOT) {
                    if (!find_node(source, "/", file)) return -ENOENT;
                    path[1] = 0;
                    length = 1;
                } else {
                    long result = linux64_myfs_lookup(file->myfs_ino, "..", file);
                    if (result) return result;
                    result = linux64_myfs_path(file->myfs_ino, path);
                    if (result) return result;
                    length = path_length(path);
                }
                continue;
            }
            if (length == 1 || same_path(path, root->path)) continue;
            if (file->proc_fd_owner && file->proc_fd_owner != linux64_current->process->pid)
                return -EACCES;
            while (length > 1 && path[--length] != '/') {}
            path[length] = 0;
            if (same_path(path, root->path)) *file = root->file;
            else if (!find_node(source, path, file)) return -ENOENT;
            continue;
        }
        uptr parent_length = length;
        if (length > 1) path[length++] = '/';
        if (count >= sizeof(path) - length) return -ENAMETOOLONG;
        for (uptr i = 0; i < count; ++i) path[length++] = start[i];
        path[length] = 0;
        if (final && action == WALK_UNLINK && !file->writable_directory) return -EROFS;
        struct linux64_file child;
        const char *name = path + length - count;
        bool found;
        if (file->myfs_ino) {
            long result = linux64_myfs_lookup(file->myfs_ino, name, &child);
            if (result && result != -ENOENT) return result;
            found = !result;
        } else if (file->proc_fd_owner && file->proc_fd_number < 0) {
            long result = linux64_proc_fd_entry(file->proc_fd_owner, start, count, &child);
            if (result && result != -ENOENT) return result;
            found = !result;
        } else if (file->proc_peer_exe_owner) {
            found = linux64_proc_peer_exe_entry(file, name, &child);
        } else {
            found = !file->private_directory && find_node(source, path, &child);
        }
        if (entry && final) {
            entry->found = found;
            entry->trailing = trailing;
            entry->node = found && !file->proc_fd_owner ? temporary_node(path) : NULL;
            if (found) entry->child = child;
            for (uptr i = 0; i <= count; ++i) entry->leaf[i] = name[i];
            if (resolved)
                for (uptr i = 0; i <= length; ++i) resolved[i] = path[i];
            return 0;
        }
        if (!found) {
            if (!final || !creating ||
                (trailing && (create->mode & LINUX64_S_IFMT) != LINUX64_S_IFDIR)) return -ENOENT;
            if (!file->writable_directory) return -EROFS;
            if (!(linux64_file_permissions(file) & 2u)) return -EACCES;
            if (file->myfs_ino) {
                if (!file->myfs_links) return -ENOENT;
                return linux64_myfs_create(file->myfs_ino, name, create, file);
            }
            return create_node(path, length, *create, file);
        }
        if (final && creating && (action == WALK_CREATE || (child.mode & LINUX64_S_IFMT) != LINUX64_S_IFLNK))
            return -EEXIST;
        if (final && action == WALK_UNLINK) {
            if (!file->myfs_ino) return unlink_node(file, &child, path, trailing);
            if ((child.mode & LINUX64_S_IFMT) == LINUX64_S_IFDIR) return -EISDIR;
            if (trailing) return -ENOTDIR;
            long result = may_remove(file, &child);
            return result ? result : linux64_myfs_remove(file->myfs_ino, name, child.myfs_ino);
        }
        if (child.proc_fd_owner && child.proc_fd_number >= 0) {
            /* Ссылка ведёт к объекту дескриптора, а не к текстовому пути. */
            if (!final) return -ENOTDIR;
            if (trailing && !child.proc_fd_directory) return -ENOTDIR;
            if (trailing) child.mode = LINUX64_S_IFDIR | 0555;
            *file = child;
            continue;
        }
        u32 type = child.mode & LINUX64_S_IFMT;
        if (type == LINUX64_S_IFLNK && (trailing || action == WALK_FOLLOW || action == WALK_CREATE_FOLLOW)) {
            if (++links > LINK_LIMIT) return -ELOOP;
            /* Пустой хвост сохраняет завершающий '/', который требует каталог. */
            if (trailing) suffixes[depth++] = absolute;
            if (child.myfs_ino) {
                long result = read_link(scratch, &child, &absolute);
                if (result) return result;
            } else if (child.proc_peer_exe_owner) {
                long result = linux64_proc_peer_exe_target(child.proc_peer_exe_owner, &absolute);
                if (result < 0) return result;
            } else {
                absolute = (const char *)child.bytes;
            }
            if (*absolute == '/') {
                position = start_at(path, root, file);
                if (position < 0) return position;
                length = (uptr)position;
            } else {
                length = parent_length;
                path[length] = 0;
            }
            continue;
        }
        if (trailing && type != LINUX64_S_IFDIR) return -ENOTDIR;
        *file = child;
    }
    if (entry) return -EBUSY;
    if (creating) return -EEXIST;
    if (action == WALK_UNLINK) return -EISDIR;
    if (resolved)
        for (uptr i = 0; i <= length; ++i) resolved[i] = path[i];
    return 0;
}

static long walk(const struct linux64_directory *base, const char *input,
                 struct linux64_file *file, char *resolved, enum walk_action action,
                 const struct linux64_file *create, struct rename_entry *entry) {
    struct link_scratch scratch = {0};
    long result = walk_inner(base, input, file, resolved, action, create, entry, &scratch);
    for (unsigned i = 0; i < scratch.count; ++i) pmm64_free(scratch.pages[i]);
    return result;
}

long linux64_vfs_walk(const struct linux64_directory *base, const char *path,
                      struct linux64_file *file, char *resolved, bool follow_final) {
    return walk(base, path, file, resolved, follow_final ? WALK_FOLLOW : WALK_NOFOLLOW, NULL, NULL);
}

long linux64_vfs_mkdir(const struct linux64_directory *base, const char *path, u32 mode) {
    const struct linux64_file node = {.mode = mode, .writable_directory = true};
    struct linux64_file file;
    return walk(base, path, &file, NULL, WALK_CREATE, &node, NULL);
}

long linux64_vfs_create_file(const struct linux64_directory *base, const char *path,
                             u32 mode, bool follow_final, struct linux64_file *file) {
    const struct linux64_file node = {.mode = LINUX64_S_IFREG | mode};
    return walk(base, path, file, NULL, follow_final ? WALK_CREATE_FOLLOW : WALK_CREATE, &node, NULL);
}

long linux64_vfs_symlink(const struct linux64_directory *base, const char *path,
                        const char *target, uptr length) {
    const struct linux64_file node = {
        .bytes = (const u8 *)target, .size = length, .mode = LINUX64_S_IFLNK | 0777,
    };
    struct linux64_file file;
    return walk(base, path, &file, NULL, WALK_CREATE, &node, NULL);
}

long linux64_vfs_socket(const struct linux64_directory *base, const char *path, u32 mode,
                        u64 *inode) {
    const struct linux64_file node = {.mode = LINUX64_S_IFSOCK | mode};
    struct linux64_file file;
    long result = walk(base, path, &file, NULL, WALK_CREATE, &node, NULL);
    if (!result) *inode = file.inode;
    return result;
}

long linux64_vfs_unlink(const struct linux64_directory *base, const char *path) {
    struct linux64_file file;
    return walk(base, path, &file, NULL, WALK_UNLINK, NULL, NULL);
}

long linux64_vfs_rename(const struct linux64_directory *old_base, const char *old_path,
                        const struct linux64_directory *new_base, char *new_path) {
    struct rename_entry old, new;
    long result = walk(old_base, old_path, &old.parent, NULL, WALK_RENAME, NULL, &old);
    if (result) return result;
    if (!old.found) return -ENOENT;
    bool disk = old.parent.myfs_ino != 0;
    if (!old.parent.writable_directory || (!disk && !old.node)) return -EROFS;
    bool old_directory = (old.child.mode & LINUX64_S_IFMT) == LINUX64_S_IFDIR;
    if (old_directory && !disk) return -EOPNOTSUPP;
    if (old.trailing && !old_directory) return -ENOTDIR;

    result = walk(new_base, new_path, &new.parent, new_path, WALK_RENAME, NULL, &new);
    if (result) return result;
    if (disk != (new.parent.myfs_ino != 0)) return -EXDEV;
    if (new.trailing && !old_directory) return -ENOTDIR;
    if (!new.parent.writable_directory || (!disk && new.found && !new.node)) return -EROFS;
    if (new.found && old.child.inode == new.child.inode) return 0;
    if (new.found && !old_directory && (new.child.mode & LINUX64_S_IFMT) == LINUX64_S_IFDIR) return -EISDIR;
    result = may_remove(&old.parent, &old.child);
    if (result) return result;
    if (new.found) {
        result = may_remove(&new.parent, &new.child);
        if (result) return result;
    } else if (!(linux64_file_permissions(&new.parent) & 2u)) {
        return -EACCES;
    }

    if (disk) return linux64_myfs_rename(old.parent.myfs_ino, old.leaf, new.parent.myfs_ino, new.leaf,
                                         new.found ? new.child.myfs_ino : 0);

    /* После проверок меняются только имена. Открытые описания удерживают данные. */
    if (new.node) remove_temporary_node(new.node);
    char *name = pmm64_pointer(old.node->name_page);
    while ((*name++ = *new_path++)) {}
    return 0;
}
