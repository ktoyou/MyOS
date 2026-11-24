#include "linux_task.h"
#include "paging.h"

enum {
    EPERM = 1, ESRCH = 3, EFAULT = 14, EINVAL = 22, ENOSPC = 28,
    OVERFLOW_ID = 65534, USERNS_COUNT = 64, USERNS_MAX_DEPTH = 32,
    CAP_VERSION_1 = 0x19980330, CAP_VERSION_2 = 0x20071026, CAP_VERSION_3 = 0x20080522,
};

struct linux64_userns {
    struct linux64_userns *parent;
    u64 inode;
    u32 ids[2];
    bool mapped[2], deny_setgroups, parent_could_setfcap;
    unsigned references, depth;
};

static struct linux64_userns namespaces[USERNS_COUNT];
static u64 next_inode = 2;

void linux64_userns_retain(struct linux64_userns *ns) {
    if (ns) ++ns->references;
}

void linux64_userns_release(struct linux64_userns *ns) {
    while (ns && !--ns->references) ns = ns->parent;
}

u64 linux64_userns_inode(const struct linux64_userns *ns) {
    return ns ? ns->inode : 1;
}

u32 linux64_visible_id(const struct linux64_userns *ns, bool group, u32 id) {
    if (!ns) return id;
    u32 canonical = group ? LINUX64_GID : LINUX64_UID;
    return ns->mapped[group] && id == canonical ? ns->ids[group] : OVERFLOW_ID;
}

long linux64_userns_create(struct linux64_userns *parent, struct linux64_userns **result) {
    if (parent && (!parent->mapped[0] || !parent->mapped[1])) return -EPERM;
    unsigned depth = parent ? parent->depth + 1 : 1;
    if (depth > USERNS_MAX_DEPTH) return -ENOSPC;
    for (unsigned i = 0; i < USERNS_COUNT; ++i) {
        struct linux64_userns *ns = &namespaces[i];
        if (ns->references) continue;
        *ns = (struct linux64_userns){
            .parent = parent, .inode = next_inode++, .references = 1, .depth = depth,
            .deny_setgroups = parent && parent->deny_setgroups,
            .parent_could_setfcap = (linux64_current->caps.effective & LINUX64_CAP_SETFCAP) != 0,
        };
        linux64_userns_retain(parent);
        *result = ns;
        return 0;
    }
    return -ENOSPC;
}

void linux64_userns_caps(struct linux64_task *task) {
    /* Эти права относятся только к пространству процесса, а не к родителю. */
    const u64 all = (1ull << 41) - 1;
    task->caps = (struct linux64_caps){.effective = all, .permitted = all};
}

struct cap_header { u32 version; i32 pid; };
struct cap_data { u32 effective, permitted, inheritable; };

long linux64_capabilities(bool set, uptr address, uptr data) {
    struct cap_header header;
    if (paging64_copy_from_user(&header, address, sizeof(header)) != sizeof(header)) return -EFAULT;
    unsigned words;
    switch (header.version) {
    case CAP_VERSION_1: words = 1; break;
    case CAP_VERSION_2:
    case CAP_VERSION_3: words = 2; break;
    default:
        if (!paging64_put_user_u32(address, CAP_VERSION_3)) return -EFAULT;
        return !set && !data ? 0 : -EINVAL;
    }
    if (!set && !data) return 0;
    if (header.pid < 0) return -EINVAL;
    if (header.pid && header.pid != linux64_current->tid) return set ? -EPERM : -ESRCH;
    struct linux64_caps *caps = &linux64_current->caps;
    struct cap_data payload[2] = {0};
    uptr length = words * sizeof(payload[0]);
    if (!set) {
        for (unsigned i = 0; i < words; ++i) {
            unsigned shift = 32 * i;
            payload[i] = (struct cap_data){
                (u32)(caps->effective >> shift), (u32)(caps->permitted >> shift),
                (u32)(caps->inheritable >> shift),
            };
        }
        return paging64_copy_to_user(data, payload, length) == length ? 0 : -EFAULT;
    }
    if (paging64_copy_from_user(payload, data, length) != length) return -EFAULT;
    struct linux64_caps requested = {
        payload[0].effective | (u64)payload[1].effective << 32,
        payload[0].permitted | (u64)payload[1].permitted << 32,
        payload[0].inheritable | (u64)payload[1].inheritable << 32,
    };
    if ((requested.permitted & ~caps->permitted) || (requested.effective & ~requested.permitted) ||
        (requested.inheritable & ~caps->inheritable)) return -EPERM;
    *caps = requested;
    return 0;
}

static bool whitespace(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
}

static bool read_id(const char **cursor, const char *end, u32 *id) {
    const char *p = *cursor;
    while (p < end && whitespace(*p)) ++p;
    const char *start = p;
    u32 value = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        u32 digit = (u32)(*p++ - '0');
        if (value > (0xffffffffu - digit) / 10) return false;
        value = value * 10 + digit;
    }
    if (p == start || (p < end && !whitespace(*p))) return false;
    *cursor = p;
    *id = value;
    return true;
}

long linux64_userns_write(struct linux64_userns *ns, enum linux64_proc_node file,
                          uptr buffer, uptr count, uptr offset) {
    if (!ns) return -EPERM;
    char text[64];
    if (!count || count > sizeof(text) || offset) return -EINVAL;
    if (paging64_copy_from_user(text, buffer, count) != count) return -EFAULT;
    const char *p = text, *end = text + count;
    if (file == USERNS_SETGROUPS) {
        if (count < 4 || p[0] != 'd' || p[1] != 'e' || p[2] != 'n' || p[3] != 'y')
            return -EPERM;
        p += 4;
        while (p < end && whitespace(*p)) ++p;
        if (p != end) return -EINVAL;
        if (ns->mapped[1]) return -EPERM;
        ns->deny_setgroups = true;
        return (long)count;
    }
    u32 local, lower, size;
    if (!read_id(&p, end, &local) || !read_id(&p, end, &lower) || !read_id(&p, end, &size) ||
        local == 0xffffffffu || lower == 0xffffffffu || !size) return -EINVAL;
    while (p < end && whitespace(*p)) ++p;
    if (p != end) return -EINVAL;
    bool group = file == USERNS_GID_MAP;
    u32 owner = group ? LINUX64_GID : LINUX64_UID;
    if (ns->mapped[group] || (group && !ns->deny_setgroups) || size != 1 ||
        (!group && !lower && !ns->parent_could_setfcap) ||
        lower != linux64_visible_id(ns->parent, group, owner)) return -EPERM;
    /* Разрешено отобразить только собственный идентификатор в родителе. */
    ns->ids[group] = local;
    ns->mapped[group] = true;
    return (long)count;
}

static char *write_number(char *out, u64 value) {
    char reverse[20];
    unsigned length = 0;
    do {
        reverse[length++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (length) *out++ = reverse[--length];
    return out;
}

long linux64_userns_readlink(const struct linux64_userns *ns, uptr buffer, uptr size) {
    char text[27] = {'u', 's', 'e', 'r', ':', '['};
    char *end = write_number(text + 6, linux64_userns_inode(ns));
    *end++ = ']';
    uptr count = (uptr)(end - text);
    if (size < count) count = size;
    return paging64_copy_to_user(buffer, text, count) == count ? (long)count : -EFAULT;
}

long linux64_userns_read(const struct linux64_userns *ns, enum linux64_proc_node file,
                         uptr buffer, uptr count, uptr offset) {
    char text[40], *end = text;
    if (file == USERNS_SETGROUPS) {
        const char *value = ns && ns->deny_setgroups ? "deny\n" : "allow\n";
        while (*value) *end++ = *value++;
    } else {
        bool group = file == USERNS_GID_MAP;
        if (ns && !ns->mapped[group]) return 0;
        u32 owner = group ? LINUX64_GID : LINUX64_UID;
        end = write_number(end, ns ? ns->ids[group] : 0);
        *end++ = ' ';
        end = write_number(end, ns ? linux64_visible_id(ns->parent, group, owner) : 0);
        *end++ = ' ';
        end = write_number(end, ns ? 1 : 0xffffffffu);
        *end++ = '\n';
    }
    uptr size = (uptr)(end - text);
    if (offset >= size) return 0;
    if (count > size - offset) count = size - offset;
    return paging64_copy_to_user(buffer, text + offset, count) == count ? (long)count : -EFAULT;
}
