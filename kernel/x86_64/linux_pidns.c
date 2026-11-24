#include "linux_task.h"
#include "paging.h"

enum { PIDNS_MAX_DEPTH = 32, ENOMEM = 12, EFAULT = 14, ENOSPC = 28 };

struct linux64_pidns {
    struct linux64_pidns *parent;
    struct linux64_userns *owner;
    uptr physical;
    u64 inode;
    unsigned level, references;
    i32 next, reaper;
};

struct linux64_pid {
    struct linux64_pidns *ns;
    uptr physical;
    unsigned references;
    i32 numbers[PIDNS_MAX_DEPTH + 1];
};

static struct linux64_pidns initial_ns = {.inode = 0x100000000ull, .next = 2, .reaper = LINUX64_PID};
static struct linux64_pid initial_pid = {.ns = &initial_ns, .numbers = {LINUX64_PID}};
static u64 next_inode = 0x100000001ull;

struct linux64_pidns *linux64_pidns_init(void) {
    return &initial_ns;
}

void linux64_pidns_retain(struct linux64_pidns *ns) {
    if (ns != &initial_ns) ++ns->references;
}

void linux64_pidns_release(struct linux64_pidns *ns) {
    if (!ns) return;
    while (ns != &initial_ns && !--ns->references) {
        struct linux64_pidns *parent = ns->parent;
        linux64_userns_release(ns->owner);
        pmm64_free(ns->physical);
        ns = parent;
    }
}

long linux64_pidns_create(struct linux64_pidns *parent, struct linux64_userns *owner,
                         struct linux64_pidns **result) {
    if (parent->level == PIDNS_MAX_DEPTH || !next_inode) return -ENOSPC;
    uptr physical = pmm64_alloc();
    if (!physical) return -ENOMEM;
    struct linux64_pidns *ns = pmm64_pointer(physical);
    *ns = (struct linux64_pidns){
        .parent = parent, .owner = owner, .physical = physical, .inode = next_inode++,
        .level = parent->level + 1, .references = 1, .next = 1,
    };
    linux64_pidns_retain(parent);
    linux64_userns_retain(owner);
    *result = ns;
    return 0;
}

u64 linux64_pidns_inode(const struct linux64_pidns *ns) {
    return ns->inode;
}

long linux64_pidns_readlink(const struct linux64_pidns *ns, uptr destination, uptr size) {
    char name[26] = "pid:[";
    char digits[20];
    u64 inode = ns->inode;
    unsigned count = 0;
    do {
        digits[count++] = (char)('0' + inode % 10);
        inode /= 10;
    } while (inode);
    unsigned length = 5;
    while (count) name[length++] = digits[--count];
    name[length++] = ']';
    if (size > length) size = length;
    return paging64_copy_to_user(destination, name, size) == size ? (long)size : -EFAULT;
}

i32 linux64_pidns_reaper(const struct linux64_pidns *ns) {
    return ns->reaper;
}

void linux64_pidns_set_reaper(struct linux64_pidns *ns, i32 pid) {
    ns->reaper = pid;
}

bool linux64_pidns_contains(const struct linux64_pidns *ns, const struct linux64_pidns *member) {
    while (member->level > ns->level) member = member->parent;
    return member == ns;
}

struct linux64_pid *linux64_pid_create(struct linux64_pidns *ns) {
    uptr physical = pmm64_alloc();
    if (!physical) return NULL;
    struct linux64_pid *pid = pmm64_pointer(physical);
    *pid = (struct linux64_pid){.ns = ns, .physical = physical, .references = 1};
    linux64_pidns_retain(ns);
    return pid;
}

struct linux64_pid *linux64_pid_init(void) {
    return &initial_pid;
}

void linux64_pid_retain(struct linux64_pid *pid) {
    if (pid && pid != &initial_pid) ++pid->references;
}

void linux64_pid_release(struct linux64_pid *pid) {
    if (!pid || pid == &initial_pid || --pid->references) return;
    linux64_pidns_release(pid->ns);
    pmm64_free(pid->physical);
}

i32 linux64_pid_number(const struct linux64_pid *pid, const struct linux64_pidns *ns) {
    return pid && linux64_pidns_contains(ns, pid->ns) ? pid->numbers[ns->level] : 0;
}

long linux64_pid_allocate(struct linux64_pidns *ns, i32 global, struct linux64_pid *pid) {
    for (struct linux64_pidns *level = ns; level->parent; level = level->parent)
        if (level->next == 0x7fffffff) return -ENOSPC;
    i32 local = ns->parent ? ns->next : global;
    if (pid) pid->numbers[0] = global;
    for (struct linux64_pidns *level = ns; level->parent; level = level->parent) {
        if (pid) pid->numbers[level->level] = level->next;
        ++level->next;
    }
    return local;
}
