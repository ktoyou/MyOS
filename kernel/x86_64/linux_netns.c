#include "linux_task.h"
#include "paging.h"

enum { ENOMEM = 12, EFAULT = 14, ENOSPC = 28 };

struct linux64_netns {
    struct linux64_userns *owner;
    uptr physical;
    u64 inode;
    unsigned references;
};

static struct linux64_netns initial_ns = {.inode = 1ull << 36};
static u64 next_inode = (1ull << 36) + 1;

struct linux64_netns *linux64_netns_init(void) {
    return &initial_ns;
}

bool linux64_netns_is_initial(const struct linux64_netns *ns) {
    return ns == &initial_ns;
}

long linux64_netns_create(struct linux64_userns *owner, struct linux64_netns **result) {
    if (next_inode == (1ull << 37)) return -ENOSPC;
    uptr physical = pmm64_alloc();
    if (!physical) return -ENOMEM;
    struct linux64_netns *ns = pmm64_pointer(physical);
    *ns = (struct linux64_netns){
        .owner = owner, .physical = physical, .inode = next_inode++, .references = 1,
    };
    linux64_userns_retain(owner);
    *result = ns;
    return 0;
}

void linux64_netns_retain(struct linux64_netns *ns) {
    if (ns && !linux64_netns_is_initial(ns)) ++ns->references;
}

void linux64_netns_release(struct linux64_netns *ns) {
    if (!ns || linux64_netns_is_initial(ns) || --ns->references) return;
    linux64_userns_release(ns->owner);
    pmm64_free(ns->physical);
}

u64 linux64_netns_inode(const struct linux64_netns *ns) {
    return ns->inode;
}

long linux64_netns_readlink(const struct linux64_netns *ns, uptr destination, uptr size) {
    char name[26] = "net:[";
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
