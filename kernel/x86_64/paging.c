#include "paging.h"

#define PRESENT       (1ull << 0)
#define WRITE         (1ull << 1)
#define USER          (1ull << 2)
#define MMAP_OWNED    (1ull << 9)
#define MMAP_PENDING  (1ull << 10)
#define FILE_BACKED   (1ull << 11)
#define NO_EXECUTE    (1ull << 63)
#define ADDRESS_MASK  0x000ffffffffff000ull
#define CR0_WP        (1ul << 16)
#define EFER_MSR      0xc0000080u
#define EFER_NXE      (1u << 11)

extern const u8 _start[], __text_end[], __rodata_end[], __kernel_end[];

static bool nx_supported(void) {
    u32 eax = 0x80000000u, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (eax < 0x80000001u) return false;
    eax = 0x80000001u;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return (edx & (1u << 20)) != 0;
}

static bool map_entry(uptr root, uptr virtual, u64 value) {
    u64 *table = pmm64_pointer(root);
    u64 *entries[3];
    uptr created[3] = {0, 0, 0};
    unsigned depth = 0;
    for (int shift = 39; shift > 12; shift -= 9) {
        u64 *entry = &table[(virtual >> shift) & 511u];
        entries[depth] = entry;
        if (!(*entry & PRESENT)) {
            uptr child = pmm64_alloc();
            if (!child) goto fail;
            *entry = child | WRITE | PRESENT;
            created[depth] = child;
        }
        table = pmm64_pointer(*entry & ADDRESS_MASK);
        ++depth;
    }
    u64 *leaf = &table[(virtual >> 12) & 511u];
    if (*leaf) goto fail;
    *leaf = value;
    /* Верхние записи пропускают ring 3 только к листам с собственным флагом USER. */
    if (value & USER)
        for (unsigned i = 0; i < depth; ++i) *entries[i] |= USER;
    return true;

fail:
    while (depth) {
        --depth;
        if (!created[depth]) continue;
        *entries[depth] = 0;
        pmm64_free(created[depth]);
    }
    return false;
}

static bool map_page(uptr root, uptr virtual, uptr physical, u64 flags) {
    return map_entry(root, virtual, physical | flags | PRESENT);
}

static bool map_identity(uptr root, uptr start, uptr end, u64 flags) {
    for (uptr page = start; page < end; page += PMM_PAGE_SIZE)
        if (!map_page(root, page, page, flags)) return false;
    return true;
}

static bool map_ram(uptr root, const struct boot_info *boot) {
    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    u64 fb_start = boot->fb_phys;
    u64 fb_end = fb_start + (u64)boot->pitch * boot->height;
    for (u32 i = 0; i < boot->map_count; ++i) {
        if (map[i].type != 1 || !(map[i].attributes & 1u)) continue;
        u64 end = map[i].base + map[i].length;
        for (uptr page = (uptr)map[i].base; page < end; page += PMM_PAGE_SIZE) {
            if (page < 0x100000u ||
                (fb_start < fb_end && page < fb_end && fb_start < page + PMM_PAGE_SIZE))
                continue;
            /* Прямое отображение не должно давать запись в код и rodata. */
            bool readonly = page >= (uptr)_start && page < (uptr)__rodata_end;
            if (!map_page(root, X64_DIRECT_BASE + page, page,
                          NO_EXECUTE | (readonly ? 0 : WRITE))) return false;
        }
    }
    return true;
}

bool paging64_init(const struct boot_info *boot) {
    uptr previous;
    __asm__ volatile("mov %%cr3,%0" : "=r"(previous));
    if (!nx_supported()) return false;
    uptr root = pmm64_alloc();
    if (!root ||
        !map_identity(root, (uptr)_start, (uptr)__text_end, 0) ||
        !map_identity(root, (uptr)__text_end, (uptr)__rodata_end, NO_EXECUTE) ||
        !map_identity(root, (uptr)__rodata_end, (uptr)__kernel_end, WRITE | NO_EXECUTE) ||
        !map_identity(root, boot->arena_phys, (uptr)boot->arena_phys + boot->arena_bytes,
                      WRITE | NO_EXECUTE) ||
        !map_ram(root, boot))
        return false;

    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(EFER_MSR));
    __asm__ volatile("wrmsr" : : "a"(low | EFER_NXE), "d"(high), "c"(EFER_MSR) : "memory");
    uptr cr0, active;
    __asm__ volatile("mov %%cr0,%0" : "=r"(cr0));
    __asm__ volatile("mov %0,%%cr0" : : "r"(cr0 | CR0_WP) : "memory");
    __asm__ volatile("mov %0,%%cr3" : : "r"(root) : "memory");
    pmm64_use_direct_map();
    __asm__ volatile("mov %%cr3,%0" : "=r"(active));
    return active == root && active != previous;
}

static u64 *find_leaf_span(uptr root, uptr address, uptr *next) {
    u64 *table = pmm64_pointer(root);
    for (int shift = 39; shift > 12; shift -= 9) {
        u64 entry = table[(address >> shift) & 511u];
        if (!(entry & PRESENT)) {
            if (next) *next = (address | ((1ul << shift) - 1)) + 1;
            return NULL;
        }
        table = pmm64_pointer(entry & ADDRESS_MASK);
    }
    if (next) *next = address + PMM_PAGE_SIZE;
    return &table[(address >> 12) & 511u];
}

static u64 *find_leaf(uptr root, uptr address) {
    return find_leaf_span(root, address, NULL);
}

static void invalidate(uptr address) {
    __asm__ volatile("invlpg (%0)" : : "r"(address) : "memory");
}

static uptr active_root(void) {
    uptr root;
    __asm__ volatile("mov %%cr3,%0" : "=r"(root));
    return root & ADDRESS_MASK;
}

bool paging64_range_free(uptr start, uptr end) {
    return paging64_first_mapped(start, end) == end;
}

uptr paging64_first_mapped(uptr start, uptr end) {
    uptr root = active_root(), next;
    for (uptr address = start; address < end; address = next) {
        const u64 *leaf = find_leaf_span(root, address, &next);
        if (leaf && *leaf) return address;
    }
    return end;
}

static void prune_empty_tables(uptr root, uptr address) {
    u64 *parents[3];
    unsigned depth = 0;
    u64 *table = pmm64_pointer(root);
    for (int shift = 39; shift > 12; shift -= 9) {
        u64 *entry = &table[(address >> shift) & 511u];
        if (!(*entry & PRESENT)) break;
        parents[depth++] = entry;
        table = pmm64_pointer(*entry & ADDRESS_MASK);
    }
    while (depth) {
        for (unsigned i = 0; i < 512; ++i)
            if (table[i]) return;
        u64 *entry = parents[--depth];
        uptr physical = *entry & ADDRESS_MASK;
        *entry = 0;
        invalidate(address);
        pmm64_free(physical);
        table = (void *)((uptr)entry & ~(PMM_PAGE_SIZE - 1ul));
    }
}

static void set_alias_write(uptr root, uptr physical, bool writable) {
    uptr direct = (uptr)pmm64_pointer(physical);
    u64 *alias = find_leaf(root, direct);
    if (writable) *alias |= WRITE;
    else *alias &= ~WRITE;
    invalidate(direct);
}

static void clear_private(uptr root, uptr start, uptr end, u64 marker) {
    uptr next, last = 0;
    for (uptr address = start; address < end; address = next) {
        u64 *leaf = find_leaf_span(root, address, &next);
        if (!leaf || !(*leaf & marker)) continue;
        if (last && (last ^ address) >= 512 * PMM_PAGE_SIZE) prune_empty_tables(root, last);
        uptr physical = *leaf & ADDRESS_MASK;
        *leaf = 0;
        invalidate(address);
        if (physical) {
            set_alias_write(root, physical, true);
            pmm64_free(physical);
        }
        last = address;
    }
    if (last) prune_empty_tables(root, last);
}

bool paging64_remove_private(uptr start, uptr end) {
    uptr root = active_root(), next;
    for (uptr address = start; address < end; address = next) {
        const u64 *leaf = find_leaf_span(root, address, &next);
        if (leaf && *leaf && !(*leaf & MMAP_OWNED)) return false;
    }
    clear_private(root, start, end, MMAP_OWNED);
    return true;
}

bool paging64_protect(uptr start, uptr end, bool accessible, bool writable, bool executable,
                      uptr (*reserved_end)(uptr)) {
    if (start < 0x400000ul || end > X64_USER_TOP || start >= end ||
        ((start | end) & (PMM_PAGE_SIZE - 1)) || (writable && executable)) return false;
    uptr root = active_root(), next;
    bool needs_backing = false;
    for (uptr address = start; address < end; address = next) {
        next = address + PMM_PAGE_SIZE;
        const u64 *leaf = find_leaf(root, address);
        if (!leaf || !*leaf) {
            next = reserved_end(address);
            if (!next) return false;
            needs_backing = accessible;
        } else if (*leaf != MMAP_OWNED && !((*leaf & USER) && (*leaf & ADDRESS_MASK))) {
            return false;
        }
    }
    if (needs_backing) {
        for (uptr address = start; address < end; address += PMM_PAGE_SIZE) {
            const u64 *leaf = find_leaf(root, address);
            if (leaf && *leaf) continue;
            uptr physical = pmm64_alloc();
            if (physical && map_entry(root, address, physical | MMAP_PENDING | USER)) continue;
            if (physical) pmm64_free(physical);
            clear_private(root, start, address, MMAP_PENDING);
            return false;
        }
    }
    for (uptr address = start; address < end; address = next) {
        u64 *leaf = find_leaf_span(root, address, &next);
        if (!leaf) continue;
        uptr physical = *leaf & ADDRESS_MASK;
        /* Метка страницы за EOF сохраняет диапазон, но у неё нет данных. */
        if (!physical) continue;
        u64 value = (*leaf & ~(PRESENT | WRITE | NO_EXECUTE | MMAP_PENDING)) |
                    (accessible ? PRESENT : 0) | (writable ? WRITE : 0) |
                    (executable ? 0 : NO_EXECUTE);
        if (*leaf & MMAP_PENDING) value |= MMAP_OWNED;
        if (value == *leaf) continue;
        if (!writable) set_alias_write(root, physical, false);
        *leaf = value;
        invalidate(address);
        /* Старое исполняемое отображение уже недоступно через TLB. */
        if (writable) set_alias_write(root, physical, true);
    }
    return true;
}

/* Страницы и таблицы резервируются до замены старых отображений. */
bool paging64_map_private(uptr start, uptr end, const u8 *source, uptr file_bytes,
                          bool anonymous, bool accessible, bool writable, bool executable) {
    if (start < 0x400000ul || end > X64_USER_TOP || start >= end ||
        ((start | end) & (PMM_PAGE_SIZE - 1)) || (writable && executable) ||
        (file_bytes && !source) || file_bytes > end - start) return false;
    uptr root = active_root(), physical_list = 0, prepared = start;
    for (uptr address = start; address < end; address += PMM_PAGE_SIZE) {
        const u64 *leaf = find_leaf(root, address);
        if (leaf && *leaf && !(*leaf & MMAP_OWNED)) return false;
    }
    uptr backed = anonymous ? end - start : file_bytes;
    for (uptr offset = 0; offset < backed; offset += PMM_PAGE_SIZE) {
        uptr physical = pmm64_alloc();
        if (!physical) goto fail;
        *(uptr *)pmm64_pointer(physical) = physical_list;
        physical_list = physical;
    }
    for (; prepared < end; prepared += PMM_PAGE_SIZE) {
        const u64 *leaf = find_leaf(root, prepared);
        if ((!leaf || !*leaf) && !map_entry(root, prepared, MMAP_PENDING | USER)) goto fail;
    }

    for (uptr address = start; address < end; address += PMM_PAGE_SIZE) {
        u64 *leaf = find_leaf(root, address);
        uptr old = *leaf & ADDRESS_MASK;
        *leaf = MMAP_OWNED;
        invalidate(address);
        if (old) {
            set_alias_write(root, old, true);
            pmm64_free(old);
        }
        uptr offset = address - start;
        if (offset >= backed) continue;
        uptr physical = physical_list;
        u8 *target = pmm64_pointer(physical);
        physical_list = *(uptr *)target;
        *(uptr *)target = 0;
        if (offset < file_bytes) {
            uptr count = file_bytes - offset;
            if (count > PMM_PAGE_SIZE) count = PMM_PAGE_SIZE;
            for (uptr i = 0; i < count; ++i) target[i] = source[offset + i];
        }
        if (!writable) set_alias_write(root, physical, false);
        *leaf = physical | MMAP_OWNED | USER | (anonymous ? 0 : FILE_BACKED) |
                (accessible ? PRESENT : 0) |
                (writable ? WRITE : 0) | (executable ? 0 : NO_EXECUTE);
        invalidate(address);
    }
    return true;

fail:
    while (physical_list) {
        uptr physical = physical_list;
        physical_list = *(uptr *)pmm64_pointer(physical);
        pmm64_free(physical);
    }
    clear_private(root, start, prepared, MMAP_PENDING);
    return false;
}

static void *map_user_page(uptr address, const u8 *source, uptr offset, uptr length,
                           bool writable, bool executable) {
    if (address < 0x400000ul || address >= X64_USER_TOP ||
        (address & (PMM_PAGE_SIZE - 1)) || (writable && executable) ||
        offset >= PMM_PAGE_SIZE || length > PMM_PAGE_SIZE - offset || (length && !source))
        return NULL;
    uptr root = active_root();
    uptr page = pmm64_alloc();
    if (!page) return NULL;
    u8 *direct = pmm64_pointer(page);
    u64 *alias = NULL;
    for (uptr i = 0; i < length; ++i) direct[offset + i] = source[i];
    if (!writable) {
        alias = find_leaf(root, (uptr)direct);
        if (!alias || !(*alias & WRITE)) {
            pmm64_free(page);
            return NULL;
        }
        __asm__ volatile("" : : : "memory");
        /* Псевдоним страницы только для чтения тоже защищён от записи. */
        *alias &= ~WRITE;
        invalidate((uptr)direct);
    }
    if (!map_page(root, address, page, USER | (length ? FILE_BACKED : 0) | (writable ? WRITE : 0) |
                  (executable ? 0 : NO_EXECUTE))) {
        if (alias) {
            *alias |= WRITE;
            invalidate((uptr)direct);
        }
        pmm64_free(page);
        return NULL;
    }
    invalidate(address);
    return direct;
}

void *paging64_user_page(uptr address) {
    return map_user_page(address, NULL, 0, 0, true, false);
}

bool paging64_user_code(uptr address, const u8 *code, uptr length) {
    return code && length && paging64_user_load(address, code, 0, length, false, true);
}

bool paging64_user_load(uptr address, const u8 *source, uptr offset, uptr length,
                        bool writable, bool executable) {
    return map_user_page(address, source, offset, length, writable, executable) != NULL;
}

static u8 *user_pointer(uptr address, u64 required) {
    if (address < 0x400000ul || address >= X64_USER_TOP) return NULL;
    const u64 *table = pmm64_pointer(active_root());
    for (int shift = 39; shift >= 12; shift -= 9) {
        u64 entry = table[(address >> shift) & 511u];
        if ((entry & required) != required) return NULL;
        if (shift == 12)
            return pmm64_pointer((entry & ADDRESS_MASK) | (address & (PMM_PAGE_SIZE - 1)));
        table = pmm64_pointer(entry & ADDRESS_MASK);
    }
    return NULL;
}

const u8 *paging64_user_read(uptr address) {
    return user_pointer(address, PRESENT | USER);
}

uptr paging64_copy_from_user(void *destination, uptr address, uptr length) {
    u8 *target = destination;
    uptr copied = 0;
    while (copied < length) {
        uptr current = address + copied;
        const u8 *source = paging64_user_read(current);
        if (!source) break;
        uptr chunk = PMM_PAGE_SIZE - (current & (PMM_PAGE_SIZE - 1));
        if (chunk > length - copied) chunk = length - copied;
        for (uptr i = 0; i < chunk; ++i) target[copied + i] = source[i];
        copied += chunk;
    }
    return copied;
}

bool paging64_shared_futex_address(uptr address) {
    if (!paging64_user_read(address)) return false;
    return (*find_leaf(active_root(), address) & (WRITE | FILE_BACKED)) != 0;
}

uptr paging64_copy_to_user(uptr address, const void *source, uptr length) {
    const u8 *bytes = source;
    uptr copied = 0;
    while (copied < length) {
        uptr current = address + copied;
        u8 *target = user_pointer(current, PRESENT | USER | WRITE);
        if (!target) break;
        uptr chunk = PMM_PAGE_SIZE - (current & (PMM_PAGE_SIZE - 1));
        if (chunk > length - copied) chunk = length - copied;
        for (uptr i = 0; i < chunk; ++i) target[i] = bytes[copied + i];
        copied += chunk;
    }
    return copied;
}

bool paging64_put_user_u64(uptr address, u64 value) {
    const u64 required = PRESENT | USER | WRITE;
    if (!user_pointer(address, required) ||
        !user_pointer(address + sizeof(value) - 1, required)) return false;
    return paging64_copy_to_user(address, &value, sizeof(value)) == sizeof(value);
}
