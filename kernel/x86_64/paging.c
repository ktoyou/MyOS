#include "paging.h"
#include "framebuffer.h"

#define PRESENT       (1ull << 0)
#define WRITE         (1ull << 1)
#define USER          (1ull << 2)
#define WRITE_THROUGH (1ull << 3)
#define CACHE_DISABLE (1ull << 4)
#define LEAF_PAT      (1ull << 7)
#define MMAP_OWNED    (1ull << 9)
#define MMAP_PENDING  (1ull << 10)
#define FILE_BACKED   (1ull << 11)
/* Эти биты доступны ПО в листе x86-64 и не входят в физический адрес. */
#define DATA_MAPPING  (1ull << 54)
#define LIVE_ELF      (1ull << 55)
#define ZERO_LAZY     (1ull << 56)
#define MMAP_NO_WRITE (1ull << 57)
#define MMAP_SHARED_FRAME (1ull << 58)
#define NO_EXECUTE    (1ull << 63)
#define ADDRESS_MASK  0x000ffffffffff000ull
#define CR0_WP        (1ul << 16)
#define EFER_MSR      0xc0000080u
#define EFER_NXE      (1u << 11)
#define PAT_MSR       0x277u

extern const u8 _start[], __text_end[], __rodata_end[], __kernel_end[];
static uptr live_first, live_end;

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

static bool map_ram(uptr root, const struct boot_info *boot, const struct gop64_framebuffer *fb) {
    const struct boot_region *map = (const void *)(uptr)boot->map_phys;
    uptr fb_end = fb->physical + fb->page_bytes;
    for (u32 i = 0; i < boot->map_count; ++i) {
        if (map[i].type != 1 || !(map[i].attributes & 1u)) continue;
        u64 end = map[i].base + map[i].length;
        for (uptr page = (uptr)map[i].base; page < end; page += PMM_PAGE_SIZE) {
            if (page < 0x100000u || (page >= fb->physical && page < fb_end))
                continue;
            /* Прямое отображение не должно давать запись в код и rodata. */
            bool readonly = (page >= (uptr)_start && page < (uptr)__rodata_end) ||
                            (page >= live_first && page < live_end);
            if (!map_page(root, X64_DIRECT_BASE + page, page,
                          NO_EXECUTE | (readonly ? 0 : WRITE))) return false;
        }
    }
    return true;
}

static bool uncached_flags(u64 *flags) {
    u32 eax = 1, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (!(edx & (1u << 16))) {
        *flags = CACHE_DISABLE | WRITE_THROUGH;
        return true;
    }
    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(PAT_MSR));
    u64 pat = ((u64)high << 32) | low;
    for (unsigned index = 0; index < 8; ++index) {
        if ((pat >> (index * 8)) & 0xff) continue;
        *flags = (index & 1 ? WRITE_THROUGH : 0) | (index & 2 ? CACHE_DISABLE : 0) |
                 (index & 4 ? LEAF_PAT : 0);
        return true;
    }
    return false;
}

static bool map_framebuffer(uptr root, const struct gop64_framebuffer *fb) {
    u64 flags;
    if (!uncached_flags(&flags)) return false;
    for (uptr offset = 0; offset < fb->page_bytes; offset += PMM_PAGE_SIZE) {
        if (!map_page(root, X64_FRAMEBUFFER_BASE + offset, fb->physical + offset,
                      flags | WRITE | NO_EXECUTE)) return false;
    }
    return true;
}

bool paging64_init(const struct boot_info *boot, const struct gop64_framebuffer *fb) {
    uptr previous;
    __asm__ volatile("mov %%cr3,%0" : "=r"(previous));
    if (!nx_supported()) return false;
    if (boot->root_phys && boot->root_phys < BOOT_MEMORY_LIMIT &&
        boot->root_bytes <= BOOT_MEMORY_LIMIT - boot->root_phys) {
        live_first = boot->root_phys;
        live_end = live_first + boot->root_bytes;
    }
    uptr root = pmm64_alloc();
    if (!root ||
        !map_identity(root, (uptr)_start, (uptr)__text_end, 0) ||
        !map_identity(root, (uptr)__text_end, (uptr)__rodata_end, NO_EXECUTE) ||
        !map_identity(root, (uptr)__rodata_end, (uptr)__kernel_end, WRITE | NO_EXECUTE) ||
        !map_identity(root, boot->arena_phys, (uptr)boot->arena_phys + boot->arena_bytes,
                      WRITE | NO_EXECUTE) ||
        !map_ram(root, boot, fb) || !map_framebuffer(root, fb))
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

uptr paging64_active_root(void) {
    uptr root;
    __asm__ volatile("mov %%cr3,%0" : "=r"(root));
    return root & ADDRESS_MASK;
}

void paging64_switch_root(uptr root) {
    __asm__ volatile("mov %0,%%cr3" : : "r"(root) : "memory");
}

bool paging64_range_free(uptr start, uptr end) {
    return paging64_first_mapped(start, end) == end;
}

uptr paging64_first_mapped(uptr start, uptr end) {
    uptr root = paging64_active_root(), next;
    for (uptr address = start; address < end; address = next) {
        const u64 *leaf = find_leaf_span(root, address, &next);
        if (leaf && *leaf) return address;
    }
    return end;
}

uptr paging64_data_bytes(uptr start, uptr end) {
    uptr root = paging64_active_root(), next, bytes = 0;
    for (uptr address = start; address < end; address = next) {
        const u64 *leaf = find_leaf_span(root, address, &next);
        if (leaf && (*leaf & (DATA_MAPPING | WRITE)) == (DATA_MAPPING | WRITE))
            bytes += PMM_PAGE_SIZE;
    }
    return bytes;
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

static bool materialize_zero(uptr root, uptr address, u64 *leaf, bool write, bool execute) {
    const u64 value = *leaf;
    if (!(value & ZERO_LAZY) || !(value & USER) || (write && !(value & WRITE)) ||
        (execute && (value & NO_EXECUTE))) return false;
    uptr physical = pmm64_alloc();
    if (!physical) return false;
    if (!(value & WRITE)) set_alias_write(root, physical, false);
    *leaf = physical | (value & ~ZERO_LAZY) | PRESENT;
    invalidate(address);
    return true;
}

bool paging64_zero_fault(uptr address, u64 error) {
    const u64 write = 1u << 1, user = 1u << 2, instruction = 1u << 4;
    if (!(error & user) || (error & ~(write | user | instruction)) || address >= X64_USER_TOP)
        return false;
    uptr root = paging64_active_root();
    u64 *leaf = find_leaf(root, address);
    return leaf && materialize_zero(root, address, leaf, (error & write) != 0,
                                    (error & instruction) != 0);
}

static void release_mapping(uptr root, u64 value) {
    uptr physical = value & ADDRESS_MASK;
    if (!physical || (value & LIVE_ELF)) return;
    if (!(value & MMAP_SHARED_FRAME) && !pmm64_has_aliases(physical))
        set_alias_write(root, physical, true);
    pmm64_free(physical);
}

static void copy_page(uptr target, uptr source) {
    u64 *to = pmm64_pointer(target);
    const u64 *from = pmm64_pointer(source);
    for (unsigned i = 0; i < PMM_PAGE_SIZE / sizeof(*to); ++i) to[i] = from[i];
}

static bool needs_private_copy(u64 entry) {
    return !(entry & MMAP_SHARED_FRAME) && (entry & ADDRESS_MASK) &&
           ((entry & LIVE_ELF) || pmm64_has_aliases(entry & ADDRESS_MASK));
}

static void drop_lower_table(uptr root, uptr physical, unsigned level, unsigned entries) {
    const u64 *table = pmm64_pointer(physical);
    for (unsigned i = 0; i < entries; ++i) {
        u64 entry = table[i];
        if (level) {
            if (entry & PRESENT) drop_lower_table(root, entry & ADDRESS_MASK, level - 1, 512);
        } else if (entry & USER) {
            release_mapping(root, entry);
        }
    }
    pmm64_free(physical);
}

void paging64_drop_root(uptr root) {
    drop_lower_table(paging64_active_root(), root, 3, 256);
}

static bool clone_lower_table(uptr target, uptr source, unsigned level, unsigned entries) {
    u64 *to = pmm64_pointer(target);
    const u64 *from = pmm64_pointer(source);
    for (unsigned i = 0; i < entries; ++i) {
        u64 entry = from[i];
        uptr physical = entry & ADDRESS_MASK;
        if (level) {
            if (!(entry & PRESENT)) continue;
            uptr child = pmm64_alloc();
            if (!child) return false;
            to[i] = child | (entry & ~ADDRESS_MASK);
            if (!clone_lower_table(child, physical, level - 1, 512)) return false;
        } else if ((entry & USER) && physical && !(entry & LIVE_ELF)) {
            if ((entry & WRITE) && !(entry & MMAP_SHARED_FRAME)) {
                uptr copy = pmm64_alloc();
                if (!copy) return false;
                copy_page(copy, physical);
                to[i] = copy | (entry & ~ADDRESS_MASK);
            } else {
                if (!pmm64_retain(physical)) return false;
                to[i] = entry;
            }
        } else {
            to[i] = entry;
        }
    }
    return true;
}

uptr paging64_fork_root(void) {
    uptr parent = paging64_active_root(), child = pmm64_alloc();
    if (!child) return 0;
    if (!clone_lower_table(child, parent, 3, 256)) {
        paging64_drop_root(child);
        return 0;
    }
    /* Прямое отображение общее, включая изменения защиты физических страниц. */
    u64 *to = pmm64_pointer(child);
    const u64 *from = pmm64_pointer(parent);
    for (unsigned i = 256; i < 512; ++i) to[i] = from[i];
    return child;
}

static bool copy_supervisor_mappings(uptr target, uptr source, unsigned shift, unsigned entries,
                                     uptr base) {
    const u64 *table = pmm64_pointer(source);
    for (unsigned i = 0; i < entries; ++i) {
        u64 entry = table[i];
        if (!(entry & PRESENT)) continue;
        uptr address = base | ((uptr)i << shift);
        if (shift > 12) {
            if (!copy_supervisor_mappings(target, entry & ADDRESS_MASK, shift - 9, 512, address))
                return false;
        } else if (!(entry & USER) && !map_entry(target, address, entry)) {
            return false;
        }
    }
    return true;
}

uptr paging64_exec_root(void) {
    uptr previous = paging64_active_root(), root = pmm64_alloc();
    if (!root) return 0;
    if (!copy_supervisor_mappings(root, previous, 39, 256, 0)) {
        paging64_drop_root(root);
        return 0;
    }
    u64 *to = pmm64_pointer(root);
    const u64 *from = pmm64_pointer(previous);
    for (unsigned i = 256; i < 512; ++i) to[i] = from[i];
    return root;
}

static void clear_mappings(uptr root, uptr start, uptr end, u64 marker) {
    uptr next, last = 0;
    for (uptr address = start; address < end; address = next) {
        u64 *leaf = find_leaf_span(root, address, &next);
        if (!leaf || !(*leaf & marker)) continue;
        if (last && (last ^ address) >= 512 * PMM_PAGE_SIZE) prune_empty_tables(root, last);
        u64 old = *leaf;
        *leaf = 0;
        invalidate(address);
        release_mapping(root, old);
        last = address;
    }
    if (last) prune_empty_tables(root, last);
}

bool paging64_reserve_stack(uptr start, uptr end) {
    if (start < 0x400000ul || start > end || end > X64_USER_TOP ||
        ((start | end) & (PMM_PAGE_SIZE - 1))) return false;
    uptr root = paging64_active_root();
    for (uptr address = start; address < end; address += PMM_PAGE_SIZE) {
        if (map_entry(root, address, ZERO_LAZY | USER | WRITE | NO_EXECUTE)) continue;
        clear_mappings(root, start, address, ZERO_LAZY);
        return false;
    }
    return true;
}

bool paging64_remove_mmap(uptr start, uptr end) {
    uptr root = paging64_active_root(), next;
    for (uptr address = start; address < end; address = next) {
        const u64 *leaf = find_leaf_span(root, address, &next);
        if (leaf && *leaf && !(*leaf & MMAP_OWNED)) return false;
    }
    clear_mappings(root, start, end, MMAP_OWNED);
    return true;
}

enum paging64_discard_result paging64_discard_anon(uptr start, uptr end, uptr (*reserved_end)(uptr)) {
    uptr root = paging64_active_root(), next;
    enum paging64_discard_result result = PAGING64_DISCARD_OK;
    for (uptr address = start; address < end; address = next) {
        const u64 *leaf = find_leaf_span(root, address, &next);
        u64 value = leaf ? *leaf : 0;
        if (!value || !(value & (USER | MMAP_OWNED | ZERO_LAZY))) {
            uptr reserved = reserved_end(address);
            if (reserved) next = reserved;
            else result = PAGING64_DISCARD_HOLE;
            continue;
        }
        /* Без источника файловых страниц нельзя восстановить их содержимое. */
        if (!(value & MMAP_OWNED) || (value & (FILE_BACKED | MMAP_SHARED_FRAME | MMAP_NO_WRITE)) ||
            !(value & (ADDRESS_MASK | ZERO_LAZY))) return PAGING64_DISCARD_UNSUPPORTED;
    }
    for (uptr address = start; address < end; address = next) {
        u64 *leaf = find_leaf_span(root, address, &next);
        if (!leaf || !(*leaf & MMAP_OWNED) || !(*leaf & ADDRESS_MASK)) continue;
        u64 old = *leaf;
        /* Отбрасываем ссылку, не меняя данные чужого отображения после fork. */
        *leaf = MMAP_OWNED | ZERO_LAZY | (old & (DATA_MAPPING | WRITE | NO_EXECUTE)) |
                (old & PRESENT ? USER : 0);
        invalidate(address);
        release_mapping(root, old);
    }
    return result;
}

enum paging64_protect_result paging64_protect(uptr start, uptr end, bool accessible,
                                             bool writable, bool executable,
                                             uptr (*reserved_end)(uptr), uptr *data_bytes, u64 data_limit) {
    if (start < 0x400000ul || end > X64_USER_TOP || start >= end ||
        ((start | end) & (PMM_PAGE_SIZE - 1))) return PAGING64_PROTECT_UNMAPPED;
    if (writable && executable) return PAGING64_PROTECT_DENIED;
    uptr root = paging64_active_root(), next;
    uptr usage = *data_bytes;
    bool needs_backing = false;
    for (uptr address = start; address < end; address = next) {
        next = address + PMM_PAGE_SIZE;
        const u64 *leaf = find_leaf(root, address);
        if (!leaf || !*leaf) {
            next = reserved_end(address);
            if (!next) return PAGING64_PROTECT_UNMAPPED;
            if (writable) usage += (next < end ? next : end) - address;
            needs_backing = accessible;
            continue;
        }
        if (!(*leaf & ZERO_LAZY) &&
            (*leaf & ~(DATA_MAPPING | WRITE | MMAP_NO_WRITE | MMAP_SHARED_FRAME)) != MMAP_OWNED &&
            !((*leaf & USER) && (*leaf & ADDRESS_MASK)))
            return PAGING64_PROTECT_UNMAPPED;
        if (writable && (*leaf & MMAP_NO_WRITE)) return PAGING64_PROTECT_DENIED;
        if (executable && (*leaf & MMAP_SHARED_FRAME)) return PAGING64_PROTECT_DENIED;
        if (*leaf & DATA_MAPPING) {
            if (*leaf & WRITE) usage -= PMM_PAGE_SIZE;
            if (writable) usage += PMM_PAGE_SIZE;
        }
    }
    if (usage > *data_bytes && usage > data_limit) return PAGING64_PROTECT_UNMAPPED;
    if (needs_backing) {
        for (uptr address = start; address < end; address += PMM_PAGE_SIZE) {
            const u64 *leaf = find_leaf(root, address);
            if (leaf && *leaf) continue;
            uptr physical = pmm64_alloc();
            if (physical && map_entry(root, address, physical | MMAP_PENDING | USER | DATA_MAPPING)) continue;
            if (physical) pmm64_free(physical);
            clear_mappings(root, start, address, MMAP_PENDING);
            return PAGING64_PROTECT_UNMAPPED;
        }
    }
    uptr copies = 0;
    if (writable) {
        for (uptr address = start; address < end; address = next) {
            const u64 *leaf = find_leaf_span(root, address, &next);
            if (!leaf || !needs_private_copy(*leaf)) continue;
            uptr physical = pmm64_alloc();
            if (!physical) goto fail_copies;
            *(uptr *)pmm64_pointer(physical) = copies;
            copies = physical;
        }
    }
    for (uptr address = start; address < end; address = next) {
        u64 *leaf = find_leaf_span(root, address, &next);
        if (!leaf) continue;
        if (*leaf & ZERO_LAZY) {
            /* Для отсутствующей страницы USER хранит разрешение доступа до выделения. */
            *leaf = (*leaf & ~(USER | WRITE | NO_EXECUTE)) |
                    (accessible ? USER : 0) | (writable ? WRITE : 0) |
                    (executable ? 0 : NO_EXECUTE);
            continue;
        }
        uptr physical = *leaf & ADDRESS_MASK;
        /* Метка страницы за EOF сохраняет диапазон, но у неё нет данных. */
        if (!physical) {
            *leaf = (*leaf & ~WRITE) | (writable ? WRITE : 0);
            continue;
        }
        u64 value = (*leaf & ~(PRESENT | WRITE | NO_EXECUTE | MMAP_PENDING)) |
                    (accessible ? PRESENT : 0) | (writable ? WRITE : 0) |
                    (executable ? 0 : NO_EXECUTE);
        if (*leaf & MMAP_PENDING) value |= MMAP_OWNED;
        if (writable && needs_private_copy(*leaf)) {
            u64 old = *leaf;
            uptr copy = copies;
            copies = *(uptr *)pmm64_pointer(copy);
            copy_page(copy, physical);
            *leaf = (value & ~(ADDRESS_MASK | LIVE_ELF)) | copy;
            invalidate(address);
            release_mapping(root, old);
            continue;
        }
        if (value == *leaf) continue;
        bool fixed_alias = (*leaf & (MMAP_SHARED_FRAME | LIVE_ELF)) != 0;
        if (!fixed_alias && !writable) set_alias_write(root, physical, false);
        *leaf = value;
        invalidate(address);
        /* Старое исполняемое отображение уже недоступно через TLB. */
        if (!fixed_alias && writable) set_alias_write(root, physical, true);
    }
    *data_bytes = usage;
    return PAGING64_PROTECT_OK;

fail_copies:
    while (copies) {
        uptr physical = copies;
        copies = *(uptr *)pmm64_pointer(physical);
        pmm64_free(physical);
    }
    if (needs_backing) clear_mappings(root, start, end, MMAP_PENDING);
    return PAGING64_PROTECT_UNMAPPED;
}

/* Страницы и таблицы резервируются до замены старых отображений. */
bool paging64_map_mmap(uptr start, uptr end, const struct paging64_mmap_file *file,
                       bool accessible, bool writable, bool executable,
                       bool shared, bool no_write) {
    bool shared_frames = shared && file && file->frame;
    if (start < 0x400000ul || end > X64_USER_TOP || start >= end ||
        ((start | end) & (PMM_PAGE_SIZE - 1)) || (writable && executable) ||
        (no_write && writable) || (shared_frames && executable) ||
        (file && (file->length > end - start || (file->length && !file->bytes && !file->frame))))
        return false;
    uptr root = paging64_active_root(), physical_list = 0, prepared = start;
    uptr retained = 0;
    const u64 owner = MMAP_OWNED | (no_write ? MMAP_NO_WRITE : 0) |
                      (shared ? 0 : DATA_MAPPING) |
                      (shared_frames ? MMAP_SHARED_FRAME : 0);
    for (uptr address = start; address < end; address += PMM_PAGE_SIZE) {
        const u64 *leaf = find_leaf(root, address);
        if (leaf && *leaf && !(*leaf & MMAP_OWNED)) return false;
    }
    uptr backed = file ? file->length : end - start;
    for (uptr offset = 0; offset < backed; offset += PMM_PAGE_SIZE) {
        if (shared_frames) {
            if (!pmm64_retain(file->frame(file->object, file->offset + offset))) goto fail;
            retained += PMM_PAGE_SIZE;
            continue;
        }
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
        u64 old = *leaf;
        *leaf = owner | (writable ? WRITE : 0);
        invalidate(address);
        release_mapping(root, old);
        uptr offset = address - start;
        if (offset >= backed) continue;
        uptr physical;
        if (shared_frames) {
            /* Прямой алиас остаётся RW+NX для объекта и всех его отображений. */
            physical = file->frame(file->object, file->offset + offset);
        } else {
            physical = physical_list;
            u8 *target = pmm64_pointer(physical);
            physical_list = *(uptr *)target;
            *(uptr *)target = 0;
            if (file) {
                const u8 *source = file->frame
                    ? pmm64_pointer(file->frame(file->object, file->offset + offset))
                    : file->bytes + offset;
                uptr count = backed - offset;
                if (count > PMM_PAGE_SIZE) count = PMM_PAGE_SIZE;
                for (uptr i = 0; i < count; ++i) target[i] = source[i];
            }
            if (!writable) set_alias_write(root, physical, false);
        }
        *leaf = physical | owner | USER | (file ? FILE_BACKED : 0) |
                (accessible ? PRESENT : 0) |
                (writable ? WRITE : 0) | (executable ? 0 : NO_EXECUTE);
        invalidate(address);
    }
    return true;

fail:
    for (uptr offset = 0; offset < retained; offset += PMM_PAGE_SIZE)
        pmm64_free(file->frame(file->object, file->offset + offset));
    while (physical_list) {
        uptr physical = physical_list;
        physical_list = *(uptr *)pmm64_pointer(physical);
        pmm64_free(physical);
    }
    clear_mappings(root, start, prepared, MMAP_PENDING);
    return false;
}

static void *map_user_page(uptr address, const u8 *source, uptr offset, uptr length,
                           bool writable, bool executable, u64 software_flags) {
    if (address < 0x400000ul || address >= X64_USER_TOP ||
        (address & (PMM_PAGE_SIZE - 1)) || (writable && executable) ||
        offset >= PMM_PAGE_SIZE || length > PMM_PAGE_SIZE - offset || (length && !source))
        return NULL;
    uptr root = paging64_active_root();
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
    if (!map_page(root, address, page, USER | software_flags | (length ? FILE_BACKED : 0) | (writable ? WRITE : 0) |
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
    return map_user_page(address, NULL, 0, 0, true, false, 0);
}

bool paging64_user_code(uptr address, const u8 *code, uptr length) {
    return code && length && paging64_user_load(address, code, 0, length, false, true);
}

bool paging64_user_load(uptr address, const u8 *source, uptr offset, uptr length,
                        bool writable, bool executable) {
    return map_user_page(address, source, offset, length, writable, executable, DATA_MAPPING) != NULL;
}

bool paging64_user_live_elf(uptr address, const u8 *source, bool executable) {
    uptr direct = (uptr)source;
    if (address < 0x400000ul || address >= X64_USER_TOP || direct < X64_DIRECT_BASE ||
        ((address | direct) & (PMM_PAGE_SIZE - 1))) return false;
    uptr physical = direct - X64_DIRECT_BASE;
    if (physical < live_first || physical >= live_end || live_end - physical < PMM_PAGE_SIZE)
        return false;
    uptr root = paging64_active_root();
    const u64 *alias = find_leaf(root, direct);
    if (!alias || (*alias & (ADDRESS_MASK | PRESENT | WRITE | USER | NO_EXECUTE)) !=
                  (physical | PRESENT | NO_EXECUTE)) return false;
    if (!map_page(root, address, physical, USER | FILE_BACKED | LIVE_ELF | DATA_MAPPING |
                  (executable ? 0 : NO_EXECUTE))) return false;
    invalidate(address);
    return true;
}

static u8 *user_pointer(uptr address, u64 required) {
    if (address < 0x400000ul || address >= X64_USER_TOP) return NULL;
    uptr root = paging64_active_root();
    u64 *table = pmm64_pointer(root);
    for (int shift = 39; shift >= 12; shift -= 9) {
        u64 *slot = &table[(address >> shift) & 511u];
        if (shift == 12 && (*slot & ZERO_LAZY))
            materialize_zero(root, address, slot, (required & WRITE) != 0, false);
        u64 entry = *slot;
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
    return (*find_leaf(paging64_active_root(), address) & (WRITE | FILE_BACKED)) != 0;
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

static bool put_user_scalar(uptr address, const void *value, uptr size) {
    const u64 required = PRESENT | USER | WRITE;
    /* Ошибка на границе страниц не должна оставлять часть значения. */
    if (!user_pointer(address, required) ||
        !user_pointer(address + size - 1, required)) return false;
    return paging64_copy_to_user(address, value, size) == size;
}

bool paging64_put_user_u16(uptr address, u16 value) {
    return put_user_scalar(address, &value, sizeof(value));
}

bool paging64_put_user_u32(uptr address, u32 value) {
    return put_user_scalar(address, &value, sizeof(value));
}

bool paging64_put_user_u64(uptr address, u64 value) {
    return put_user_scalar(address, &value, sizeof(value));
}
