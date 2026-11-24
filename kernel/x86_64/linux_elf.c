#include "linux.h"
#include "paging.h"
#include "segments.h"

#define USER_MIN        0x400000ul
#define STACK_TOP       0x00007ffffff00000ul
#define STACK_BOTTOM    (STACK_TOP - 4 * PMM_PAGE_SIZE)
#define STACK_GUARD     (STACK_BOTTOM - PMM_PAGE_SIZE)
#define PT_LOAD         1u
#define PT_DYNAMIC      2u
#define PT_INTERP       3u
#define PT_PHDR         6u
#define PT_GNU_STACK    0x6474e551u
#define PF_X            1u
#define PF_W            2u
#define PF_R            4u

struct elf_header {
    u8 ident[16];
    u16 type, machine;
    u32 version;
    u64 entry, phoff, shoff;
    u32 flags;
    u16 ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} __attribute__((packed));

struct elf_segment {
    u32 type, flags;
    u64 offset, address, physical, filesz, memsz, align;
} __attribute__((packed));

_Static_assert(sizeof(struct elf_header) == 64, "ELF64 file header");
_Static_assert(sizeof(struct elf_segment) == 56, "ELF64 program header");

static u64 floor_page(u64 address) {
    return address & ~(u64)(PMM_PAGE_SIZE - 1);
}

static u64 ceil_page(u64 address) {
    return floor_page(address + PMM_PAGE_SIZE - 1);
}

static bool valid_header(const struct elf_header *e, uptr size) {
    return size >= sizeof(*e) &&
           e->ident[0] == 0x7f && e->ident[1] == 'E' && e->ident[2] == 'L' &&
           e->ident[3] == 'F' && e->ident[4] == 2 && e->ident[5] == 1 &&
           e->ident[6] == 1 && (e->ident[7] == 0 || e->ident[7] == 3) &&
           e->type == 2 && e->machine == 62 && e->version == 1 &&
           e->ehsize == sizeof(*e) && e->phentsize == sizeof(struct elf_segment) &&
           e->phnum > 0 && e->phnum <= 64 && e->phoff <= size &&
           (u64)e->phnum * e->phentsize <= size - e->phoff;
}

static bool load_layout(const struct elf_header *e, const struct elf_segment *segments,
                        uptr size, u64 *phdr_address) {
    bool valid_entry = false;
    const struct elf_segment *phdr = NULL;
    u64 phdr_size = (u64)e->phnum * e->phentsize;
    u64 mapped = 0;
    for (unsigned i = 0; i < e->phnum; ++i) {
        const struct elf_segment *p = &segments[i];
        if (p->type == PT_INTERP || p->type == PT_DYNAMIC ||
            (p->type == PT_GNU_STACK && (p->flags & PF_X))) return false;
        if (p->type == PT_PHDR) {
            if (phdr) return false;
            phdr = p;
        }
        if (p->type != PT_LOAD) continue;
        if (p->filesz > p->memsz || p->offset > size || p->filesz > size - p->offset)
            return false;
        if (!p->memsz) continue;
        if (p->address < USER_MIN || p->address >= STACK_GUARD ||
            p->memsz > STACK_GUARD - p->address ||
            !(p->flags & PF_R) || (p->flags & (PF_W | PF_X)) == (PF_W | PF_X) ||
            (p->align && ((p->align & (p->align - 1)) ||
                          ((p->address ^ p->offset) & (p->align - 1)))) ||
            ((p->address ^ p->offset) & (PMM_PAGE_SIZE - 1)))
            return false;
        u64 first = floor_page(p->address), end = ceil_page(p->address + p->memsz);
        if (end - first > BOOT_MEMORY_LIMIT - mapped || !paging64_range_free(first, end))
            return false;
        mapped += end - first;

        for (unsigned j = 0; j < i; ++j) {
            const struct elf_segment *q = &segments[j];
            if (q->type == PT_LOAD && q->memsz &&
                floor_page(p->address) < ceil_page(q->address + q->memsz) &&
                floor_page(q->address) < ceil_page(p->address + p->memsz))
                return false;
        }
        if ((p->flags & PF_X) && e->entry >= p->address && e->entry - p->address < p->filesz)
            valid_entry = true;
        if (p->offset <= e->phoff && phdr_size <= p->filesz &&
            e->phoff - p->offset <= p->filesz - phdr_size)
            *phdr_address = p->address + e->phoff - p->offset;
    }
    return valid_entry && *phdr_address && paging64_range_free(STACK_GUARD, STACK_TOP) &&
           (!phdr || (phdr->address == *phdr_address && phdr->offset == e->phoff &&
                      phdr->filesz == phdr_size && phdr->memsz == phdr_size));
}

static bool map_load(const u8 *image, const struct elf_segment *p) {
    u64 file_end = p->address + p->filesz;
    for (u64 page = floor_page(p->address); page < p->address + p->memsz; page += PMM_PAGE_SIZE) {
        u64 first = page > p->address ? page : p->address;
        u64 end = page + PMM_PAGE_SIZE;
        if (end > file_end) end = file_end;
        uptr count = end > first ? end - first : 0;
        const u8 *source = count ? image + p->offset + (first - p->address) : NULL;
        if (!paging64_user_load(page, source, first - page, count,
                               (p->flags & PF_W) != 0, (p->flags & PF_X) != 0))
            return false;
    }
    return true;
}

static uptr make_stack(const struct elf_header *e, u64 phdr) {
    u8 *top_page = NULL;
    for (uptr page = STACK_BOTTOM; page < STACK_TOP; page += PMM_PAGE_SIZE) {
        top_page = paging64_user_page(page);
        if (!top_page) return 0;
    }
    static const char command[] = "linux-elf";
    const uptr command_address = STACK_TOP - sizeof(command);
    const u64 initial[] = {
        1, command_address, 0, 0,
        3, phdr, 4, e->phentsize, 5, e->phnum, 6, PMM_PAGE_SIZE,
        7, 0, 9, e->entry, 31, command_address, 0, 0,
    };
    uptr stack = (command_address - sizeof(initial)) & ~15ul;
    for (unsigned i = 0; i < sizeof(command); ++i)
        top_page[PMM_PAGE_SIZE - sizeof(command) + i] = (u8)command[i];
    u64 *words = (void *)(top_page + (stack & (PMM_PAGE_SIZE - 1)));
    for (unsigned i = 0; i < sizeof(initial) / sizeof(*initial); ++i) words[i] = initial[i];
    return stack;
}

bool linux64_run(const void *image, uptr size) {
    const struct elf_header *e = image;
    if (!valid_header(e, size)) return false;
    const struct elf_segment *segments = (const void *)((const u8 *)image + e->phoff);
    u64 phdr = 0;
    if (!load_layout(e, segments, size, &phdr)) return false;
    for (unsigned i = 0; i < e->phnum; ++i)
        if (segments[i].type == PT_LOAD && segments[i].memsz && !map_load(image, &segments[i]))
            return false;
    uptr stack = make_stack(e, phdr);
    if (!stack || !linux64_enable_syscall()) return false;
    segments64_enter_user(e->entry, stack);
}
