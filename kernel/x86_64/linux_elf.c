#include "linux.h"
#include "paging.h"
#include "segments.h"

#define USER_MIN        0x400000ul
#define STACK_TOP       0x00007ffffff00000ul
#define STACK_BOTTOM    (STACK_TOP - 4 * PMM_PAGE_SIZE)
#define STACK_GUARD     (STACK_BOTTOM - PMM_PAGE_SIZE)
#define PROGRAM_BIAS    0x100000000ul
#define INTERP_BIAS     0x200000000ul
#define ET_EXEC         2u
#define ET_DYN          3u
#define PT_LOAD         1u
#define PT_DYNAMIC      2u
#define PT_INTERP       3u
#define PT_PHDR         6u
#define PT_GNU_STACK    0x6474e551u
#define PF_X            1u
#define PF_W            2u
#define PF_R            4u
#define AT_RANDOM       25u

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

struct elf_image {
    const struct elf_header *header;
    const struct elf_segment *segments;
    const char *interp;
    u64 bias, entry, phdr, first, end;
};

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
           (e->type == ET_EXEC || e->type == ET_DYN) && e->machine == 62 && e->version == 1 &&
           e->ehsize == sizeof(*e) && e->phentsize == sizeof(struct elf_segment) &&
           e->phnum > 0 && e->phnum <= 64 && e->phoff <= size &&
           (u64)e->phnum * e->phentsize <= size - e->phoff;
}

static const char *interp_path(const struct elf_header *e, const struct elf_segment *p,
                               uptr size) {
    if (p->filesz < 2 || p->filesz > 4096 || p->offset > size || p->filesz > size - p->offset)
        return NULL;
    const char *path = (const char *)e + p->offset;
    if (path[0] != '/' || path[p->filesz - 1]) return NULL;
    for (u64 i = 1; i < p->filesz - 1; ++i)
        if (!path[i]) return NULL;
    return path;
}

static bool load_layout(struct elf_image *elf, const void *image, uptr size,
                        bool interpreter, u64 *mapped) {
    const struct elf_header *e = image;
    if (!valid_header(e, size)) return false;
    const struct elf_segment *segments = (const void *)((const u8 *)image + e->phoff);
    u64 bias = e->type == ET_DYN ? (interpreter ? INTERP_BIAS : PROGRAM_BIAS) : 0;
    *elf = (struct elf_image){.header = e, .segments = segments, .bias = bias,
                              .first = STACK_GUARD};
    bool valid_entry = false;
    bool dynamic = false;
    const struct elf_segment *phdr = NULL;
    u64 phdr_size = (u64)e->phnum * e->phentsize;
    for (unsigned i = 0; i < e->phnum; ++i) {
        const struct elf_segment *p = &segments[i];
        if (p->type == PT_INTERP) {
            if (interpreter || elf->interp || elf->end) return false;
            elf->interp = interp_path(e, p, size);
            if (!elf->interp) return false;
        }
        if (p->type == PT_DYNAMIC) dynamic = true;
        if (p->type == PT_GNU_STACK && (p->flags & PF_X)) return false;
        if (p->type == PT_PHDR) {
            if (phdr) return false;
            phdr = p;
        }
        if (p->type != PT_LOAD) continue;
        if (p->filesz > p->memsz || p->offset > size || p->filesz > size - p->offset)
            return false;
        if (!p->memsz) continue;
        if (p->address >= STACK_GUARD - bias) return false;
        u64 address = bias + p->address;
        if (address < USER_MIN || p->memsz > STACK_GUARD - address ||
            !(p->flags & PF_R) || (p->flags & (PF_W | PF_X)) == (PF_W | PF_X) ||
            (p->align && ((p->align & (p->align - 1)) ||
                          ((address ^ p->offset) & (p->align - 1)))) ||
            ((p->address ^ p->offset) & (PMM_PAGE_SIZE - 1)))
            return false;
        u64 first = floor_page(address), end = ceil_page(address + p->memsz);
        if (end - first > BOOT_MEMORY_LIMIT - *mapped || !paging64_range_free(first, end))
            return false;
        *mapped += end - first;
        if (first < elf->first) elf->first = first;
        if (end > elf->end) elf->end = end;

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
            elf->phdr = address + (e->phoff - p->offset);
    }
    if (!valid_entry || (!interpreter && !elf->interp && (dynamic || e->type == ET_DYN)))
        return false;
    elf->entry = bias + e->entry;
    return (interpreter || elf->phdr) &&
           (!phdr || (elf->phdr && phdr->address == elf->phdr - bias && phdr->offset == e->phoff &&
                      phdr->filesz == phdr_size && phdr->memsz == phdr_size));
}

static bool map_load(const u8 *image, const struct elf_segment *p, u64 bias) {
    u64 address = bias + p->address;
    u64 file_end = address + p->filesz;
    for (u64 page = floor_page(address); page < address + p->memsz; page += PMM_PAGE_SIZE) {
        u64 first = page > address ? page : address;
        u64 end = page + PMM_PAGE_SIZE;
        if (end > file_end) end = file_end;
        uptr count = end > first ? end - first : 0;
        const u8 *source = count ? image + p->offset + (first - address) : NULL;
        if (!paging64_user_load(page, source, first - page, count,
                               (p->flags & PF_W) != 0, (p->flags & PF_X) != 0))
            return false;
    }
    return true;
}

static bool map_image(const struct elf_image *elf) {
    for (unsigned i = 0; i < elf->header->phnum; ++i) {
        const struct elf_segment *p = &elf->segments[i];
        if (p->type == PT_LOAD && p->memsz && !map_load((const u8 *)elf->header, p, elf->bias))
            return false;
    }
    return true;
}

static uptr make_stack(const struct elf_image *main, u64 interp_bias, const u64 entropy[2]) {
    u8 *top_page = NULL;
    for (uptr page = STACK_BOTTOM; page < STACK_TOP; page += PMM_PAGE_SIZE) {
        top_page = paging64_user_page(page);
        if (!top_page) return 0;
    }
    static const char command[] = "linux-elf";
    const uptr command_address = STACK_TOP - sizeof(command);
    const uptr random_address = (command_address - 2 * sizeof(u64)) & ~7ul;
    const u64 initial[] = {
        1, command_address, 0, 0,
        3, main->phdr, 4, main->header->phentsize, 5, main->header->phnum, 6, PMM_PAGE_SIZE,
        7, interp_bias, 9, main->entry, AT_RANDOM, random_address, 31, command_address, 0, 0,
    };
    uptr stack = (random_address - sizeof(initial)) & ~15ul;
    for (unsigned i = 0; i < sizeof(command); ++i)
        top_page[PMM_PAGE_SIZE - sizeof(command) + i] = (u8)command[i];
    u64 *random_bytes = (void *)(top_page + (random_address & (PMM_PAGE_SIZE - 1)));
    for (unsigned i = 0; i < 2; ++i) random_bytes[i] = entropy[i];
    u64 *words = (void *)(top_page + (stack & (PMM_PAGE_SIZE - 1)));
    for (unsigned i = 0; i < sizeof(initial) / sizeof(*initial); ++i) words[i] = initial[i];
    return stack;
}

bool linux64_run(const void *image, uptr size, const struct linux64_file_source *source) {
    struct elf_image main, interpreter = {0};
    u64 mapped = 0;
    if (!load_layout(&main, image, size, false, &mapped) ||
        !paging64_range_free(STACK_GUARD, STACK_TOP)) return false;
    if (main.interp) {
        struct linux64_file interp;
        if (!source || !source->lookup || !source->lookup(source->context, main.interp, &interp) ||
            !load_layout(&interpreter, interp.bytes, interp.size, true, &mapped) ||
            (main.first < interpreter.end && interpreter.first < main.end)) return false;
    }
    u64 entropy[2];
    if (linux64_random_bytes(entropy, sizeof(entropy)) != sizeof(entropy)) {
        static const char message[] = "Linux x86-64 AT_RANDOM entropy unavailable\n";
        for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
        return false;
    }
    if (!map_image(&main) || (main.interp && !map_image(&interpreter))) return false;
    uptr stack = make_stack(&main, interpreter.bias, entropy);
    if (!stack || !linux64_enable_syscall()) return false;
    linux64_use_files(source);
    linux64_clock_init();
    segments64_enter_user(main.interp ? interpreter.entry : main.entry, stack);
}
