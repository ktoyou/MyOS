#include "linux_task.h"
#include "paging.h"
#include "segments.h"

#define USER_MIN        0x400000ul
#define BOOT_STACK_SIZE (4 * PMM_PAGE_SIZE)
#define EXEC_STACK_SIZE (32 * PMM_PAGE_SIZE)
#define EXEC_POINTERS   256u
#define EXEC_STRINGS    (8 * PMM_PAGE_SIZE)
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

enum { ENOENT = 2, EIO = 5, E2BIG = 7, ENOEXEC = 8, ENOMEM = 12, EFAULT = 14,
       ENAMETOOLONG = 36, ELIBBAD = 80 };

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

struct stack_arguments {
    const char *path, *strings;
    const unsigned *offsets;
    uptr path_length, string_bytes;
    unsigned argc, count;
};

/* Подготовка execve не уступает CPU и не держит строки на syscall-стеке. */
static struct {
    char path[LINUX64_PATH_LIMIT], absolute[LINUX64_PATH_LIMIT], strings[EXEC_STRINGS];
    unsigned offsets[EXEC_POINTERS];
    unsigned used, count;
} exec_args;

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
    if (p->filesz < 2 || p->filesz > LINUX64_PATH_LIMIT ||
        p->offset > size || p->filesz > size - p->offset)
        return NULL;
    const char *path = (const char *)e + p->offset;
    if (path[0] != '/' || path[p->filesz - 1]) return NULL;
    for (u64 i = 1; i < p->filesz - 1; ++i)
        if (!path[i]) return NULL;
    return path;
}

static bool load_layout(struct elf_image *elf, const void *image, uptr size,
                        bool interpreter, uptr stack_guard, u64 *mapped) {
    const struct elf_header *e = image;
    if (!valid_header(e, size)) return false;
    const struct elf_segment *segments = (const void *)((const u8 *)image + e->phoff);
    u64 bias = e->type == ET_DYN ? (interpreter ? INTERP_BIAS : PROGRAM_BIAS) : 0;
    *elf = (struct elf_image){.header = e, .segments = segments, .bias = bias,
                              .first = stack_guard};
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
        if (p->address >= stack_guard - bias) return false;
        u64 address = bias + p->address;
        if (address < USER_MIN || p->memsz > stack_guard - address ||
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

static uptr make_stack(const struct elf_image *main, u64 interp_bias, const u64 entropy[2],
                       const struct stack_arguments *args, uptr bottom,
                       const struct linux64_userns *ns) {
    const uptr path_size = args->path_length + 1;
    const uptr execfn_address = LINUX64_STACK_TOP - path_size;
    const uptr strings_address = execfn_address - args->string_bytes;
    const uptr random_address = (strings_address - 2 * sizeof(u64)) & ~7ul;
    u64 vectors[EXEC_POINTERS + 3];
    unsigned used = 0;
    vectors[used++] = args->argc;
    for (unsigned i = 0; i < args->argc; ++i) vectors[used++] = strings_address + args->offsets[i];
    vectors[used++] = 0;
    for (unsigned i = args->argc; i < args->count; ++i)
        vectors[used++] = strings_address + args->offsets[i];
    vectors[used++] = 0;
    u32 uid = linux64_visible_id(ns, false, LINUX64_UID);
    u32 gid = linux64_visible_id(ns, true, LINUX64_GID);
    const u64 auxv[] = {
        3, main->phdr, 4, main->header->phentsize, 5, main->header->phnum, 6, PMM_PAGE_SIZE,
        7, interp_bias, 9, main->entry, 11, uid, 12, uid,
        13, gid, 14, gid, AT_RANDOM, random_address, 31, execfn_address, 0, 0,
    };
    uptr vector_size = used * sizeof(*vectors);
    uptr stack = (random_address - sizeof(auxv) - vector_size) & ~15ul;
    if (stack < bottom) return 0;
    for (uptr page = bottom; page < LINUX64_STACK_TOP; page += PMM_PAGE_SIZE) {
        if (!paging64_user_page(page)) return 0;
    }
    /* argv[0] изменяется программой независимо от AT_EXECFN. */
    if (paging64_copy_to_user(execfn_address, args->path, path_size) != path_size ||
        paging64_copy_to_user(strings_address, args->strings, args->string_bytes) != args->string_bytes ||
        paging64_copy_to_user(random_address, entropy, 2 * sizeof(u64)) != 2 * sizeof(u64) ||
        paging64_copy_to_user(stack, vectors, vector_size) != vector_size ||
        paging64_copy_to_user(stack + vector_size, auxv, sizeof(auxv)) != sizeof(auxv)) return 0;
    return stack;
}

static long prepare_image(const void *image, uptr size, const struct linux64_file_source *source,
                          const struct stack_arguments *args, uptr stack_size,
                          uptr *entry, uptr *stack, const struct linux64_userns *ns) {
    struct elf_image main, interpreter = {0};
    u64 mapped = 0;
    uptr bottom = LINUX64_STACK_TOP - stack_size, guard = LINUX64_STACK_FLOOR - PMM_PAGE_SIZE;
    if (!load_layout(&main, image, size, false, guard, &mapped) ||
        !paging64_range_free(guard, LINUX64_STACK_TOP)) return -ENOEXEC;
    if (main.interp) {
        struct linux64_file interp;
        if (!source || !source->lookup || !source->lookup(source->context, main.interp, &interp))
            return -ENOENT;
        if (!load_layout(&interpreter, interp.bytes, interp.size, true, guard, &mapped) ||
            (main.first < interpreter.end && interpreter.first < main.end)) return -ELIBBAD;
    }
    u64 entropy[2];
    if (linux64_random_bytes(entropy, sizeof(entropy)) != sizeof(entropy)) {
        static const char message[] = "Linux x86-64 AT_RANDOM entropy unavailable\n";
        for (unsigned i = 0; message[i]; ++i) kernel64_serial_char(message[i]);
        return -EIO;
    }
    if (!map_image(&main) || (main.interp && !map_image(&interpreter))) return -ENOMEM;
    if (!paging64_reserve_stack(LINUX64_STACK_FLOOR, bottom)) return -ENOMEM;
    *entry = main.interp ? interpreter.entry : main.entry;
    *stack = make_stack(&main, interpreter.bias, entropy, args, bottom, ns);
    return *stack ? 0 : -ENOMEM;
}

static long stage_vector(uptr vector) {
    if (!vector) return 0;
    for (;;) {
        uptr string;
        if (vector > X64_USER_TOP - sizeof(string) ||
            paging64_copy_from_user(&string, vector, sizeof(string)) != sizeof(string)) return -EFAULT;
        if (!string) return 0;
        if (exec_args.count == EXEC_POINTERS) return -E2BIG;
        long length = linux64_user_string(string, exec_args.strings + exec_args.used,
                                          EXEC_STRINGS - exec_args.used);
        if (length < 0) return length == -ENAMETOOLONG ? -E2BIG : length;
        exec_args.offsets[exec_args.count++] = exec_args.used;
        exec_args.used += (unsigned)length + 1;
        vector += sizeof(string);
    }
}

long linux64_execve(struct linux64_frame *frame, uptr filename, uptr argv, uptr envp) {
    char *path = exec_args.path;
    long length = linux64_user_string(filename, path, LINUX64_PATH_LIMIT);
    if (length <= 0) return length ? length : -ENOENT;
    const char *absolute = path;
    uptr absolute_length = (uptr)length;
    if (path[0] != '/') {
        const char *relative = path;
        while (relative[0] == '.' && relative[1] == '/') {
            relative += 2;
            while (*relative == '/') ++relative;
        }
        absolute_length = (uptr)length - (uptr)(relative - path) + 1;
        if (absolute_length >= LINUX64_PATH_LIMIT) return -ENAMETOOLONG;
        exec_args.absolute[0] = '/';
        for (uptr i = 1; i <= absolute_length; ++i) exec_args.absolute[i] = relative[i - 1];
        absolute = exec_args.absolute;
    }
    const struct linux64_file_source *source = linux64_file_source();
    struct linux64_file file;
    if (!source->lookup || !source->lookup(source->context, absolute, &file)) return -ENOENT;

    exec_args.used = exec_args.count = 0;
    long result = stage_vector(argv);
    if (result) return result;
    if (!exec_args.count) {
        exec_args.offsets[0] = 0;
        exec_args.strings[0] = 0;
        exec_args.used = exec_args.count = 1;
    }
    unsigned argc = exec_args.count;
    result = stage_vector(envp);
    if (result) return result;
    const struct stack_arguments args = {
        .path = path, .path_length = (uptr)length, .strings = exec_args.strings,
        .offsets = exec_args.offsets, .string_bytes = exec_args.used, .argc = argc,
        .count = exec_args.count,
    };
    uptr previous = paging64_active_root(), root = paging64_exec_root();
    if (!root) return -ENOMEM;
    paging64_switch_root(root);
    uptr entry, stack;
    result = prepare_image(file.bytes, file.size, source, &args, EXEC_STACK_SIZE, &entry, &stack,
                           linux64_current->process->userns);
    if (!result && linux64_commit_exec(frame, root, entry, stack, absolute, absolute_length)) return 0;
    paging64_switch_root(previous);
    paging64_drop_root(root);
    return result ? result : -ENOMEM;
}

bool linux64_run(const void *image, uptr size, const char *path, uptr path_length,
                 const struct linux64_file_source *source) {
    if (!path || !path_length || path_length >= LINUX64_PATH_LIMIT || path[0] != '/' ||
        path[path_length]) return false;
    const unsigned offset = 0;
    const struct stack_arguments args = {
        .path = path, .path_length = path_length, .strings = path, .string_bytes = path_length + 1,
        .offsets = &offset, .argc = 1, .count = 1,
    };
    uptr entry, stack;
    if (prepare_image(image, size, source, &args, BOOT_STACK_SIZE, &entry, &stack, NULL) ||
        !linux64_enable_syscall()) return false;
    linux64_task_init();
    linux64_use_files(source, path, path_length);
    linux64_reset_signals();
    linux64_clock_init();
    segments64_enter_user(entry, stack);
}
