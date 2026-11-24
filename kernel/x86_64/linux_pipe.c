#include "linux_task.h"
#include "paging.h"

enum { EAGAIN = 11, EFAULT = 14, EPIPE = 32, PIPE_BUF = 4096 };
_Static_assert(PMM_PAGE_SIZE >= PIPE_BUF, "Linux pipe buffer");

struct linux64_pipe {
    uptr physical;
    uptr head, used;
    bool reader, writer;
};

static struct linux64_pipe pipes[LINUX64_OPEN_FILE_COUNT];

struct linux64_pipe *linux64_pipe_create(void) {
    for (unsigned i = 0; i < sizeof(pipes) / sizeof(*pipes); ++i) {
        struct linux64_pipe *pipe = &pipes[i];
        if (pipe->physical) continue;
        uptr physical = pmm64_alloc();
        if (!physical) return NULL;
        *pipe = (struct linux64_pipe){.physical = physical, .reader = true, .writer = true};
        return pipe;
    }
    return NULL;
}

void linux64_pipe_close(struct linux64_pipe *pipe, bool writer) {
    if (writer) pipe->writer = false;
    else pipe->reader = false;
    if (pipe->reader || pipe->writer) return;
    pmm64_free(pipe->physical);
    pipe->physical = 0;
}

bool linux64_pipe_ready(const struct linux64_pipe_io *io) {
    const struct linux64_pipe *pipe = io->pipe;
    if (!io->write) return pipe->used || !pipe->writer;
    uptr required = io->length <= PIPE_BUF ? io->length : 1;
    return !pipe->reader || PMM_PAGE_SIZE - pipe->used >= required;
}

u16 linux64_pipe_poll(const struct linux64_pipe *pipe, bool writer) {
    if (writer)
        return (pipe->used < PMM_PAGE_SIZE ? LINUX64_POLL_WRITE : 0) |
               (pipe->reader ? 0 : LINUX64_POLLERR);
    return (pipe->used ? LINUX64_POLL_READ : 0) | (pipe->writer ? 0 : LINUX64_POLLHUP);
}

static bool copy_pipe(struct linux64_pipe_io *io, uptr index, uptr count) {
    u8 *buffer = pmm64_pointer(io->pipe->physical);
    uptr first = PMM_PAGE_SIZE - index;
    if (first > count) first = count;
    uptr address = io->address + io->transferred;
    if (io->write) {
        return paging64_copy_from_user(buffer + index, address, first) == first &&
               paging64_copy_from_user(buffer, address + first, count - first) == count - first;
    }
    return paging64_copy_to_user(address, buffer + index, first) == first &&
           paging64_copy_to_user(address + first, buffer, count - first) == count - first;
}

static long wait_for_pipe(struct linux64_pipe_io *io) {
    if (io->nonblock) return io->transferred ? (long)io->transferred : -EAGAIN;
    linux64_current->state = TASK_PIPE_WAIT;
    return 0;
}

long linux64_pipe_resume(void) {
    struct linux64_pipe_io *io = &linux64_current->pipe_io;
    struct linux64_pipe *pipe = io->pipe;
    if (!io->write) {
        if (!pipe->used) return pipe->writer ? wait_for_pipe(io) : 0;
        uptr count = io->length < pipe->used ? io->length : pipe->used;
        if (!copy_pipe(io, pipe->head, count)) return -EFAULT;
        pipe->head = (pipe->head + count) % PMM_PAGE_SIZE;
        pipe->used -= count;
        return (long)count;
    }
    while (io->transferred < io->length) {
        if (!pipe->reader) return io->transferred ? (long)io->transferred : -EPIPE;
        if (!linux64_pipe_ready(io)) return wait_for_pipe(io);
        uptr count = io->length - io->transferred, space = PMM_PAGE_SIZE - pipe->used;
        if (count > space) count = space;
        if (!copy_pipe(io, (pipe->head + pipe->used) % PMM_PAGE_SIZE, count))
            return io->transferred ? (long)io->transferred : -EFAULT;
        /* До успешного копирования обеих частей запись не видна читателю. */
        pipe->used += count;
        io->transferred += count;
    }
    return (long)io->transferred;
}

long linux64_pipe_io(struct linux64_pipe *pipe, bool write, bool nonblock, uptr address, uptr length) {
    if (address >= X64_USER_TOP || length > X64_USER_TOP - address) return -EFAULT;
    if (!length) return 0;
    if (length > 0x7ffff000u) length = 0x7ffff000u;
    linux64_current->pipe_io = (struct linux64_pipe_io){
        .pipe = pipe, .address = address, .length = length, .write = write, .nonblock = nonblock,
    };
    return linux64_pipe_resume();
}
