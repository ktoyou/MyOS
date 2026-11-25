#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>

#include "xdg-shell-client-protocol.h"

static const char socket_path[] = "/tmp/wayland-0";
static struct wl_compositor *compositor;
static struct wl_shm *shm;
static struct xdg_wm_base *shell;
static struct wl_output *output;
static int output_width, output_height, output_scale, width, height;
static bool output_ready, configured, presented, released, xrgb;

static void fail(const char *stage) {
    fprintf(stderr, "Wayland smoke: %s\n", stage);
    _exit(1);
}

static void ping(void *data, struct xdg_wm_base *base, uint32_t serial) {
    (void)data;
    xdg_wm_base_pong(base, serial);
}

static const struct xdg_wm_base_listener shell_events = { .ping = ping };

static void format(void *data, struct wl_shm *obj, uint32_t value) {
    (void)data;
    (void)obj;
    if (value == WL_SHM_FORMAT_XRGB8888) xrgb = true;
}

static const struct wl_shm_listener shm_events = { .format = format };

static void geometry(void *data, struct wl_output *obj, int32_t x, int32_t y,
                     int32_t mw, int32_t mh, int32_t subpixel, const char *make,
                     const char *model, int32_t transform) {
    (void)data;
    (void)obj;
    (void)x;
    (void)y;
    (void)mw;
    (void)mh;
    (void)subpixel;
    (void)make;
    (void)model;
    if (transform != WL_OUTPUT_TRANSFORM_NORMAL) fail("output transform");
}

static void mode(void *data, struct wl_output *obj, uint32_t flags, int32_t w, int32_t h, int32_t refresh) {
    (void)data;
    (void)obj;
    (void)refresh;
    if (flags & WL_OUTPUT_MODE_CURRENT) {
        output_width = w;
        output_height = h;
    }
}

static void output_done(void *data, struct wl_output *obj) {
    (void)data;
    (void)obj;
    output_ready = true;
}

static void scale(void *data, struct wl_output *obj, int32_t value) {
    (void)data;
    (void)obj;
    output_scale = value;
}

static const struct wl_output_listener output_events = {
    .geometry = geometry, .mode = mode, .done = output_done, .scale = scale,
};

static void global(void *data, struct wl_registry *registry, uint32_t id,
                   const char *interface, uint32_t version) {
    (void)data;
    if (!strcmp(interface, "wl_compositor") && version >= 4) {
        compositor = wl_registry_bind(registry, id, &wl_compositor_interface, 4);
    } else if (!strcmp(interface, "wl_shm")) {
        shm = wl_registry_bind(registry, id, &wl_shm_interface, 1);
        wl_shm_add_listener(shm, &shm_events, NULL);
    } else if (!strcmp(interface, "xdg_wm_base")) {
        shell = wl_registry_bind(registry, id, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(shell, &shell_events, NULL);
    } else if (!strcmp(interface, "wl_output") && version >= 2) {
        output = wl_registry_bind(registry, id, &wl_output_interface, 2);
        wl_output_add_listener(output, &output_events, NULL);
    }
}

static void global_remove(void *data, struct wl_registry *registry, uint32_t id) {
    (void)data;
    (void)registry;
    (void)id;
}

static const struct wl_registry_listener registry_events = { .global = global, .global_remove = global_remove };

static void configure_toplevel(void *data, struct xdg_toplevel *obj, int32_t w, int32_t h,
                               struct wl_array *states) {
    (void)data;
    (void)obj;
    (void)states;
    width = w;
    height = h;
}

static void close_toplevel(void *data, struct xdg_toplevel *obj) {
    (void)data;
    (void)obj;
    fail("unexpected close");
}

static const struct xdg_toplevel_listener toplevel_events = {
    .configure = configure_toplevel, .close = close_toplevel,
};

static void configured_surface(void *data, struct xdg_surface *obj, uint32_t serial) {
    (void)data;
    xdg_surface_ack_configure(obj, serial);
    configured = true;
}

static const struct xdg_surface_listener surface_events = { .configure = configured_surface };

static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    (void)data;
    (void)time;
    presented = true;
    wl_callback_destroy(callback);
}

static const struct wl_callback_listener frame_events = { .done = frame_done };

static void buffer_release(void *data, struct wl_buffer *buffer) {
    (void)data;
    (void)buffer;
    released = true;
}

static const struct wl_buffer_listener buffer_events = { .release = buffer_release };

static struct wl_display *start_compositor(void) {
    pid_t pid = fork();
    if (pid < 0) fail("fork");
    if (!pid) {
        char *const args[] = { "/myos/wayland-compositor", (char *)socket_path, NULL };
        char *const env[] = { NULL };
        execve(args[0], args, env);
        fail("exec compositor");
    }

    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) fail("clock");
    do {
        struct wl_display *display = wl_display_connect(socket_path);
        if (display) return display;
        sched_yield();
        if (clock_gettime(CLOCK_MONOTONIC, &now)) fail("clock");
    } while (now.tv_sec - start.tv_sec < 5);
    fail("connect");
    return NULL;
}

static struct wl_buffer *create_buffer(void) {
    const int offset = 64;
    int stride = width * 4 + 32;
    size_t length = offset + (size_t)stride * height;
    int fd = memfd_create("wayland-frame", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, length) || fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) < 0)
        fail("sealed shared memory");
    unsigned char *memory = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (memory == MAP_FAILED) fail("map shared memory");
    const uint32_t colors[2][2] = { {0xf14c88, 0x13c5a2}, {0x8254ec, 0xd49d12} };
    for (int y = 0; y < height; ++y) {
        uint32_t *row = (uint32_t *)(memory + offset + (size_t)y * stride);
        for (int x = 0; x < width; ++x) row[x] = colors[y >= height / 2][x >= width / 2];
    }
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, length);
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, offset, width, height, stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    if (munmap(memory, length) || close(fd)) fail("close local shared memory");
    wl_buffer_add_listener(buffer, &buffer_events, NULL);
    return buffer;
}

static void commit_frame(struct wl_display *display, struct wl_surface *surface, struct wl_buffer *buffer) {
    presented = false;
    released = false;
    wl_surface_attach(surface, buffer, 0, 0);
    wl_surface_damage_buffer(surface, 0, 0, width, height);
    wl_callback_add_listener(wl_surface_frame(surface), &frame_events, NULL);
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || !presented || !released) fail("present frame");
}

int main(void) {
    struct wl_display *display = start_compositor();
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_events, NULL);
    if (wl_display_roundtrip(display) < 0 || !compositor || !shm || !shell || !output ||
        wl_display_roundtrip(display) < 0 || !output_ready || !xrgb || output_scale != 1)
        fail("bind display globals");

    struct wl_surface *surface = wl_compositor_create_surface(compositor);
    struct xdg_surface *role = xdg_wm_base_get_xdg_surface(shell, surface);
    xdg_surface_add_listener(role, &surface_events, NULL);
    struct xdg_toplevel *toplevel = xdg_surface_get_toplevel(role);
    xdg_toplevel_add_listener(toplevel, &toplevel_events, NULL);
    xdg_toplevel_set_title(toplevel, "MyOS Wayland smoke");
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || !configured || width <= 0 || height <= 0 ||
        width != output_width || height != output_height || width > 8192 || height > 8192)
        fail("configure toplevel");

    struct wl_buffer *buffer = create_buffer();
    commit_frame(display, surface, buffer);

    int fb = open("/dev/fb0", O_RDONLY | O_CLOEXEC);
    uint32_t pixel;
    if (fb < 0 || pread(fb, &pixel, sizeof(pixel), 0) != sizeof(pixel) || !pixel)
        fail("mapped framebuffer");
    wl_surface_attach(surface, NULL, 0, 0);
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || pread(fb, &pixel, sizeof(pixel), 0) != sizeof(pixel) || pixel)
        fail("unmap toplevel");
    close(fb);

    configured = false;
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || !configured) fail("configure remapped toplevel");
    commit_frame(display, surface, buffer);

    /* Выход исходного процесса останавливает гостя с последним кадром для QMP. */
    static const char marker[] = "Wayland shared memory frame presented\n";
    if (write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) fail("serial marker");
    return 0;
}
