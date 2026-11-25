#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/input-event-codes.h>
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
static struct wl_seat *seat;
static struct wl_keyboard *keyboard;
static struct wl_pointer *pointer;
static struct wl_surface *input_surface;
static int output_width, output_height, output_scale, width, height;
static bool output_ready, configured, presented, released, xrgb;
static bool keymap_ready, focused, repeat_ready, shift_down, shift_active;
static unsigned key_events;

enum {
    POINTER_ENTER = 1u << 0, POINTER_LEAVE = 1u << 1, POINTER_MOTION = 1u << 2,
    POINTER_PRESS = 1u << 3, POINTER_RELEASE = 1u << 4,
    POINTER_AXIS = 1u << 5, POINTER_DISCRETE = 1u << 6,
    POINTER_DX = 48, POINTER_DY = 36, CURSOR_DX = 5, CURSOR_DY = 3,
    CURSOR_HOTSPOT_X = 2, CURSOR_HOTSPOT_Y = 1,
};
static const unsigned pointer_sequence[] = {
    POINTER_ENTER, POINTER_MOTION, POINTER_MOTION, POINTER_PRESS, POINTER_RELEASE,
    POINTER_AXIS | POINTER_DISCRETE, POINTER_LEAVE, POINTER_ENTER,
};
static bool pointer_focused;
static unsigned pointer_events, pointer_frames;
static uint32_t pointer_enter_serial;

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

static void keyboard_keymap(void *data, struct wl_keyboard *obj, uint32_t format, int32_t fd, uint32_t size) {
    (void)data;
    (void)obj;
    if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 || size < sizeof("xkb_keymap")) fail("keyboard keymap format");
    const char *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED || map[size - 1] || strncmp(map, "xkb_keymap", 10)) fail("keyboard keymap file");
    munmap((void *)map, size);
    close(fd);
    keymap_ready = true;
}

static void keyboard_enter(void *data, struct wl_keyboard *obj, uint32_t serial,
                           struct wl_surface *surface, struct wl_array *keys) {
    (void)data;
    (void)obj;
    (void)serial;
    if (!keymap_ready || focused || surface != input_surface || keys->size) fail("keyboard enter");
    focused = true;
}

static void keyboard_leave(void *data, struct wl_keyboard *obj, uint32_t serial,
                           struct wl_surface *surface) {
    (void)data;
    (void)obj;
    (void)serial;
    if (!focused || surface != input_surface) fail("keyboard leave");
    focused = false;
}

static void keyboard_key(void *data, struct wl_keyboard *obj, uint32_t serial,
                         uint32_t time, uint32_t key, uint32_t state) {
    (void)data;
    (void)obj;
    (void)serial;
    (void)time;
    static const uint32_t expected_keys[] = {42, 30, 30, 42};
    static const uint32_t expected_states[] = {1, 1, 0, 0};
    if (!focused || !repeat_ready || key_events >= 4 || key != expected_keys[key_events] ||
        state != expected_states[key_events] || (key == 30 && !shift_active)) fail("keyboard key sequence");
    if (key == 42) shift_down = state != 0;
    ++key_events;
}

static void keyboard_modifiers(void *data, struct wl_keyboard *obj, uint32_t serial,
                               uint32_t depressed, uint32_t latched, uint32_t locked, uint32_t group) {
    (void)data;
    (void)obj;
    (void)serial;
    if (!focused || (depressed != 0) != shift_down || latched || locked || group) fail("keyboard modifiers");
    shift_active = depressed != 0;
}

static void keyboard_repeat(void *data, struct wl_keyboard *obj, int32_t rate, int32_t delay) {
    (void)data;
    (void)obj;
    if (rate < 0 || delay < 0) fail("keyboard repeat");
    repeat_ready = true;
}

static const struct wl_keyboard_listener keyboard_events = {
    .keymap = keyboard_keymap, .enter = keyboard_enter, .leave = keyboard_leave,
    .key = keyboard_key, .modifiers = keyboard_modifiers, .repeat_info = keyboard_repeat,
};

static void pointer_event(unsigned event) {
    if (pointer_events & event) fail("duplicate pointer event in frame");
    pointer_events |= event;
}

static bool pointer_position(wl_fixed_t x, wl_fixed_t y) {
    int expected_x = width / 2, expected_y = height / 2;
    if (pointer_frames) {
        expected_x += POINTER_DX;
        expected_y += POINTER_DY;
    }
    if (pointer_frames > 1) {
        expected_x += CURSOR_DX;
        expected_y += CURSOR_DY;
    }
    return x == wl_fixed_from_int(expected_x) && y == wl_fixed_from_int(expected_y);
}

static void pointer_enter(void *data, struct wl_pointer *obj, uint32_t serial,
                          struct wl_surface *surface, wl_fixed_t x, wl_fixed_t y) {
    (void)data;
    (void)obj;
    if (pointer_focused || surface != input_surface || !pointer_position(x, y))
        fail("pointer enter");
    pointer_enter_serial = serial;
    pointer_focused = true;
    pointer_event(POINTER_ENTER);
}

static void pointer_leave(void *data, struct wl_pointer *obj, uint32_t serial,
                          struct wl_surface *surface) {
    (void)data;
    (void)obj;
    (void)serial;
    if (!pointer_focused || surface != input_surface) fail("pointer leave");
    pointer_focused = false;
    pointer_event(POINTER_LEAVE);
}

static void pointer_motion(void *data, struct wl_pointer *obj, uint32_t time, wl_fixed_t x, wl_fixed_t y) {
    (void)data;
    (void)obj;
    (void)time;
    if (!pointer_focused || !pointer_position(x, y)) fail("pointer motion coordinates");
    pointer_event(POINTER_MOTION);
}

static void pointer_button(void *data, struct wl_pointer *obj, uint32_t serial,
                           uint32_t time, uint32_t button, uint32_t state) {
    (void)data;
    (void)obj;
    (void)serial;
    (void)time;
    if (!pointer_focused || button != BTN_LEFT) fail("pointer button");
    if (state == WL_POINTER_BUTTON_STATE_PRESSED) pointer_event(POINTER_PRESS);
    else if (state == WL_POINTER_BUTTON_STATE_RELEASED) pointer_event(POINTER_RELEASE);
    else fail("pointer button state");
}

static void pointer_axis(void *data, struct wl_pointer *obj, uint32_t time, uint32_t axis, wl_fixed_t value) {
    (void)data;
    (void)obj;
    (void)time;
    if (!pointer_focused || axis != WL_POINTER_AXIS_VERTICAL_SCROLL || value >= 0 ||
        !(pointer_events & POINTER_DISCRETE)) fail("pointer wheel axis");
    pointer_event(POINTER_AXIS);
}

static void pointer_axis_discrete(void *data, struct wl_pointer *obj, uint32_t axis, int32_t steps) {
    (void)data;
    (void)obj;
    if (!pointer_focused || axis != WL_POINTER_AXIS_VERTICAL_SCROLL || steps != -1)
        fail("pointer wheel step");
    pointer_event(POINTER_DISCRETE);
}

static void pointer_axis_source(void *data, struct wl_pointer *obj, uint32_t source) {
    (void)data;
    (void)obj;
    if (source != WL_POINTER_AXIS_SOURCE_WHEEL) fail("pointer wheel source");
}

static void pointer_frame(void *data, struct wl_pointer *obj) {
    (void)data;
    (void)obj;
    if (pointer_frames >= sizeof(pointer_sequence) / sizeof(pointer_sequence[0]) ||
        pointer_events != pointer_sequence[pointer_frames]) fail("pointer frame sequence");
    ++pointer_frames;
    pointer_events = 0;
}

static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter, .leave = pointer_leave, .motion = pointer_motion, .button = pointer_button,
    .axis = pointer_axis, .frame = pointer_frame, .axis_source = pointer_axis_source,
    .axis_discrete = pointer_axis_discrete,
};

static void seat_capabilities(void *data, struct wl_seat *obj, uint32_t capabilities) {
    (void)data;
    if (capabilities != (WL_SEAT_CAPABILITY_KEYBOARD | WL_SEAT_CAPABILITY_POINTER)) fail("seat capabilities");
    if (!keyboard) {
        keyboard = wl_seat_get_keyboard(obj);
        wl_keyboard_add_listener(keyboard, &keyboard_events, NULL);
    }
    if (!pointer) {
        pointer = wl_seat_get_pointer(obj);
        wl_pointer_add_listener(pointer, &pointer_listener, NULL);
    }
}

static void seat_name(void *data, struct wl_seat *obj, const char *name) {
    (void)data;
    (void)obj;
    (void)name;
}

static const struct wl_seat_listener seat_events = { .capabilities = seat_capabilities, .name = seat_name };

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
    } else if (!strcmp(interface, "wl_seat") && version >= 7) {
        seat = wl_registry_bind(registry, id, &wl_seat_interface, 7);
        wl_seat_add_listener(seat, &seat_events, NULL);
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

static struct wl_surface *set_client_cursor(struct wl_display *display) {
    const int cursor_width = 4, cursor_height = 3;
    const int stride = cursor_width * sizeof(uint32_t);
    const int length = stride * cursor_height;
    int fd = memfd_create("wayland-cursor", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, length) || fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) < 0)
        fail("cursor shared memory");
    uint32_t *pixels = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pixels == MAP_FAILED) fail("map cursor shared memory");
    pixels[0] = 0xffed117au;
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, length);
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, cursor_width, cursor_height,
                                                        stride, WL_SHM_FORMAT_ARGB8888);
    wl_shm_pool_destroy(pool);
    if (munmap(pixels, length) || close(fd)) fail("close cursor shared memory");

    struct wl_surface *cursor = wl_compositor_create_surface(compositor);
    released = false;
    wl_buffer_add_listener(buffer, &buffer_events, NULL);
    wl_surface_attach(cursor, buffer, 0, 0);
    wl_pointer_set_cursor(pointer, pointer_enter_serial, cursor, CURSOR_HOTSPOT_X, CURSOR_HOTSPOT_Y);
    wl_surface_damage_buffer(cursor, 0, 0, cursor_width, cursor_height);
    wl_surface_commit(cursor);
    if (wl_display_roundtrip(display) < 0 || !released) fail("present client cursor");
    wl_buffer_destroy(buffer);
    if (wl_display_roundtrip(display) < 0) fail("destroy client cursor buffer");
    return cursor;
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
    input_surface = surface;
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
    if (!keyboard || !focused || !pointer || !pointer_focused || pointer_frames != 1) fail("missing input focus");
    static const char ready[] = "Wayland keyboard focused\n";
    if (write(1, ready, sizeof(ready) - 1) != sizeof(ready) - 1) fail("keyboard marker");
    while (key_events != 4 || shift_active)
        if (wl_display_dispatch(display) < 0) fail("dispatch keyboard events");

    static const char *const pointer_markers[] = {
        "Wayland pointer focused\n", "Wayland pointer moved\n", "Wayland client cursor presented\n",
        "Wayland left button down\n", "Wayland left button up\n", "Wayland wheel up\n",
    };
    struct wl_surface *cursor = NULL;
    for (unsigned frame = 1; frame <= sizeof(pointer_markers) / sizeof(pointer_markers[0]); ++frame) {
        while (pointer_frames < frame)
            if (wl_display_dispatch(display) < 0) fail("dispatch pointer events");
        if (pointer_frames != frame) fail("unexpected pointer frame");
        if (frame == 3) cursor = set_client_cursor(display);
        const char *marker = pointer_markers[frame - 1];
        if (write(1, marker, strlen(marker)) != (ssize_t)strlen(marker)) fail("pointer marker");
    }

    int fb = open("/dev/fb0", O_RDONLY | O_CLOEXEC);
    uint32_t pixel;
    if (fb < 0 || pread(fb, &pixel, sizeof(pixel), 0) != sizeof(pixel) || !pixel)
        fail("mapped framebuffer");
    wl_surface_attach(surface, NULL, 0, 0);
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || focused || pointer_focused || pointer_frames != 7 ||
        pread(fb, &pixel, sizeof(pixel), 0) != sizeof(pixel) || pixel)
        fail("unmap toplevel");
    close(fb);

    configured = false;
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || !configured) fail("configure remapped toplevel");
    commit_frame(display, surface, buffer);
    if (!focused || !pointer_focused || pointer_frames != 8) fail("focus remapped toplevel");
    wl_surface_destroy(cursor);

    /* Выход исходного процесса останавливает гостя с последним кадром для QMP. */
    static const char marker[] = "Wayland shared memory frame presented\n";
    if (write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) fail("serial marker");
    return 0;
}
