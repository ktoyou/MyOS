#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/input-event-codes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>

#include "xdg-shell-client-protocol.h"

static const char socket_path[] = "/tmp/wayland-0";
static struct wl_compositor *compositor;
static struct wl_subcompositor *subcompositor;
static struct wl_shm *shm;
static struct xdg_wm_base *shell;
static struct wl_output *output;
static struct wl_seat *seat;
static struct wl_keyboard *keyboard;
static struct wl_pointer *pointer;
static struct wl_data_device_manager *data_manager;
static struct wl_data_device *source_device;
static struct wl_data_source *selection_source;
static struct wl_surface *input_surface;
static int output_width, output_height, output_scale, width, height;
static bool output_ready, configured, presented, released, xrgb;
static bool keymap_ready, focused, repeat_ready, shift_down, shift_active;
static bool late_usb, seat_capabilities_seen;
static uint32_t seat_mask;
static unsigned key_events;
static const uint32_t window_colors[2][2] = {{0xf14c88, 0x13c5a2}, {0x8254ec, 0xd49d12}};
static const char clipboard_mime[] = "text/plain;charset=utf-8";
static const char clipboard_text[] = "MyOS Wayland clipboard\n";
static bool clipboard_sent;

enum {
    SUBSURFACE_X = 61, SUBSURFACE_MOVED_X = 103, SUBSURFACE_Y = 54,
    SUBSURFACE_WIDTH = 31, SUBSURFACE_HEIGHT = 23,
    SUBSURFACE_COLOR = 0x58ab0f, SUBSURFACE_DESYNC_COLOR = 0x3e57d1,
};
static const uint32_t subsurface_colors[2][2] = {
    {SUBSURFACE_COLOR, SUBSURFACE_COLOR}, {SUBSURFACE_COLOR, SUBSURFACE_COLOR},
};
static const uint32_t subsurface_desync_colors[2][2] = {
    {SUBSURFACE_DESYNC_COLOR, SUBSURFACE_DESYNC_COLOR},
    {SUBSURFACE_DESYNC_COLOR, SUBSURFACE_DESYNC_COLOR},
};

enum { POPUP_X = 98, POPUP_Y = 92, POPUP_WIDTH = 47, POPUP_HEIGHT = 35, POPUP_COLOR = 0x196dea };
static const uint32_t popup_colors[2][2] = {{POPUP_COLOR, POPUP_COLOR}, {POPUP_COLOR, POPUP_COLOR}};

struct popup_state {
    int x, y;
    bool geometry_received, acknowledged;
};

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
    (void)time;
    static const uint32_t expected_keys[] = {42, 30, 30, 42};
    static const uint32_t expected_states[] = {1, 1, 0, 0};
    if (!focused || !repeat_ready || key_events >= 4 || key != expected_keys[key_events] ||
        state != expected_states[key_events] || (key == 30 && !shift_active)) fail("keyboard key sequence");
    if (key == KEY_A && state == WL_KEYBOARD_KEY_STATE_PRESSED) {
        if (!serial) fail("clipboard key serial");
        wl_data_device_set_selection(source_device, selection_source, serial);
        /* Повтор номера того же нажатия не должен очистить новый буфер. */
        wl_data_device_set_selection(source_device, NULL, serial);
    }
    if (key == 42) shift_down = state != 0;
    ++key_events;
    if (late_usb && key_events == 3) {
        static const char marker[] = "Wayland USB A released\n";
        if (write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) fail("USB key release marker");
    }
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
    const uint32_t input = WL_SEAT_CAPABILITY_KEYBOARD | WL_SEAT_CAPABILITY_POINTER;
    if (capabilities & ~input || (!late_usb && capabilities != input) ||
        (late_usb && !seat_capabilities_seen && capabilities) ||
        (late_usb && seat_capabilities_seen && (capabilities == seat_mask || (capabilities & seat_mask) != seat_mask)))
        fail("seat capabilities");
    seat_capabilities_seen = true;
    seat_mask = capabilities;
    if ((capabilities & WL_SEAT_CAPABILITY_KEYBOARD) && !keyboard) {
        keyboard = wl_seat_get_keyboard(obj);
        wl_keyboard_add_listener(keyboard, &keyboard_events, NULL);
    }
    if ((capabilities & WL_SEAT_CAPABILITY_POINTER) && !pointer) {
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
    } else if (!strcmp(interface, "wl_subcompositor")) {
        subcompositor = wl_registry_bind(registry, id, &wl_subcompositor_interface, 1);
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
    } else if (!strcmp(interface, "wl_data_device_manager")) {
        data_manager = wl_registry_bind(registry, id, &wl_data_device_manager_interface, 1);
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

static void configure_popup(void *data, struct xdg_popup *popup, int32_t x, int32_t y, int32_t w, int32_t h) {
    (void)popup;
    struct popup_state *state = data;
    if (state->geometry_received || x != state->x || y != state->y || w != POPUP_WIDTH || h != POPUP_HEIGHT)
        fail("popup configure geometry");
    state->geometry_received = true;
}

static void popup_done(void *data, struct xdg_popup *popup) {
    (void)data;
    (void)popup;
    fail("unexpected popup dismissal");
}

static const struct xdg_popup_listener popup_events = { .configure = configure_popup, .popup_done = popup_done };

static void configured_popup_surface(void *data, struct xdg_surface *surface, uint32_t serial) {
    struct popup_state *state = data;
    if (!state->geometry_received || state->acknowledged || !serial) fail("popup configure sequence");
    xdg_surface_ack_configure(surface, serial);
    state->acknowledged = true;
}

static const struct xdg_surface_listener popup_surface_events = { .configure = configured_popup_surface };

static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    (void)time;
    bool *done = data ? data : &presented;
    *done = true;
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

static struct wl_buffer *create_buffer(struct wl_shm *shared, int width, int height, const uint32_t colors[2][2]) {
    const int offset = 64;
    int stride = width * 4 + 32;
    size_t length = offset + (size_t)stride * height;
    int fd = memfd_create("wayland-frame", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, length) || fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) < 0)
        fail("sealed shared memory");
    unsigned char *memory = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (memory == MAP_FAILED) fail("map shared memory");
    for (int y = 0; y < height; ++y) {
        uint32_t *row = (uint32_t *)(memory + offset + (size_t)y * stride);
        for (int x = 0; x < width; ++x) row[x] = colors[y >= height / 2][x >= width / 2];
    }
    struct wl_shm_pool *pool = wl_shm_create_pool(shared, fd, length);
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

static void commit_frame(struct wl_display *display, struct wl_surface *surface, struct wl_buffer *buffer,
                         int width, int height) {
    presented = false;
    released = false;
    wl_surface_attach(surface, buffer, 0, 0);
    wl_surface_damage_buffer(surface, 0, 0, width, height);
    wl_callback_add_listener(wl_surface_frame(surface), &frame_events, NULL);
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || !presented || !released) fail("present frame");
}

static uint32_t framebuffer_color(int fb, const struct fb_fix_screeninfo *layout,
                                  const struct fb_var_screeninfo *mode, int x, int y) {
    uint32_t pixel;
    off_t offset = (off_t)y * layout->line_length + (off_t)x * sizeof(pixel);
    if (pread(fb, &pixel, sizeof(pixel), offset) != sizeof(pixel)) fail("read framebuffer pixel");
    return ((pixel >> mode->red.offset) & 0xff) << 16 |
           ((pixel >> mode->green.offset) & 0xff) << 8 | ((pixel >> mode->blue.offset) & 0xff);
}

static void check_popup_pixels(int fb, const struct fb_fix_screeninfo *layout,
                               const struct fb_var_screeninfo *mode, const struct popup_state *state, bool mapped) {
    int x = state->x, y = state->y;
    const uint32_t background = window_colors[y >= (int)mode->yres / 2][x >= (int)mode->xres / 2];
    const uint32_t inside = mapped ? POPUP_COLOR : background;
    if (framebuffer_color(fb, layout, mode, x, y) != inside ||
        framebuffer_color(fb, layout, mode, x + POPUP_WIDTH - 1, y + POPUP_HEIGHT - 1) != inside ||
        framebuffer_color(fb, layout, mode, x - 1, y) != background ||
        framebuffer_color(fb, layout, mode, x, y - 1) != background ||
        framebuffer_color(fb, layout, mode, x + POPUP_WIDTH, y) != background)
        fail(mapped ? "render placed popup" : "restore popup background");
}

static void check_popup(struct wl_display *display, struct xdg_surface *parent, int fb, bool detach) {
    struct fb_fix_screeninfo layout;
    struct fb_var_screeninfo mode;
    if (ioctl(fb, FBIOGET_FSCREENINFO, &layout) || ioctl(fb, FBIOGET_VSCREENINFO, &mode) ||
        mode.bits_per_pixel != 32 || mode.red.length != 8 || mode.green.length != 8 || mode.blue.length != 8 ||
        mode.red.offset > 24 || mode.green.offset > 24 || mode.blue.offset > 24 ||
        mode.xres / 2 <= POPUP_X + POPUP_WIDTH || mode.yres / 2 <= POPUP_Y + POPUP_HEIGHT)
        fail("popup framebuffer layout");
    const int anchor_width = 25, anchor_height = 21;
    struct popup_state state = {.x = POPUP_X, .y = POPUP_Y};
    int anchor_x = 64, anchor_y = 64;
    if (detach) {
        anchor_x = (int)mode.xres - anchor_width;
        anchor_y = (int)mode.yres - anchor_height;
        /* Ось X отражается от якоря, ось Y сдвигается до нижнего края. */
        state.x = anchor_x - POPUP_WIDTH;
        state.y = (int)mode.yres - POPUP_HEIGHT;
    }
    check_popup_pixels(fb, &layout, &mode, &state, false);

    struct xdg_positioner *positioner = xdg_wm_base_create_positioner(shell);
    xdg_positioner_set_size(positioner, POPUP_WIDTH, POPUP_HEIGHT);
    xdg_positioner_set_anchor_rect(positioner, anchor_x, anchor_y, anchor_width, anchor_height);
    xdg_positioner_set_anchor(positioner, XDG_POSITIONER_ANCHOR_BOTTOM_RIGHT);
    xdg_positioner_set_gravity(positioner, XDG_POSITIONER_GRAVITY_BOTTOM_RIGHT);
    if (detach)
        xdg_positioner_set_constraint_adjustment(positioner, XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_X |
                                               XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_Y);
    else
        xdg_positioner_set_offset(positioner, 9, 7);

    struct wl_surface *surface = wl_compositor_create_surface(compositor);
    struct xdg_surface *role = xdg_wm_base_get_xdg_surface(shell, surface);
    xdg_surface_add_listener(role, &popup_surface_events, &state);
    struct xdg_popup *popup = xdg_surface_get_popup(role, parent, positioner);
    xdg_popup_add_listener(popup, &popup_events, &state);
    xdg_positioner_destroy(positioner);
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || !state.acknowledged || wl_display_roundtrip(display) < 0)
        fail("configure and acknowledge popup");
    check_popup_pixels(fb, &layout, &mode, &state, false);

    struct wl_buffer *buffer = create_buffer(shm, POPUP_WIDTH, POPUP_HEIGHT, popup_colors);
    commit_frame(display, surface, buffer, POPUP_WIDTH, POPUP_HEIGHT);
    check_popup_pixels(fb, &layout, &mode, &state, true);
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0) fail("repeat popup commit");
    check_popup_pixels(fb, &layout, &mode, &state, true);

    if (detach) {
        wl_surface_attach(surface, NULL, 0, 0);
        wl_surface_commit(surface);
        if (wl_display_roundtrip(display) < 0) fail("detach popup buffer");
        check_popup_pixels(fb, &layout, &mode, &state, false);
    }
    xdg_popup_destroy(popup);
    xdg_surface_destroy(role);
    wl_surface_destroy(surface);
    wl_buffer_destroy(buffer);
    if (wl_display_roundtrip(display) < 0) fail("destroy popup");
    check_popup_pixels(fb, &layout, &mode, &state, false);
}

static void check_subsurface_pixels(int fb, const struct fb_fix_screeninfo *layout,
                                    const struct fb_var_screeninfo *mode, int x, uint32_t color,
                                    const char *message) {
    const int y = SUBSURFACE_Y;
    const uint32_t background = window_colors[0][0];
    if (framebuffer_color(fb, layout, mode, x, y) != color ||
        framebuffer_color(fb, layout, mode, x + SUBSURFACE_WIDTH - 1, y + SUBSURFACE_HEIGHT - 1) != color ||
        framebuffer_color(fb, layout, mode, x - 1, y) != background ||
        framebuffer_color(fb, layout, mode, x + SUBSURFACE_WIDTH, y) != background)
        fail(message);
}

static void check_subsurface(struct wl_display *display, struct wl_surface *parent, int fb) {
    struct fb_fix_screeninfo layout;
    struct fb_var_screeninfo mode;
    if (ioctl(fb, FBIOGET_FSCREENINFO, &layout) || ioctl(fb, FBIOGET_VSCREENINFO, &mode) ||
        mode.xres / 2 <= SUBSURFACE_MOVED_X + SUBSURFACE_WIDTH || mode.yres / 2 <= SUBSURFACE_Y + SUBSURFACE_HEIGHT)
        fail("subsurface framebuffer layout");

    struct wl_surface *child = wl_compositor_create_surface(compositor);
    struct wl_subsurface *role = wl_subcompositor_get_subsurface(subcompositor, child, parent);
    struct wl_buffer *buffer = create_buffer(shm, SUBSURFACE_WIDTH, SUBSURFACE_HEIGHT, subsurface_colors);
    struct wl_buffer *next = create_buffer(shm, SUBSURFACE_WIDTH, SUBSURFACE_HEIGHT, subsurface_desync_colors);
    const uint32_t background = window_colors[0][0];
    wl_subsurface_set_position(role, SUBSURFACE_X, SUBSURFACE_Y);
    wl_surface_attach(child, buffer, 0, 0);
    wl_surface_damage_buffer(child, 0, 0, SUBSURFACE_WIDTH, SUBSURFACE_HEIGHT);
    wl_surface_commit(child);
    if (wl_display_roundtrip(display) < 0) fail("commit synchronized subsurface");
    check_subsurface_pixels(fb, &layout, &mode, SUBSURFACE_X, background, "subsurface mapped before parent commit");

    wl_surface_commit(parent);
    if (wl_display_roundtrip(display) < 0) fail("apply synchronized subsurface");
    check_subsurface_pixels(fb, &layout, &mode, SUBSURFACE_X, SUBSURFACE_COLOR, "render synchronized subsurface");

    wl_subsurface_set_desync(role);
    wl_subsurface_set_position(role, SUBSURFACE_MOVED_X, SUBSURFACE_Y);
    wl_surface_attach(child, next, 0, 0);
    wl_surface_damage_buffer(child, 0, 0, SUBSURFACE_WIDTH, SUBSURFACE_HEIGHT);
    wl_surface_commit(child);
    if (wl_display_roundtrip(display) < 0) fail("commit desynchronized subsurface");
    check_subsurface_pixels(fb, &layout, &mode, SUBSURFACE_X, SUBSURFACE_DESYNC_COLOR, "render desynchronized subsurface");
    check_subsurface_pixels(fb, &layout, &mode, SUBSURFACE_MOVED_X, background, "subsurface moved before parent commit");

    wl_surface_commit(parent);
    if (wl_display_roundtrip(display) < 0) fail("apply subsurface position");
    check_subsurface_pixels(fb, &layout, &mode, SUBSURFACE_X, background, "restore moved subsurface background");
    check_subsurface_pixels(fb, &layout, &mode, SUBSURFACE_MOVED_X, SUBSURFACE_DESYNC_COLOR, "render moved subsurface");

    wl_subsurface_destroy(role);
    if (wl_display_roundtrip(display) < 0) fail("destroy subsurface role");
    check_subsurface_pixels(fb, &layout, &mode, SUBSURFACE_MOVED_X, background, "restore destroyed subsurface background");
    wl_surface_destroy(child);
    wl_buffer_destroy(next);
    wl_buffer_destroy(buffer);
    if (wl_display_roundtrip(display) < 0) fail("destroy subsurface resources");
}

struct clipboard_selection {
    struct wl_data_offer *pending, *current;
    unsigned updates;
    bool has_mime;
};

static struct clipboard_selection owner_selection;

static void clipboard_mime_offered(void *data, struct wl_data_offer *offer, const char *mime) {
    struct clipboard_selection *selection = data;
    if (offer != selection->pending) fail("clipboard MIME without offer");
    if (!strcmp(mime, clipboard_mime)) selection->has_mime = true;
}

static const struct wl_data_offer_listener clipboard_offer_events = {.offer = clipboard_mime_offered};

static void clipboard_offer(void *data, struct wl_data_device *device, struct wl_data_offer *offer) {
    (void)device;
    struct clipboard_selection *selection = data;
    if (selection->pending) fail("unclaimed clipboard offer");
    selection->pending = offer;
    selection->has_mime = false;
    wl_data_offer_add_listener(offer, &clipboard_offer_events, data);
}

static void clipboard_selected(void *data, struct wl_data_device *device, struct wl_data_offer *offer) {
    (void)device;
    struct clipboard_selection *selection = data;
    if (offer && (offer != selection->pending || !selection->has_mime)) fail("clipboard selection MIME");
    if (selection->current) wl_data_offer_destroy(selection->current);
    selection->current = offer;
    selection->pending = NULL;
    ++selection->updates;
}

static const struct wl_data_device_listener clipboard_device_events = {
    .data_offer = clipboard_offer, .selection = clipboard_selected,
};

static void clipboard_send(void *data, struct wl_data_source *source, const char *mime, int32_t fd) {
    (void)data;
    if (source != selection_source || clipboard_sent || strcmp(mime, clipboard_mime) ||
        write(fd, clipboard_text, sizeof(clipboard_text) - 1) != sizeof(clipboard_text) - 1 || close(fd))
        fail("write clipboard pipe");
    clipboard_sent = true;
}

static const struct wl_data_source_listener clipboard_source_events = {.send = clipboard_send};

struct clipboard_receiver {
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *shell;
    struct wl_seat *seat;
    struct wl_data_device_manager *manager;
    struct wl_surface *surface;
    struct clipboard_selection selection;
    bool configured, focused;
    unsigned key_events;
};

static void receiver_global(void *data, struct wl_registry *registry, uint32_t id,
                            const char *interface, uint32_t version) {
    struct clipboard_receiver *receiver = data;
    if (!strcmp(interface, "wl_compositor") && version >= 4)
        receiver->compositor = wl_registry_bind(registry, id, &wl_compositor_interface, 4);
    else if (!strcmp(interface, "wl_shm"))
        receiver->shm = wl_registry_bind(registry, id, &wl_shm_interface, 1);
    else if (!strcmp(interface, "xdg_wm_base")) {
        receiver->shell = wl_registry_bind(registry, id, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(receiver->shell, &shell_events, NULL);
    } else if (!strcmp(interface, "wl_seat") && version >= 7)
        receiver->seat = wl_registry_bind(registry, id, &wl_seat_interface, 7);
    else if (!strcmp(interface, "wl_data_device_manager"))
        receiver->manager = wl_registry_bind(registry, id, &wl_data_device_manager_interface, 1);
}

static const struct wl_registry_listener receiver_registry_events = {
    .global = receiver_global, .global_remove = global_remove,
};

static void receiver_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    struct clipboard_receiver *receiver = data;
    xdg_surface_ack_configure(surface, serial);
    receiver->configured = true;
}

static const struct xdg_surface_listener receiver_surface_events = {.configure = receiver_configure};

static void receiver_keyboard_enter(void *data, struct wl_keyboard *object, uint32_t serial,
                                    struct wl_surface *surface, struct wl_array *keys) {
    (void)object;
    struct clipboard_receiver *receiver = data;
    if (!serial || keys->size || surface != receiver->surface || receiver->focused) fail("clipboard focus enter");
    receiver->focused = true;
}

static void receiver_keyboard_leave(void *data, struct wl_keyboard *object, uint32_t serial,
                                    struct wl_surface *surface) {
    (void)object;
    (void)serial;
    struct clipboard_receiver *receiver = data;
    if (surface != receiver->surface || !receiver->focused) fail("clipboard focus leave");
    receiver->focused = false;
}

static void receiver_keyboard_key(void *data, struct wl_keyboard *object, uint32_t serial,
                                  uint32_t time, uint32_t key, uint32_t state) {
    (void)object;
    (void)time;
    struct clipboard_receiver *receiver = data;
    uint32_t expected = receiver->key_events ? WL_KEYBOARD_KEY_STATE_RELEASED : WL_KEYBOARD_KEY_STATE_PRESSED;
    if (!receiver->focused || !serial || key != KEY_B || receiver->key_events >= 2 || state != expected)
        fail("clipboard receiver key sequence");
    ++receiver->key_events;
    if (late_usb && receiver->key_events == 1) {
        static const char marker[] = "Wayland USB clipboard key pressed\n";
        if (write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) fail("USB clipboard key marker");
    }
}

static void receiver_keyboard_modifiers(void *data, struct wl_keyboard *object, uint32_t serial,
                                        uint32_t depressed, uint32_t latched, uint32_t locked, uint32_t group) {
    (void)data;
    (void)object;
    (void)serial;
    if (depressed || latched || locked || group) fail("clipboard keyboard modifiers");
}

static const struct wl_keyboard_listener receiver_keyboard_events = {
    .keymap = keyboard_keymap, .enter = receiver_keyboard_enter, .leave = receiver_keyboard_leave,
    .key = receiver_keyboard_key, .modifiers = receiver_keyboard_modifiers, .repeat_info = keyboard_repeat,
};

static void read_clipboard(struct wl_display *owner, struct wl_display *reader,
                           struct wl_data_offer *offer, bool expected) {
    int pipe_fd[2];
    if (pipe2(pipe_fd, O_NONBLOCK | O_CLOEXEC)) fail("clipboard pipe");
    wl_data_offer_receive(offer, clipboard_mime, pipe_fd[1]);
    if (close(pipe_fd[1]) || wl_display_roundtrip(reader) < 0 ||
        (owner != reader && wl_display_roundtrip(owner) < 0)) fail("dispatch clipboard receive");
    char received[sizeof(clipboard_text)];
    ssize_t length = read(pipe_fd[0], received, sizeof(received));
    if (expected) {
        if (!clipboard_sent || length != sizeof(clipboard_text) - 1 || memcmp(received, clipboard_text, length) ||
            read(pipe_fd[0], received, sizeof(received))) fail("clipboard payload or EOF");
    } else if (clipboard_sent || length) {
        fail("stale clipboard offer was readable");
    }
    if (close(pipe_fd[0])) fail("close clipboard pipe");
}

static void check_clipboard(struct wl_display *owner, struct wl_surface *owner_surface, struct wl_buffer *owner_buffer) {
    static const uint32_t front_color = 0x2365a7;
    const uint32_t front_colors[2][2] = {{front_color, front_color}, {front_color, front_color}};
    int fb = open("/dev/fb0", O_RDONLY | O_CLOEXEC);
    struct fb_fix_screeninfo layout;
    struct fb_var_screeninfo mode;
    if (fb < 0 || ioctl(fb, FBIOGET_FSCREENINFO, &layout) || ioctl(fb, FBIOGET_VSCREENINFO, &mode))
        fail("framebuffer for window restoration");

    struct wl_display *display = wl_display_connect(socket_path);
    if (!display) fail("connect clipboard receiver");
    struct clipboard_receiver receiver = {0};
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &receiver_registry_events, &receiver);
    if (wl_display_roundtrip(display) < 0 || !receiver.compositor || !receiver.shm || !receiver.shell ||
        !receiver.seat || !receiver.manager) fail("bind clipboard receiver globals");

    struct wl_data_device *device = wl_data_device_manager_get_data_device(receiver.manager, receiver.seat);
    wl_data_device_add_listener(device, &clipboard_device_events, &receiver.selection);
    struct wl_keyboard *reader_keyboard = wl_seat_get_keyboard(receiver.seat);
    wl_keyboard_add_listener(reader_keyboard, &receiver_keyboard_events, &receiver);
    receiver.surface = wl_compositor_create_surface(receiver.compositor);
    struct xdg_surface *role = xdg_wm_base_get_xdg_surface(receiver.shell, receiver.surface);
    xdg_surface_add_listener(role, &receiver_surface_events, &receiver);
    struct xdg_toplevel *toplevel = xdg_surface_get_toplevel(role);
    xdg_toplevel_add_listener(toplevel, &toplevel_events, NULL);
    wl_surface_commit(receiver.surface);
    if (wl_display_roundtrip(display) < 0 || !receiver.configured || receiver.focused || receiver.selection.current)
        fail("clipboard exposed before receiver focus");

    struct wl_buffer *frame = create_buffer(receiver.shm, width, height, front_colors);
    commit_frame(display, receiver.surface, frame, width, height);
    if (wl_display_roundtrip(owner) < 0 || focused || !receiver.focused || !receiver.selection.current)
        fail("clipboard offer after keyboard focus change");
    presented = false;
    wl_surface_attach(owner_surface, owner_buffer, 0, 0);
    wl_surface_damage_buffer(owner_surface, 0, 0, width, height);
    wl_callback_add_listener(wl_surface_frame(owner_surface), &frame_events, NULL);
    wl_surface_commit(owner_surface);
    bool uncommitted_frame_done = false;
    wl_callback_add_listener(wl_surface_frame(owner_surface), &frame_events, &uncommitted_frame_done);
    if (wl_display_roundtrip(owner) < 0 || wl_display_roundtrip(display) < 0 || presented ||
        uncommitted_frame_done || focused || !receiver.focused ||
        framebuffer_color(fb, &layout, &mode, 0, 0) != front_color)
        fail("clipboard keyboard focus after background repaint");
    if (!owner_selection.current) fail("missing stale clipboard offer");
    read_clipboard(owner, owner, owner_selection.current, false);
    read_clipboard(owner, display, receiver.selection.current, false);
    static const char ready[] = "Wayland clipboard receiver focused\n";
    if (write(1, ready, sizeof(ready) - 1) != sizeof(ready) - 1) fail("clipboard receiver marker");
    while (receiver.key_events != 2)
        if (wl_display_dispatch(display) < 0) fail("dispatch clipboard receiver keyboard");
    read_clipboard(owner, display, receiver.selection.current, true);

    unsigned updates = receiver.selection.updates;
    wl_data_source_destroy(selection_source);
    selection_source = NULL;
    if (wl_display_roundtrip(owner) < 0 || wl_display_roundtrip(display) < 0 || receiver.selection.current ||
        receiver.selection.updates == updates) fail("clear clipboard after source destruction");

    /* Нижний клиент получает свой кадр и фокус без нового commit. */
    wl_surface_attach(receiver.surface, NULL, 0, 0);
    wl_surface_commit(receiver.surface);
    if (wl_display_roundtrip(display) < 0 || receiver.focused || wl_display_roundtrip(owner) < 0 || !focused || !presented ||
        uncommitted_frame_done || framebuffer_color(fb, &layout, &mode, 0, 0) != window_colors[0][0])
        fail("restore previous window after detach");

    receiver.configured = false;
    wl_surface_commit(receiver.surface);
    if (wl_display_roundtrip(display) < 0 || !receiver.configured) fail("configure remapped foreground window");
    commit_frame(display, receiver.surface, frame, width, height);
    if (wl_display_roundtrip(owner) < 0 || focused || !receiver.focused ||
        framebuffer_color(fb, &layout, &mode, 0, 0) != front_color)
        fail("focus remapped foreground window");

    xdg_toplevel_destroy(toplevel);
    if (wl_display_roundtrip(display) < 0 || receiver.focused || wl_display_roundtrip(owner) < 0 || !focused ||
        uncommitted_frame_done || framebuffer_color(fb, &layout, &mode, 0, 0) != window_colors[0][0])
        fail("restore previous window after close");
    wl_surface_commit(owner_surface);
    if (wl_display_roundtrip(owner) < 0 || !uncommitted_frame_done)
        fail("frame callback after first owner commit");
    wl_keyboard_release(reader_keyboard);
    xdg_surface_destroy(role);
    wl_surface_destroy(receiver.surface);
    wl_buffer_destroy(frame);
    if (wl_display_roundtrip(display) < 0) fail("close clipboard receiver");
    wl_display_disconnect(display);
    if (close(fb)) fail("close framebuffer after window restoration");
    static const char restored[] = "Wayland previous window and focus restored\n";
    if (write(1, restored, sizeof(restored) - 1) != sizeof(restored) - 1) fail("window restoration marker");
}

int main(void) {
    late_usb = access("/myos/wayland-late-usb-input", F_OK) == 0;
    struct wl_display *display = start_compositor();
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_events, NULL);
    if (wl_display_roundtrip(display) < 0 || !compositor || !subcompositor || !shm || !shell || !output ||
        !seat || !data_manager || wl_display_roundtrip(display) < 0 || !seat_capabilities_seen ||
        !output_ready || !xrgb || output_scale != 1)
        fail("bind display globals");

    source_device = wl_data_device_manager_get_data_device(data_manager, seat);
    wl_data_device_add_listener(source_device, &clipboard_device_events, &owner_selection);
    selection_source = wl_data_device_manager_create_data_source(data_manager);
    wl_data_source_add_listener(selection_source, &clipboard_source_events, NULL);
    wl_data_source_offer(selection_source, clipboard_mime);

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

    struct wl_buffer *buffer = create_buffer(shm, width, height, window_colors);
    commit_frame(display, surface, buffer, width, height);
    if (late_usb) {
        static const char marker[] = "Wayland surface mapped without input\n";
        if (seat_mask || keyboard || pointer || focused || pointer_focused ||
            write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) fail("empty seat after mapping surface");
        while (!focused || !pointer_focused || !pointer_frames)
            if (wl_display_dispatch(display) < 0) fail("dispatch hotplug seat capabilities and focus");
    }
    if (!keyboard || !focused || !pointer || !pointer_focused || pointer_frames != 1) fail("missing input focus");
    static const char ready[] = "Wayland keyboard focused\n";
    if (write(1, ready, sizeof(ready) - 1) != sizeof(ready) - 1) fail("keyboard marker");
    while (key_events < 2)
        if (wl_display_dispatch(display) < 0) fail("dispatch clipboard key press");
    static const char published[] = "Wayland clipboard serial published\n";
    if (wl_display_roundtrip(display) < 0 || !owner_selection.current ||
        write(1, published, sizeof(published) - 1) != sizeof(published) - 1) fail("publish clipboard selection");
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
    check_popup(display, role, fb, false);
    check_popup(display, role, fb, true);
    static const char popup_marker[] = "Wayland popup configured, presented and restored\n";
    if (!focused || !pointer_focused || pointer_frames != 6 ||
        write(1, popup_marker, sizeof(popup_marker) - 1) != sizeof(popup_marker) - 1)
        fail("popup completion and focus");
    check_subsurface(display, surface, fb);
    static const char subsurface_marker[] = "Wayland subsurface synchronized, presented and restored\n";
    if (!focused || !pointer_focused || pointer_frames != 6 ||
        write(1, subsurface_marker, sizeof(subsurface_marker) - 1) != sizeof(subsurface_marker) - 1)
        fail("subsurface completion and focus");
    wl_surface_attach(surface, NULL, 0, 0);
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || focused || pointer_focused || pointer_frames != 7 ||
        pread(fb, &pixel, sizeof(pixel), 0) != sizeof(pixel) || pixel)
        fail("unmap toplevel");
    close(fb);

    configured = false;
    wl_surface_commit(surface);
    if (wl_display_roundtrip(display) < 0 || !configured) fail("configure remapped toplevel");
    commit_frame(display, surface, buffer, width, height);
    if (!focused || !pointer_focused || pointer_frames != 8) fail("focus remapped toplevel");
    wl_surface_destroy(cursor);
    wl_pointer_release(pointer);
    check_clipboard(display, surface, buffer);
    static const char clipboard_marker[] = "Wayland clipboard received and cleared\n";
    if (write(1, clipboard_marker, sizeof(clipboard_marker) - 1) != sizeof(clipboard_marker) - 1)
        fail("clipboard completion marker");
    /* Выход исходного процесса останавливает гостя с последним кадром для QMP. */
    static const char marker[] = "Wayland shared memory frame presented\n";
    if (write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) fail("serial marker");
    return 0;
}
