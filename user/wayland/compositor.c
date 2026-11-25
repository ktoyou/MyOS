#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fb.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server.h>

#include "seat.h"
#include "xdg-shell-server-protocol.h"

struct compositor {
    struct wl_display *display;
    struct fb_var_screeninfo mode;
    struct fb_fix_screeninfo layout;
    struct surface *visible;
    struct wl_resource *cursor_surface;
    struct wayland_seat *seat;
    uint32_t *row;
    uint32_t *cursor_background;
    size_t cursor_capacity;
    int cursor_x, cursor_y, cursor_width, cursor_rows;
    int drawn_width, drawn_height;
    int fb;
};

struct frame {
    struct wl_list link;
    struct wl_resource *resource;
};

struct region_rect {
    int32_t x, y, width, height;
    bool add;
};

enum surface_role { SURFACE_NONE, SURFACE_XDG, SURFACE_CURSOR };

struct surface {
    struct compositor *server;
    struct wl_resource *resource;
    struct wl_resource *shell;
    struct wl_resource *toplevel;
    struct wl_resource *buffer;
    struct wl_listener buffer_destroy;
    struct wl_list frames;
    struct wl_array input_region, pending_input_region;
    uint32_t *cursor_pixels;
    int cursor_width, cursor_height;
    int32_t attach_x, attach_y;
    int64_t cursor_x, cursor_y;
    uint32_t serial;
    enum surface_role role;
    bool configured, acknowledged, detach, mapped, input_pending, input_set, pending_input_set;
    int scale, transform;
};

static volatile sig_atomic_t stopping;

static void stop(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static off_t row_offset(const struct compositor *server, int x, int y) {
    return (off_t)y * server->layout.line_length + (off_t)x * (off_t)sizeof(*server->row);
}

static bool write_pixels(struct compositor *server, int x, int y, int width, const uint32_t *pixels) {
    size_t bytes = (size_t)width * sizeof(*pixels);
    return pwrite(server->fb, pixels, bytes, row_offset(server, x, y)) == (ssize_t)bytes;
}

static void restore_cursor(struct compositor *server) {
    for (int row = 0; row < server->cursor_rows; ++row) {
        if (!write_pixels(server, server->cursor_x, server->cursor_y + row, server->cursor_width,
                          server->cursor_background + (size_t)row * server->cursor_width)) {
            perror("Restore cursor background");
            break;
        }
    }
    server->cursor_rows = 0;
}

static void hide_surface(struct surface *surface) {
    struct compositor *server = surface->server;
    surface->mapped = false;
    bool visible = server->visible == surface;
    if (visible) server->visible = NULL;
    wayland_seat_pointer_detach(server->seat, surface->resource);
    if (visible) {
        wayland_seat_keyboard_focus(server->seat, NULL);
        restore_cursor(server);
        memset(server->row, 0, (size_t)server->drawn_width * sizeof(*server->row));
        for (int y = 0; y < server->drawn_height; ++y) {
            if (!write_pixels(server, 0, y, server->drawn_width, server->row)) {
                perror("Clear framebuffer");
                break;
            }
        }
        server->drawn_width = 0;
        server->drawn_height = 0;
    }
    wayland_seat_pointer_update(server->seat);
}

static void destroy_request(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void clear_pending_buffer(struct surface *surface) {
    if (surface->buffer) wl_list_remove(&surface->buffer_destroy.link);
    surface->buffer = NULL;
}

static void buffer_destroyed(struct wl_listener *listener, void *data) {
    (void)data;
    struct surface *surface = wl_container_of(listener, surface, buffer_destroy);
    clear_pending_buffer(surface);
}

static void frame_destroyed(struct wl_resource *resource) {
    struct frame *frame = wl_resource_get_user_data(resource);
    wl_list_remove(&frame->link);
    free(frame);
}

static void toplevel_destroyed(struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    hide_surface(surface);
    surface->toplevel = NULL;
    surface->configured = false;
    surface->acknowledged = false;
}

static void shell_surface_destroyed(struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->toplevel) wl_resource_destroy(surface->toplevel);
    surface->shell = NULL;
}

static void surface_destroyed(struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    struct frame *frame, *next;
    if (surface->server->cursor_surface == resource) surface->server->cursor_surface = NULL;
    if (surface->shell) wl_resource_destroy(surface->shell);
    clear_pending_buffer(surface);
    wl_list_for_each_safe(frame, next, &surface->frames, link) {
        wl_resource_destroy(frame->resource);
    }
    wl_array_release(&surface->input_region);
    wl_array_release(&surface->pending_input_region);
    free(surface->cursor_pixels);
    free(surface);
}

static void destroy_surface_request(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    hide_surface(surface);
    wl_resource_destroy(resource);
}

static void surface_attach(struct wl_client *client, struct wl_resource *resource,
                           struct wl_resource *buffer, int32_t x, int32_t y) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    clear_pending_buffer(surface);
    surface->attach_x = x;
    surface->attach_y = y;
    surface->detach = !buffer;
    surface->buffer = buffer;
    if (buffer) wl_resource_add_destroy_listener(buffer, &surface->buffer_destroy);
}

static void rectangle_request(struct wl_client *client, struct wl_resource *resource,
                              int32_t x, int32_t y, int32_t width, int32_t height) {
    (void)client;
    (void)resource;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
}

static void region_request(struct wl_client *client, struct wl_resource *resource,
                           struct wl_resource *region) {
    (void)client;
    (void)resource;
    (void)region;
}

static void set_input_region(struct wl_client *client, struct wl_resource *resource,
                             struct wl_resource *region) {
    struct surface *surface = wl_resource_get_user_data(resource);
    struct wl_array *source = region ? wl_resource_get_user_data(region) : NULL;
    struct wl_array copy;
    wl_array_init(&copy);
    if (source && source->size && wl_array_copy(&copy, source) < 0) {
        wl_array_release(&copy);
        wl_client_post_no_memory(client);
        return;
    }
    wl_array_release(&surface->pending_input_region);
    surface->pending_input_region = copy;
    surface->pending_input_set = region != NULL;
    surface->input_pending = true;
}

static struct wl_resource *pick_surface(void *data, int x, int y) {
    struct compositor *server = data;
    struct surface *surface = server->visible;
    if (!surface || x < 0 || y < 0 || x >= server->drawn_width || y >= server->drawn_height) return NULL;
    if (!surface->input_set) return surface->resource;

    bool inside = false;
    const struct region_rect *rect;
    wl_array_for_each(rect, &surface->input_region) {
        if (x >= rect->x && y >= rect->y && (int64_t)x - rect->x < rect->width &&
            (int64_t)y - rect->y < rect->height) inside = rect->add;
    }
    return inside ? surface->resource : NULL;
}

static bool assign_cursor(void *data, struct wl_resource *resource) {
    (void)data;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->role == SURFACE_XDG) return false;
    surface->role = SURFACE_CURSOR;
    surface->cursor_x = 0;
    surface->cursor_y = 0;
    return true;
}

static const char arrow[][13] = {
    "X...........",
    "XX..........",
    "XoX.........",
    "XooX........",
    "XoooX.......",
    "XooooX......",
    "XoooooX.....",
    "XooooooX....",
    "XoooooooX...",
    "XooooooooX..",
    "XoooooooooX.",
    "XooooXXXXXXX",
    "XooXoX......",
    "XoXXooX.....",
    "XX..XooX....",
    "X...XooX....",
    ".....XX.....",
};

static uint32_t arrow_pixel(int x, int y) {
    switch (arrow[y][x]) {
    case 'X': return 0xff000000u;
    case 'o': return 0xffffffffu;
    default: return 0;
    }
}

static uint32_t rgb_pixel(const struct compositor *server, uint32_t source) {
    return ((source >> 16) & 255) << server->mode.red.offset |
           ((source >> 8) & 255) << server->mode.green.offset |
           (source & 255) << server->mode.blue.offset;
}

static unsigned blend_channel(unsigned foreground, unsigned background, unsigned inverse_alpha) {
    unsigned value = foreground + (background * inverse_alpha + 127) / 255;
    return value < 255 ? value : 255;
}

static uint32_t blend_pixel(const struct compositor *server, uint32_t source, uint32_t background) {
    unsigned alpha = source >> 24;
    if (!alpha) return background;
    if (alpha == 255) return rgb_pixel(server, source);
    unsigned inverse = 255 - alpha;
    unsigned red = blend_channel((source >> 16) & 255, (background >> server->mode.red.offset) & 255, inverse);
    unsigned green = blend_channel((source >> 8) & 255, (background >> server->mode.green.offset) & 255, inverse);
    unsigned blue = blend_channel(source & 255, (background >> server->mode.blue.offset) & 255, inverse);
    return red << server->mode.red.offset | green << server->mode.green.offset | blue << server->mode.blue.offset;
}

static void paint_cursor(void *data, int x, int y, struct wl_resource *resource,
                         int32_t hotspot_x, int32_t hotspot_y, bool visible) {
    struct compositor *server = data;
    restore_cursor(server);
    server->cursor_surface = visible ? resource : NULL;
    if (!visible) return;

    struct surface *surface = resource ? wl_resource_get_user_data(resource) : NULL;
    int width = surface ? surface->cursor_width : (int)sizeof(arrow[0]) - 1;
    int height = surface ? surface->cursor_height : (int)(sizeof(arrow) / sizeof(arrow[0]));
    if (!width || !height) return;

    int64_t left = (int64_t)x - hotspot_x;
    int64_t top = (int64_t)y - hotspot_y;
    if (surface) {
        left += surface->cursor_x;
        top += surface->cursor_y;
    }
    int64_t right = left + width, bottom = top + height;
    if (right <= 0 || bottom <= 0 || left >= server->mode.xres || top >= server->mode.yres) return;
    int first_x = left < 0 ? 0 : (int)left;
    int first_y = top < 0 ? 0 : (int)top;
    int last_x = right > server->mode.xres ? (int)server->mode.xres : (int)right;
    int last_y = bottom > server->mode.yres ? (int)server->mode.yres : (int)bottom;
    int columns = last_x - first_x;
    size_t pixels = (size_t)columns * (last_y - first_y);
    if (pixels > server->cursor_capacity) {
        uint32_t *background = realloc(server->cursor_background, pixels * sizeof(*background));
        if (!background) return;
        server->cursor_background = background;
        server->cursor_capacity = pixels;
    }

    server->cursor_x = first_x;
    server->cursor_y = first_y;
    server->cursor_width = columns;
    size_t bytes = (size_t)columns * sizeof(*server->row);
    int image_x = (int)(first_x - left);
    for (int row = first_y; row < last_y; ++row) {
        uint32_t *background = server->cursor_background + (size_t)(row - first_y) * columns;
        if (pread(server->fb, background, bytes, row_offset(server, first_x, row)) != (ssize_t)bytes) {
            perror("Read cursor background");
            break;
        }
        int image_y = (int)(row - top);
        for (int col = 0; col < columns; ++col) {
            uint32_t source = surface ? surface->cursor_pixels[(size_t)image_y * width + image_x + col]
                                      : arrow_pixel(image_x + col, image_y);
            server->row[col] = blend_pixel(server, source, background[col]);
        }
        ++server->cursor_rows;
        if (!write_pixels(server, first_x, row, columns, server->row)) {
            perror("Draw cursor");
            break;
        }
    }
}

static const struct wayland_pointer_ops pointer_ops = {
    .pick = pick_surface,
    .assign_cursor = assign_cursor,
    .paint = paint_cursor,
};

static void surface_frame(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct surface *surface = wl_resource_get_user_data(resource);
    struct frame *frame = calloc(1, sizeof(*frame));
    if (!frame) {
        wl_client_post_no_memory(client);
        return;
    }
    frame->resource = wl_resource_create(client, &wl_callback_interface, 1, id);
    if (!frame->resource) {
        free(frame);
        wl_client_post_no_memory(client);
        return;
    }
    wl_list_insert(surface->frames.prev, &frame->link);
    wl_resource_set_implementation(frame->resource, NULL, frame, frame_destroyed);
}

static void surface_scale(struct wl_client *client, struct wl_resource *resource, int32_t scale) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (scale < 1) {
        wl_resource_post_error(resource, WL_SURFACE_ERROR_INVALID_SCALE, "Invalid buffer scale");
        return;
    }
    surface->scale = scale;
}

static void surface_transform(struct wl_client *client, struct wl_resource *resource, int32_t transform) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (transform < WL_OUTPUT_TRANSFORM_NORMAL || transform > WL_OUTPUT_TRANSFORM_FLIPPED_270) {
        wl_resource_post_error(resource, WL_SURFACE_ERROR_INVALID_TRANSFORM, "Invalid buffer transform");
        return;
    }
    surface->transform = transform;
}

struct buffer_view {
    int width, height, stride, scale, transform;
    int output_width, output_height;
    bool opaque;
};

static bool read_buffer_view(struct buffer_view *view, const struct surface *surface,
                             struct wl_shm_buffer *buffer) {
    view->width = wl_shm_buffer_get_width(buffer);
    view->height = wl_shm_buffer_get_height(buffer);
    view->stride = wl_shm_buffer_get_stride(buffer);
    view->scale = surface->scale;
    view->transform = surface->transform;
    int width = view->width, height = view->height;
    if (width <= 0 || height <= 0 || view->stride < 0 || width > view->stride / 4 ||
        width % view->scale || height % view->scale) return false;
    bool swapped = view->transform % 2;
    view->output_width = (swapped ? height : width) / view->scale;
    view->output_height = (swapped ? width : height) / view->scale;
    view->opaque = wl_shm_buffer_get_format(buffer) == WL_SHM_FORMAT_XRGB8888;
    return view->opaque || wl_shm_buffer_get_format(buffer) == WL_SHM_FORMAT_ARGB8888;
}

static uint32_t sample_buffer(const struct buffer_view *view, const unsigned char *pixels, int x, int y) {
    int sx = x * view->scale, sy = y * view->scale;
    int width = view->width, height = view->height;
    if (view->transform >= WL_OUTPUT_TRANSFORM_FLIPPED)
        sx = (view->transform % 2 ? height : width) - 1 - sx;
    int px = sx, py = sy;
    /* Преобразование Wayland задаёт координаты пикселя в буфере. */
    switch (view->transform % 4) {
    case WL_OUTPUT_TRANSFORM_90: px = sy; py = height - 1 - sx; break;
    case WL_OUTPUT_TRANSFORM_180: px = width - 1 - sx; py = height - 1 - sy; break;
    case WL_OUTPUT_TRANSFORM_270: px = width - 1 - sy; py = sx; break;
    }
    uint32_t pixel;
    memcpy(&pixel, pixels + (size_t)py * view->stride + (size_t)px * 4, sizeof(pixel));
    return view->opaque ? pixel | 0xff000000u : pixel;
}

static void clear_cursor_image(struct surface *surface) {
    free(surface->cursor_pixels);
    surface->cursor_pixels = NULL;
    surface->cursor_width = 0;
    surface->cursor_height = 0;
}

static bool capture_cursor(struct surface *surface, struct wl_shm_buffer *buffer, const struct buffer_view *view) {
    int width = view->output_width, height = view->output_height;
    uint32_t *image = malloc((size_t)width * height * sizeof(*image));
    if (!image) return false;

    wl_shm_buffer_begin_access(buffer);
    const unsigned char *pixels = wl_shm_buffer_get_data(buffer);
    for (int y = 0; y < height; ++y)
        for (int x = 0; x < width; ++x)
            image[(size_t)y * width + x] = sample_buffer(view, pixels, x, y);
    wl_shm_buffer_end_access(buffer);
    clear_cursor_image(surface);
    surface->cursor_pixels = image;
    surface->cursor_width = width;
    surface->cursor_height = height;
    return true;
}

static bool present(struct surface *surface, struct wl_shm_buffer *buffer, const struct buffer_view *view) {
    struct compositor *server = surface->server;
    int output_width = view->output_width, output_height = view->output_height;
    if (output_width > (int)server->mode.xres) output_width = (int)server->mode.xres;
    if (output_height > (int)server->mode.yres) output_height = (int)server->mode.yres;
    int draw_width = output_width > server->drawn_width ? output_width : server->drawn_width;
    int draw_height = output_height > server->drawn_height ? output_height : server->drawn_height;

    restore_cursor(server);
    wl_shm_buffer_begin_access(buffer);
    const unsigned char *pixels = wl_shm_buffer_get_data(buffer);
    bool success = true;
    for (int y = 0; y < draw_height; ++y) {
        int content_width = y < output_height ? output_width : 0;
        for (int x = 0; x < content_width; ++x)
            server->row[x] = rgb_pixel(server, sample_buffer(view, pixels, x, y));
        memset(server->row + content_width, 0, (size_t)(draw_width - content_width) * sizeof(*server->row));
        if (!write_pixels(server, 0, y, draw_width, server->row)) {
            success = false;
            break;
        }
    }
    wl_shm_buffer_end_access(buffer);
    if (success) {
        server->drawn_width = output_width;
        server->drawn_height = output_height;
    }
    return success;
}

static void configure(struct surface *surface) {
    struct compositor *server = surface->server;
    uint32_t activated = XDG_TOPLEVEL_STATE_ACTIVATED;
    struct wl_array states = { .size = sizeof(activated), .data = &activated };
    surface->serial = wl_display_next_serial(server->display);
    surface->configured = true;
    xdg_toplevel_send_configure(surface->toplevel, server->mode.xres, server->mode.yres, &states);
    xdg_surface_send_configure(surface->shell, surface->serial);
}

static void surface_commit(struct wl_client *client, struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    struct compositor *server = surface->server;
    struct wl_resource *buffer = surface->buffer;
    clear_pending_buffer(surface);
    if (surface->shell && !surface->toplevel) {
        wl_resource_post_error(surface->shell, XDG_SURFACE_ERROR_NOT_CONSTRUCTED, "Missing surface role");
        return;
    }
    if (surface->toplevel && !surface->configured && !buffer) configure(surface);
    if (buffer && surface->shell && !surface->acknowledged) {
        wl_resource_post_error(surface->shell, XDG_SURFACE_ERROR_UNCONFIGURED_BUFFER, "Buffer before configure acknowledgement");
        return;
    }
    bool repaint = false;
    if (surface->input_pending) {
        wl_array_release(&surface->input_region);
        surface->input_region = surface->pending_input_region;
        wl_array_init(&surface->pending_input_region);
        surface->input_set = surface->pending_input_set;
        surface->input_pending = false;
        repaint = server->visible == surface;
    }
    if (buffer) {
        struct wl_shm_buffer *shm = wl_shm_buffer_get(buffer);
        struct buffer_view view;
        if (!shm || !read_buffer_view(&view, surface, shm)) {
            wl_client_post_implementation_error(client, "Unsupported shared memory buffer");
            return;
        }
        if (surface->toplevel) {
            if (!present(surface, shm, &view)) {
                wl_client_post_implementation_error(client, "Could not display shared memory buffer");
                return;
            }
            server->visible = surface;
            surface->mapped = true;
            wayland_seat_keyboard_focus(server->seat, resource);
            repaint = true;
        } else if (surface->role != SURFACE_XDG) {
            /* Изображение может быть готово к моменту назначения роли курсора. */
            if (!capture_cursor(surface, shm, &view)) {
                wl_client_post_no_memory(client);
                return;
            }
        }
        wl_buffer_send_release(buffer);
    } else if (surface->detach) {
        if (surface->mapped) {
            hide_surface(surface);
            surface->configured = false;
            surface->acknowledged = false;
            repaint = false;
        }
        clear_cursor_image(surface);
    }
    if (surface->role == SURFACE_CURSOR && (buffer || surface->detach)) {
        /* В wl_surface версии 4 смещение задаётся аргументами attach. */
        if (surface->cursor_x > INT64_MIN / 2 && surface->cursor_x < INT64_MAX / 2)
            surface->cursor_x += surface->attach_x;
        if (surface->cursor_y > INT64_MIN / 2 && surface->cursor_y < INT64_MAX / 2)
            surface->cursor_y += surface->attach_y;
        repaint |= server->cursor_surface == resource;
    }
    surface->detach = false;
    if (repaint) wayland_seat_pointer_update(server->seat);

    if (server->visible == surface || surface->role == SURFACE_CURSOR) {
        struct timespec time = {0};
        clock_gettime(CLOCK_MONOTONIC, &time);
        uint32_t ms = (uint32_t)time.tv_sec * 1000 + (uint32_t)(time.tv_nsec / 1000000);
        struct frame *frame, *next;
        wl_list_for_each_safe(frame, next, &surface->frames, link) {
            wl_callback_send_done(frame->resource, ms);
            wl_resource_destroy(frame->resource);
        }
    }
}

static const struct wl_surface_interface surface_requests = {
    .destroy = destroy_surface_request,
    .attach = surface_attach,
    .damage = rectangle_request,
    .frame = surface_frame,
    .set_opaque_region = region_request,
    .set_input_region = set_input_region,
    .commit = surface_commit,
    .set_buffer_transform = surface_transform,
    .set_buffer_scale = surface_scale,
    .damage_buffer = rectangle_request,
};

static void create_surface(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct surface *surface = calloc(1, sizeof(*surface));
    if (!surface) {
        wl_client_post_no_memory(client);
        return;
    }
    struct wl_resource *child = wl_resource_create(client, &wl_surface_interface, wl_resource_get_version(resource), id);
    if (!child) {
        free(surface);
        wl_client_post_no_memory(client);
        return;
    }
    surface->server = wl_resource_get_user_data(resource);
    surface->resource = child;
    surface->buffer_destroy.notify = buffer_destroyed;
    surface->scale = 1;
    wl_list_init(&surface->frames);
    wl_array_init(&surface->input_region);
    wl_array_init(&surface->pending_input_region);
    wl_resource_set_implementation(child, &surface_requests, surface, surface_destroyed);
}

static void region_destroyed(struct wl_resource *resource) {
    struct wl_array *rects = wl_resource_get_user_data(resource);
    wl_array_release(rects);
    free(rects);
}

static void change_region(struct wl_client *client, struct wl_resource *resource,
                          int32_t x, int32_t y, int32_t width, int32_t height, bool add) {
    if (width <= 0 || height <= 0) return;
    struct region_rect *rect = wl_array_add(wl_resource_get_user_data(resource), sizeof(*rect));
    if (!rect) {
        wl_client_post_no_memory(client);
        return;
    }
    *rect = (struct region_rect){x, y, width, height, add};
}

static void add_region(struct wl_client *client, struct wl_resource *resource,
                       int32_t x, int32_t y, int32_t width, int32_t height) {
    change_region(client, resource, x, y, width, height, true);
}

static void subtract_region(struct wl_client *client, struct wl_resource *resource,
                            int32_t x, int32_t y, int32_t width, int32_t height) {
    change_region(client, resource, x, y, width, height, false);
}

static const struct wl_region_interface region_requests = {
    .destroy = destroy_request,
    .add = add_region,
    .subtract = subtract_region,
};

static void create_region(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    (void)resource;
    struct wl_array *rects = malloc(sizeof(*rects));
    if (!rects) {
        wl_client_post_no_memory(client);
        return;
    }
    struct wl_resource *region = wl_resource_create(client, &wl_region_interface, 1, id);
    if (region) {
        wl_array_init(rects);
        wl_resource_set_implementation(region, &region_requests, rects, region_destroyed);
    } else {
        free(rects);
        wl_client_post_no_memory(client);
    }
}

static const struct wl_compositor_interface compositor_requests = {
    .create_surface = create_surface,
    .create_region = create_region,
};

static void bind_compositor(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wl_resource *resource = wl_resource_create(client, &wl_compositor_interface, version, id);
    if (resource) wl_resource_set_implementation(resource, &compositor_requests, data, NULL);
    else wl_client_post_no_memory(client);
}

static void bind_output(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct compositor *server = data;
    struct wl_resource *resource = wl_resource_create(client, &wl_output_interface, version, id);
    if (!resource) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(resource, NULL, NULL, NULL);
    wl_output_send_geometry(resource, 0, 0, 0, 0, WL_OUTPUT_SUBPIXEL_UNKNOWN,
                            "MyOS", "GOP", WL_OUTPUT_TRANSFORM_NORMAL);
    wl_output_send_mode(resource, WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED,
                        server->mode.xres, server->mode.yres, 60000);
    if (version >= 2) {
        wl_output_send_scale(resource, 1);
        wl_output_send_done(resource);
    }
}

static void toplevel_text(struct wl_client *client, struct wl_resource *resource, const char *text) {
    (void)client;
    (void)resource;
    (void)text;
}

static void toplevel_size(struct wl_client *client, struct wl_resource *resource, int32_t width, int32_t height) {
    (void)client;
    if (width < 0 || height < 0)
        wl_resource_post_error(resource, XDG_TOPLEVEL_ERROR_INVALID_SIZE, "Negative size limit");
}

static void toplevel_state(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    (void)resource;
}

static void toplevel_move(struct wl_client *client, struct wl_resource *resource,
                          struct wl_resource *seat, uint32_t serial) {
    (void)serial;
    region_request(client, resource, seat);
}

static void toplevel_resize(struct wl_client *client, struct wl_resource *resource,
                            struct wl_resource *seat, uint32_t serial, uint32_t edges) {
    (void)edges;
    toplevel_move(client, resource, seat, serial);
}

static void toplevel_menu(struct wl_client *client, struct wl_resource *resource,
                          struct wl_resource *seat, uint32_t serial, int32_t x, int32_t y) {
    (void)x;
    (void)y;
    toplevel_move(client, resource, seat, serial);
}

static const struct xdg_toplevel_interface toplevel_requests = {
    .destroy = destroy_request,
    .set_parent = region_request,
    .set_title = toplevel_text,
    .set_app_id = toplevel_text,
    .show_window_menu = toplevel_menu,
    .move = toplevel_move,
    .resize = toplevel_resize,
    .set_max_size = toplevel_size,
    .set_min_size = toplevel_size,
    .set_maximized = toplevel_state,
    .unset_maximized = toplevel_state,
    .set_fullscreen = region_request,
    .unset_fullscreen = toplevel_state,
    .set_minimized = toplevel_state,
};

static void destroy_shell_surface(struct wl_client *client, struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->toplevel) {
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_DEFUNCT_ROLE_OBJECT, "Destroy toplevel first");
        return;
    }
    destroy_request(client, resource);
}

static void get_toplevel(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->toplevel) {
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_ALREADY_CONSTRUCTED, "Surface already has a role");
        return;
    }
    surface->toplevel = wl_resource_create(client, &xdg_toplevel_interface, wl_resource_get_version(resource), id);
    if (!surface->toplevel) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(surface->toplevel, &toplevel_requests, surface, toplevel_destroyed);
}

static void get_popup(struct wl_client *client, struct wl_resource *resource, uint32_t id,
                      struct wl_resource *parent, struct wl_resource *positioner) {
    (void)resource;
    (void)id;
    (void)parent;
    (void)positioner;
    wl_client_post_implementation_error(client, "Popups are unavailable");
}

static void window_geometry(struct wl_client *client, struct wl_resource *resource,
                            int32_t x, int32_t y, int32_t width, int32_t height) {
    (void)client;
    (void)x;
    (void)y;
    if (width <= 0 || height <= 0)
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_INVALID_SIZE, "Empty window geometry");
}

static void ack_configure(struct wl_client *client, struct wl_resource *resource, uint32_t serial) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (!surface->configured || surface->acknowledged || serial != surface->serial) {
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_INVALID_SERIAL, "Unknown configure serial");
        return;
    }
    surface->acknowledged = true;
}

static const struct xdg_surface_interface shell_surface_requests = {
    .destroy = destroy_shell_surface,
    .get_toplevel = get_toplevel,
    .get_popup = get_popup,
    .set_window_geometry = window_geometry,
    .ack_configure = ack_configure,
};

static void get_shell_surface(struct wl_client *client, struct wl_resource *resource, uint32_t id,
                              struct wl_resource *parent) {
    struct surface *surface = wl_resource_get_user_data(parent);
    if (surface->role == SURFACE_CURSOR || surface->shell) {
        wl_resource_post_error(resource, XDG_WM_BASE_ERROR_ROLE, "Surface already has a role");
        return;
    }
    surface->shell = wl_resource_create(client, &xdg_surface_interface, wl_resource_get_version(resource), id);
    if (!surface->shell) {
        wl_client_post_no_memory(client);
        return;
    }
    surface->role = SURFACE_XDG;
    clear_cursor_image(surface);
    wl_resource_set_implementation(surface->shell, &shell_surface_requests, surface, shell_surface_destroyed);
}

static void create_positioner(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    (void)resource;
    (void)id;
    wl_client_post_implementation_error(client, "Popup positioners are unavailable");
}

static void pong(struct wl_client *client, struct wl_resource *resource, uint32_t serial) {
    (void)client;
    (void)resource;
    (void)serial;
}

static const struct xdg_wm_base_interface shell_requests = {
    .destroy = destroy_request,
    .create_positioner = create_positioner,
    .get_xdg_surface = get_shell_surface,
    .pong = pong,
};

static void bind_shell(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wl_resource *resource = wl_resource_create(client, &xdg_wm_base_interface, version, id);
    if (resource) wl_resource_set_implementation(resource, &shell_requests, data, NULL);
    else wl_client_post_no_memory(client);
}

static int open_listener(struct wl_display *display, const char *path) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    size_t length = strlen(path) + 1;
    if (length > sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(address.sun_path, path, length);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&address, offsetof(struct sockaddr_un, sun_path) + length)) {
        close(fd);
        return -1;
    }
    if (listen(fd, 8) || wl_display_add_socket_fd(display, fd)) {
        close(fd);
        unlink(path);
        return -1;
    }
    return 0;
}

static bool color_supported(struct fb_bitfield color) {
    return color.length == 8 && color.offset <= 24 && !color.msb_right;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fputs("Usage: wayland-compositor /path/to/wayland-socket [keymap.xkb]\n", stderr);
        return 2;
    }
    struct compositor server = { .fb = open("/dev/fb0", O_RDWR | O_CLOEXEC) };
    if (server.fb < 0 || ioctl(server.fb, FBIOGET_VSCREENINFO, &server.mode) ||
        ioctl(server.fb, FBIOGET_FSCREENINFO, &server.layout)) {
        perror("/dev/fb0");
        return 1;
    }
    if (server.mode.bits_per_pixel != 32 || !server.mode.xres || !server.mode.yres ||
        server.mode.xres > INT_MAX || server.mode.yres > INT_MAX ||
        server.mode.xres > server.layout.line_length / 4 ||
        (uint64_t)server.mode.yres * server.layout.line_length > server.layout.smem_len ||
        !color_supported(server.mode.red) || !color_supported(server.mode.green) ||
        !color_supported(server.mode.blue) || server.mode.red.offset == server.mode.green.offset ||
        server.mode.red.offset == server.mode.blue.offset || server.mode.green.offset == server.mode.blue.offset) {
        fputs("Unsupported framebuffer configuration\n", stderr);
        return 1;
    }
    server.row = malloc((size_t)server.mode.xres * sizeof(*server.row));
    server.display = wl_display_create();
    if (!server.row || !server.display || wl_display_init_shm(server.display) ||
        !wl_global_create(server.display, &wl_compositor_interface, 4, &server, bind_compositor) ||
        !wl_global_create(server.display, &wl_output_interface, 2, &server, bind_output) ||
        !wl_global_create(server.display, &xdg_wm_base_interface, 1, &server, bind_shell)) {
        fputs("Could not initialize Wayland display\n", stderr);
        return 1;
    }
    if (open_listener(server.display, argv[1])) {
        perror(argv[1]);
        return 1;
    }

    const char *keymap = argc == 3 ? argv[2] : "/myos/keyboard.xkb";
    if (argc == 2 && access(keymap, R_OK)) keymap = NULL;
    if (!wayland_seat_init(&server.seat, server.display, keymap, (int)server.mode.xres,
                           (int)server.mode.yres, &pointer_ops, &server)) {
        unlink(argv[1]);
        return 1;
    }
    wayland_seat_pointer_update(server.seat);

    struct sigaction action = { .sa_handler = stop };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) {
        perror("sigaction");
        unlink(argv[1]);
        return 1;
    }
    struct wl_event_loop *loop = wl_display_get_event_loop(server.display);
    int status = 0;
    while (!stopping) {
        wl_display_flush_clients(server.display);
        if (wl_event_loop_dispatch(loop, 250) < 0 && errno != EINTR) {
            perror("Wayland event loop");
            status = 1;
            break;
        }
    }
    wl_display_destroy_clients(server.display);
    wayland_seat_destroy(server.seat);
    restore_cursor(&server);
    wl_display_destroy(server.display);
    unlink(argv[1]);
    free(server.cursor_background);
    free(server.row);
    close(server.fb);
    return status;
}
