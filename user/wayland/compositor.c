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
    struct wl_list popups, shell_surfaces;
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

struct rectangle {
    int32_t x, y, width, height;
};

struct positioner {
    struct rectangle anchor_rect;
    int32_t width, height, offset_x, offset_y;
    uint32_t anchor, gravity, adjustment;
};

struct image {
    uint32_t *pixels;
    int width, height;
    bool opaque;
};

enum surface_role { SURFACE_NONE, SURFACE_XDG, SURFACE_CURSOR, SURFACE_SUBSURFACE };
enum layer_state { LAYER_PENDING, LAYER_CACHED, LAYER_CURRENT, LAYER_STATES };

struct layer {
    struct wl_list link;
    struct surface *surface;
    int32_t x, y;
};
enum xdg_role { XDG_NONE, XDG_TOPLEVEL, XDG_POPUP };

struct surface {
    struct compositor *server;
    struct wl_resource *resource;
    struct wl_resource *shell;
    struct wl_resource *toplevel;
    struct wl_resource *popup;
    struct wl_resource *subsurface;
    struct wl_resource *wm_base;
    struct wl_listener wm_base_destroy;
    struct wl_list popup_link, shell_link;
    struct surface *parent;
    struct positioner positioner;
    struct rectangle placement, geometry, pending_geometry;
    struct image image, cursor_image, cached_image;
    struct wl_list layers[LAYER_STATES];
    struct layer own_layer[LAYER_STATES], child_layer[LAYER_STATES];
    int64_t x, y;
    bool geometry_pending, dismissed;
    struct wl_resource *buffer;
    struct wl_listener buffer_destroy;
    struct wl_list frames, cached_frames, presented_frames;
    struct wl_array input_region, pending_input_region, cached_input_region;
    bool layers_pending, layers_cached, sync, commit_cached, buffer_cached;
    bool input_cached, cached_input_set;
    int32_t attach_x, attach_y;
    int64_t cursor_x, cursor_y;
    uint32_t serial;
    enum surface_role role;
    enum xdg_role xdg_role;
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

static bool redraw(struct compositor *server);
static bool shown(const struct surface *surface);
static void orphan_subsurface(struct surface *surface);

static void clear_image(struct image *image) {
    free(image->pixels);
    *image = (struct image){0};
}

static bool popup_descends_from(const struct surface *popup, const struct surface *ancestor) {
    for (const struct surface *parent = popup->parent; parent; parent = parent->parent)
        if (parent == ancestor) return true;
    return false;
}

static void detach_pointer_tree(struct surface *surface) {
    wayland_seat_pointer_detach(surface->server->seat, surface->resource);
    struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_CURRENT], link)
        if (layer->surface) detach_pointer_tree(layer->surface);
}

static void hide_surface(struct surface *surface) {
    struct compositor *server = surface->server;
    struct surface *child;
    bool repaint = surface->mapped && (surface->popup || server->visible == surface);
    wl_list_for_each_reverse(child, &server->popups, popup_link) {
        if (!child->dismissed && popup_descends_from(child, surface)) {
            xdg_popup_send_popup_done(child->popup);
            child->dismissed = true;
            child->mapped = false;
            clear_image(&child->image);
            detach_pointer_tree(child);
        }
    }
    surface->mapped = false;
    clear_image(&surface->image);
    detach_pointer_tree(surface);
    if (server->visible == surface) {
        server->visible = NULL;
        wayland_seat_keyboard_focus(server->seat, NULL);
    }
    if (repaint) {
        if (!redraw(server)) perror("Redraw framebuffer");
        wayland_seat_pointer_update(server->seat);
    }
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

static void popup_destroyed(struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    hide_surface(surface);
    wl_list_remove(&surface->popup_link);
    surface->parent = NULL;
    surface->popup = NULL;
    surface->configured = false;
    surface->acknowledged = false;
}

static void wm_base_destroyed(struct wl_listener *listener, void *data) {
    (void)data;
    struct surface *surface = wl_container_of(listener, surface, wm_base_destroy);
    wl_list_remove(&listener->link);
    surface->wm_base = NULL;
}

static void shell_surface_destroyed(struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->toplevel) wl_resource_destroy(surface->toplevel);
    if (surface->popup) wl_resource_destroy(surface->popup);
    if (surface->wm_base) wl_list_remove(&surface->wm_base_destroy.link);
    wl_list_remove(&surface->shell_link);
    surface->wm_base = NULL;
    surface->shell = NULL;
    surface->geometry = (struct rectangle){0};
    surface->geometry_pending = false;
}

static void destroy_frames(struct wl_list *frames) {
    struct frame *frame, *next;
    wl_list_for_each_safe(frame, next, frames, link) wl_resource_destroy(frame->resource);
}

static void surface_destroyed(struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->subsurface) {
        wl_resource_set_user_data(surface->subsurface, NULL);
        orphan_subsurface(surface);
    }
    struct layer *layer, *next_layer;
    wl_list_for_each_safe(layer, next_layer, &surface->layers[LAYER_PENDING], link)
        if (layer->surface) orphan_subsurface(layer->surface);
    if (surface->server->cursor_surface == resource) surface->server->cursor_surface = NULL;
    if (surface->shell) wl_resource_destroy(surface->shell);
    struct surface *child;
    wl_list_for_each(child, &surface->server->popups, popup_link)
        if (child->parent == surface) child->parent = NULL;
    clear_pending_buffer(surface);
    destroy_frames(&surface->frames);
    destroy_frames(&surface->cached_frames);
    destroy_frames(&surface->presented_frames);
    wl_array_release(&surface->input_region);
    wl_array_release(&surface->pending_input_region);
    wl_array_release(&surface->cached_input_region);
    clear_image(&surface->cached_image);
    clear_image(&surface->cursor_image);
    clear_image(&surface->image);
    free(surface);
}

static void destroy_surface_request(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (!surface->subsurface) hide_surface(surface);
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

static bool shown(const struct surface *surface) {
    const struct surface *root = surface;
    for (; root->parent; root = root->parent) {
        if (!root->mapped ||
            (root->role == SURFACE_SUBSURFACE && wl_list_empty(&root->child_layer[LAYER_CURRENT].link)))
            return false;
    }
    return root->mapped && root == surface->server->visible;
}

static bool accepts_pointer(const struct surface *surface, int x, int y) {
    int64_t local_x = x - surface->x, local_y = y - surface->y;
    if (local_x < 0 || local_y < 0 || local_x >= surface->image.width || local_y >= surface->image.height)
        return false;
    if (!surface->input_set) return true;

    bool inside = false;
    const struct region_rect *rect;
    wl_array_for_each(rect, &surface->input_region) {
        if (local_x >= rect->x && local_y >= rect->y && local_x - rect->x < rect->width &&
            local_y - rect->y < rect->height) inside = rect->add;
    }
    return inside;
}

static struct wl_resource *pick_surface_tree(struct surface *surface, int x, int y) {
    if (!surface->mapped) return NULL;
    struct layer *layer;
    wl_list_for_each_reverse(layer, &surface->layers[LAYER_CURRENT], link) {
        if (layer->surface) {
            struct wl_resource *child = pick_surface_tree(layer->surface, x, y);
            if (child) return child;
        } else if (accepts_pointer(surface, x, y)) {
            return surface->resource;
        }
    }
    return NULL;
}

static struct wl_resource *pick_surface(void *data, int x, int y) {
    struct compositor *server = data;
    struct surface *surface;
    wl_list_for_each_reverse(surface, &server->popups, popup_link) {
        if (!shown(surface)) continue;
        struct wl_resource *target = pick_surface_tree(surface, x, y);
        if (target) return target;
    }
    return server->visible ? pick_surface_tree(server->visible, x, y) : NULL;
}

static wl_fixed_t local_coordinate(int64_t value) {
    if (value < INT32_MIN / 256) return INT32_MIN;
    if (value > INT32_MAX / 256) return INT32_MAX;
    return wl_fixed_from_int((int)value);
}

static void pointer_coordinates(struct wl_resource *resource, int x, int y, wl_fixed_t *sx, wl_fixed_t *sy) {
    struct surface *surface = wl_resource_get_user_data(resource);
    *sx = local_coordinate(x - surface->x);
    *sy = local_coordinate(y - surface->y);
}

static bool assign_cursor(void *data, struct wl_resource *resource) {
    (void)data;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->role != SURFACE_NONE && surface->role != SURFACE_CURSOR) return false;
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
    int width = surface ? surface->cursor_image.width : (int)sizeof(arrow[0]) - 1;
    int height = surface ? surface->cursor_image.height : (int)(sizeof(arrow) / sizeof(arrow[0]));
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
            uint32_t source = surface ? surface->cursor_image.pixels[(size_t)image_y * width + image_x + col]
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
    .coordinates = pointer_coordinates,
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

static bool capture_image(struct image *image, struct wl_shm_buffer *buffer, const struct buffer_view *view,
                          int width, int height) {
    if ((size_t)width > SIZE_MAX / sizeof(uint32_t) / (size_t)height) return false;
    uint32_t *pixels = image->pixels;
    if (image->width != width || image->height != height) {
        pixels = realloc(pixels, (size_t)width * height * sizeof(*pixels));
        if (!pixels) return false;
    }
    wl_shm_buffer_begin_access(buffer);
    const unsigned char *data = wl_shm_buffer_get_data(buffer);
    for (int y = 0; y < height; ++y)
        for (int x = 0; x < width; ++x)
            pixels[(size_t)y * width + x] = sample_buffer(view, data, x, y);
    wl_shm_buffer_end_access(buffer);
    *image = (struct image){ pixels, width, height, view->opaque };
    return true;
}

static void add_extent(const struct surface *surface, int screen_width, int screen_height,
                       int *width, int *height) {
    int64_t right = surface->x + surface->image.width;
    int64_t bottom = surface->y + surface->image.height;
    if (right > *width) *width = right > screen_width ? screen_width : (int)right;
    if (bottom > *height) *height = bottom > screen_height ? screen_height : (int)bottom;
    const struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_CURRENT], link)
        if (layer->surface && layer->surface->mapped)
            add_extent(layer->surface, screen_width, screen_height, width, height);
}

static void paint_surface_row(struct compositor *server, const struct surface *surface, int y, int width) {
    int64_t row = y - surface->y;
    if (row < 0 || row >= surface->image.height) return;
    int64_t left = surface->x > 0 ? surface->x : 0;
    int64_t right = surface->x + surface->image.width;
    if (right > width) right = width;
    if (left >= right) return;
    const uint32_t *pixels = surface->image.pixels + (size_t)row * surface->image.width;
    if (surface->image.opaque) {
        for (int x = (int)left; x < right; ++x)
            server->row[x] = rgb_pixel(server, pixels[x - surface->x]);
    } else {
        for (int x = (int)left; x < right; ++x)
            server->row[x] = blend_pixel(server, pixels[x - surface->x], server->row[x]);
    }
}

static void paint_tree_row(struct compositor *server, const struct surface *surface, int y, int width) {
    if (!surface->mapped) return;
    const struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_CURRENT], link) {
        if (layer->surface) paint_tree_row(server, layer->surface, y, width);
        else paint_surface_row(server, surface, y, width);
    }
}

static void update_child_origins(struct surface *surface) {
    struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_CURRENT], link) {
        struct surface *child = layer->surface;
        if (!child) continue;
        child->x = surface->x + layer->x;
        child->y = surface->y + layer->y;
        update_child_origins(child);
    }
}

static void update_popup_origins(struct compositor *server);

static bool redraw(struct compositor *server) {
    update_popup_origins(server);
    if (server->visible) update_child_origins(server->visible);
    int width = 0, height = 0;
    struct surface *popup;
    if (server->visible)
        add_extent(server->visible, server->mode.xres, server->mode.yres, &width, &height);
    wl_list_for_each(popup, &server->popups, popup_link) {
        if (shown(popup)) {
            update_child_origins(popup);
            add_extent(popup, server->mode.xres, server->mode.yres, &width, &height);
        }
    }
    int draw_width = width > server->drawn_width ? width : server->drawn_width;
    int draw_height = height > server->drawn_height ? height : server->drawn_height;

    restore_cursor(server);
    for (int y = 0; y < draw_height; ++y) {
        memset(server->row, 0, (size_t)draw_width * sizeof(*server->row));
        if (server->visible) paint_tree_row(server, server->visible, y, draw_width);
        wl_list_for_each(popup, &server->popups, popup_link)
            if (shown(popup)) paint_tree_row(server, popup, y, draw_width);
        if (!write_pixels(server, 0, y, draw_width, server->row)) return false;
    }
    server->drawn_width = width;
    server->drawn_height = height;
    return true;
}

static void update_popup_origins(struct compositor *server) {
    struct surface *popup;
    wl_list_for_each(popup, &server->popups, popup_link) {
        if (!popup->parent) continue;
        popup->x = popup->parent->x + popup->parent->geometry.x + popup->placement.x - popup->geometry.x;
        popup->y = popup->parent->y + popup->parent->geometry.y + popup->placement.y - popup->geometry.y;
    }
}

static bool configure_popup(struct surface *surface);
static bool topmost_popup(const struct surface *surface);

static bool configure(struct surface *surface) {
    struct compositor *server = surface->server;
    uint32_t activated = XDG_TOPLEVEL_STATE_ACTIVATED;
    struct wl_array states = { .size = sizeof(activated), .data = &activated };
    surface->serial = wl_display_next_serial(server->display);
    surface->configured = true;
    if (surface->popup) {
        if (!configure_popup(surface)) return false;
    } else {
        xdg_toplevel_send_configure(surface->toplevel, server->mode.xres, server->mode.yres, &states);
    }
    xdg_surface_send_configure(surface->shell, surface->serial);
    return true;
}

static void copy_layers(struct surface *surface, enum layer_state from, enum layer_state to) {
    struct wl_list *tail = &surface->layers[to];
    const struct layer *layer;
    wl_list_for_each(layer, &surface->layers[from], link) {
        struct layer *target = layer->surface ? &layer->surface->child_layer[to] : &surface->own_layer[to];
        target->x = layer->x;
        target->y = layer->y;
        wl_list_remove(&target->link);
        wl_list_insert(tail, &target->link);
        tail = &target->link;
    }
}

static bool effectively_synchronized(const struct surface *surface) {
    for (; surface->role == SURFACE_SUBSURFACE && surface->parent; surface = surface->parent)
        if (surface->sync) return true;
    return false;
}

static void move_frames(struct wl_list *from, struct wl_list *to) {
    if (!wl_list_empty(from)) {
        wl_list_insert_list(to->prev, from);
        wl_list_init(from);
    }
}

static bool apply_subsurface(struct surface *surface) {
    if (!surface->commit_cached) return false;
    surface->commit_cached = false;
    if (surface->buffer_cached) {
        if (surface->mapped && !surface->cached_image.pixels) detach_pointer_tree(surface);
        clear_image(&surface->image);
        surface->image = surface->cached_image;
        surface->cached_image = (struct image){0};
        surface->mapped = surface->image.pixels != NULL;
        surface->buffer_cached = false;
    }
    if (surface->input_cached) {
        wl_array_release(&surface->input_region);
        surface->input_region = surface->cached_input_region;
        wl_array_init(&surface->cached_input_region);
        surface->input_set = surface->cached_input_set;
        surface->input_cached = false;
    }
    if (surface->layers_cached) {
        copy_layers(surface, LAYER_CACHED, LAYER_CURRENT);
        surface->layers_cached = false;
    }
    move_frames(&surface->cached_frames, &surface->presented_frames);
    return true;
}

static bool apply_child_commits(struct surface *surface, bool synchronized) {
    bool changed = false;
    struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_CURRENT], link) {
        struct surface *child = layer->surface;
        if (!child || (!synchronized && !child->sync)) continue;
        changed |= apply_subsurface(child);
        changed |= apply_child_commits(child, true);
    }
    return changed;
}

static void complete_frames(struct wl_list *frames, uint32_t ms) {
    struct frame *frame, *next;
    wl_list_for_each_safe(frame, next, frames, link) {
        wl_callback_send_done(frame->resource, ms);
        wl_resource_destroy(frame->resource);
    }
}

static void complete_child_frames(struct surface *surface, uint32_t ms) {
    if (!surface->mapped) return;
    complete_frames(&surface->presented_frames, ms);
    struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_CURRENT], link)
        if (layer->surface) complete_child_frames(layer->surface, ms);
}

static uint32_t frame_time(void) {
    struct timespec time = {0};
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint32_t)time.tv_sec * 1000 + (uint32_t)(time.tv_nsec / 1000000);
}

static bool present_changes(struct wl_client *client, struct compositor *server) {
    if (!redraw(server)) {
        wl_client_post_implementation_error(client, "Could not redraw shared memory buffers");
        return false;
    }
    wayland_seat_pointer_update(server->seat);
    uint32_t ms = frame_time();
    if (server->visible) complete_child_frames(server->visible, ms);
    struct surface *popup;
    wl_list_for_each(popup, &server->popups, popup_link)
        if (shown(popup)) complete_child_frames(popup, ms);
    return true;
}

static void commit_subsurface(struct wl_client *client, struct surface *surface,
                              struct wl_resource *buffer) {
    struct compositor *server = surface->server;
    if (buffer) {
        struct wl_shm_buffer *shm = wl_shm_buffer_get(buffer);
        struct buffer_view view;
        if (!shm || !read_buffer_view(&view, surface, shm) ||
            view.output_width > 2LL * server->mode.xres || view.output_height > 2LL * server->mode.yres) {
            wl_client_post_implementation_error(client, "Unsupported subsurface buffer");
            return;
        }
        if (!capture_image(&surface->cached_image, shm, &view, view.output_width, view.output_height)) {
            wl_client_post_no_memory(client);
            return;
        }
        wl_buffer_send_release(buffer);
    } else if (surface->detach) {
        clear_image(&surface->cached_image);
    }
    surface->buffer_cached |= buffer || surface->detach;
    surface->detach = false;
    if (surface->input_pending) {
        wl_array_release(&surface->cached_input_region);
        surface->cached_input_region = surface->pending_input_region;
        wl_array_init(&surface->pending_input_region);
        surface->cached_input_set = surface->pending_input_set;
        surface->input_cached = true;
        surface->input_pending = false;
    }
    if (surface->layers_pending) {
        copy_layers(surface, LAYER_PENDING, LAYER_CACHED);
        surface->layers_pending = false;
        surface->layers_cached = true;
    }
    move_frames(&surface->frames, &surface->cached_frames);
    surface->commit_cached = true;
    if (!effectively_synchronized(surface)) {
        bool repaint = shown(surface);
        apply_subsurface(surface);
        apply_child_commits(surface, false);
        if (repaint || shown(surface)) present_changes(client, server);
    }
}

static void surface_commit(struct wl_client *client, struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    struct compositor *server = surface->server;
    struct wl_resource *buffer = surface->buffer;
    clear_pending_buffer(surface);
    if (surface->role == SURFACE_SUBSURFACE) {
        if (surface->parent) commit_subsurface(client, surface, buffer);
        else if (buffer) wl_buffer_send_release(buffer);
        return;
    }
    if (surface->shell && !surface->toplevel && !surface->popup) {
        wl_resource_post_error(surface->shell, XDG_SURFACE_ERROR_NOT_CONSTRUCTED, "Missing surface role");
        return;
    }
    if (surface->dismissed) {
        if (buffer) wl_buffer_send_release(buffer);
        surface->detach = false;
        return;
    }
    if ((surface->toplevel || surface->popup) && !surface->configured && !buffer && !configure(surface)) return;
    if (buffer && surface->shell && !surface->acknowledged) {
        wl_resource_post_error(surface->shell, XDG_SURFACE_ERROR_UNCONFIGURED_BUFFER, "Buffer before configure acknowledgement");
        return;
    }
    if (buffer && surface->popup && (!surface->parent || !surface->parent->mapped)) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_INVALID_POPUP_PARENT, "Map popup parent first");
        return;
    }
    if (buffer && surface->popup && !surface->mapped && !topmost_popup(surface)) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_NOT_THE_TOPMOST_POPUP, "Map topmost popup first");
        return;
    }
    bool repaint = false, recomposite = false;
    if (surface->geometry_pending) {
        surface->geometry = surface->pending_geometry;
        surface->geometry_pending = false;
        recomposite = shown(surface);
    }
    if (surface->input_pending) {
        wl_array_release(&surface->input_region);
        surface->input_region = surface->pending_input_region;
        wl_array_init(&surface->pending_input_region);
        surface->input_set = surface->pending_input_set;
        surface->input_pending = false;
        repaint = shown(surface);
    }
    if (buffer) {
        struct wl_shm_buffer *shm = wl_shm_buffer_get(buffer);
        struct buffer_view view;
        if (!shm || !read_buffer_view(&view, surface, shm)) {
            wl_client_post_implementation_error(client, "Unsupported shared memory buffer");
            return;
        }
        if (surface->toplevel || surface->popup) {
            int width = view.output_width, height = view.output_height;
            if (surface->toplevel) {
                if (width > (int)server->mode.xres) width = (int)server->mode.xres;
                if (height > (int)server->mode.yres) height = (int)server->mode.yres;
            } else if (width > 2LL * server->mode.xres || height > 2LL * server->mode.yres) {
                /* Снимок хранится после release. Предел оставляет место для теней и обрезки у края. */
                wl_client_post_implementation_error(client, "Popup buffer exceeds output bounds");
                return;
            }
            if (!capture_image(&surface->image, shm, &view, width, height)) {
                wl_client_post_no_memory(client);
                return;
            }
            if (surface->toplevel && (!surface->mapped || !server->visible)) {
                server->visible = surface;
                wayland_seat_keyboard_focus(server->seat, resource);
            }
            surface->mapped = true;
            recomposite = shown(surface);
        } else if (surface->role != SURFACE_XDG) {
            /* Изображение может быть готово к моменту назначения роли курсора. */
            if (!capture_image(&surface->cursor_image, shm, &view, view.output_width, view.output_height)) {
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
            recomposite = false;
        }
        clear_image(&surface->cursor_image);
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
    if (surface->layers_pending) {
        copy_layers(surface, LAYER_PENDING, LAYER_CURRENT);
        surface->layers_pending = false;
        recomposite |= shown(surface);
    }
    if (apply_child_commits(surface, false)) recomposite |= shown(surface);
    if (recomposite && !present_changes(client, server)) return;
    if (repaint && !recomposite) wayland_seat_pointer_update(server->seat);
    if (shown(surface) || surface->role == SURFACE_CURSOR)
        complete_frames(&surface->frames, frame_time());
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
    wl_list_init(&surface->cached_frames);
    wl_list_init(&surface->presented_frames);
    wl_array_init(&surface->input_region);
    wl_array_init(&surface->pending_input_region);
    wl_array_init(&surface->cached_input_region);
    for (unsigned i = 0; i < LAYER_STATES; ++i) {
        wl_list_init(&surface->layers[i]);
        wl_list_init(&surface->child_layer[i].link);
        surface->child_layer[i].surface = surface;
        wl_list_insert(&surface->layers[i], &surface->own_layer[i].link);
    }
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
    if (surface->toplevel || surface->popup) {
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_DEFUNCT_ROLE_OBJECT, "Destroy role object first");
        return;
    }
    destroy_request(client, resource);
}

static void get_toplevel(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->toplevel || surface->popup) {
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_ALREADY_CONSTRUCTED, "Surface already has a role");
        return;
    }
    if (surface->xdg_role == XDG_POPUP) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_ROLE, "Popup cannot become a toplevel");
        return;
    }
    surface->toplevel = wl_resource_create(client, &xdg_toplevel_interface, wl_resource_get_version(resource), id);
    if (!surface->toplevel) {
        wl_client_post_no_memory(client);
        return;
    }
    surface->xdg_role = XDG_TOPLEVEL;
    wl_resource_set_implementation(surface->toplevel, &toplevel_requests, surface, toplevel_destroyed);
}

static void positioner_size(struct wl_client *client, struct wl_resource *resource, int32_t width, int32_t height) {
    (void)client;
    if (width <= 0 || height <= 0) {
        wl_resource_post_error(resource, XDG_POSITIONER_ERROR_INVALID_INPUT, "Empty popup size");
        return;
    }
    struct positioner *positioner = wl_resource_get_user_data(resource);
    positioner->width = width;
    positioner->height = height;
}

static void positioner_anchor_rect(struct wl_client *client, struct wl_resource *resource,
                                   int32_t x, int32_t y, int32_t width, int32_t height) {
    (void)client;
    if (width < 0 || height < 0) {
        wl_resource_post_error(resource, XDG_POSITIONER_ERROR_INVALID_INPUT, "Negative anchor rectangle size");
        return;
    }
    struct positioner *positioner = wl_resource_get_user_data(resource);
    positioner->anchor_rect = (struct rectangle){ x, y, width, height };
}

static void positioner_anchor(struct wl_client *client, struct wl_resource *resource, uint32_t anchor) {
    (void)client;
    if (anchor > XDG_POSITIONER_ANCHOR_BOTTOM_RIGHT) {
        wl_resource_post_error(resource, XDG_POSITIONER_ERROR_INVALID_INPUT, "Unknown popup anchor");
        return;
    }
    struct positioner *positioner = wl_resource_get_user_data(resource);
    positioner->anchor = anchor;
}

static void positioner_gravity(struct wl_client *client, struct wl_resource *resource, uint32_t gravity) {
    (void)client;
    if (gravity > XDG_POSITIONER_GRAVITY_BOTTOM_RIGHT) {
        wl_resource_post_error(resource, XDG_POSITIONER_ERROR_INVALID_INPUT, "Unknown popup gravity");
        return;
    }
    struct positioner *positioner = wl_resource_get_user_data(resource);
    positioner->gravity = gravity;
}

static void positioner_adjustment(struct wl_client *client, struct wl_resource *resource, uint32_t adjustment) {
    (void)client;
    const uint32_t known = XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_X |
                           XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_Y |
                           XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_X |
                           XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_Y |
                           XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_RESIZE_X |
                           XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_RESIZE_Y;
    if (adjustment & ~known) {
        wl_resource_post_error(resource, XDG_POSITIONER_ERROR_INVALID_INPUT, "Unknown popup adjustment");
        return;
    }
    struct positioner *positioner = wl_resource_get_user_data(resource);
    positioner->adjustment = adjustment;
}

static void positioner_offset(struct wl_client *client, struct wl_resource *resource, int32_t x, int32_t y) {
    (void)client;
    struct positioner *positioner = wl_resource_get_user_data(resource);
    positioner->offset_x = x;
    positioner->offset_y = y;
}

static const struct xdg_positioner_interface positioner_requests = {
    .destroy = destroy_request,
    .set_size = positioner_size,
    .set_anchor_rect = positioner_anchor_rect,
    .set_anchor = positioner_anchor,
    .set_gravity = positioner_gravity,
    .set_constraint_adjustment = positioner_adjustment,
    .set_offset = positioner_offset,
};

static void destroy_positioner(struct wl_resource *resource) {
    free(wl_resource_get_user_data(resource));
}

static int64_t place_axis(int64_t start, int anchor_size, int popup_size, int anchor, int gravity) {
    return start + (int64_t)anchor_size * (anchor + 1) / 2 - (int64_t)popup_size * (1 - gravity) / 2;
}

static int64_t constrain_axis(int64_t start, int anchor_size, int32_t *size, int anchor, int gravity,
                              int limit, uint32_t rules, bool vertical) {
    uint32_t flip = XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_X << vertical;
    uint32_t slide = XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_X << vertical;
    uint32_t resize = XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_RESIZE_X << vertical;
    int64_t pos = place_axis(start, anchor_size, *size, anchor, gravity);
    if (pos >= 0 && pos + *size <= limit) return pos;
    if (rules & flip) {
        int64_t flipped = place_axis(start, anchor_size, *size, -anchor, -gravity);
        if (flipped >= 0 && flipped + *size <= limit) return flipped;
    }
    if (rules & slide) {
        int64_t last_start = (int64_t)limit - *size;
        if (pos > last_start) pos = last_start;
        if (pos < 0) pos = 0;
    }
    if (rules & resize) {
        int64_t first = pos < 0 ? 0 : pos;
        int64_t last = pos + *size > limit ? limit : pos + *size;
        if (last > first) {
            *size = (int32_t)(last - first);
            pos = first;
        }
    }
    return pos;
}

static bool configure_popup(struct surface *surface) {
    static const struct { int x, y; } directions[] = {
        {0, 0}, {0, -1}, {0, 1}, {-1, 0}, {1, 0}, {-1, -1}, {-1, 1}, {1, -1}, {1, 1},
    };
    const struct positioner *p = &surface->positioner;
    const struct surface *parent = surface->parent;
    int64_t parent_x = parent->x + parent->geometry.x;
    int64_t parent_y = parent->y + parent->geometry.y;
    int32_t width = p->width, height = p->height;
    int64_t x = constrain_axis(parent_x + p->anchor_rect.x + p->offset_x, p->anchor_rect.width, &width,
                               directions[p->anchor].x, directions[p->gravity].x,
                               surface->server->mode.xres, p->adjustment, false) - parent_x;
    int64_t y = constrain_axis(parent_y + p->anchor_rect.y + p->offset_y, p->anchor_rect.height, &height,
                               directions[p->anchor].y, directions[p->gravity].y,
                               surface->server->mode.yres, p->adjustment, true) - parent_y;
    if (x < INT32_MIN || x > INT32_MAX || y < INT32_MIN || y > INT32_MAX) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_INVALID_POSITIONER, "Popup position out of range");
        return false;
    }
    surface->placement = (struct rectangle){ (int32_t)x, (int32_t)y, width, height };
    xdg_popup_send_configure(surface->popup, (int32_t)x, (int32_t)y, width, height);
    return true;
}

static void popup_grab(struct wl_client *client, struct wl_resource *resource,
                       struct wl_resource *seat, uint32_t serial) {
    (void)client;
    (void)seat;
    (void)serial;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface->mapped) {
        wl_resource_post_error(resource, XDG_POPUP_ERROR_INVALID_GRAB, "Popup already mapped");
        return;
    }
    /* Р—Р°С…РІР°С‚ С‚СЂРµР±СѓРµС‚ РїСЂРѕРІРµСЂРєРё serial СЃРѕР±С‹С‚РёСЏ РІРІРѕРґР° РЅР° СЃС‚РѕСЂРѕРЅРµ seat. */
    if (!surface->dismissed) xdg_popup_send_popup_done(resource);
    surface->dismissed = true;
}

static const struct surface *popup_root(const struct surface *surface) {
    while (surface->parent) surface = surface->parent;
    return surface;
}

static bool topmost_popup(const struct surface *surface) {
    const struct surface *root = popup_root(surface);
    const struct surface *above;
    wl_list_for_each_reverse(above, &surface->server->popups, popup_link) {
        if (above == surface) break;
        if (!above->dismissed && popup_root(above) == root) return false;
    }
    return true;
}

static void destroy_popup(struct wl_client *client, struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (!surface->dismissed && !topmost_popup(surface)) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_NOT_THE_TOPMOST_POPUP, "Destroy topmost popup first");
        return;
    }
    destroy_request(client, resource);
}

static const struct xdg_popup_interface popup_requests = {
    .destroy = destroy_popup,
    .grab = popup_grab,
};

static void get_popup(struct wl_client *client, struct wl_resource *resource, uint32_t id,
                      struct wl_resource *parent_resource, struct wl_resource *positioner_resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    struct surface *parent = parent_resource ? wl_resource_get_user_data(parent_resource) : NULL;
    const struct positioner *positioner = wl_resource_get_user_data(positioner_resource);
    if (surface->toplevel || surface->popup) {
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_ALREADY_CONSTRUCTED, "Surface already has a role");
        return;
    }
    if (!parent || parent == surface || (!parent->toplevel && !parent->popup) || parent->dismissed) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_INVALID_POPUP_PARENT, "Invalid popup parent");
        return;
    }
    if (!positioner->width || !positioner->anchor_rect.width || !positioner->anchor_rect.height) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_INVALID_POSITIONER, "Incomplete positioner");
        return;
    }
    if (surface->xdg_role == XDG_TOPLEVEL) {
        wl_resource_post_error(surface->wm_base, XDG_WM_BASE_ERROR_ROLE, "Toplevel cannot become a popup");
        return;
    }
    surface->popup = wl_resource_create(client, &xdg_popup_interface, 1, id);
    if (!surface->popup) {
        wl_client_post_no_memory(client);
        return;
    }
    surface->xdg_role = XDG_POPUP;
    surface->dismissed = false;
    surface->parent = parent;
    surface->positioner = *positioner;
    wl_list_insert(surface->server->popups.prev, &surface->popup_link);
    wl_resource_set_implementation(surface->popup, &popup_requests, surface, popup_destroyed);
}

static void window_geometry(struct wl_client *client, struct wl_resource *resource,
                            int32_t x, int32_t y, int32_t width, int32_t height) {
    (void)client;
    if (width <= 0 || height <= 0) {
        wl_resource_post_error(resource, XDG_SURFACE_ERROR_INVALID_SIZE, "Empty window geometry");
        return;
    }
    struct surface *surface = wl_resource_get_user_data(resource);
    surface->pending_geometry = (struct rectangle){ x, y, width, height };
    surface->geometry_pending = true;
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
    if ((surface->role != SURFACE_NONE && surface->role != SURFACE_XDG) || surface->shell) {
        wl_resource_post_error(resource, XDG_WM_BASE_ERROR_ROLE, "Surface already has a role");
        return;
    }
    surface->shell = wl_resource_create(client, &xdg_surface_interface, wl_resource_get_version(resource), id);
    if (!surface->shell) {
        wl_client_post_no_memory(client);
        return;
    }
    surface->role = SURFACE_XDG;
    surface->wm_base = resource;
    surface->wm_base_destroy.notify = wm_base_destroyed;
    wl_resource_add_destroy_listener(resource, &surface->wm_base_destroy);
    wl_list_insert(&surface->server->shell_surfaces, &surface->shell_link);
    clear_image(&surface->cursor_image);
    wl_resource_set_implementation(surface->shell, &shell_surface_requests, surface, shell_surface_destroyed);
}

static void create_positioner(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct positioner *positioner = calloc(1, sizeof(*positioner));
    if (!positioner) {
        wl_client_post_no_memory(client);
        return;
    }
    struct wl_resource *child = wl_resource_create(client, &xdg_positioner_interface, wl_resource_get_version(resource), id);
    if (!child) {
        free(positioner);
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(child, &positioner_requests, positioner, destroy_positioner);
}

static void pong(struct wl_client *client, struct wl_resource *resource, uint32_t serial) {
    (void)client;
    (void)resource;
    (void)serial;
}

static void destroy_shell(struct wl_client *client, struct wl_resource *resource) {
    struct compositor *server = wl_resource_get_user_data(resource);
    struct surface *surface;
    wl_list_for_each(surface, &server->shell_surfaces, shell_link) {
        if (surface->wm_base == resource) {
            wl_resource_post_error(resource, XDG_WM_BASE_ERROR_DEFUNCT_SURFACES, "Destroy xdg surfaces first");
            return;
        }
    }
    destroy_request(client, resource);
}

static const struct xdg_wm_base_interface shell_requests = {
    .destroy = destroy_shell,
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

static void orphan_subsurface(struct surface *surface) {
    if (!surface->parent) return;
    bool repaint = shown(surface);
    detach_pointer_tree(surface);
    for (unsigned i = 0; i < LAYER_STATES; ++i) {
        wl_list_remove(&surface->child_layer[i].link);
        wl_list_init(&surface->child_layer[i].link);
        surface->child_layer[i].x = surface->child_layer[i].y = 0;
    }
    surface->parent = NULL;
    surface->mapped = false;
    surface->commit_cached = surface->buffer_cached = surface->input_cached = false;
    surface->layers_cached = false;
    clear_image(&surface->image);
    clear_image(&surface->cached_image);
    destroy_frames(&surface->cached_frames);
    destroy_frames(&surface->presented_frames);
    if (repaint) present_changes(wl_resource_get_client(surface->resource), surface->server);
}

static void subsurface_destroyed(struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface) {
        surface->subsurface = NULL;
        orphan_subsurface(surface);
    }
}

static void set_subsurface_position(struct wl_client *client, struct wl_resource *resource,
                                    int32_t x, int32_t y) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (!surface || !surface->parent) return;
    surface->child_layer[LAYER_PENDING].x = x;
    surface->child_layer[LAYER_PENDING].y = y;
    surface->parent->layers_pending = true;
}

static void place_subsurface(struct wl_resource *resource, struct wl_resource *reference, bool above) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (!surface || !surface->parent) return;
    struct surface *parent = surface->parent;
    struct surface *sibling = wl_resource_get_user_data(reference);
    struct layer *anchor;
    if (sibling == parent) anchor = &parent->own_layer[LAYER_PENDING];
    else if (sibling != surface && sibling->subsurface && sibling->parent == parent)
        anchor = &sibling->child_layer[LAYER_PENDING];
    else {
        wl_resource_post_error(resource, WL_SUBSURFACE_ERROR_BAD_SURFACE, "Reference must be parent or sibling");
        return;
    }
    struct wl_list *link = &surface->child_layer[LAYER_PENDING].link;
    wl_list_remove(link);
    wl_list_insert(above ? &anchor->link : anchor->link.prev, link);
    parent->layers_pending = true;
}

static void place_above(struct wl_client *client, struct wl_resource *resource, struct wl_resource *reference) {
    (void)client;
    place_subsurface(resource, reference, true);
}

static void place_below(struct wl_client *client, struct wl_resource *resource, struct wl_resource *reference) {
    (void)client;
    place_subsurface(resource, reference, false);
}

static void set_sync(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    struct surface *surface = wl_resource_get_user_data(resource);
    if (surface && surface->parent) surface->sync = true;
}

static bool apply_desynchronized_tree(struct surface *surface) {
    bool changed = apply_subsurface(surface);
    changed |= apply_child_commits(surface, false);
    struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_CURRENT], link)
        if (layer->surface && !layer->surface->sync) changed |= apply_desynchronized_tree(layer->surface);
    return changed;
}

static void set_desync(struct wl_client *client, struct wl_resource *resource) {
    struct surface *surface = wl_resource_get_user_data(resource);
    if (!surface || !surface->parent) return;
    surface->sync = false;
    if (!effectively_synchronized(surface)) {
        bool repaint = shown(surface);
        if (apply_desynchronized_tree(surface) && (repaint || shown(surface)))
            present_changes(client, surface->server);
    }
}

static const struct wl_subsurface_interface subsurface_requests = {
    .destroy = destroy_request,
    .set_position = set_subsurface_position,
    .place_above = place_above,
    .place_below = place_below,
    .set_sync = set_sync,
    .set_desync = set_desync,
};

// Обходы отрисовки и синхронного коммита расходуют стек на каждый вложенный слой.
enum { MAX_SUBSURFACE_DEPTH = 128 };

static bool subsurface_tree_fits(const struct surface *surface, unsigned depth) {
    if (depth >= MAX_SUBSURFACE_DEPTH) return false;
    const struct layer *layer;
    wl_list_for_each(layer, &surface->layers[LAYER_PENDING], link)
        if (layer->surface && !subsurface_tree_fits(layer->surface, depth + 1)) return false;
    return true;
}

static void get_subsurface(struct wl_client *client, struct wl_resource *resource, uint32_t id,
                           struct wl_resource *child_resource, struct wl_resource *parent_resource) {
    struct surface *surface = wl_resource_get_user_data(child_resource);
    struct surface *parent = wl_resource_get_user_data(parent_resource);
    if (surface->subsurface || (surface->role != SURFACE_NONE && surface->role != SURFACE_SUBSURFACE)) {
        wl_resource_post_error(resource, WL_SUBCOMPOSITOR_ERROR_BAD_SURFACE, "Surface already has a role");
        return;
    }
    unsigned depth = 0;
    for (const struct surface *ancestor = parent; ancestor; ancestor = ancestor->parent) {
        if (ancestor == surface) {
            wl_resource_post_error(resource, WL_SUBCOMPOSITOR_ERROR_BAD_PARENT, "Invalid subsurface parent");
            return;
        }
        if (ancestor->role == SURFACE_SUBSURFACE) ++depth;
    }
    if (!subsurface_tree_fits(surface, depth)) {
        wl_client_post_implementation_error(client, "Subsurface tree is too deep");
        return;
    }
    surface->subsurface = wl_resource_create(client, &wl_subsurface_interface, 1, id);
    if (!surface->subsurface) {
        wl_client_post_no_memory(client);
        return;
    }
    surface->role = SURFACE_SUBSURFACE;
    surface->parent = parent;
    surface->sync = true;
    if (surface->cursor_image.pixels) {
        surface->cached_image = surface->cursor_image;
        surface->cursor_image = (struct image){0};
        surface->buffer_cached = surface->commit_cached = true;
    }
    wl_list_insert(parent->layers[LAYER_PENDING].prev, &surface->child_layer[LAYER_PENDING].link);
    parent->layers_pending = true;
    wl_resource_set_implementation(surface->subsurface, &subsurface_requests, surface, subsurface_destroyed);
}

static const struct wl_subcompositor_interface subcompositor_requests = {
    .destroy = destroy_request,
    .get_subsurface = get_subsurface,
};

static void bind_subcompositor(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wl_resource *resource = wl_resource_create(client, &wl_subcompositor_interface, version, id);
    if (resource) wl_resource_set_implementation(resource, &subcompositor_requests, data, NULL);
    else wl_client_post_no_memory(client);
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
    wl_list_init(&server.popups);
    wl_list_init(&server.shell_surfaces);
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
        !wl_global_create(server.display, &wl_subcompositor_interface, 1, &server, bind_subcompositor) ||
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
        wayland_seat_probe_input(server.seat);
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
