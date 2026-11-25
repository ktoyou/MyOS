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

#include "keyboard.h"
#include "xdg-shell-server-protocol.h"

struct compositor {
    struct wl_display *display;
    struct fb_var_screeninfo mode;
    struct fb_fix_screeninfo layout;
    struct surface *visible;
    struct wayland_keyboard *keyboard;
    uint32_t *row;
    int drawn_width, drawn_height;
    int fb;
};

struct frame {
    struct wl_list link;
    struct wl_resource *resource;
};

struct surface {
    struct compositor *server;
    struct wl_resource *shell;
    struct wl_resource *toplevel;
    struct wl_resource *buffer;
    struct wl_listener buffer_destroy;
    struct wl_list frames;
    uint32_t serial;
    bool configured, acknowledged, detach, mapped;
    int scale, transform;
};

static volatile sig_atomic_t stopping;

static void stop(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static bool write_row(struct compositor *server, int y, int width) {
    size_t bytes = (size_t)width * sizeof(*server->row);
    off_t offset = (off_t)y * server->layout.line_length;
    return pwrite(server->fb, server->row, bytes, offset) == (ssize_t)bytes;
}

static void hide_surface(struct surface *surface) {
    struct compositor *server = surface->server;
    surface->mapped = false;
    if (server->visible != surface) return;
    wayland_keyboard_focus(server->keyboard, NULL);
    memset(server->row, 0, (size_t)server->drawn_width * sizeof(*server->row));
    for (int y = 0; y < server->drawn_height; ++y) {
        if (!write_row(server, y, server->drawn_width)) {
            perror("Clear framebuffer");
            break;
        }
    }
    server->visible = NULL;
    server->drawn_width = 0;
    server->drawn_height = 0;
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
    if (surface->shell) wl_resource_destroy(surface->shell);
    clear_pending_buffer(surface);
    wl_list_for_each_safe(frame, next, &surface->frames, link) {
        wl_resource_destroy(frame->resource);
    }
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
    (void)x;
    (void)y;
    struct surface *surface = wl_resource_get_user_data(resource);
    clear_pending_buffer(surface);
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

static bool present(struct surface *surface, struct wl_shm_buffer *buffer) {
    struct compositor *server = surface->server;
    int width = wl_shm_buffer_get_width(buffer);
    int height = wl_shm_buffer_get_height(buffer);
    int stride = wl_shm_buffer_get_stride(buffer);
    if (width <= 0 || height <= 0 || stride < 0 || width > stride / 4 ||
        width % surface->scale || height % surface->scale) return false;

    int transform = surface->transform;
    bool swapped = transform % 2;
    int output_width = (swapped ? height : width) / surface->scale;
    int output_height = (swapped ? width : height) / surface->scale;
    if (output_width > (int)server->mode.xres) output_width = (int)server->mode.xres;
    if (output_height > (int)server->mode.yres) output_height = (int)server->mode.yres;
    int draw_width = output_width > server->drawn_width ? output_width : server->drawn_width;
    int draw_height = output_height > server->drawn_height ? output_height : server->drawn_height;

    wl_shm_buffer_begin_access(buffer);
    const unsigned char *pixels = wl_shm_buffer_get_data(buffer);
    bool success = true;
    for (int y = 0; y < draw_height; ++y) {
        int content_width = y < output_height ? output_width : 0;
        for (int x = 0; x < content_width; ++x) {
            int sx = x * surface->scale;
            int sy = y * surface->scale;
            if (transform >= WL_OUTPUT_TRANSFORM_FLIPPED) sx = (swapped ? height : width) - 1 - sx;
            int px = sx, py = sy;
            /* Преобразование Wayland задаёт координаты пикселя в буфере. */
            switch (transform % 4) {
            case WL_OUTPUT_TRANSFORM_90: px = sy; py = height - 1 - sx; break;
            case WL_OUTPUT_TRANSFORM_180: px = width - 1 - sx; py = height - 1 - sy; break;
            case WL_OUTPUT_TRANSFORM_270: px = width - 1 - sy; py = sx; break;
            }
            const unsigned char *pixel = pixels + (size_t)py * stride + (size_t)px * 4;
            server->row[x] = (uint32_t)pixel[2] << server->mode.red.offset |
                             (uint32_t)pixel[1] << server->mode.green.offset |
                             (uint32_t)pixel[0] << server->mode.blue.offset;
        }
        memset(server->row + content_width, 0, (size_t)(draw_width - content_width) * sizeof(*server->row));
        if (!write_row(server, y, draw_width)) {
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
    if (buffer) {
        struct wl_shm_buffer *shm = wl_shm_buffer_get(buffer);
        if (!shm) {
            wl_client_post_implementation_error(client, "Only shared memory buffers are supported");
            return;
        }
        if (surface->toplevel && !present(surface, shm)) {
            wl_client_post_implementation_error(client, "Could not display shared memory buffer");
            return;
        }
        if (surface->toplevel) {
            surface->server->visible = surface;
            surface->mapped = true;
            wayland_keyboard_focus(surface->server->keyboard, resource);
        }
        wl_buffer_send_release(buffer);
    } else if (surface->detach && surface->mapped) {
        hide_surface(surface);
        surface->configured = false;
        surface->acknowledged = false;
    }
    surface->detach = false;

    if (surface->server->visible == surface) {
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
    .set_input_region = region_request,
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
    surface->buffer_destroy.notify = buffer_destroyed;
    surface->scale = 1;
    wl_list_init(&surface->frames);
    wl_resource_set_implementation(child, &surface_requests, surface, surface_destroyed);
}

static const struct wl_region_interface region_requests = {
    .destroy = destroy_request,
    .add = rectangle_request,
    .subtract = rectangle_request,
};

static void create_region(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    (void)resource;
    struct wl_resource *region = wl_resource_create(client, &wl_region_interface, 1, id);
    if (region) wl_resource_set_implementation(region, &region_requests, NULL, NULL);
    else wl_client_post_no_memory(client);
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
    if (surface->shell) {
        wl_resource_post_error(resource, XDG_WM_BASE_ERROR_ROLE, "Surface already has an xdg_surface");
        return;
    }
    surface->shell = wl_resource_create(client, &xdg_surface_interface, wl_resource_get_version(resource), id);
    if (!surface->shell) {
        wl_client_post_no_memory(client);
        return;
    }
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
    struct compositor server = { .fb = open("/dev/fb0", O_WRONLY | O_CLOEXEC) };
    if (server.fb < 0 || ioctl(server.fb, FBIOGET_VSCREENINFO, &server.mode) ||
        ioctl(server.fb, FBIOGET_FSCREENINFO, &server.layout)) {
        perror("/dev/fb0");
        return 1;
    }
    if (server.mode.bits_per_pixel != 32 || !server.mode.xres || !server.mode.yres ||
        server.mode.xres > server.layout.line_length / 4 || server.mode.yres > INT_MAX ||
        !color_supported(server.mode.red) || !color_supported(server.mode.green) ||
        !color_supported(server.mode.blue)) {
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
    if ((argc == 3 || access(keymap, R_OK) == 0) &&
        !wayland_keyboard_init(&server.keyboard, server.display, keymap)) {
        unlink(argv[1]);
        return 1;
    }

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
    wayland_keyboard_destroy(server.keyboard);
    wl_display_destroy(server.display);
    unlink(argv[1]);
    free(server.row);
    close(server.fb);
    return status;
}
