#define _GNU_SOURCE
#include "pointer.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server-protocol.h>

enum { BUTTON_COUNT = 3, WHEEL_STEP = 10 };

struct wayland_pointer {
    struct wl_display *display;
    struct wl_event_source *input;
    struct wl_resource *focus, *cursor;
    struct wl_listener focus_destroy, cursor_destroy;
    struct wl_list clients;
    const struct wayland_pointer_ops *ops;
    void *data;
    void (*changed)(void *);
    void *changed_data;
    int fd, width, height, x, y;
    int32_t hotspot_x, hotspot_y;
    int64_t dx, dy, wheel;
    unsigned buttons, next_buttons, delivered;
    bool dropped, cursor_visible;
};

struct pointer_client {
    struct wl_list link;
    struct wayland_pointer *pointer;
    struct wl_resource *resource;
    uint32_t enter_serial;
};

static bool client_owns(const struct pointer_client *client, struct wl_resource *surface) {
    return surface && wl_resource_get_client(client->resource) == wl_resource_get_client(surface);
}

static void send_frame(struct wl_resource *resource) {
    if (wl_resource_get_version(resource) >= WL_POINTER_FRAME_SINCE_VERSION)
        wl_pointer_send_frame(resource);
}

static void send_enter(struct wayland_pointer *pointer, struct pointer_client *client, uint32_t serial) {
    client->enter_serial = serial;
    wl_pointer_send_enter(client->resource, serial, pointer->focus,
                          wl_fixed_from_int(pointer->x), wl_fixed_from_int(pointer->y));
    send_frame(client->resource);
}

static void paint(struct wayland_pointer *pointer) {
    pointer->ops->paint(pointer->data, pointer->x, pointer->y, pointer->cursor,
                        pointer->hotspot_x, pointer->hotspot_y, pointer->input && pointer->cursor_visible);
}

static void default_cursor(struct wayland_pointer *pointer) {
    if (pointer->cursor) wl_list_remove(&pointer->cursor_destroy.link);
    pointer->cursor = NULL;
    pointer->hotspot_x = pointer->hotspot_y = 0;
    pointer->cursor_visible = true;
}

static void cursor_destroyed(struct wl_listener *listener, void *data) {
    (void)data;
    struct wayland_pointer *pointer = wl_container_of(listener, pointer, cursor_destroy);
    default_cursor(pointer);
    paint(pointer);
}

static void focus_destroyed(struct wl_listener *listener, void *data) {
    (void)data;
    struct wayland_pointer *pointer = wl_container_of(listener, pointer, focus_destroy);
    wl_list_remove(&listener->link);
    pointer->focus = NULL;
    pointer->delivered = 0;
    default_cursor(pointer);
    paint(pointer);
}

static void set_focus(struct wayland_pointer *pointer, struct wl_resource *surface) {
    if (pointer->focus == surface) return;
    struct pointer_client *client;
    if (pointer->focus) {
        uint32_t serial = wl_display_next_serial(pointer->display);
        wl_list_for_each(client, &pointer->clients, link) {
            if (!client_owns(client, pointer->focus)) continue;
            wl_pointer_send_leave(client->resource, serial, pointer->focus);
            send_frame(client->resource);
        }
        wl_list_remove(&pointer->focus_destroy.link);
    }
    pointer->focus = surface;
    pointer->delivered = 0;
    default_cursor(pointer);
    if (!surface) return;
    wl_resource_add_destroy_listener(surface, &pointer->focus_destroy);
    uint32_t serial = wl_display_next_serial(pointer->display);
    wl_list_for_each(client, &pointer->clients, link)
        if (client_owns(client, surface)) send_enter(pointer, client, serial);
}

static void update_focus(struct wayland_pointer *pointer) {
    /* Пока нажата кнопка, события получает поверхность первого нажатия. */
    if (pointer->input && !pointer->dropped && !pointer->delivered)
        set_focus(pointer, pointer->ops->pick(pointer->data, pointer->x, pointer->y));
}

void wayland_pointer_update(struct wayland_pointer *pointer) {
    if (!pointer) return;
    update_focus(pointer);
    paint(pointer);
}

void wayland_pointer_detach(struct wayland_pointer *pointer, struct wl_resource *surface) {
    if (pointer && surface && pointer->focus == surface) set_focus(pointer, NULL);
}

static void cursor_request(struct wl_client *client, struct wl_resource *resource, uint32_t serial,
                           struct wl_resource *surface, int32_t x, int32_t y) {
    (void)client;
    struct pointer_client *entry = wl_resource_get_user_data(resource);
    struct wayland_pointer *pointer = entry->pointer;
    if (!client_owns(entry, pointer->focus) || serial != entry->enter_serial) return;
    if (surface && !pointer->ops->assign_cursor(pointer->data, surface)) {
        wl_resource_post_error(resource, WL_POINTER_ERROR_ROLE, "Surface already has a role");
        return;
    }
    default_cursor(pointer);
    pointer->cursor = surface;
    pointer->cursor_visible = surface != NULL;
    pointer->hotspot_x = x;
    pointer->hotspot_y = y;
    if (surface) wl_resource_add_destroy_listener(surface, &pointer->cursor_destroy);
    paint(pointer);
}

static void release_request(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void pointer_destroyed(struct wl_resource *resource) {
    struct pointer_client *client = wl_resource_get_user_data(resource);
    wl_list_remove(&client->link);
    free(client);
}

static const struct wl_pointer_interface pointer_requests = {
    .set_cursor = cursor_request,
    .release = release_request,
};

void wayland_pointer_bind(struct wayland_pointer *pointer, struct wl_client *client, int version, uint32_t id) {
    struct pointer_client *entry = calloc(1, sizeof(*entry));
    if (entry) entry->resource = wl_resource_create(client, &wl_pointer_interface, version, id);
    if (!entry || !entry->resource) {
        free(entry);
        wl_client_post_no_memory(client);
        return;
    }
    entry->pointer = pointer;
    wl_list_insert(&pointer->clients, &entry->link);
    wl_resource_set_implementation(entry->resource, &pointer_requests, entry, pointer_destroyed);
    if (client_owns(entry, pointer->focus))
        send_enter(pointer, entry, wl_display_next_serial(pointer->display));
}

static int clamp(int64_t value, int low, int high) {
    if (value < low) return low;
    if (value > high) return high;
    return (int)value;
}

static void send_wheel(struct wl_resource *resource, int steps, uint32_t time) {
    if (wl_resource_get_version(resource) >= WL_POINTER_AXIS_SOURCE_SINCE_VERSION) {
        wl_pointer_send_axis_source(resource, WL_POINTER_AXIS_SOURCE_WHEEL);
        wl_pointer_send_axis_discrete(resource, WL_POINTER_AXIS_VERTICAL_SCROLL, steps);
    }
    wl_pointer_send_axis(resource, time, WL_POINTER_AXIS_VERTICAL_SCROLL, wl_fixed_from_int(steps * WHEEL_STEP));
}

static void report(struct wayland_pointer *pointer, uint32_t time) {
    int x = clamp(pointer->x + pointer->dx, 0, pointer->width - 1);
    int y = clamp(pointer->y + pointer->dy, 0, pointer->height - 1);
    bool moved = x != pointer->x || y != pointer->y;
    pointer->x = x;
    pointer->y = y;
    struct wl_resource *before = pointer->focus;
    update_focus(pointer);
    bool motion = moved && pointer->focus == before;
    unsigned changed = pointer->buttons ^ pointer->next_buttons;
    unsigned pressed = changed & pointer->next_buttons;
    unsigned released = changed & ~pointer->next_buttons & pointer->delivered;
    pointer->buttons = pointer->next_buttons;
    unsigned transitions = pressed | released;
    /* В Wayland отрицательное значение вертикальной оси означает прокрутку вверх. */
    int wheel = -clamp(pointer->wheel, -INT32_MAX / (256 * WHEEL_STEP), INT32_MAX / (256 * WHEEL_STEP));
    pointer->dx = pointer->dy = pointer->wheel = 0;

    if (pointer->focus && (motion || transitions || wheel)) {
        uint32_t serials[BUTTON_COUNT];
        for (unsigned i = 0; i < BUTTON_COUNT; ++i)
            if (transitions & (1u << i)) serials[i] = wl_display_next_serial(pointer->display);
        struct pointer_client *client;
        wl_list_for_each(client, &pointer->clients, link) {
            if (!client_owns(client, pointer->focus)) continue;
            struct wl_resource *resource = client->resource;
            if (motion) wl_pointer_send_motion(resource, time, wl_fixed_from_int(x), wl_fixed_from_int(y));
            for (unsigned i = 0; i < BUTTON_COUNT; ++i) {
                unsigned bit = 1u << i;
                if (transitions & bit)
                    wl_pointer_send_button(resource, serials[i], time, BTN_LEFT + i,
                        (pressed & bit) ? WL_POINTER_BUTTON_STATE_PRESSED : WL_POINTER_BUTTON_STATE_RELEASED);
            }
            if (wheel) send_wheel(resource, wheel, time);
            send_frame(resource);
            pointer->delivered |= pressed;
        }
        pointer->delivered &= ~released;
    }
    update_focus(pointer);
    if (moved || pointer->focus != before) paint(pointer);
}

static bool sync_buttons(struct wayland_pointer *pointer) {
    unsigned char keys[(KEY_CNT + 7) / 8] = {0};
    if (ioctl(pointer->fd, EVIOCGKEY(sizeof(keys)), keys) < 0) return false;
    unsigned buttons = 0;
    for (unsigned i = 0; i < BUTTON_COUNT; ++i) {
        unsigned code = BTN_LEFT + i;
        if (keys[code / 8] & (1u << (code % 8))) buttons |= 1u << i;
    }
    pointer->buttons = pointer->next_buttons = buttons;
    return true;
}

static int read_input(int fd, uint32_t mask, void *data) {
    (void)mask;
    struct wayland_pointer *pointer = data;
    struct input_event events[32];
    ssize_t size = read(fd, events, sizeof(events));
    if (size < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    if (size <= 0 || size % sizeof(*events)) {
        fputs("Wayland pointer input stopped\n", stderr);
        wl_event_source_remove(pointer->input);
        pointer->input = NULL;
        set_focus(pointer, NULL);
        paint(pointer);
        pointer->changed(pointer->changed_data);
        return 0;
    }
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint32_t time = (uint32_t)now.tv_sec * 1000 + (uint32_t)(now.tv_nsec / 1000000);
    bool buttons_synced = false;
    for (size_t i = 0; i < (size_t)size / sizeof(*events); ++i) {
        const struct input_event *event = &events[i];
        if (event->type == EV_SYN && event->code == SYN_DROPPED) {
            pointer->dx = pointer->dy = pointer->wheel = 0;
            pointer->dropped = true;
            set_focus(pointer, NULL);
            paint(pointer);
        } else if (event->type == EV_SYN && event->code == SYN_REPORT) {
            if (!pointer->dropped) {
                report(pointer, time);
            } else if (sync_buttons(pointer)) {
                pointer->dropped = false;
                wayland_pointer_update(pointer);
                /* Снимок учитывает кнопки из остатка буфера, а смещения всё ещё нужны. */
                buttons_synced = true;
            }
        } else if (!pointer->dropped && event->type == EV_REL) {
            if (event->code == REL_X) pointer->dx += event->value;
            else if (event->code == REL_Y) pointer->dy += event->value;
            else if (event->code == REL_WHEEL) pointer->wheel += event->value;
        } else if (!pointer->dropped && !buttons_synced && event->type == EV_KEY && event->code >= BTN_LEFT &&
                   event->code < BTN_LEFT + BUTTON_COUNT) {
            unsigned bit = 1u << (event->code - BTN_LEFT);
            if (event->value == 1) pointer->next_buttons |= bit;
            else if (event->value == 0) pointer->next_buttons &= ~bit;
        }
    }
    return 0;
}

bool wayland_pointer_available(const struct wayland_pointer *pointer) {
    return pointer && pointer->input;
}

bool wayland_pointer_init(struct wayland_pointer **result, struct wl_display *display, int width, int height,
                          const struct wayland_pointer_ops *ops, void *data,
                          void (*changed)(void *), void *changed_data) {
    int fd = open("/dev/input/event1", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENODEV) return true;
        perror("/dev/input/event1");
        return false;
    }
    struct wayland_pointer *pointer = calloc(1, sizeof(*pointer));
    if (!pointer) {
        close(fd);
        return false;
    }
    pointer->display = display;
    pointer->ops = ops;
    pointer->data = data;
    pointer->changed = changed;
    pointer->changed_data = changed_data;
    pointer->fd = fd;
    pointer->width = width;
    pointer->height = height;
    pointer->x = width / 2;
    pointer->y = height / 2;
    pointer->cursor_visible = true;
    pointer->focus_destroy.notify = focus_destroyed;
    pointer->cursor_destroy.notify = cursor_destroyed;
    wl_list_init(&pointer->clients);
    if (width > INT32_MAX / 256 || height > INT32_MAX / 256 || !sync_buttons(pointer)) {
        fputs("Could not initialize Wayland pointer\n", stderr);
        wayland_pointer_destroy(pointer);
        return false;
    }
    pointer->input = wl_event_loop_add_fd(wl_display_get_event_loop(display), fd, WL_EVENT_READABLE,
                                         read_input, pointer);
    if (!pointer->input) {
        wayland_pointer_destroy(pointer);
        return false;
    }
    *result = pointer;
    return true;
}

void wayland_pointer_destroy(struct wayland_pointer *pointer) {
    if (!pointer) return;
    if (pointer->focus) wl_list_remove(&pointer->focus_destroy.link);
    if (pointer->cursor) wl_list_remove(&pointer->cursor_destroy.link);
    if (pointer->input) wl_event_source_remove(pointer->input);
    close(pointer->fd);
    free(pointer);
}
