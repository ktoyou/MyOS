#define _GNU_SOURCE
#include "keyboard.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server-protocol.h>
#include <xkbcommon/xkbcommon.h>

struct keyboard_client {
    struct wl_list link;
    struct wl_resource *resource;
};

struct wayland_keyboard {
    struct wl_display *display;
    struct wl_global *seat;
    struct wl_event_source *input;
    struct wl_resource *focus;
    struct wl_listener focus_destroy;
    struct wl_list clients;
    struct xkb_state *state;
    bool down[KEY_CNT];
    bool dropped;
    int fd, keymap_fd;
    uint32_t keymap_size;
};

static bool client_owns(struct wl_resource *keyboard, struct wl_resource *surface) {
    return surface && wl_resource_get_client(keyboard) == wl_resource_get_client(surface);
}

static void send_modifiers(struct wayland_keyboard *keyboard, struct wl_resource *resource,
                           uint32_t serial) {
    struct xkb_state *state = keyboard->state;
    wl_keyboard_send_modifiers(resource, serial,
        xkb_state_serialize_mods(state, XKB_STATE_MODS_DEPRESSED),
        xkb_state_serialize_mods(state, XKB_STATE_MODS_LATCHED),
        xkb_state_serialize_mods(state, XKB_STATE_MODS_LOCKED),
        xkb_state_serialize_layout(state, XKB_STATE_LAYOUT_EFFECTIVE));
}

static void send_enter(struct wayland_keyboard *keyboard, struct wl_resource *resource,
                       uint32_t serial) {
    uint32_t held[KEY_CNT];
    size_t count = 0;
    for (uint32_t code = 0; code < KEY_CNT; ++code)
        if (keyboard->down[code]) held[count++] = code;
    struct wl_array keys = { .size = count * sizeof(*held), .data = held };
    wl_keyboard_send_enter(resource, serial, keyboard->focus, &keys);
    send_modifiers(keyboard, resource, serial);
}

static void focus_destroyed(struct wl_listener *listener, void *data) {
    (void)data;
    struct wayland_keyboard *keyboard = wl_container_of(listener, keyboard, focus_destroy);
    wl_list_remove(&listener->link);
    keyboard->focus = NULL;
}

void wayland_keyboard_focus(struct wayland_keyboard *keyboard, struct wl_resource *surface) {
    if (!keyboard || keyboard->focus == surface || (surface && !keyboard->input)) return;
    struct keyboard_client *client;
    if (keyboard->focus) {
        uint32_t serial = wl_display_next_serial(keyboard->display);
        wl_list_for_each(client, &keyboard->clients, link)
            if (client_owns(client->resource, keyboard->focus))
                wl_keyboard_send_leave(client->resource, serial, keyboard->focus);
        wl_list_remove(&keyboard->focus_destroy.link);
    }
    keyboard->focus = surface;
    if (!surface) return;
    wl_resource_add_destroy_listener(surface, &keyboard->focus_destroy);
    uint32_t serial = wl_display_next_serial(keyboard->display);
    wl_list_for_each(client, &keyboard->clients, link)
        if (client_owns(client->resource, surface)) send_enter(keyboard, client->resource, serial);
}

static void set_key(struct wayland_keyboard *keyboard, uint32_t code, bool down, uint32_t time) {
    if (code >= KEY_CNT || keyboard->down[code] == down) return;
    keyboard->down[code] = down;
    /* XKB использует смещение +8. В Wayland передаётся исходный код evdev. */
    enum xkb_state_component changes = xkb_state_update_key(keyboard->state, code + 8,
                                                             down ? XKB_KEY_DOWN : XKB_KEY_UP);
    if (!keyboard->focus) return;
    uint32_t serial = wl_display_next_serial(keyboard->display);
    struct keyboard_client *client;
    wl_list_for_each(client, &keyboard->clients, link) {
        if (!client_owns(client->resource, keyboard->focus)) continue;
        wl_keyboard_send_key(client->resource, serial, time, code,
            down ? WL_KEYBOARD_KEY_STATE_PRESSED : WL_KEYBOARD_KEY_STATE_RELEASED);
        if (changes & (XKB_STATE_MODS_DEPRESSED | XKB_STATE_MODS_LATCHED | XKB_STATE_MODS_LOCKED |
                       XKB_STATE_LAYOUT_EFFECTIVE)) send_modifiers(keyboard, client->resource, serial);
    }
}

static bool sync_keys(struct wayland_keyboard *keyboard, uint32_t time) {
    unsigned char bits[(KEY_CNT + 7) / 8] = {0};
    if (ioctl(keyboard->fd, EVIOCGKEY(sizeof(bits)), bits) < 0) return false;
    for (uint32_t code = 0; code < KEY_CNT; ++code)
        if (keyboard->down[code] && !(bits[code / 8] & (1u << (code % 8))))
            set_key(keyboard, code, false, time);
    for (uint32_t code = 0; code < KEY_CNT; ++code)
        if (!keyboard->down[code] && (bits[code / 8] & (1u << (code % 8))))
            set_key(keyboard, code, true, time);
    return true;
}

static int read_input(int fd, uint32_t mask, void *data) {
    (void)mask;
    struct wayland_keyboard *keyboard = data;
    struct input_event events[32];
    ssize_t size = read(fd, events, sizeof(events));
    if (size < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    if (size <= 0 || size % sizeof(*events)) {
        fputs("Wayland keyboard input stopped\n", stderr);
        wl_event_source_remove(keyboard->input);
        keyboard->input = NULL;
        wayland_keyboard_focus(keyboard, NULL);
        return 0;
    }
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint32_t time = (uint32_t)now.tv_sec * 1000 + (uint32_t)(now.tv_nsec / 1000000);
    for (size_t i = 0; i < (size_t)size / sizeof(*events); ++i) {
        const struct input_event *event = &events[i];
        if (event->type == EV_SYN && event->code == SYN_DROPPED) keyboard->dropped = true;
        else if (keyboard->dropped && event->type == EV_SYN && event->code == SYN_REPORT) {
            if (sync_keys(keyboard, time)) {
                keyboard->dropped = false;
                /* Снимок состояния уже учитывает события из оставшейся части буфера. */
                break;
            }
        } else if (!keyboard->dropped && event->type == EV_KEY && (event->value == 0 || event->value == 1)) {
            set_key(keyboard, event->code, event->value != 0, time);
        }
    }
    return 0;
}

static void release_request(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void keyboard_destroyed(struct wl_resource *resource) {
    struct keyboard_client *client = wl_resource_get_user_data(resource);
    wl_list_remove(&client->link);
    free(client);
}

static const struct wl_keyboard_interface keyboard_requests = { .release = release_request };

static void get_keyboard(struct wl_client *client, struct wl_resource *seat, uint32_t id) {
    struct wayland_keyboard *keyboard = wl_resource_get_user_data(seat);
    struct keyboard_client *entry = calloc(1, sizeof(*entry));
    if (entry) entry->resource = wl_resource_create(client, &wl_keyboard_interface, wl_resource_get_version(seat), id);
    if (!entry || !entry->resource) {
        free(entry);
        wl_client_post_no_memory(client);
        return;
    }
    struct wl_resource *resource = entry->resource;
    wl_list_insert(&keyboard->clients, &entry->link);
    wl_resource_set_implementation(resource, &keyboard_requests, entry, keyboard_destroyed);
    wl_keyboard_send_keymap(resource, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, keyboard->keymap_fd, keyboard->keymap_size);
    if (wl_resource_get_version(resource) >= WL_KEYBOARD_REPEAT_INFO_SINCE_VERSION)
        wl_keyboard_send_repeat_info(resource, 25, 600);
    if (client_owns(resource, keyboard->focus)) send_enter(keyboard, resource, wl_display_next_serial(keyboard->display));
}

static void missing_capability(struct wl_client *client, struct wl_resource *seat, uint32_t id) {
    (void)client;
    (void)id;
    wl_resource_post_error(seat, WL_SEAT_ERROR_MISSING_CAPABILITY, "Seat has only a keyboard");
}

static const struct wl_seat_interface seat_requests = {
    .get_pointer = missing_capability,
    .get_keyboard = get_keyboard,
    .get_touch = missing_capability,
    .release = release_request,
};

static void bind_seat(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wl_resource *seat = wl_resource_create(client, &wl_seat_interface, version, id);
    if (!seat) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(seat, &seat_requests, data, NULL);
    struct wayland_keyboard *keyboard = data;
    wl_seat_send_capabilities(seat, keyboard->input ? WL_SEAT_CAPABILITY_KEYBOARD : 0);
    if (version >= WL_SEAT_NAME_SINCE_VERSION) wl_seat_send_name(seat, "MyOS");
}

static bool load_keymap(struct wayland_keyboard *keyboard, const char *path) {
    struct stat info;
    keyboard->keymap_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (keyboard->keymap_fd < 0 || fstat(keyboard->keymap_fd, &info) ||
        info.st_size <= 0 || info.st_size > UINT32_MAX) return false;
    keyboard->keymap_size = (uint32_t)info.st_size;
    const char *map = mmap(NULL, keyboard->keymap_size, PROT_READ, MAP_PRIVATE, keyboard->keymap_fd, 0);
    if (map == MAP_FAILED) return false;
    struct xkb_context *ctx = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES);
    if (ctx && !map[keyboard->keymap_size - 1]) {
        struct xkb_keymap *layout = xkb_keymap_new_from_string(ctx, map, XKB_KEYMAP_FORMAT_TEXT_V1,
                                                               XKB_KEYMAP_COMPILE_NO_FLAGS);
        if (layout) {
            keyboard->state = xkb_state_new(layout);
            xkb_keymap_unref(layout);
        }
    }
    xkb_context_unref(ctx);
    munmap((void *)map, keyboard->keymap_size);
    return keyboard->state != NULL;
}

bool wayland_keyboard_init(struct wayland_keyboard **result, struct wl_display *display,
                           const char *keymap_path) {
    int fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENODEV) return true;
        perror("/dev/input/event0");
        return false;
    }
    struct wayland_keyboard *keyboard = calloc(1, sizeof(*keyboard));
    if (!keyboard) {
        close(fd);
        return false;
    }
    keyboard->display = display;
    keyboard->fd = fd;
    keyboard->keymap_fd = -1;
    keyboard->focus_destroy.notify = focus_destroyed;
    wl_list_init(&keyboard->clients);
    if (!load_keymap(keyboard, keymap_path) || !sync_keys(keyboard, 0)) {
        fprintf(stderr, "Could not initialize Wayland keyboard with %s\n", keymap_path);
        wayland_keyboard_destroy(keyboard);
        return false;
    }
    keyboard->input = wl_event_loop_add_fd(wl_display_get_event_loop(display), fd, WL_EVENT_READABLE,
                                          read_input, keyboard);
    if (keyboard->input) keyboard->seat = wl_global_create(display, &wl_seat_interface, 7, keyboard, bind_seat);
    if (!keyboard->seat) {
        wayland_keyboard_destroy(keyboard);
        return false;
    }
    *result = keyboard;
    return true;
}

void wayland_keyboard_destroy(struct wayland_keyboard *keyboard) {
    if (!keyboard) return;
    if (keyboard->focus) wl_list_remove(&keyboard->focus_destroy.link);
    if (keyboard->seat) wl_global_destroy(keyboard->seat);
    if (keyboard->input) wl_event_source_remove(keyboard->input);
    if (keyboard->keymap_fd >= 0) close(keyboard->keymap_fd);
    xkb_state_unref(keyboard->state);
    close(keyboard->fd);
    free(keyboard);
}
