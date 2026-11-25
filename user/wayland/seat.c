#include "seat.h"
#include "keyboard.h"

#include <stdlib.h>
#include <wayland-server-protocol.h>

struct wayland_seat {
    struct wl_global *global;
    struct wl_list clients;
    struct wayland_keyboard *keyboard;
    struct wayland_pointer *pointer;
};

struct seat_client {
    struct wl_list link;
    struct wayland_seat *seat;
    struct wl_resource *resource;
};

static uint32_t capabilities(const struct wayland_seat *seat) {
    uint32_t result = 0;
    if (wayland_keyboard_available(seat->keyboard)) result |= WL_SEAT_CAPABILITY_KEYBOARD;
    if (wayland_pointer_available(seat->pointer)) result |= WL_SEAT_CAPABILITY_POINTER;
    return result;
}

static void capabilities_changed(void *data) {
    struct wayland_seat *seat = data;
    struct seat_client *client;
    uint32_t mask = capabilities(seat);
    wl_list_for_each(client, &seat->clients, link) wl_seat_send_capabilities(client->resource, mask);
}

static void missing_capability(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    (void)client;
    (void)id;
    wl_resource_post_error(resource, WL_SEAT_ERROR_MISSING_CAPABILITY, "Seat has no requested device");
}

static void get_pointer(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct seat_client *entry = wl_resource_get_user_data(resource);
    if (entry->seat->pointer)
        wayland_pointer_bind(entry->seat->pointer, client, wl_resource_get_version(resource), id);
    else
        missing_capability(client, resource, id);
}

static void get_keyboard(struct wl_client *client, struct wl_resource *resource, uint32_t id) {
    struct seat_client *entry = wl_resource_get_user_data(resource);
    if (entry->seat->keyboard)
        wayland_keyboard_bind(entry->seat->keyboard, client, wl_resource_get_version(resource), id);
    else
        missing_capability(client, resource, id);
}

static void release_request(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void seat_destroyed(struct wl_resource *resource) {
    struct seat_client *client = wl_resource_get_user_data(resource);
    wl_list_remove(&client->link);
    free(client);
}

static const struct wl_seat_interface seat_requests = {
    .get_pointer = get_pointer,
    .get_keyboard = get_keyboard,
    .get_touch = missing_capability,
    .release = release_request,
};

static void bind_seat(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wayland_seat *seat = data;
    struct seat_client *entry = calloc(1, sizeof(*entry));
    if (entry) entry->resource = wl_resource_create(client, &wl_seat_interface, version, id);
    if (!entry || !entry->resource) {
        free(entry);
        wl_client_post_no_memory(client);
        return;
    }
    entry->seat = seat;
    wl_list_insert(&seat->clients, &entry->link);
    wl_resource_set_implementation(entry->resource, &seat_requests, entry, seat_destroyed);
    wl_seat_send_capabilities(entry->resource, capabilities(seat));
    if (version >= WL_SEAT_NAME_SINCE_VERSION) wl_seat_send_name(entry->resource, "MyOS");
}

bool wayland_seat_init(struct wayland_seat **result, struct wl_display *display, const char *keymap_path,
                       int width, int height, const struct wayland_pointer_ops *ops, void *data) {
    struct wayland_seat *seat = calloc(1, sizeof(*seat));
    if (!seat) return false;
    wl_list_init(&seat->clients);
    if (!wayland_keyboard_init(&seat->keyboard, display, keymap_path, capabilities_changed, seat) ||
        !wayland_pointer_init(&seat->pointer, display, width, height, ops, data, capabilities_changed, seat)) {
        wayland_seat_destroy(seat);
        return false;
    }
    if (seat->keyboard || seat->pointer) {
        seat->global = wl_global_create(display, &wl_seat_interface, 7, seat, bind_seat);
        if (!seat->global) {
            wayland_seat_destroy(seat);
            return false;
        }
    }
    *result = seat;
    return true;
}

void wayland_seat_keyboard_focus(struct wayland_seat *seat, struct wl_resource *surface) {
    if (seat) wayland_keyboard_focus(seat->keyboard, surface);
}

void wayland_seat_pointer_update(struct wayland_seat *seat) {
    if (seat) wayland_pointer_update(seat->pointer);
}

void wayland_seat_pointer_detach(struct wayland_seat *seat, struct wl_resource *surface) {
    if (seat) wayland_pointer_detach(seat->pointer, surface);
}

void wayland_seat_destroy(struct wayland_seat *seat) {
    if (!seat) return;
    if (seat->global) wl_global_destroy(seat->global);
    wayland_pointer_destroy(seat->pointer);
    wayland_keyboard_destroy(seat->keyboard);
    free(seat);
}
