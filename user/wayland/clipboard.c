#include "clipboard.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wayland-server-protocol.h>

enum { INPUT_SERIAL_COUNT = 8, MAX_MIME_BYTES = 64 * 1024 };

struct wayland_clipboard {
    struct wl_global *global;
    struct wl_list devices;
    struct wl_client *focus;
    struct selection_source *selection;
    bool (*owns_seat)(void *, struct wl_resource *);
    void *seat;
    uint64_t generation;
    uint32_t input_serials[INPUT_SERIAL_COUNT], selection_serial;
    unsigned serial_count;
    bool input_seen, selection_serial_valid;
};

struct selection_source {
    struct wayland_clipboard *clipboard;
    struct wl_resource *resource;
    struct wl_list types;
    size_t type_bytes;
    bool used, drag_actions_set;
};

struct mime_type {
    struct wl_list link;
    char name[];
};

struct selection_device {
    struct wl_list link;
    struct wayland_clipboard *clipboard;
    struct wl_resource *resource;
};

struct selection_offer {
    struct wayland_clipboard *clipboard;
    uint64_t generation;
};

static void destroy_request(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static const struct mime_type *find_type(const struct selection_source *source, const char *name) {
    const struct mime_type *type;
    wl_list_for_each(type, &source->types, link)
        if (!strcmp(type->name, name)) return type;
    return NULL;
}

static void accept_offer(struct wl_client *client, struct wl_resource *resource,
                         uint32_t serial, const char *name) {
    (void)client;
    (void)resource;
    (void)serial;
    (void)name;
}

static void receive_offer(struct wl_client *client, struct wl_resource *resource,
                          const char *name, int32_t fd) {
    struct selection_offer *offer = wl_resource_get_user_data(resource);
    struct wayland_clipboard *clipboard = offer->clipboard;
    struct selection_source *source = clipboard->selection;
    /* Новое окно может получить фокус при отображении. Для чтения нужен ввод этому клиенту. */
    if (clipboard->focus == client && clipboard->input_seen &&
        offer->generation == clipboard->generation && source && find_type(source, name))
        wl_data_source_send_send(source->resource, name, fd);
    close(fd);
}

static void offer_destroyed(struct wl_resource *resource) {
    free(wl_resource_get_user_data(resource));
}

static void finish_selection(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_post_error(resource, WL_DATA_OFFER_ERROR_INVALID_FINISH, "Selection offers do not finish a drag");
}

static void set_offer_actions(struct wl_client *client, struct wl_resource *resource,
                              uint32_t actions, uint32_t preferred) {
    (void)client;
    (void)actions;
    (void)preferred;
    wl_resource_post_error(resource, WL_DATA_OFFER_ERROR_INVALID_OFFER, "Selection offers have no drag actions");
}

static const struct wl_data_offer_interface offer_requests = {
    .accept = accept_offer,
    .receive = receive_offer,
    .destroy = destroy_request,
    .finish = finish_selection,
    .set_actions = set_offer_actions,
};

static void send_selection(struct selection_device *device) {
    struct wayland_clipboard *clipboard = device->clipboard;
    struct selection_source *source = clipboard->selection;
    if (!source) {
        wl_data_device_send_selection(device->resource, NULL);
        return;
    }

    struct wl_client *client = wl_resource_get_client(device->resource);
    struct selection_offer *offer = calloc(1, sizeof(*offer));
    struct wl_resource *resource = offer ?
        wl_resource_create(client, &wl_data_offer_interface, wl_resource_get_version(device->resource), 0) : NULL;
    if (!resource) {
        free(offer);
        wl_client_post_no_memory(client);
        return;
    }

    offer->clipboard = clipboard;
    offer->generation = clipboard->generation;
    wl_resource_set_implementation(resource, &offer_requests, offer, offer_destroyed);
    wl_data_device_send_data_offer(device->resource, resource);
    const struct mime_type *type;
    wl_list_for_each(type, &source->types, link) wl_data_offer_send_offer(resource, type->name);
    wl_data_device_send_selection(device->resource, resource);
}

static void publish_selection(struct wayland_clipboard *clipboard) {
    ++clipboard->generation;
    struct selection_device *device;
    wl_list_for_each(device, &clipboard->devices, link)
        if (wl_resource_get_client(device->resource) == clipboard->focus) send_selection(device);
}

static void add_type(struct wl_client *client, struct wl_resource *resource, const char *name) {
    struct selection_source *source = wl_resource_get_user_data(resource);
    if (source->used || find_type(source, name)) return;
    size_t length = strlen(name) + 1;
    size_t bytes = sizeof(struct mime_type) + length;
    if (bytes > MAX_MIME_BYTES - source->type_bytes) {
        wl_client_post_no_memory(client);
        return;
    }
    struct mime_type *type = malloc(bytes);
    if (!type) {
        wl_client_post_no_memory(client);
        return;
    }
    source->type_bytes += bytes;
    memcpy(type->name, name, length);
    wl_list_insert(source->types.prev, &type->link);
}

static void source_destroyed(struct wl_resource *resource) {
    struct selection_source *source = wl_resource_get_user_data(resource);
    struct wayland_clipboard *clipboard = source->clipboard;
    if (clipboard->selection == source) {
        clipboard->selection = NULL;
        publish_selection(clipboard);
    }
    struct mime_type *type, *next;
    wl_list_for_each_safe(type, next, &source->types, link) {
        wl_list_remove(&type->link);
        free(type);
    }
    free(source);
}

static void set_source_actions(struct wl_client *client, struct wl_resource *resource,
                                uint32_t actions) {
    (void)client;
    const uint32_t allowed = WL_DATA_DEVICE_MANAGER_DND_ACTION_COPY |
                             WL_DATA_DEVICE_MANAGER_DND_ACTION_MOVE |
                             WL_DATA_DEVICE_MANAGER_DND_ACTION_ASK;
    struct selection_source *source = wl_resource_get_user_data(resource);
    if (actions & ~allowed) {
        wl_resource_post_error(resource, WL_DATA_SOURCE_ERROR_INVALID_ACTION_MASK, "Invalid drag actions");
        return;
    }
    if (source->used || source->drag_actions_set) {
        wl_resource_post_error(resource, WL_DATA_SOURCE_ERROR_INVALID_SOURCE, "Drag actions already set");
        return;
    }
    source->drag_actions_set = true;
}

static const struct wl_data_source_interface source_requests = {
    .offer = add_type,
    .destroy = destroy_request,
    .set_actions = set_source_actions,
};

static int input_serial_index(const struct wayland_clipboard *clipboard, uint32_t serial) {
    for (unsigned i = 0; i < clipboard->serial_count; ++i)
        if (clipboard->input_serials[i] == serial) return (int)i;
    return -1;
}

static void set_selection(struct wl_client *client, struct wl_resource *resource,
                          struct wl_resource *source_resource, uint32_t serial) {
    struct selection_device *device = wl_resource_get_user_data(resource);
    struct wayland_clipboard *clipboard = device->clipboard;
    if (client != clipboard->focus) return;
    int index = input_serial_index(clipboard, serial);
    if (index < 0) return;
    bool repeat = clipboard->selection_serial_valid && clipboard->selection_serial == serial;
    if (repeat && (clipboard->selection || !source_resource)) return;

    struct selection_source *source = source_resource ? wl_resource_get_user_data(source_resource) : NULL;
    if (source && source->used) {
        wl_resource_post_error(resource, WL_DATA_DEVICE_ERROR_USED_SOURCE, "Data source has already been used");
        return;
    }
    if (source && source->drag_actions_set) {
        wl_resource_post_error(source_resource, WL_DATA_SOURCE_ERROR_INVALID_SOURCE, "Drag source cannot select data");
        return;
    }

    /* Клиент может пересоздать свой источник на то же нажатие после его удаления.
     * Более старые события больше не смогут заменить выбор. */
    clipboard->serial_count -= (unsigned)index;
    memmove(clipboard->input_serials, clipboard->input_serials + index,
            clipboard->serial_count * sizeof(*clipboard->input_serials));
    clipboard->selection_serial = serial;
    clipboard->selection_serial_valid = true;
    if (clipboard->selection) wl_data_source_send_cancelled(clipboard->selection->resource);
    clipboard->selection = source;
    if (source) source->used = true;
    publish_selection(clipboard);
}

static void start_drag(struct wl_client *client, struct wl_resource *resource,
                       struct wl_resource *source_resource, struct wl_resource *origin,
                       struct wl_resource *icon, uint32_t serial) {
    (void)origin;
    (void)icon;
    struct selection_device *device = wl_resource_get_user_data(resource);
    if (!source_resource || client != device->clipboard->focus ||
        input_serial_index(device->clipboard, serial) < 0) return;
    struct selection_source *source = wl_resource_get_user_data(source_resource);
    if (source->used) {
        wl_resource_post_error(resource, WL_DATA_DEVICE_ERROR_USED_SOURCE, "Data source has already been used");
        return;
    }
    /* Обмен через selection доступен без отдельного сеанса перетаскивания. */
    if (wl_resource_get_version(source_resource) >= WL_DATA_SOURCE_ACTION_SINCE_VERSION) {
        source->used = true;
        wl_data_source_send_cancelled(source_resource);
    }
}

static const struct wl_data_device_interface device_requests = {
    .start_drag = start_drag,
    .set_selection = set_selection,
    .release = destroy_request,
};

static void device_destroyed(struct wl_resource *resource) {
    struct selection_device *device = wl_resource_get_user_data(resource);
    wl_list_remove(&device->link);
    free(device);
}

static void create_source(struct wl_client *client, struct wl_resource *manager, uint32_t id) {
    struct selection_source *source = calloc(1, sizeof(*source));
    if (source)
        source->resource = wl_resource_create(client, &wl_data_source_interface,
                                              wl_resource_get_version(manager), id);
    if (!source || !source->resource) {
        free(source);
        wl_client_post_no_memory(client);
        return;
    }
    source->clipboard = wl_resource_get_user_data(manager);
    wl_list_init(&source->types);
    wl_resource_set_implementation(source->resource, &source_requests, source, source_destroyed);
}

static void get_device(struct wl_client *client, struct wl_resource *manager,
                       uint32_t id, struct wl_resource *seat_resource) {
    struct wayland_clipboard *clipboard = wl_resource_get_user_data(manager);
    if (!clipboard->owns_seat(clipboard->seat, seat_resource)) {
        wl_client_post_implementation_error(client, "Unknown seat for data device");
        return;
    }
    struct selection_device *device = calloc(1, sizeof(*device));
    if (device)
        device->resource = wl_resource_create(client, &wl_data_device_interface,
                                              wl_resource_get_version(manager), id);
    if (!device || !device->resource) {
        free(device);
        wl_client_post_no_memory(client);
        return;
    }
    device->clipboard = clipboard;
    wl_list_insert(&clipboard->devices, &device->link);
    wl_resource_set_implementation(device->resource, &device_requests, device, device_destroyed);
    if (client == clipboard->focus) send_selection(device);
}

static const struct wl_data_device_manager_interface manager_requests = {
    .create_data_source = create_source,
    .get_data_device = get_device,
};

static void bind_manager(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    struct wl_resource *resource = wl_resource_create(client, &wl_data_device_manager_interface, version, id);
    if (!resource) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(resource, &manager_requests, data, NULL);
}

bool wayland_clipboard_init(struct wayland_clipboard **result, struct wl_display *display,
                            bool (*owns_seat)(void *, struct wl_resource *), void *data) {
    struct wayland_clipboard *clipboard = calloc(1, sizeof(*clipboard));
    if (!clipboard) return false;
    clipboard->owns_seat = owns_seat;
    clipboard->seat = data;
    wl_list_init(&clipboard->devices);
    clipboard->global = wl_global_create(display, &wl_data_device_manager_interface, 3, clipboard, bind_manager);
    if (!clipboard->global) {
        free(clipboard);
        return false;
    }
    *result = clipboard;
    return true;
}

void wayland_clipboard_focus(struct wayland_clipboard *clipboard, struct wl_client *client) {
    if (!clipboard || clipboard->focus == client) return;
    clipboard->focus = client;
    clipboard->serial_count = 0;
    clipboard->selection_serial_valid = clipboard->input_seen = false;
    publish_selection(clipboard);
}

void wayland_clipboard_input(struct wayland_clipboard *clipboard, struct wl_client *client,
                             uint32_t serial) {
    if (!clipboard || !client || clipboard->focus != client) return;
    if (clipboard->serial_count == INPUT_SERIAL_COUNT) {
        --clipboard->serial_count;
        memmove(clipboard->input_serials, clipboard->input_serials + 1,
                clipboard->serial_count * sizeof(*clipboard->input_serials));
    }
    clipboard->input_serials[clipboard->serial_count++] = serial;
    clipboard->input_seen = true;
}

void wayland_clipboard_destroy(struct wayland_clipboard *clipboard) {
    if (!clipboard) return;
    wl_global_destroy(clipboard->global);
    free(clipboard);
}
