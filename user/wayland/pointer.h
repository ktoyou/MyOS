#ifndef MYOS_WAYLAND_POINTER_H
#define MYOS_WAYLAND_POINTER_H

#include <stdbool.h>
#include <stdint.h>
#include <wayland-server-core.h>

struct wayland_pointer;

struct wayland_pointer_ops {
    struct wl_resource *(*pick)(void *data, int x, int y);
    void (*coordinates)(struct wl_resource *surface, int x, int y, wl_fixed_t *sx, wl_fixed_t *sy);
    bool (*assign_cursor)(void *data, struct wl_resource *surface);
    void (*paint)(void *data, int x, int y, struct wl_resource *cursor,
                  int32_t hotspot_x, int32_t hotspot_y, bool visible);
};

bool wayland_pointer_init(struct wayland_pointer **result, struct wl_display *display, int width, int height,
                          const struct wayland_pointer_ops *ops, void *data,
                          void (*changed)(void *), void *changed_data);
bool wayland_pointer_available(const struct wayland_pointer *pointer);
void wayland_pointer_bind(struct wayland_pointer *pointer, struct wl_client *client, int version, uint32_t id);
void wayland_pointer_update(struct wayland_pointer *pointer);
void wayland_pointer_detach(struct wayland_pointer *pointer, struct wl_resource *surface);
void wayland_pointer_destroy(struct wayland_pointer *pointer);

#endif
