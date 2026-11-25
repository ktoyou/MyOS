#ifndef MYOS_WAYLAND_SEAT_H
#define MYOS_WAYLAND_SEAT_H

#include "pointer.h"

struct wayland_seat;

bool wayland_seat_init(struct wayland_seat **result, struct wl_display *display, const char *keymap_path,
                       int width, int height, const struct wayland_pointer_ops *ops, void *data);
void wayland_seat_keyboard_focus(struct wayland_seat *seat, struct wl_resource *surface);
void wayland_seat_pointer_update(struct wayland_seat *seat);
void wayland_seat_pointer_detach(struct wayland_seat *seat, struct wl_resource *surface);
void wayland_seat_destroy(struct wayland_seat *seat);

#endif
