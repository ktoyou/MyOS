#ifndef MYOS_WAYLAND_KEYBOARD_H
#define MYOS_WAYLAND_KEYBOARD_H

#include <stdbool.h>
#include <wayland-server-core.h>

struct wayland_keyboard;

bool wayland_keyboard_init(struct wayland_keyboard **result, struct wl_display *display,
                           const char *keymap_path);
void wayland_keyboard_focus(struct wayland_keyboard *keyboard, struct wl_resource *surface);
void wayland_keyboard_destroy(struct wayland_keyboard *keyboard);

#endif
