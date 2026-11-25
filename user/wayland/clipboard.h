#ifndef MYOS_WAYLAND_CLIPBOARD_H
#define MYOS_WAYLAND_CLIPBOARD_H

#include <stdbool.h>
#include <stdint.h>
#include <wayland-server-core.h>

struct wayland_clipboard;

bool wayland_clipboard_init(struct wayland_clipboard **result, struct wl_display *display,
                            bool (*owns_seat)(void *, struct wl_resource *), void *data);
void wayland_clipboard_focus(struct wayland_clipboard *clipboard, struct wl_client *client);
void wayland_clipboard_input(struct wayland_clipboard *clipboard, struct wl_client *client,
                             uint32_t serial);
void wayland_clipboard_destroy(struct wayland_clipboard *clipboard);

#endif
