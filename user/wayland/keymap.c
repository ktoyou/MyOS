#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xkbcommon/xkbcommon.h>

int main(void) {
    const struct xkb_rule_names names = {.rules = "evdev", .model = "pc105", .layout = "us"};
    struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
    if (!context) return 1;
    struct xkb_keymap *keymap = xkb_keymap_new_from_names(context, &names, XKB_KEYMAP_COMPILE_NO_FLAGS);
    char *text = keymap ? xkb_keymap_get_as_string(keymap, XKB_KEYMAP_FORMAT_TEXT_V1) : NULL;
    int status = 1;
    if (text) {
        size_t length = strlen(text) + 1;
        status = fwrite(text, 1, length, stdout) != length || fflush(stdout) != 0;
        free(text);
    }
    xkb_keymap_unref(keymap);
    xkb_context_unref(context);
    return status;
}
