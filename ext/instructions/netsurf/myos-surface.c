/* Оконная поверхность для framebuffer-интерфейса NetSurf 3.11. */
#include "win.h"
#include "libnsfb.h"
#include "libnsfb_event.h"
#include "surface.h"
#include "plot.h"

struct surface_state {
    window *window;
    nsfb_event_t pending;
};

static int set_geometry(nsfb_t *fb, int width, int height, enum nsfb_format_e format)
{
    if (width <= 0 || height <= 0 || format != NSFB_FMT_XRGB8888)
        return -1;
    if (fb->surface_priv && (width != fb->width || height != fb->height))
        return -1;
    fb->width = width;
    fb->height = height;
    fb->format = format;
    return select_plotters(fb) ? 0 : -1;
}

static int initialise(nsfb_t *fb)
{
    struct surface_state *state = calloc(1, sizeof(*state));
    if (!state)
        return -1;
    state->window = win_create("NetSurf", fb->width, fb->height);
    if (!state->window) {
        free(state);
        return -1;
    }
    fb->surface_priv = state;
    fb->ptr = (uint8_t *)state->window->pixels;
    fb->linelen = state->window->w * sizeof(color_t);
    return 0;
}

static int finalise(nsfb_t *fb)
{
    struct surface_state *state = fb->surface_priv;
    if (state) {
        win_destroy(state->window);
        free(state);
    }
    fb->surface_priv = NULL;
    fb->ptr = NULL;
    return 0;
}

static int update(nsfb_t *fb, nsfb_bbox_t *box)
{
    struct surface_state *state = fb->surface_priv;
    if (!state)
        return -1;
    if (box)
        win_update_rect(state->window, box->x0, box->y0,
                        box->x1 - box->x0, box->y1 - box->y0);
    else
        win_update(state->window);
    return 0;
}

static int keycode(int key)
{
    static const int navigation[] = {
        NSFB_KEY_UP, NSFB_KEY_DOWN, NSFB_KEY_RIGHT, NSFB_KEY_LEFT,
        NSFB_KEY_HOME, NSFB_KEY_END, NSFB_KEY_PAGEUP, NSFB_KEY_PAGEDOWN,
        NSFB_KEY_DELETE, NSFB_KEY_INSERT
    };
    if (key >= KEY_UP && key <= KEY_INS)
        return navigation[key - KEY_UP];
    return key == '\n' ? NSFB_KEY_RETURN : key;
}

static bool input(nsfb_t *fb, nsfb_event_t *out, int timeout)
{
    struct surface_state *state = fb->surface_priv;
    struct event e;
    if (state->pending.type) {
        *out = state->pending;
        state->pending.type = NSFB_EVENT_NONE;
        return true;
    }
    if (!win_event(&e, timeout) || e.type == EV_CLOSE || e.type == EV_QUIT) {
        out->type = NSFB_EVENT_CONTROL;
        out->value.controlcode = NSFB_CONTROL_QUIT;
        return true;
    }
    if (e.type == EV_KEY) {
        out->type = NSFB_EVENT_KEY_DOWN;
        out->value.keycode = keycode(e.key);
        state->pending = *out;
        state->pending.type = NSFB_EVENT_KEY_UP;
        return true;
    }
    if (e.type == EV_MOUSE_MOVE || e.type == EV_MOUSE_DOWN || e.type == EV_MOUSE_UP ||
        e.type == EV_MOUSE_WHEEL) {
        out->type = NSFB_EVENT_MOVE_ABSOLUTE;
        out->value.vector.x = e.x;
        out->value.vector.y = e.y;
        out->value.vector.z = 0;
        if (e.type != EV_MOUSE_MOVE) {
            state->pending.type = e.type == EV_MOUSE_UP ? NSFB_EVENT_KEY_UP : NSFB_EVENT_KEY_DOWN;
            state->pending.value.keycode = e.type == EV_MOUSE_WHEEL ?
                (e.wheel > 0 ? NSFB_KEY_MOUSE_4 : NSFB_KEY_MOUSE_5) : NSFB_KEY_MOUSE_1;
        }
        return true;
    }
    return false;
}

static const nsfb_surface_rtns_t methods = {
    .geometry = set_geometry, .initialise = initialise, .finalise = finalise,
    .input = input, .update = update
};

/* crt0 MyOS требует явной регистрации перед nsfb_new. */
void netsurf_myos_register(void)
{
    extern const nsfb_surface_rtns_t ram_rtns;
    /* Миниатюры истории рисуются в RAM, без создания окна рабочего стола. */
    _nsfb_register_surface(NSFB_SURFACE_RAM, &ram_rtns, "ram");
    _nsfb_register_surface(NSFB_SURFACE_COUNT + 1, &methods, "myos");
}
