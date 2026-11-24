#include "win.h"
#include "libnsfb.h"
#include "libnsfb_plot.h"
#include "libnsfb_event.h"

void netsurf_myos_register(void);

int main(void)
{
    netsurf_myos_register();
    nsfb_t *fb = nsfb_new(nsfb_type_from_name("myos"));
    if (!fb)
        return 1;
    int result = 1;
    if (nsfb_set_geometry(fb, 480, 300, NSFB_FMT_XRGB8888) == 0 &&
        nsfb_init(fb) == 0) {
        nsfb_bbox_t area = {0, 0, 480, 300};
        if (nsfb_plot_rectangle_fill(fb, &area, 0xff8844) && nsfb_update(fb, &area) == 0) {
            puts("NetSurf: frame submitted");
            nsfb_event_t event;
            while (nsfb_event(fb, &event, -1) == false ||
                   event.type != NSFB_EVENT_CONTROL || event.value.controlcode != NSFB_CONTROL_QUIT)
                ;
            result = 0;
        }
    }
    nsfb_free(fb);
    return result;
}
