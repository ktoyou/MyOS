/* Смена разрешения экрана целиком: видеокарта, консоль, границы мыши.
 * Выбор пользователя хранится в файле /etc/display (строка «1280x720»),
 * его читает ядро при загрузке, а пишут программы mode и Display. */
#include "display.h"
#include "fb.h"
#include "vga.h"
#include "mouse.h"
#include "fs.h"
#include "pmm.h"

static int display_auto(void) {
    struct fb_info fi;fb_get_info(&fi);
    struct candidate {u32 w,h,rank;} modes[256];unsigned n=0;u32 w,h;
    for(unsigned i=0;n<256 && fb_mode_at(i,&w,&h);i++)
        if(fb_mode_ok(w,h))modes[n++]=(struct candidate){w,h,video_rank(w,h,0,0,fi.native_w,fi.native_h)};
    for(unsigned attempt=0;attempt<n;attempt++) {
        unsigned best=n;u32 rank=0;
        for(unsigned i=0;i<n;i++)if(modes[i].rank>rank){best=i;rank=modes[i].rank;}
        if(best==n)break;
        modes[best].rank=0;
        if(!display_set_mode(modes[best].w,modes[best].h))return 0;
    }
    return -1;
}

int display_set_mode(u32 w, u32 h) {
    if (!fb_ready()) return -1;
    if(!w && !h)return display_auto();
    struct fb_info fi;
    fb_get_info(&fi);
    if (fi.width == w && fi.height == h) {
        mouse_set_bounds(fi.width,fi.height);
        return 0;
    }
    struct pmm_stats memory;pmm_stats(&memory);
    unsigned available=(memory.total_frames-memory.used_frames)*4096;
    /* Уже выделенные экранные буферы освобождаются после смены режима. */
    if((u64)w*h*4>video_memory_budget(available))return -1;
    if (fb_set_mode(w, h) < 0) return -1;
    vga_resize();
    mouse_set_bounds(w, h);
    return 0;
}

/* «1280x720» -> w, h */
bool display_parse(const char *s, u32 *w, u32 *h) {
    return video_parse_mode(s,w,h);
}

void display_load_config(void) {
    if (!fb_ready() || !fs_ready()) return;
    u32 ino;
    if (fs_resolve(FS_ROOT, "/etc/display", &ino) != FS_OK) return;
    char buf[64];
    int n = fs_read(ino, 0, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = 0;
    u32 w, h;
    if (display_parse(buf, &w, &h)) display_set_mode(w, h);
}
