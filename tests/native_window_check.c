/* Нативное окно занимает почти весь экран: publication превышает старые 16 МиБ. */
#include "win.h"
int main(void) {
    struct gfx_info2 gi;
    if(gfx_info2(&gi)<0)return 1;
    int w=gi.width-80,h=gi.height-100;
    window *win=win_create("Native resolution buffer check",w,h);
    if(!win || !win->shared || !win->pixels){printf("NATIVE WINDOW FAIL allocation\n");return 1;}
    gfx_clear(RGB(20,60,120));
    gfx_fill_rect(w-64,h-64,64,64,RGB(220,40,60));
    gfx_fill_rect(w-64,0,64,64,RGB(40,220,60));
    gfx_fill_rect(0,h-64,64,64,RGB(40,60,220));
    gfx_text_scaled(24,24,"Full resolution shared window",C_WHITE,2);
    win_update(win);
    if(win->shared[(h-1)*w+w-1]!=RGB(220,40,60)) {printf("NATIVE WINDOW FAIL last pixel\n");return 1;}
    printf("NATIVE WINDOW PASS %dx%d bytes=%u\n",w,h,w*h*4);
    char *args[]={"display",NULL};
    if(spawn("/bin/display",args,-1)<0){printf("NATIVE WINDOW FAIL display launch\n");return 1;}
    sleep_ms(10000);win_destroy(win);return 0;
}
