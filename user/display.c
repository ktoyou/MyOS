/* Каталог драйвера с прокруткой: редкие режимы монитора тоже доступны. */
#include "win.h"
#define W 600
#define H 440
#define COLS 4
#define ROWS 6
#define GX 14
#define GY 104
#define BW 138
#define BH 30
static window *win;
static struct gfx_mode modes[256];
static int nmodes,top,selected,focus,hw_cursor,policy_w,policy_h;
static char status[92];
static int rows(void){return (nmodes+COLS-1)/COLS;}
static void scroll(int delta){top+=delta;if(top>rows()-ROWS)top=rows()-ROWS;if(top<0)top=0;}
static void visible(void){if(selected/COLS<top)top=selected/COLS;if(selected/COLS>=top+ROWS)top=selected/COLS-ROWS+1;}
static void draw(void) {
    struct gfx_info2 gi;memset(&gi,0,sizeof(gi));gfx_info2(&gi);
    gfx_clear(UI_FACE);
    gfx_fill_rect(0,0,W,44,UI_ACCENT);gfx_text_scaled(14,6,"Display",C_WHITE,2);
    char text[100];
    snprintf(text,sizeof(text),"%s   %ux%u, %u bpp",gi.driver,gi.width,gi.height,gi.bpp);
    gfx_text(GX,54,text,UI_TEXT,TRANSPARENT);
    snprintf(text,sizeof(text),"%d modes   rows %d-%d/%d   Wheel / arrows / Tab",nmodes,top+1,top+ROWS<rows()?top+ROWS:rows(),rows());
    gfx_text(GX,78,text,UI_DARK,TRANSPARENT);
    for(int cell=0;cell<COLS*ROWS;cell++) {
        int i=top*COLS+cell;if(i>=nmodes)break;
        int x=GX+cell%COLS*(BW+6),y=GY+cell/COLS*(BH+5);
        snprintf(text,sizeof(text),"%dx%d",modes[i].w,modes[i].h);
        bool current=modes[i].w==(int)gi.width && modes[i].h==(int)gi.height;
        ui_button_state(x,y,BW,BH,text,(current?UI_BUTTON_PRESSED:0)|(!focus && i==selected?UI_BUTTON_FOCUSED:0)|(!modes[i].ok?UI_BUTTON_DISABLED:0));
    }
    ui_button_state(GX,322,W-2*GX,32,"Auto / native monitor resolution",(!policy_w?UI_BUTTON_PRESSED:0)|(focus==1?UI_BUTTON_FOCUSED:0));
    ui_button_state(GX,366,W-2*GX,28,hw_cursor?"Hardware cursor: on":"Hardware cursor: off",(hw_cursor?UI_BUTTON_PRESSED:0)|(focus==2?UI_BUTTON_FOCUSED:0)|(!(gi.caps&GFX_CAP_CURSOR)?UI_BUTTON_DISABLED:0));
    gfx_text(GX,410,status,UI_DARK,TRANSPARENT);win_update(win);
}
static void save(void) {
    snprintf(status,sizeof(status),gfx_save_config(policy_w,policy_h,hw_cursor)<0?
        "Applied, but could not save /etc/display":"Applied and saved to /etc/display");
}
static void apply(int i) {
    int w=i<0?0:modes[i].w,h=i<0?0:modes[i].h;
    if(gfx_set_mode(w,h)<0){snprintf(status,sizeof(status),"Mode unavailable: firmware or memory limit");return;}
    policy_w=w;policy_h=h;save();
    nmodes=gfx_modes(modes,256);if(selected>=nmodes)selected=nmodes?nmodes-1:0;scroll(0);
}
static void cursor(void) {
    struct gfx_info2 gi;if(gfx_info2(&gi)<0 || !(gi.caps&GFX_CAP_CURSOR))return;
    hw_cursor=!hw_cursor;
    struct msg m;memset(&m,0,sizeof(m));m.type=WM_DISPLAY;m.a=hw_cursor;
    msg_send(win_desktop_pid(),&m);save();
}
int main(void) {
    win=win_create("Display",W,H);
    if(!win){dprintf(STDERR,"display: the desktop is not running\n");return 1;}
    nmodes=gfx_modes(modes,256);
    struct gfx_info2 gi;memset(&gi,0,sizeof(gi));gfx_info2(&gi);
    hw_cursor=gi.hw_cursor;
    /* Отсутствие настройки означает политику загрузчика Auto. */
    gfx_load_config(&policy_w,&policy_h,&hw_cursor);
    for(int i=0;i<nmodes;i++)if(modes[i].w==(int)gi.width && modes[i].h==(int)gi.height)selected=i;
    visible();
    snprintf(status,sizeof(status),(gi.caps&GFX_CAP_FIXED_MODE)?"Firmware fixes the mode until reboot":"Choose a resolution or Auto.");
    draw();struct event e;
    while(win_event(&e,500)) {
        if(e.type==EV_CLOSE || e.type==EV_QUIT || (e.type==EV_KEY && e.key==27))break;
        if(e.type==EV_MOUSE_WHEEL)scroll(-e.wheel);
        if(e.type==EV_MOUSE_DOWN) {
            if(ui_inside(e.x,e.y,GX,GY,W-2*GX,ROWS*(BH+5))) {
                int c=(e.x-GX)/(BW+6),r=(e.y-GY)/(BH+5),i=(top+r)*COLS+c;
                if(c<COLS && i<nmodes && (e.x-GX)%(BW+6)<BW && (e.y-GY)%(BH+5)<BH){selected=i;focus=0;apply(i);}
            } else if(ui_inside(e.x,e.y,GX,322,W-2*GX,32)){focus=1;apply(-1);}
            else if(ui_inside(e.x,e.y,GX,366,W-2*GX,28)){focus=2;cursor();}
        }
        if(e.type==EV_KEY) {
            if(e.key=='\t')focus=(focus+1)%3;
            else if(e.key=='\r' || e.key=='\n' || e.key==' '){if(focus==1)apply(-1);else if(focus==2)cursor();else if(nmodes)apply(selected);}
            else if(!focus && nmodes) {
                if(e.key==KEY_LEFT)selected--;
                if(e.key==KEY_RIGHT)selected++;
                if(e.key==KEY_UP)selected-=COLS;
                if(e.key==KEY_DOWN)selected+=COLS;
                if(e.key==KEY_PGUP)selected-=COLS*ROWS;
                if(e.key==KEY_PGDN)selected+=COLS*ROWS;
                if(e.key==KEY_HOME)selected=0;
                if(e.key==KEY_END)selected=nmodes-1;
                if(selected<0)selected=0;
                if(selected>=nmodes)selected=nmodes-1;
                visible();
            }
        }
        draw();
    }
    win_destroy(win);return 0;
}
