/* Настоящий диалог; тест умеет прервать процесс без пользовательского отката. */
#define win_update observed_update
#define win_event observed_event
#define gfx_save_config observed_save
#define main display_main
#include "../user/display.c"
#undef main
#undef gfx_save_config
#undef win_event
#undef win_update
void win_update(window *w);
int win_event(struct event *e,int timeout);
int gfx_save_config(int w,int h,int cursor);
static unsigned last_token=~0u;
static int last_seconds=-1;
void observed_update(window *w) {
    win_update(w);
    int seconds=(trial_remaining+999)/1000;
    if(trial_token!=last_token || (trial_token && seconds!=last_seconds)) {
        struct gfx_info2 gi;gfx_info2(&gi);
        printf("DISPLAY UI: token=%u screen=%ux%u seconds=%d policy=%dx%d pid=%d\n",trial_token,gi.width,gi.height,trial_token?seconds:0,policy_w,policy_h,getpid());
        last_token=trial_token;last_seconds=seconds;
    }
}
int observed_event(struct event *e,int timeout) {
    int r=win_event(e,timeout);
    if(r && trial_token && e->type==EV_KEY && e->key=='k'){puts("DISPLAY UI: abrupt exit");exit(91);}
    if(r && trial_token && e->type==EV_KEY && e->key=='q')e->type=EV_CLOSE;
    if(r && trial_token && e->type==EV_KEY && e->key=='z') {
        puts("DISPLAY UI: blocked for 20 seconds");sleep_ms(20000);e->type=EV_TIMEOUT;
    }
    return r;
}
int observed_save(int w,int h,int cursor) {
    int r=gfx_save_config(w,h,cursor);
    printf("DISPLAY SAVE: %dx%d result=%d\n",w,h,r);return r;
}
int main(void){return display_main();}
