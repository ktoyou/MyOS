/* Проверяем, что временный режим не попадает в настройки без явного согласия. */
#define main display_program_main
#include "../user/display.c"
#undef main
static unsigned writes,keeps,reverts;
static int next_token=7,next_keep,remaining=15000,save_error;
static int saved_w,saved_h;
static void check(bool ok,const char *what){if(!ok){printf("Display UI FAIL: %s\n",what);exit(1);}}
int gfx_try_mode(int w,int h){(void)w;(void)h;return next_token;}
int gfx_keep_mode(unsigned token){check(token==7,"keep token");keeps++;return next_keep;}
int gfx_revert_mode(unsigned token){check(token==7,"revert token");reverts++;return 0;}
int gfx_mode_remaining(unsigned token){check(token==7,"remaining token");return remaining;}
int gfx_save_config(int w,int h,int cursor){(void)cursor;writes++;saved_w=w;saved_h=h;return save_error;}
int gfx_modes(struct gfx_mode *out,int max){check(max>=2,"catalogue capacity");out[0]=(struct gfx_mode){1024,768,1};out[1]=(struct gfx_mode){1280,720,1};return 2;}
bool ui_inside(int px,int py,int x,int y,int w,int h){return px>=x && py>=y && px<x+w && py<y+h;}
static void key(int code){struct event e={.type=EV_KEY,.key=code};trial_event(&e);}
static void reset(void){trial_token=0;writes=keeps=reverts=0;next_token=7;next_keep=save_error=0;remaining=15000;policy_w=1024;policy_h=768;refresh_modes();}
int main(void) {
    reset();apply(1);check(trial_token==7 && !writes && policy_w==1024,"preview does not save");
    key('\r');check(!trial_token && reverts==1 && !keeps && !writes,"Enter defaults to revert");
    reset();apply(1);key(27);check(!trial_token && reverts==1 && !writes,"Escape reverts");
    reset();apply(1);key('\t');key('\r');check(!trial_token && keeps==1 && writes==1 && saved_w==1280 && saved_h==720,"explicit keep saves");
    reset();apply(-1);key(KEY_LEFT);key(' ');check(writes==1 && !saved_w && !saved_h,"Auto saved as policy");
    reset();apply(1);remaining=-ENOENT;trial_poll();check(!trial_token && !writes && policy_w==1024,"timeout preserves saved policy");
    reset();apply(1);remaining=0;trial_poll();key(KEY_LEFT);key('\r');check(!keeps && !writes && trial_token,"failed rollback cannot be kept");
    key(KEY_RIGHT);key('\r');check(!trial_token && reverts==1,"retry revert button");
    reset();apply(1);next_keep=-ENOENT;key(KEY_LEFT);key('\r');check(!writes && !trial_token,"stale acceptance never saves");
    reset();next_token=-EBUSY;apply(1);check(!trial_token && !writes && policy_w==1024,"another pending change untouched");
    reset();next_token=0;apply(-1);check(!trial_token && writes==1 && !saved_w,"unchanged geometry has no black-screen risk");
    reset();apply(1);save_error=-EIO;key(KEY_LEFT);key('\r');check(!trial_token && strstr(status,"could not save"),"save failure reported after confirmation");
    reset();apply(1);struct event e={.type=EV_MOUSE_DOWN,.buttons=MOUSE_RIGHT,.x=80,.y=300};trial_event(&e);
    check(!keeps && !reverts && !writes,"right click ignored");e.buttons=MOUSE_LEFT;trial_event(&e);check(keeps==1 && writes==1,"left click keep");
    puts("Display UI: explicit keep, safe Enter/Escape, timeout, Auto policy, contention and save failure: PASS");
}
