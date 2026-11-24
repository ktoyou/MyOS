/* Production-контроллер с отказами видеодрайвера и исчезновением процесса. */
#include "../kernel/display.c"
extern int printf(const char *,...);
extern int puts(const char *);
extern void exit(int) __attribute__((noreturn));
#define CHECK(x) do{if(!(x)){printf("Display trial line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static struct fb_info screen={.width=1024,.height=768,.native_w=1280,.native_h=720};
static struct task owner={.id=42,.state=TASK_READY};
static unsigned now,created,attempts,free_bytes=512u*1024*1024;
static bool allocation_failure,set_failure,restore_failure,missing_owner,reenter;
bool fb_ready(void){return true;}
void fb_get_info(struct fb_info *out){*out=screen;}
bool fb_mode_at(unsigned i,u32 *w,u32 *h){return video_common_mode(i,w,h);}
int fb_set_mode(u32 w,u32 h) {
    attempts++;
    if(reenter){reenter=false;CHECK(display_trial_ctl(VIDEO_MODE_TRY,800,600,43)==-EBUSY);}
    if(set_failure || (restore_failure && w==1024 && h==768))return -1;
    if(w!=800 && w!=1024 && w!=1280)return -1;
    screen.width=w;screen.height=h;screen.gen++;return 0;
}
bool fb_mode_ok(u32 w,u32 h){return (w==800 && h==600) || (w==1024 && h==768) || (w==1280 && h==720);}
void pmm_stats(struct pmm_stats *p){p->used_frames=0;p->total_frames=free_bytes/4096;}
void vga_resize(void){}
void mouse_set_bounds(int w,int h){CHECK((unsigned)w==screen.width && (unsigned)h==screen.height);}
void kprintf(const char *format,...){(void)format;}
u32 timer_ticks(void){return now;}
void sleep_ms(u32 ms){(void)ms;}
struct task *task_by_id(u32 id){return !missing_owner && id==owner.id?&owner:NULL;}
int task_create(const char *name,void (*entry)(void *),void *arg){(void)name;(void)arg;CHECK(entry==display_guard);created++;return allocation_failure?-1:100;}
static void reset(void) {
    CHECK(!trial.token);screen.width=1024;screen.height=768;now=100;
    allocation_failure=set_failure=restore_failure=missing_owner=reenter=false;
    free_bytes=512u*1024*1024;owner.state=TASK_READY;owner.kill_pending=false;
}
static unsigned begin(void){int r=display_trial_ctl(VIDEO_MODE_TRY,1280,720,42);CHECK(r>0 && screen.width==1280);return r;}
static int ctl(unsigned op,unsigned token){return display_trial_ctl(op,token,0,42);}
int main(void) {
    reset();CHECK(ctl(99,1)==-EINVAL && display_trial_ctl(VIDEO_MODE_KEEP,1,1,42)==-EINVAL);
    allocation_failure=true;CHECK(display_trial_ctl(VIDEO_MODE_TRY,1280,720,42)==-ENOMEM && screen.width==1024);
    allocation_failure=false;CHECK(display_trial_ctl(VIDEO_MODE_TRY,1024,768,42)==0 && !trial.token);
    unsigned t=begin();CHECK(ctl(VIDEO_MODE_REMAINING,t)==15000);
    CHECK(display_set_mode(800,600)==-EBUSY && display_trial_ctl(VIDEO_MODE_TRY,800,600,43)==-EBUSY);
    CHECK(display_trial_ctl(VIDEO_MODE_KEEP,t,0,43)==-EPERM && ctl(VIDEO_MODE_KEEP,t+1)==-ENOENT);
    free_bytes=0;CHECK(ctl(VIDEO_MODE_REVERT,t)==0 && screen.width==1024 && !trial.token);
    reset();reenter=true;t=begin();now+=100;CHECK(ctl(VIDEO_MODE_KEEP,t)==0 && !trial.token);
    now+=2000;poll_trial();CHECK(screen.width==1280 && ctl(VIDEO_MODE_KEEP,t)==-ENOENT);
    reset();t=begin();now+=1500;CHECK(ctl(VIDEO_MODE_KEEP,t)==-ENOENT && screen.width==1024);
    reset();t=begin();owner.state=TASK_ZOMBIE;poll_trial();CHECK(!trial.token && screen.width==1024);
    reset();t=begin();missing_owner=true;poll_trial();CHECK(!trial.token && screen.width==1024);
    reset();t=begin();owner.kill_pending=true;poll_trial();CHECK(!trial.token && screen.width==1024);
    reset();set_failure=true;CHECK(display_trial_ctl(VIDEO_MODE_TRY,1280,720,42)==-EINVAL && !trial.token);
    reset();t=begin();restore_failure=true;now+=1500;poll_trial();CHECK(trial.token==t && trial.failed);
    unsigned attempted=attempts;CHECK(ctl(VIDEO_MODE_REMAINING,t)==0 && attempts==attempted);
    CHECK(ctl(VIDEO_MODE_KEEP,t)==-ETIMEDOUT && trial.token==t);
    CHECK(display_trial_ctl(VIDEO_MODE_TRY,800,600,42)==-EBUSY);
    restore_failure=false;now+=100;poll_trial();CHECK(!trial.token && screen.width==1024);
    reset();t=begin();CHECK(display_set_mode(1024,768)==0 && !trial.token);
    reset();t=display_trial_ctl(VIDEO_MODE_TRY,0,0,42);CHECK(t>0 && screen.width==1280);CHECK(ctl(VIDEO_MODE_REVERT,t)==0);
    reset();now=0xfffffff0u;t=begin();CHECK(ctl(VIDEO_MODE_REMAINING,t)==15000);
    now+=1499;CHECK(ctl(VIDEO_MODE_REMAINING,t)==10);now++;poll_trial();CHECK(!trial.token && screen.width==1024);
    CHECK(created==2); /* Один отказ выделения и один постоянный watchdog. */
    puts("Display trial: deadline/wrap, ownership, crashes, cancellation, OOM rollback, driver failure and retry: PASS");
}
