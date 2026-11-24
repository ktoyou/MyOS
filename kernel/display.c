/* Смена разрешения экрана целиком: видеокарта, консоль, границы мыши.
 * Выбор пользователя хранится в файле /etc/display (строка «1280x720»),
 * его читает ядро при загрузке, а пишут программы mode и Display. */
#include "display.h"
#include "fb.h"
#include "vga.h"
#include "mouse.h"
#include "fs.h"
#include "pmm.h"
#include "task.h"
#include "timer.h"
#include "syscall.h"

static struct {u32 token,owner,w,h,deadline,retry_at;bool failed;} trial;
static u32 trial_serial;
static bool guard_started;
static bool transition;
static int change_mode(u32 w,u32 h);

static bool trial_expired(void) {return (i32)(timer_ticks()-trial.deadline)>=0;}
static int restore_trial(void) {
    if(transition)return -EBUSY;
    transition=true;
    /* Возврат к уже проверенному режиму не блокируется оценкой свободной RAM. */
    if(fb_set_mode(trial.w,trial.h)<0) {
        if(!trial.failed)kprintf("Display: rollback to %ux%u failed; retrying\n",trial.w,trial.h);
        trial.failed=true;trial.retry_at=timer_ticks()+TIMER_HZ;transition=false;return -EIO;
    }
    vga_resize();mouse_set_bounds(trial.w,trial.h);
    kprintf("Display: restored %ux%u\n",trial.w,trial.h);
    trial.token=0;trial.failed=false;transition=false;return 0;
}
static void poll_trial(void) {
    if(!trial.token || transition)return;
    if(trial.failed && (i32)(timer_ticks()-trial.retry_at)<0)return;
    struct task *owner=task_by_id(trial.owner);
    if(trial.failed || trial_expired() || !owner || owner->state==TASK_ZOMBIE || owner->kill_pending)
        restore_trial();
}
static void display_guard(void *unused) {
    (void)unused;
    /* BIOS и консоль нельзя переключать из обработчика IRQ таймера. */
    for(;;){poll_trial();sleep_ms(trial.failed?1000:100);}
}

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
        if(!change_mode(modes[best].w,modes[best].h))return 0;
    }
    return -1;
}

static int change_mode(u32 w, u32 h) {
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

int display_set_mode(u32 w,u32 h) {
    if(transition)return -EBUSY;
    poll_trial();
    if(trial.token) {
        /* Композитор тоже вправе отменить preview, если новый буфер не выделился. */
        if(w==trial.w && h==trial.h)return restore_trial();
        return -EBUSY;
    }
    transition=true;
    int result=change_mode(w,h);transition=false;return result;
}

int display_trial_ctl(u32 operation,u32 w,u32 h,u32 owner) {
    if(operation<VIDEO_MODE_TRY || operation>VIDEO_MODE_REMAINING ||
       (operation!=VIDEO_MODE_TRY && h))return -EINVAL;
    if(transition)return -EBUSY;
    poll_trial();
    if(operation==VIDEO_MODE_TRY) {
        if(trial.token)return -EBUSY;
        if(!guard_started) {
            if(task_create("display-guard",display_guard,NULL)<0)return -ENOMEM;
            guard_started=true;
        }
        struct fb_info before,after;fb_get_info(&before);
        transition=true;
        int result=change_mode(w,h);transition=false;
        if(result<0)return -EINVAL;
        fb_get_info(&after);
        if(before.width==after.width && before.height==after.height)return 0;
        trial_serial=(trial_serial+1)&0x7fffffffu;if(!trial_serial)trial_serial=1;
        trial.token=trial_serial;trial.owner=owner;trial.w=before.width;trial.h=before.height;
        trial.deadline=timer_ticks()+VIDEO_TRIAL_MS*TIMER_HZ/1000;trial.failed=false;
        return trial.token;
    }
    if(!trial.token || !w || trial.token!=w)return -ENOENT;
    if(trial.owner!=owner)return -EPERM;
    if(operation==VIDEO_MODE_REVERT)return restore_trial();
    if(operation==VIDEO_MODE_KEEP) {
        if(trial.failed || trial_expired())return -ETIMEDOUT;
        trial.token=0;return 0;
    }
    i32 left=(i32)(trial.deadline-timer_ticks());
    return trial.failed || left<=0?0:(u32)left*(1000/TIMER_HZ);
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
