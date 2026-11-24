/* Рисование и события — только в главном потоке; копирование не блокирует окно. */
#include "win.h"
#include "setup-copy.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"

#define STACK_BYTES (256u*1024u)
#define INK RGB(36,43,54)
#define MUTED RGB(116,125,139)
#define BORDER RGB(224,228,235)
#define BG RGB(247,248,250)
#define NAV RGB(36,43,57)
#define RED RGB(192,53,53)
enum { SCANNING, CHOOSE, PLANNING, REVIEW, INSTALLING, DONE, ERROR };
enum { JOB_SCAN, JOB_PLAN, JOB_INSTALL };
struct target {unsigned index;struct disk_install_info info;};
struct view {
    int state,count,selected;
    unsigned planned_at,files;
    unsigned long long bytes;
    struct target disks[INSTALL_TARGETS];
    struct disk_install_info plan;
    char phase[16],path[1024],error[1400];
};
static struct view shared;
static thread_mutex_t lock;
static window *win;
static int worker,job,hx=-1,hy=-1,focus=1;
static void *stack;
static bool fullscreen,close_requested,close_blocked,fatal_error,ack;
static int width=900,height=620,ox,oy;
static char confirmation[64];
static struct ui_edit confirmation_edit;

static bool busy(int state){return state==SCANNING || state==PLANNING || state==INSTALLING;}
static struct view snapshot(void){struct view v;thread_mutex_lock(&lock);v=shared;thread_mutex_unlock(&lock);return v;}
static void text(int size,int x,int y,const char *s,color_t color){text_draw(FONT_UI,size,x+ox,y+oy,s,color);}
static void bold(int size,int x,int y,const char *s,color_t color){text_draw(FONT_UI_MEDIUM,size,x+ox,y+oy,s,color);}
static void box(int x,int y,int w,int h,color_t fill){gfx_round_rect(x+ox,y+oy,w,h,9,fill);}
static bool inside(int x,int y,int bx,int by,int bw,int bh){return ui_inside(x,y,bx,by,bw,bh);}
static void clipped(int size,int x,int y,int w,const char *s,color_t color){gfx_set_clip(x+ox,y+oy,w,size+5);text(size,x,y,s,color);gfx_no_clip();}
static void wrapped(const char *s,int x,int y,int w,int rows,color_t color) {
    for(int row=0;*s && row<rows;row++) {
        char line[256];unsigned used=0,last_space=0;const char *start=s;
        while(*s && *s!='\n' && used<240) {
            unsigned char c=*s;unsigned n=c<128?1:(c&224)==192?2:(c&240)==224?3:4;
            if(strlen(s)<n)n=1;
            memcpy(line+used,s,n);line[used+n]=0;
            if(text_width(FONT_UI,13,line)>w && used)break;
            if(*s==' ')last_space=used;
            used+=n;s+=n;
        }
        if(*s && *s!='\n' && last_space){used=last_space;s=start+used;}
        line[used]=0;clipped(13,x,y+row*20,w,line,color);
        while(*s==' ')s++;
        if(*s=='\n')s++;
    }
}
static void button(int x,int y,int w,const char *label,int kind,bool enabled,bool focused) {
    unsigned state=kind==2?UI_BUTTON_DANGER:kind==1?UI_BUTTON_ACCENT:0;
    if(!enabled)state|=UI_BUTTON_DISABLED;
    if(focused)state|=UI_BUTTON_FOCUSED;
    if(inside(hx,hy,x,y,w,38))state|=UI_BUTTON_HOVER;
    ui_button_state(x+ox,y+oy,w,38,label,state);
}
static void capacity(char *out,unsigned sectors) {
    unsigned mib=sectors/2048;
    if(mib>=1024)snprintf(out,32,"%u.%u ГиБ",mib/1024,mib%1024*10/1024);
    else snprintf(out,32,"%u МиБ",mib);
}
static void progress(const char *phase,const char *path,unsigned files,unsigned long long bytes,void *arg) {
    (void)arg;thread_mutex_lock(&lock);
    snprintf(shared.phase,sizeof(shared.phase),"%s",phase);snprintf(shared.path,sizeof(shared.path),"%s",path);
    shared.files=files;shared.bytes=bytes;thread_mutex_unlock(&lock);
}
static void work(void *arg) {
    (void)arg;struct view v=snapshot();int result=0;
    if(job==JOB_SCAN) {
        result=disk_install(INSTALL_PROBE,0,NULL);v.count=0;
        if(!result)for(unsigned i=0;i<INSTALL_TARGETS;i++) {
            struct disk_install_info info;if(disk_install(INSTALL_LIST,i,&info)<0)continue;
            v.disks[v.count].index=i;v.disks[v.count++].info=info;
        }
        v.selected=v.count?0:-1;v.state=CHOOSE;
    } else if(job==JOB_PLAN) {
        result=disk_install(INSTALL_PLAN,v.disks[v.selected].index,&v.plan);
        v.planned_at=ticks();v.state=REVIEW;
    } else {
        struct disk_install_info current;unsigned index=v.disks[v.selected].index;
        result=disk_install(INSTALL_LIST,index,&current);
        if(!result && (strcmp(current.device,v.plan.device) || strcmp(current.model,v.plan.model) || current.sectors!=v.plan.sectors))result=-EBUSY;
        struct setup_copy_result copied;memset(&copied,0,sizeof(copied));
        if(!result) {
            result=setup_copy(index,&v.plan,&copied,progress,NULL);
            v.files=copied.files;v.bytes=copied.bytes;
            if(result)snprintf(v.error,sizeof(v.error),"%s",copied.error[0]?copied.error:"Installation failed");
        }
        if(result && !v.error[0])snprintf(v.error,sizeof(v.error),"%s",strerror(result<0?-result:EIO));
        v.state=result?ERROR:DONE;
    }
    if(result){v.state=ERROR;if(!v.error[0])snprintf(v.error,sizeof(v.error),"%s",strerror(result<0?-result:EIO));}
    thread_mutex_lock(&lock);shared=v;thread_mutex_unlock(&lock);
}
static void reap(void) {
    if(worker>0 && !busy(snapshot().state)){thread_join(worker,NULL);free(stack);stack=NULL;worker=0;}
}
static void start_job(int which) {
    reap();if(worker>0)return;
    stack=malloc(STACK_BYTES);if(!stack){thread_mutex_lock(&lock);shared.state=ERROR;strcpy(shared.error,"Not enough memory");thread_mutex_unlock(&lock);return;}
    job=which;thread_mutex_lock(&lock);shared.state=which==JOB_SCAN?SCANNING:which==JOB_PLAN?PLANNING:INSTALLING;
    shared.error[0]=0;shared.phase[0]=0;shared.path[0]=0;shared.files=0;shared.bytes=0;thread_mutex_unlock(&lock);
    worker=thread_create(work,NULL,stack,STACK_BYTES);
    if(worker<0){free(stack);stack=NULL;worker=0;thread_mutex_lock(&lock);shared.state=ERROR;strcpy(shared.error,"Could not start worker");thread_mutex_unlock(&lock);}
}
static void cancel_plan(void) {
    struct view v=snapshot();if(v.state!=REVIEW)return;
    disk_install(INSTALL_ABORT,v.disks[v.selected].index,&v.plan);
    thread_mutex_lock(&lock);shared.state=CHOOSE;shared.plan.token=0;thread_mutex_unlock(&lock);
    ack=false;confirmation[0]=0;focus=1;
}
static bool can_install(const struct view *v) {
    char expected[40];snprintf(expected,sizeof(expected),"erase %s",v->plan.device);
    return v->state==REVIEW && ack && !strcmp(confirmation,expected);
}
static void begin_install(void) {
    struct view v=snapshot();if(!can_install(&v))return;
    if((unsigned)(ticks()-v.planned_at)>300000u){cancel_plan();thread_mutex_lock(&lock);strcpy(shared.error,"План устарел. Выберите диск заново; диск не изменён.");thread_mutex_unlock(&lock);return;}
    start_job(JOB_INSTALL);
}
static void detail(int y,const char *key,const char *value) {
    text(13,218,y,key,MUTED);clipped(13,360,y,width-386,value,INK);
}
static void draw(const struct view *v) {
    if(win){win_select(win);width=win->w;height=win->h;ox=oy=0;}
    else {width=gfx_w<900?gfx_w:900;height=gfx_h<620?gfx_h:620;ox=(gfx_w-width)/2;oy=(gfx_h-height)/2;}
    gfx_clear(BG);gfx_fill_rect(ox,oy,170,height,NAV);
    box(22,27,36,36,UI_ACCENT);bold(23,29,30,"M",C_WHITE);bold(21,68,33,"MyOS",C_WHITE);
    text(12,22,83,"Установка системы",RGB(183,193,210));
    const char *steps[]={"Выбор диска","Подтверждение","Установка"};
    int step=v->state==CHOOSE || v->state==SCANNING?0:v->state==REVIEW || v->state==PLANNING?1:2;
    for(int i=0;i<3;i++) {
        char n[2]={'1'+i,0};gfx_fill_circle(35+ox,153+i*53+oy,13,i==step?UI_ACCENT:RGB(62,71,88));
        text(12,31,145+i*53,n,C_WHITE);text(12,58,145+i*53,steps[i],i==step?C_WHITE:RGB(151,163,183));
    }
    text(11,22,height-54,"SATA / AHCI · NVMe",RGB(151,163,183));text(11,22,height-33,"BIOS / UEFI x64",RGB(151,163,183));
    const char *title=v->state==REVIEW?"Проверьте выбранный диск":v->state==INSTALLING?"Устанавливаем MyOS":v->state==DONE?"MyOS установлена":v->state==ERROR?"Установка не завершена":"Куда установить MyOS?";
    bold(24,194,29,title,INK);
    text(12,194,67,v->state==REVIEW?"До подтверждения диск не изменяется.":v->state==INSTALLING?"Не выключайте компьютер до завершения проверки.":"Нативный установщик MyOS",MUTED);
    gfx_round_frame(194+ox,100+oy,width-216,height-124,12,BORDER,C_WHITE);
    if(v->state==CHOOSE) {
        for(int i=0;i<v->count;i++) {
            int y=118+i*77;bool selected=i==v->selected;char size[32];capacity(size,v->disks[i].info.sectors);
            gfx_round_frame(218+ox,y+oy,width-264,65,8,selected?UI_ACCENT:BORDER,selected?RGB(255,246,240):C_WHITE);
            gfx_round_frame(233+ox,y+17+oy,22,29,4,selected?UI_ACCENT:MUTED,C_WHITE);
            gfx_line(237+ox,y+37+oy,251+ox,y+37+oy,MUTED);
            clipped(13,270,y+12,width-520,v->disks[i].info.model,INK);
            clipped(12,270,y+36,width-520,v->disks[i].info.device,MUTED);
            bold(13,width-218,y+14,size,INK);text(11,width-218,y+37,strstr(v->disks[i].info.device,"nvme")?"NVMe":"SATA / AHCI",MUTED);
        }
        if(!v->count)wrapped("Свободных дисков для установки нет. Проверьте подключение SATA/NVMe и повторите поиск.",218,137,width-264,3,MUTED);
        wrapped(v->error[0]?v->error:"Выбранный диск будет полностью очищен. Загрузочный носитель и подключённые тома не предлагаются.",218,438,width-264,3,v->error[0]?RED:MUTED);
        button(218,height-78,140,"Обновить",0,true,focus==2);
        button(width-208,height-78,160,"Продолжить",1,v->selected>=0,focus==3);
    } else if(v->state==REVIEW) {
        char size[32];detail(124,"Модель",v->plan.model);detail(154,"Устройство",v->plan.device);
        capacity(size,v->plan.sectors);detail(184,"Ёмкость диска",size);capacity(size,v->plan.root_sectors);detail(214,"Раздел MyOS",size);
        detail(244,"Загрузка","UEFI x64 и BIOS / CSM");
        box(218,276,width-264,58,RGB(255,242,228));bold(13,232,286,"Все разделы и данные на диске будут удалены.",RGB(133,79,28));
        text(12,232,309,"Другие операционные системы не сохранятся.",RGB(133,79,28));
        char label[100];snprintf(label,sizeof(label),"Введите: erase %s",v->plan.device);text(13,218,350,label,INK);
        ui_edit_draw(&confirmation_edit,218+ox,374+oy,width-264,40,focus==1);
        gfx_round_frame(218+ox,437+oy,18,18,4,focus==2?UI_ACCENT:BORDER,ack?UI_ACCENT:C_WHITE);
        if(ack){gfx_line(222+ox,445+oy,226+ox,450+oy,C_WHITE);gfx_line(226+ox,450+oy,233+ox,441+oy,C_WHITE);}
        text(12,245,437,"Я проверил диск и согласен удалить все его данные.",INK);
        text(11,218,474,"План действует 5 минут. Enter в поле ввода не запускает запись.",MUTED);
        button(218,height-78,148,"Назад",0,true,focus==3);
        button(width-282,height-78,234,"Стереть и установить",2,can_install(v),focus==4);
    } else if(v->state==SCANNING || v->state==PLANNING) {
        bold(18,218,145,v->state==SCANNING?"Поиск дисков…":"Проверка загрузочного образа…",INK);
        wrapped("Дождитесь завершения проверки. На диски ничего не записывается.",218,189,width-264,3,MUTED);
        int w=width-264;box(218,267,w,7,BG);box(218+(ticks()/12)%(w-84),267,84,7,UI_ACCENT);
    } else if(v->state==ERROR) {
        box(218,122,width-264,54,RGB(255,237,237));bold(16,234,139,"Не удалось продолжить установку",RED);
        wrapped(v->error,218,201,width-264,7,INK);
        if(!fatal_error)wrapped("Если запись уже началась, на диске может остаться незавершённая установка.",218,365,width-264,3,MUTED);
        button(218,height-78,145,"Закрыть",0,true,focus==1);
        if(!fatal_error)button(width-254,height-78,206,"К выбору диска",1,true,focus==2);
    } else {
        const char *phase=!strcmp(v->phase,"copy")?"Копирование файлов":!strcmp(v->phase,"commit")?"Проверка и запись загрузчика":"Подготовка диска";
        bold(18,218,128,v->state==DONE?"Данные записаны и проверены":phase,v->state==DONE?RGB(40,126,79):INK);
        detail(170,"Устройство",v->plan.device);
        clipped(12,218,208,width-264,v->path,MUTED);
        int w=width-264;box(218,242,w,7,BG);
        if(v->state==DONE)box(218,242,w,7,RGB(50,151,94));else box(218+(ticks()/12)%(w-84),242,84,7,UI_ACCENT);
        char count[40];snprintf(count,sizeof(count),"%u",v->files);box(218,280,(w-14)/2,87,BG);bold(26,234,294,count,INK);text(12,234,334,"файлов скопировано",MUTED);
        snprintf(count,sizeof(count),"%u МиБ",(unsigned)(v->bytes/1048576));box(232+(w-14)/2,280,(w-14)/2,87,BG);bold(26,248+(w-14)/2,294,count,INK);text(12,248+(w-14)/2,334,"данных скопировано",MUTED);
        if(v->state==DONE) {
            wrapped("Выключите MyOS командой poweroff. Извлеките Live-носитель и выберите установленный диск в меню загрузки.",218,405,w,4,INK);
            button(width-208,height-78,160,"Закрыть",1,true,true);
        } else wrapped(close_blocked?"Сначала дождитесь завершения установки. Закрытие окна сейчас отключено.":"Не выключайте компьютер и не извлекайте диски. Прогресс обновляется автоматически.",218,405,w,4,MUTED);
    }
    if(win)win_update(win);else {struct mouse m;mouse_get(&m);gfx_cursor_draw(m.x,m.y);gfx_flip();gfx_cursor_erase();}
}
static void action(struct view *v,int key,int x,int y,bool click) {
    if(v->state==CHOOSE) {
        if(click){for(int i=0;i<v->count;i++)if(inside(x,y,218,118+i*77,width-264,65)){thread_mutex_lock(&lock);shared.selected=i;thread_mutex_unlock(&lock);focus=1;return;}}
        if(key==KEY_UP || key==KEY_DOWN){if(v->count){thread_mutex_lock(&lock);shared.selected=(v->selected+(key==KEY_DOWN?1:v->count-1))%v->count;thread_mutex_unlock(&lock);}focus=1;}
        if(key=='\t')focus=ui_focus_step(focus,3,v->selected<0?4:0,1);
        if((click && inside(x,y,218,height-78,140,38)) || (key==13 && focus==2))start_job(JOB_SCAN);
        else if(v->selected>=0 && ((click && inside(x,y,width-208,height-78,160,38)) || (key==13 && focus!=2))){ack=false;confirmation[0]=0;focus=1;start_job(JOB_PLAN);}
    } else if(v->state==REVIEW) {
        if(click){if(inside(x,y,218,374,width-264,40)){focus=1;ui_edit_click(&confirmation_edit,218,x);}else if(inside(x,y,218,431,width-264,32)){focus=2;ack=!ack;}
            else if(inside(x,y,218,height-78,148,38)){cancel_plan();return;}
            else if(inside(x,y,width-282,height-78,234,38)){focus=4;begin_install();return;}}
        if(key=='\t')focus=ui_focus_step(focus,4,can_install(v)?0:8,1);
        else if(key==27)cancel_plan();
        else if(focus==1)ui_edit_key(&confirmation_edit,key);
        else if(focus==2 && (key==' ' || key==13))ack=!ack;
        else if(focus==3 && key==13)cancel_plan();
        else if(focus==4 && key==13)begin_install();
    } else if(v->state==DONE){if(key==13 || key==27 || (click && inside(x,y,width-208,height-78,160,38)))close_requested=true;}
    else if(v->state==ERROR){if(key=='\t')focus=ui_focus_step(focus,fatal_error?1:2,0,1);
        if(!fatal_error && ((click && inside(x,y,width-254,height-78,206,38)) || (key==13 && focus==2)))start_job(JOB_SCAN);
        else if(key==27 || (key==13 && focus==1) || (click && inside(x,y,218,height-78,145,38)))close_requested=true;}
}
int main(void) {
    ui_edit_init(&confirmation_edit,confirmation,sizeof(confirmation),UI_EDIT_ASCII);
    win=win_create("Установка MyOS",900,620);
    if(win)win_set_resizable(win,800,600);
    else {if(gfx_open()<0){puts("setup-gui: graphics unavailable; use setup DEVICE");return 1;}fullscreen=true;}
    if(gfx_w<800 || gfx_h<600){if(win)win_destroy(win);else gfx_close();puts("setup-gui: requires at least 800x600");return 1;}
    shared.selected=-1;
    if(geteuid() || service_register("disk-setup")<0){fatal_error=true;shared.state=ERROR;strcpy(shared.error,geteuid()?"Для установки войдите в MyOS под root.":"Другой установщик уже работает. Закройте его перед запуском этого окна.");}
    else start_job(JOB_SCAN);
    unsigned painted=0;int last_state=-1;bool desktop_lost=false;
    for(;;) {
        reap();struct view v=snapshot();
        if(v.state!=last_state){static const char *names[]={"scanning","choose","planning","review","installing","done","error"};printf("SETUP GUI: %s device=%s\n",names[v.state],v.plan.device);last_state=v.state;if(v.state==ERROR || v.state==DONE)focus=1;painted=0;}
        if(close_requested && !busy(v.state))break;
        if((unsigned)(ticks()-painted)>=120 && !desktop_lost){draw(&v);painted=ticks();}
        int key=-1,x=-1,y=-1;bool click=false,closing=false;
        if(win && !desktop_lost) {
            struct event e;if(!win_event(&e,60)){desktop_lost=true;close_requested=true;continue;}
            if(e.type==EV_CLOSE || e.type==EV_QUIT)closing=true;
            if(e.type==EV_KEY)key=e.key;
            if(e.type==EV_MOUSE_MOVE){hx=e.x;hy=e.y;}
            if(e.type==EV_MOUSE_DOWN && (e.buttons&MOUSE_LEFT)){x=e.x;y=e.y;click=true;}
        } else if(fullscreen) {
            if(gfx_check_mode())painted=0;
            struct mouse m;mouse_get(&m);static unsigned old_buttons;hx=m.x-ox;hy=m.y-oy;
            if((m.buttons&MOUSE_LEFT) && !(old_buttons&MOUSE_LEFT)){x=hx;y=hy;click=true;}old_buttons=m.buttons;
            key=readkey();sleep_ms(20);
        } else sleep_ms(30);
        if(key=='\n')key=13;
        if(key==27 && v.state!=REVIEW)closing=true;
        if(closing){if(v.state==INSTALLING){close_blocked=true;printf("SETUP GUI: close blocked while installing\n");}else close_requested=true;painted=0;}
        if(key>=0 || click){action(&v,key,x,y,click);painted=0;}
        if(desktop_lost && !busy(v.state))break;
    }
    reap();cancel_plan();if(win)win_destroy(win);else gfx_close();return 0;
}
