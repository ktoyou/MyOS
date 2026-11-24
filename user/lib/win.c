/* Окна для программ: разговор с рабочим столом (desktop) сообщениями + общая память. */
#include "win.h"

#define MAX_WINDOWS 8
static int desktop;                             /* pid рабочего стола */
static window *wins[MAX_WINDOWS];
static struct msg pending[16];                  /* пришли, пока ждали ответа на WM_CREATE */
static int n_pending;
static bool font_loaded;

/* Pixel copies precede publication/acknowledgement on all guest CPUs. */
static void frame_barrier(void) {
#ifndef __MYOS_CC__
    __asm__ volatile ("mfence" : : : "memory");
#endif
}

static bool wait_consumed(window *w) {
    unsigned start = ticks();
    int yields=0;
    while (w->frame->submitted != w->frame->consumed) {
        frame_barrier();
        if (ticks() - start >= 2000 || service_find("desktop") != desktop) return false;
        /* Let a ready desktop capture this frame immediately instead of
         * imposing the PIT's 10 ms sleep quantum on every publication. */
        if(yields++<16)yield();else sleep_ms(1);
    }
    frame_barrier();
    return true;
}

static void release_buffer(window *w) {
    if (w->frame) { shm_unmap(w->frame); free(w->pixels); }
    else shm_unmap(w->pixels);
}

int win_desktop_pid(void) {
    if (!desktop) desktop = service_find("desktop");
    return desktop;
}

static void copy_title(char *dst, const char *src) {
    int i = 0;
    for (; src[i] && i < 39; i++) dst[i] = src[i];
    dst[i] = 0;
}

window *win_create(const char *title, int w, int h) {
    if (!win_desktop_pid() || w <= 0 || h <= 0 || w > VIDEO_MAX_WIDTH || h > VIDEO_MAX_HEIGHT) return NULL;
    if (!font_loaded) { gfx_load_font(); font_loaded = true; }
    int slot = -1;
    for (int i = 0; i < MAX_WINDOWS; i++) if (!wins[i]) { slot = i; break; }
    if (slot < 0) return NULL;

    int id = shm_alloc(WM_FRAME_BYTES + w * h * 4);
    if (id < 0) return NULL;
    if(shm_grant(id,desktop,SHM_READ|SHM_WRITE)<0){shm_discard(id);return NULL;}
    color_t *px = shm_map(id);
    if (!px) { shm_discard(id); return NULL; }

    struct msg m;
    memset(&m, 0, sizeof(m));
    m.type = WM_CREATE;
    m.a = id; m.b = w; m.c = h; m.d = WM_BUFFERED;
    copy_title(m.data, title);
    if (msg_send(desktop, &m) < 0) { shm_unmap(px); return NULL; }

    for (;;) {                                  /* ждём номер окна */
        struct msg r;
        if (msg_recv(&r, 2000) < 0) { shm_unmap(px); return NULL; }
        if (r.from == desktop && r.type == WM_CREATED) {
            if (r.a < 0) { shm_unmap(px); return NULL; }
            window *win = calloc(1, sizeof(window));
            color_t *draw = (unsigned)r.b == WM_BUFFERED ? calloc(w * h, 4) : px;
            if (!win || !draw) {
                struct msg close = {0}; close.type = WM_DESTROY; close.a = r.a;
                msg_send(desktop, &close);
                if ((unsigned)r.b == WM_BUFFERED) free(draw);
                free(win); shm_unmap(px); return NULL;
            }
            win->id = r.a;
            win->w = w; win->h = h;
            win->pixels = draw;
            win->shm = id;
            if ((unsigned)r.b == WM_BUFFERED) {
                win->frame = (struct win_frame *)px;
                win->shared = (color_t *)((char *)px + WM_FRAME_BYTES);
            }
            wins[slot] = win;
            win_select(win);
            return win;
        }
        if (n_pending < 16) pending[n_pending++] = r;
    }
}

void win_destroy(window *w) {
    if (!w) return;
    struct msg m;
    memset(&m, 0, sizeof(m));
    m.type = WM_DESTROY;
    m.a = w->id;
    msg_send(desktop, &m);
    for (int i = 0; i < MAX_WINDOWS; i++) if (wins[i] == w) wins[i] = NULL;
    release_buffer(w);
    free(w);
}

void win_select(window *w) {
    gfx_buf = w->pixels;
    gfx_w = w->w;
    gfx_h = w->h;
}

void win_update_rect(window *w, int x, int y, int rw, int rh) {
    if (!w || rw <= 0 || rh <= 0) return;
    if (w->full_update) { x = y = 0; rw = w->w; rh = w->h; }
    if (x < 0) { rw += x; x = 0; }
    if (y < 0) { rh += y; y = 0; }
    if (x >= w->w || y >= w->h || rw <= 0 || rh <= 0) return;
    if (rw > w->w - x) rw = w->w - x;
    if (rh > w->h - y) rh = w->h - y;
    if (w->frame) {
        if (!wait_consumed(w)) { w->full_update = true; return; }
        for (int row = y; row < y + rh; row++)
            memcpy(w->shared + row * w->w + x, w->pixels + row * w->w + x, rw * 4);
        frame_barrier();
        w->frame->submitted++;
        frame_barrier();
    }
    struct msg m;
    memset(&m, 0, sizeof(m));
    m.type = WM_UPDATE;
    m.a = w->id;
    m.b = x; m.c = y;
    m.d = (rw & 0xFFFF) | (rh << 16);
    int result;
    unsigned start = ticks();
    while ((result = msg_send(desktop, &m)) == -EAGAIN && ticks() - start < 2000)
        sleep_ms(1);
    /* No message references this publication after a failed send. The next
     * update publishes the entire buffer so its earlier damage is not lost. */
    if (result < 0 && w->frame) {
        w->frame->consumed = w->frame->submitted;
        w->full_update = true;
    } else if (result == 0) w->full_update = false;
}

void win_update(window *w) { win_update_rect(w, 0, 0, w->w, w->h); }

void win_set_title(window *w, const char *title) {
    struct msg m;
    memset(&m, 0, sizeof(m));
    m.type = WM_TITLE;
    m.a = w->id;
    copy_title(m.data, title);
    msg_send(desktop, &m);
}

void win_set_resizable(window *w, int min_w, int min_h) {
    struct msg m;
    memset(&m, 0, sizeof(m));
    m.type = WM_RESIZABLE;
    m.a = w->id; m.b = min_w; m.c = min_h;
    msg_send(desktop, &m);
}

/* Новый буфер под новый размер: старое содержимое — в левый верхний угол, остальное
 * цветом правого нижнего пикселя (обычно это фон окна), чтобы до перерисовки не мигало. */
static bool resize_buffer(window *w, int nw, int nh) {
    if (nw <= 0 || nh <= 0 || nw > VIDEO_MAX_WIDTH || nh > VIDEO_MAX_HEIGHT) return false;
    if (nw == w->w && nh == w->h) return false;
    int id = shm_alloc((w->frame ? WM_FRAME_BYTES : 0) + nw * nh * 4);
    if (id < 0) return false;
    if(shm_grant(id,desktop,SHM_READ|SHM_WRITE)<0){shm_discard(id);return false;}
    void *mapping = shm_map(id);
    if (!mapping) { shm_discard(id); return false; }
    color_t *px = w->frame ? malloc(nw * nh * 4) : mapping;
    if (!px) { shm_unmap(mapping); return false; }
    color_t fill = w->pixels[w->w * w->h - 1];
    int cw = nw < w->w ? nw : w->w, ch = nh < w->h ? nh : w->h;
    for (int y = 0; y < nh; y++) {
        color_t *d = px + y * nw;
        int x = 0;
        if (y < ch) { memcpy(d, w->pixels + y * w->w, cw * 4); x = cw; }
        for (; x < nw; x++) d[x] = fill;
    }
    struct msg m;
    memset(&m, 0, sizeof(m));
    m.type = WM_SETBUF;
    m.a = w->id; m.b = id; m.c = nw; m.d = nh;
    if (w->frame) {
        unsigned marker = WM_BUFFERED; memcpy(m.data, &marker, sizeof(marker));
        memcpy((char *)mapping + WM_FRAME_BYTES, px, nw * nh * 4);
        ((struct win_frame *)mapping)->submitted = 1;
        frame_barrier();
    }
    if (msg_send(desktop, &m) < 0) {
        if (w->frame) free(px);
        shm_unmap(mapping); return false;
    }
    bool selected = gfx_buf == w->pixels;
    bool buffered = w->frame != NULL;
    release_buffer(w);
    w->pixels = px;
    w->shm = id;
    w->w = nw; w->h = nh;
    if (buffered) {
        w->frame = mapping;
        w->shared = (color_t *)((char *)mapping + WM_FRAME_BYTES);
    }
    if (selected) win_select(w);
    return true;
}

static window *find_win(int id) {
    for (int i = 0; i < MAX_WINDOWS; i++) if (wins[i] && wins[i]->id == id) return wins[i];
    return NULL;
}

/* -> 1 — событие в e, 0 — рабочего стола больше нет (пора выходить) */
int win_event(struct event *e, int timeout_ms) {
    memset(e, 0, sizeof(*e));
    unsigned start = ticks();
    for (;;) {
        struct msg m;
        if (n_pending) {
            m = pending[0];
            for (int i = 1; i < n_pending; i++) pending[i - 1] = pending[i];
            n_pending--;
        } else {
            int wait = timeout_ms;
            if (wait < 0 || wait > 1000) wait = 1000;   /* раз в секунду проверяем, жив ли стол */
            int r = msg_recv(&m, wait);
            if (r < 0) {
                if (r == -EINTR) { e->type = EV_QUIT; return 0; }
                desktop = service_find("desktop");
                if (!desktop) { e->type = EV_QUIT; return 0; }
                if (timeout_ms >= 0 && (int)(ticks() - start) >= timeout_ms) { e->type = EV_TIMEOUT; return 1; }
                continue;
            }
        }
        if (m.from != desktop) { e->type = EV_MESSAGE; e->msg = m; return 1; }
        e->win = find_win(m.a);
        switch (m.type) {
        case WM_KEY: e->type = EV_KEY; e->key = m.b; return 1;
        case WM_MOUSE_WHEEL:
            e->type = EV_MOUSE_WHEEL; e->x = m.b; e->y = m.c; e->wheel = m.d; return 1;
        case WM_MOUSE:
            e->x = m.b; e->y = m.c;
            e->buttons = m.d & 0xFF;
            e->type = (m.d >> 8) == 1 ? EV_MOUSE_DOWN : (m.d >> 8) == 2 ? EV_MOUSE_UP : EV_MOUSE_MOVE;
            return 1;
        case WM_CLOSE: e->type = EV_CLOSE; return 1;
        case WM_FOCUS: e->type = EV_FOCUS; e->key = m.b; return 1;
        case WM_QUIT: e->type = EV_QUIT; return 0;
        case WM_RESIZE:
            if (!e->win || !resize_buffer(e->win, m.b, m.c)) continue;
            e->type = EV_RESIZE; e->x = e->win->w; e->y = e->win->h;
            return 1;
        default: continue;
        }
    }
}

/* ------------------------------------------------------------ элементы интерфейса */

bool ui_inside(int px, int py, int x, int y, int w, int h) {
    return px >= x && py >= y && px < x + w && py < y + h;
}

int ui_text(int x, int y, const char *s, color_t c) { return text_draw(FONT_UI, UI_FONT_SIZE, x, y, s, c); }
int ui_text_width(const char *s) { return text_width(FONT_UI, UI_FONT_SIZE, s); }

void ui_text_center(int x, int y, int w, int h, const char *s, color_t c) {
    int tw = ui_text_width(s), th = text_line_h(FONT_UI, UI_FONT_SIZE);
    ui_text(x + (w - tw) / 2, y + (h - th) / 2, s, c);
}

void ui_button(int x, int y, int w, int h, const char *label, bool pressed) {
    gfx_round_frame(x, y, w, h, 6, pressed ? RGB(190, 184, 178) : UI_SHADOW, pressed ? RGB(222, 221, 218) : RGB(246, 245, 244));
    ui_text_center(x, y, w, h, label, UI_TEXT);
}

void ui_button_accent(int x, int y, int w, int h, const char *label, bool pressed) {
    gfx_round_rect(x, y, w, h, 6, pressed ? RGB(200, 66, 20) : UI_ACCENT);
    int tw = text_width(FONT_UI_MEDIUM, UI_FONT_SIZE, label), th = text_line_h(FONT_UI_MEDIUM, UI_FONT_SIZE);
    text_draw(FONT_UI_MEDIUM, UI_FONT_SIZE, x + (w - tw) / 2, y + (h - th) / 2, label, C_WHITE);
}

void ui_sunken(int x, int y, int w, int h, color_t bg) {
    gfx_round_frame(x, y, w, h, 5, UI_SHADOW, bg);
}

void ui_button_state(int x,int y,int w,int h,const char *label,unsigned state) {
    if(w<8 || h<8)return;
    bool disabled=state&UI_BUTTON_DISABLED;
    bool accent=state&UI_BUTTON_ACCENT, danger=state&UI_BUTTON_DANGER;
    color_t bg=danger?RGB(192,53,53):accent?UI_ACCENT:C_WHITE;
    color_t ink=(accent || danger)?C_WHITE:RGB(39,44,52);
    if(disabled){bg=RGB(234,236,240);ink=RGB(150,157,168);}
    else if(state&UI_BUTTON_PRESSED)bg=danger?RGB(149,36,36):accent?RGB(185,61,20):RGB(227,231,237);
    else if(state&UI_BUTTON_HOVER)bg=danger?RGB(168,42,42):accent?RGB(210,71,24):RGB(239,241,244);
    if(!disabled && (state&UI_BUTTON_FOCUSED))
        gfx_round_frame(x-3,y-3,w+6,h+6,10,UI_ACCENT,RGB(255,227,213));
    gfx_round_frame(x,y,w,h,8,(accent || danger || disabled)?bg:RGB(225,228,233),bg);
    int tw=text_width(FONT_UI_MEDIUM,UI_FONT_SIZE,label),th=text_line_h(FONT_UI_MEDIUM,UI_FONT_SIZE);
    /* Длинная подпись не должна затереть соседние элементы. */
    int tx=x+(w-tw)/2;if(tx<x+6)tx=x+6;
    int cx,cy,cw,ch,clipped=gfx_clip_get(&cx,&cy,&cw,&ch);
    int left=x+4,top=y+2,right=x+w-4,bottom=y+h-2;
    if(clipped){if(left<cx)left=cx;if(top<cy)top=cy;if(right>cx+cw)right=cx+cw;if(bottom>cy+ch)bottom=cy+ch;}
    gfx_set_clip(left,top,right>left?right-left:0,bottom>top?bottom-top:0);
    text_draw(FONT_UI_MEDIUM,UI_FONT_SIZE,tx,y+(h-th)/2,label,ink);
    if(clipped)gfx_set_clip(cx,cy,cw,ch);else gfx_no_clip();
}

static unsigned edit_length(struct ui_edit *e) {
    if(!e || !e->text || !e->capacity)return 0;
    e->text[e->capacity-1]=0;
    unsigned n=strlen(e->text);if(e->cursor>n)e->cursor=n;
    while(e->cursor && ((unsigned char)e->text[e->cursor]&192)==128)e->cursor--;
    return n;
}
static unsigned edit_prev(const struct ui_edit *e,unsigned at) {
    if(at)do{at--;}while(at && ((unsigned char)e->text[at]&192)==128);
    return at;
}
static unsigned edit_next(const struct ui_edit *e,unsigned at,unsigned length) {
    if(at<length)do{at++;}while(at<length && ((unsigned char)e->text[at]&192)==128);
    return at;
}
void ui_edit_init(struct ui_edit *e,char *text,unsigned capacity,unsigned flags) {
    memset(e,0,sizeof(*e));e->text=text;e->capacity=capacity;e->flags=flags;
    e->cursor=edit_length(e);
}
bool ui_edit_key(struct ui_edit *e,int key) {
    if(!e || !e->text || !e->capacity)return false;
    unsigned length=edit_length(e),at=e->cursor;
    if(key==KEY_LEFT)e->cursor=edit_prev(e,at);
    else if(key==KEY_RIGHT)e->cursor=edit_next(e,at,length);
    else if(key==KEY_HOME)e->cursor=0;
    else if(key==KEY_END)e->cursor=length;
    else if(key==21){e->text[0]=0;e->cursor=0;e->scroll=0;}
    else if(key==8 || key==127) {
        unsigned before=edit_prev(e,at);
        memmove(e->text+before,e->text+at,length-at+1);e->cursor=before;
    } else if(key==KEY_DEL) {
        unsigned after=edit_next(e,at,length);
        memmove(e->text+at,e->text+after,length-after+1);
    } else {
        if(key<32 || key==127 || (key>=KEY_UP && key<=KEY_INS) || (key>=0xd800 && key<=0xdfff) || key>0xffff)return false;
        if(key>=128 && (key<160 || (e->flags&UI_EDIT_ASCII)))return false;
        char encoded[3];unsigned count;
        if(key<128){encoded[0]=key;count=1;}
        else if(key<2048){encoded[0]=192|(key>>6);encoded[1]=128|(key&63);count=2;}
        else{encoded[0]=224|(key>>12);encoded[1]=128|((key>>6)&63);encoded[2]=128|(key&63);count=3;}
        if(count>=e->capacity-length)return true;
        memmove(e->text+at+count,e->text+at,length-at+1);
        memcpy(e->text+at,encoded,count);e->cursor+=count;
    }
    return true;
}
void ui_edit_draw(struct ui_edit *e,int x,int y,int w,int h,bool focused) {
    if(!e || !e->text || !e->capacity || w<28 || h<12)return;
    edit_length(e);
    int caret=text_width_n(FONT_UI,UI_FONT_SIZE,e->text,e->cursor),inner=w-24;
    if(e->scroll<0)e->scroll=0;
    if(caret<e->scroll)e->scroll=caret;
    if(caret-e->scroll>inner-2)e->scroll=caret-inner+2;
    int max_scroll=text_width(FONT_UI,UI_FONT_SIZE,e->text)-inner+2;
    if(max_scroll<0)max_scroll=0;
    if(e->scroll>max_scroll)e->scroll=max_scroll;
    gfx_round_frame(x,y,w,h,8,focused?UI_ACCENT:RGB(225,228,233),C_WHITE);
    int cx,cy,cw,ch,clipped=gfx_clip_get(&cx,&cy,&cw,&ch);
    int left=x+12,top=y+3,right=x+w-12,bottom=y+h-3;
    if(clipped){if(left<cx)left=cx;if(top<cy)top=cy;if(right>cx+cw)right=cx+cw;if(bottom>cy+ch)bottom=cy+ch;}
    gfx_set_clip(left,top,right>left?right-left:0,bottom>top?bottom-top:0);
    int ty=y+(h-text_line_h(FONT_UI,UI_FONT_SIZE))/2;
    text_draw(FONT_UI,UI_FONT_SIZE,x+12-e->scroll,ty,e->text,UI_TEXT);
    if(focused && (ticks()/500)%2==0)gfx_fill_rect(x+12+caret-e->scroll,y+8,1,h-16,UI_ACCENT);
    if(clipped)gfx_set_clip(cx,cy,cw,ch);else gfx_no_clip();
}
void ui_edit_click(struct ui_edit *e,int x,int px) {
    unsigned length=edit_length(e);if(!e || !e->text || !e->capacity)return;
    int target=px-x-12+e->scroll,previous=0;e->cursor=0;
    for(unsigned at=0;at<length;) {
        unsigned next=edit_next(e,at,length);
        int width=text_width_n(FONT_UI,UI_FONT_SIZE,e->text,next);
        if(target<(previous+width)/2)return;
        e->cursor=next;at=next;previous=width;
    }
}
int ui_focus_step(int current,int count,unsigned disabled,int direction) {
    if(count<1 || count>32)return 0;
    if(current<1 || current>count)current=direction<0?1:count;
    for(int i=0;i<count;i++) {
        current=(current-1+(direction<0?count-1:1))%count+1;
        if(!(disabled&(1u<<(current-1))))return current;
    }
    return 0;
}
