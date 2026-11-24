/* tests/gfx_host.c — сглаженная графика и шрифты на Linux: рисует пробную
 * картинку в PPM (stdout).  make gfxtest -> build/gfxtest.ppm */
#include "win.h"

int ttymode(int m) { return m; }
unsigned ticks(void) { return 0; }
int myos_open_default(const char *path,int flags) { return open(path,flags,0666); }

int main(int argc, char **argv) {
    font_set_dir(argc > 1 ? argv[1] : "fonts");
    gfx_w = 720; gfx_h = 780;
    gfx_buf = malloc(gfx_w * gfx_h * 4);
    color_t sentinel=RGB(11,22,33);gfx_clear(sentinel);
    gfx_set_clip(40,40,20,20);
    ui_button_state(20,20,140,38,"Обрезка",UI_BUTTON_FOCUSED);
    char clipped_text[48]="Проверка поля";struct ui_edit clipped_edit;
    ui_edit_init(&clipped_edit,clipped_text,sizeof(clipped_text),0);
    ui_edit_draw(&clipped_edit,20,20,140,38,true);
    int cx,cy,cw,ch;
    if(!gfx_clip_get(&cx,&cy,&cw,&ch) || cx!=40 || cy!=40 || cw!=20 || ch!=20)return 1;
    int changed=0;
    for(int y=0;y<gfx_h;y++)for(int x=0;x<gfx_w;x++) {
        if(x>=40 && x<60 && y>=40 && y<60){changed+=gfx_buf[y*gfx_w+x]!=sentinel;continue;}
        if(gfx_buf[y*gfx_w+x]!=sentinel)return 2;
    }
    if(!changed)return 3;
    gfx_no_clip();
    gfx_gradient(0, 0, gfx_w, gfx_h, RGB(119, 33, 111), RGB(233, 84, 32));
    gfx_shadow(40, 40, 400, 300, 12, 18, 4, 110, 40, 40, 400, 300);
    gfx_round_rect_ex(40, 40, 400, 38, 12, 3, RGB(235, 235, 235), 255);
    gfx_fill_rect(40, 78, 400, 262, RGB(250, 250, 250));
    text_draw(FONT_UI_BOLD, 15, 180, 50, "Terminal — Files", RGB(46, 52, 54));
    gfx_disc16((40 + 400 - 22) * 16, (40 + 19) * 16, 12 * 16, RGB(218, 218, 218), 255);
    gfx_line16((418 - 4) * 16, 55 * 16, (418 + 4) * 16, 63 * 16, 24, RGB(46, 52, 54), 255);
    gfx_line16((418 + 4) * 16, 55 * 16, (418 - 4) * 16, 63 * 16, 24, RGB(46, 52, 54), 255);
    int y = 90;
    for (int sz = 11; sz <= 20; sz += 3) {
        text_draw(FONT_UI, sz, 56, y, "The quick brown fox — Съешь же ещё этих мягких булок", RGB(40, 40, 40));
        y += text_line_h(FONT_UI, sz) + 2;
    }
    text_draw(FONT_UI_MEDIUM, 14, 56, y, "Medium: AVATAR Wave Toyota 1234567890", RGB(40, 40, 40)); y += 20;
    gfx_text(56, y, "gfx_text: ls -la /bin  Привет, мир! {}[]<>", RGB(30, 30, 30), TRANSPARENT); y += 16;
    gfx_fill_rect(56, y, 360, 48, RGB(48, 10, 36));
    gfx_text(60, y + 2, "user@myos:~$ cc hello.c -o hello", RGB(138, 226, 52), TRANSPARENT);
    gfx_text(60, y + 18, "\xC9\xCD\xCD\xCD\xBB box \xB0\xB1\xB2\xDB", C_WHITE, TRANSPARENT);
    gfx_text_scaled(60 + 280, y + 2, "7", C_WHITE, 2);
    y += 60;
    gfx_round_frame(56, y, 100, 32, 6, RGB(205, 199, 194), RGB(246, 245, 244));
    text_draw(FONT_UI, 14, 56 + (100 - text_width(FONT_UI, 14, "Button")) / 2, y + 8, "Button", RGB(46, 52, 54));
    gfx_round_rect(170, y, 100, 32, 6, RGB(233, 84, 32));
    text_draw(FONT_UI_MEDIUM, 14, 170 + (100 - text_width(FONT_UI_MEDIUM, 14, "OK")) / 2, y + 8, "OK", C_WHITE);
    gfx_ellipse(290, y, 32, 32, RGB(52, 101, 164), 255);
    gfx_ellipse(330, y + 4, 60, 24, RGB(78, 154, 6), 180);
    text_draw(FONT_UI_BOLD, 40, 470, 380, "MyOS", C_WHITE);
    text_draw(FONT_UI, 13, 470, 430, "Activities", C_WHITE);
    gfx_cursor_draw(600, 200);
    gfx_fill_rect(30,490,660,145,RGB(247,248,250));
    text_draw(FONT_UI_MEDIUM,14,46,500,"Общие кнопки MyOS",UI_TEXT);
    ui_button_state(46,530,180,38,"Обычная",0);
    ui_button_state(250,530,180,38,"Наведение",UI_BUTTON_HOVER);
    ui_button_state(454,530,180,38,"Фокус",UI_BUTTON_ACCENT|UI_BUTTON_FOCUSED);
    ui_button_state(46,582,180,38,"Недоступно",UI_BUTTON_ACCENT|UI_BUTTON_DISABLED|UI_BUTTON_HOVER);
    ui_button_state(250,582,180,38,"Нажатие",UI_BUTTON_ACCENT|UI_BUTTON_PRESSED);
    ui_button_state(454,582,180,38,"Удалить",UI_BUTTON_DANGER);
    gfx_fill_rect(30,640,660,112,RGB(247,248,250));
    text_draw(FONT_UI_MEDIUM,14,46,650,"Общие поля ввода · UTF-8 и курсор",UI_TEXT);
    char path[128]="/root/Изображения/длинное имя файла с обоями.png",confirm[32]="erase /dev/nvme0";
    struct ui_edit path_edit,confirmation_edit;
    ui_edit_init(&path_edit,path,sizeof(path),0);ui_edit_init(&confirmation_edit,confirm,sizeof(confirm),UI_EDIT_ASCII);
    ui_edit_draw(&path_edit,46,680,300,38,true);
    if(path_edit.scroll<=0)return 4;
    ui_edit_key(&path_edit,KEY_HOME);ui_edit_draw(&path_edit,46,680,300,38,true);
    if(path_edit.scroll!=0)return 5;
    ui_edit_click(&path_edit,46,58);if(path_edit.cursor!=0)return 6;
    ui_edit_click(&confirmation_edit,368,2000);if(confirmation_edit.cursor!=strlen(confirm))return 7;
    ui_edit_draw(&confirmation_edit,368,680,266,38,false);
    printf("P6\n%d %d\n255\n", gfx_w, gfx_h);
    for (int i = 0; i < gfx_w * gfx_h; i++) { putchar(gfx_buf[i] >> 16 & 255); putchar(gfx_buf[i] >> 8 & 255); putchar(gfx_buf[i] & 255); }
    return 0;
}
