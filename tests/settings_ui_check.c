/* Наблюдаем состояние настоящего приложения после его обычной перерисовки. */
#define win_update observed_update
#define set_dns observed_dns
#define main settings_main
#include "../user/settings.c"
#undef main
#undef set_dns
#undef win_update
void win_update(window *w);
int set_dns(unsigned ip);
static unsigned applied;
int observed_dns(unsigned ip){applied++;return set_dns(ip);}
void observed_update(window *w) {
    win_update(w);
    struct ui_edit *edit=page==0?&dns_edit:&path_edit;
    printf("SETTINGS UI: page=%d focus=%d applies=%u gallery=%d cursor=%u scroll=%d dns=[%s] path=[%s] status=[%s]\n",page,focus,applied,gallery_cursor,edit->cursor,edit->scroll,dns,path,status);
}
int main(void){return settings_main();}
