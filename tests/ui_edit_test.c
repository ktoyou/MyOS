/* Проверяем редактирование через модель символов, а не через байтовые смещения. */
#include "win.h"
static void check(bool ok,const char *message){if(!ok){printf("FAIL: %s\n",message);exit(1);}}
int main(void) {
    char text[128]="/root/фон.png";struct ui_edit e;
    ui_edit_init(&e,text,sizeof(text),0);
    ui_edit_key(&e,KEY_HOME);ui_edit_key(&e,KEY_RIGHT);ui_edit_key(&e,'X');
    check(!strcmp(text,"/Xroot/фон.png"),"insert inside text");
    ui_edit_key(&e,8);check(!strcmp(text,"/root/фон.png"),"backspace inside text");
    ui_edit_key(&e,KEY_END);ui_edit_key(&e,21);
    ui_edit_key(&e,0x416);ui_edit_key(&e,0x754c);ui_edit_key(&e,'!');
    ui_edit_key(&e,KEY_LEFT);ui_edit_key(&e,8);
    check(!strcmp(text,"Ж!"),"backspace removes a whole multibyte symbol");
    ui_edit_key(&e,KEY_HOME);ui_edit_key(&e,KEY_DEL);
    check(!strcmp(text,"!"),"delete removes a whole multibyte symbol");
    check(!ui_edit_key(&e,13) && !ui_edit_key(&e,9) && !ui_edit_key(&e,27),"form keys remain with caller");
    check(!ui_edit_key(&e,0xd800) && !ui_edit_key(&e,KEY_COPY),"invalid/special keys are not inserted");
    char small[5]="";ui_edit_init(&e,small,sizeof(small),0);
    ui_edit_key(&e,0x754c);ui_edit_key(&e,0x416);ui_edit_key(&e,'x');
    check(!strcmp(small,"界x") && e.cursor==4,"capacity never splits UTF-8");
    char only_nul[1]={0};ui_edit_init(&e,only_nul,1,0);ui_edit_key(&e,'x');
    check(!only_nul[0],"one-byte buffer");
    ui_edit_init(&e,NULL,0,0);check(!ui_edit_key(&e,'x'),"empty buffer");
    ui_edit_init(&e,text,sizeof(text),UI_EDIT_ASCII);ui_edit_key(&e,21);
    check(!ui_edit_key(&e,0x416),"ASCII confirmation rejects Unicode");
    ui_edit_key(&e,'a');check(!strcmp(text,"a"),"ASCII insertion");
    static const int cps[]={'a',0x416,0x754c,'/',' '};
    static const char *symbols[]={"a","Ж","界","/"," "};
    int model[128],count=0,cursor=0;unsigned random=7;
    ui_edit_init(&e,text,sizeof(text),0);ui_edit_key(&e,21);
    for(int iteration=0;iteration<10000;iteration++) {
        random=random*1664525+1013904223;int op=random%11;
        if(op<5) {
            ui_edit_key(&e,cps[op]);
            unsigned bytes=0;for(int i=0;i<count;i++)bytes+=strlen(symbols[model[i]]);
            if(bytes+strlen(symbols[op])<sizeof(text)) {
                memmove(model+cursor+1,model+cursor,(count-cursor)*sizeof(int));model[cursor++]=op;count++;
            }
        } else if(op==5){ui_edit_key(&e,KEY_LEFT);if(cursor)cursor--;}
        else if(op==6){ui_edit_key(&e,KEY_RIGHT);if(cursor<count)cursor++;}
        else if(op==7){ui_edit_key(&e,8);if(cursor){cursor--;count--;memmove(model+cursor,model+cursor+1,(count-cursor)*sizeof(int));}}
        else if(op==8){ui_edit_key(&e,KEY_DEL);if(cursor<count){count--;memmove(model+cursor,model+cursor+1,(count-cursor)*sizeof(int));}}
        else if(op==9){ui_edit_key(&e,KEY_HOME);cursor=0;}
        else{ui_edit_key(&e,KEY_END);cursor=count;}
        char expected[128]="";unsigned expected_cursor=0;
        for(int i=0;i<count;i++){strcat(expected,symbols[model[i]]);if(i<cursor)expected_cursor+=strlen(symbols[model[i]]);}
        check(!strcmp(text,expected) && e.cursor==expected_cursor,"random Unicode editing matches character model");
    }
    check(ui_focus_step(0,4,0,1)==1 && ui_focus_step(4,4,0,1)==1,"focus wraps");
    check(ui_focus_step(1,4,0,-1)==4,"reverse focus");
    check(ui_focus_step(2,4,12,1)==1 && ui_focus_step(1,4,15,1)==0,"disabled controls skipped");
    check(ui_focus_step(31,32,0x80000000u,1)==1 && ui_focus_step(1,33,0,1)==0,"focus mask bounds");
    puts("PASS: 10000 UTF-8 editing steps, insertion/deletion, capacity, form safety and keyboard focus");
    return 0;
}
