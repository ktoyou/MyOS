/* Run the production overlapping drag copy against a snapshot reference.
 * The display stub observes uploads; no GPU/framebuffer reads are available. */
#define gfx_flip_rect observed_flip
#define main desktop_main
#include "../user/desktop.c"
#undef main
#undef gfx_flip_rect
static color_t *shown;
static int uploads;
unsigned ticks(void){return 100;}
void observed_flip(int x,int y,int w,int h) {
    uploads++;
    for(int row=y;row<y+h;row++)memcpy(shown+row*SW+x,back+row*SW+x,w*4);
}
static void check(bool ok,const char *message){if(!ok){printf("FAIL: %s\n",message);exit(1);}}
static void check_damage(unsigned *random) {
    unsigned char expected[73*59],covered[73*59];
    for(int iteration=0;iteration<400;iteration++) {
        memset(expected,0,sizeof(expected));memset(covered,0,sizeof(covered));ndirty=0;
        int requested=0;
        for(int i=0;i<20;i++) {
            *random=*random*1664525+1013904223;int x=(int)(*random%93)-10;
            *random=*random*1664525+1013904223;int y=(int)(*random%79)-10;
            *random=*random*1664525+1013904223;int w=1+*random%30;
            *random=*random*1664525+1013904223;int h=1+*random%25;
            struct rect r;
            if(intersect(mkrect(x,y,w,h),mkrect(0,0,SW,SH),&r)) {
                requested+=r.w*r.h;
                for(int py=r.y;py<r.y+r.h;py++)for(int px=r.x;px<r.x+r.w;px++)expected[py*SW+px]=1;
            }
            add_dirty(x,y,w,h);
        }
        int painted=0;
        for(int i=0;i<ndirty;i++) {
            struct rect r=dirty[i];painted+=r.w*r.h;
            check(r.x>=0 && r.y>=0 && r.x+r.w<=SW && r.y+r.h<=SH,"damage clipped to screen");
            for(int py=r.y;py<r.y+r.h;py++)for(int px=r.x;px<r.x+r.w;px++)covered[py*SW+px]=1;
        }
        check(painted<=requested,"merging must not increase repaint work");
        for(int p=0;p<SW*SH;p++)check(!expected[p] || covered[p],"damage coverage");
    }
    ndirty=0;add_dirty(1,1,70,2);add_dirty(1,1,2,55);
    int area=0;for(int i=0;i<ndirty;i++)area+=dirty[i].w*dirty[i].h;
    check(area==250,"crossing thin strips stay small instead of 3850 pixels");
    ndirty=0;
    for(int i=0;i<MAXDIRTY+5;i++)add_dirty(i*2,3,1,1);
    check(ndirty>0 && ndirty<=MAXDIRTY,"bounded damage queue");
    for(int i=0;i<MAXDIRTY+5;i++) {
        bool covered=false;
        for(int k=0;k<ndirty;k++)if(i*2>=dirty[k].x && i*2<dirty[k].x+dirty[k].w && 3>=dirty[k].y && 3<dirty[k].y+dirty[k].h)covered=true;
        check(covered,"damage overflow retains every region");
    }
    ndirty=0;
}
int main(void) {
    SW=73;SH=59;unsigned bytes=SW*SH*4;
    back=malloc(bytes);shown=malloc(bytes);color_t *before=malloc(bytes),*expected=malloc(bytes);
    check(back && shown && before && expected,"allocation");
    unsigned random=12345;
    for(int iteration=0;iteration<1000;iteration++) {
        for(int i=0;i<SW*SH;i++)before[i]=0xff000000u+(unsigned)i;
        memcpy(back,before,bytes);memcpy(shown,before,bytes);memcpy(expected,before,bytes);
        random=random*1664525+1013904223;int w=1+random%SW;
        random=random*1664525+1013904223;int h=1+random%SH;
        random=random*1664525+1013904223;int sx=random%(SW-w+1);
        random=random*1664525+1013904223;int sy=random%(SH-h+1);
        random=random*1664525+1013904223;int dx=random%(SW-w+1);
        random=random*1664525+1013904223;int dy=random%(SH-h+1);
        for(int j=0;j<h;j++)memcpy(expected+(dy+j)*SW+dx,before+(sy+j)*SW+sx,w*4);
        uploads=0;copy_window_pixels(mkrect(dx,dy,w,h),dx-sx,dy-sy);
        check(!memcmp(back,expected,bytes),"RAM overlap copy");
        check(!memcmp(shown,expected,bytes) && uploads==1,"single coherent upload");
    }
    check_damage(&random);
    check(motion_wait()==10,"idle input polling interval");
    wins[0].used=true;wins[0].motion=true;motion_deadline=200;
    check(motion_wait()==10,"animation must not delay input");
    motion_deadline=105;check(motion_wait()==5,"earlier animation deadline");
    motion_deadline=99;check(motion_wait()==0,"expired animation deadline");
    puts("PASS: 1000 drag copies, 400 damage batches, thin strips 3850 -> 250 pixels, overflow coverage and <=10ms input polling");
    free(expected);free(before);free(shown);free(back);return 0;
}
