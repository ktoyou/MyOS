#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../user/lib/video_mode.h"
static unsigned char edid[1024];
static void checksum(unsigned char *p,unsigned n){p[n-1]=0;for(unsigned i=0;i<n-1;i++)p[n-1]-=p[i];}
static void base(unsigned w,unsigned h) {
    memset(edid,0,sizeof(edid));memset(edid+1,255,6);edid[18]=1;edid[19]=4;edid[24]=2;
    if(w){unsigned char *d=edid+54;d[0]=1;d[2]=w;d[4]=(w>>8)<<4;d[5]=h;d[7]=(h>>8)<<4;}
    checksum(edid,128);
}
static void displayid(unsigned w,unsigned h) {
    edid[126]=1;checksum(edid,128);unsigned char *e=edid+128;
    e[0]=0x70;e[1]=0x20;e[2]=23;e[5]=0x22;e[7]=20;
    e[11]=128;w--;h--;e[12]=w;e[13]=w>>8;e[20]=h;e[21]=h>>8;
    checksum(e+1,28);checksum(e,128);
}
int main(void) {
    unsigned w,h;
    assert(video_aperture(0xf8000000)==VIDEO_BUFFER_BYTES);
    assert(video_aperture(0xfc000000)==VIDEO_BUFFER_BYTES);
    assert(video_aperture(0xfd000000)==48u*1024*1024);
    assert(video_aperture(0xfffff000)==4096);
    assert(video_geometry(3440,1440,3440*4,VIDEO_BUFFER_BYTES));
    assert(video_geometry(5120,2880,5120*4,VIDEO_BUFFER_BYTES));
    assert(video_geometry(2160,3840,2160*4,VIDEO_BUFFER_BYTES));
    assert(!video_geometry(5120,5120,5120*4,VIDEO_BUFFER_BYTES));
    assert(!video_geometry(3440,1440,3440*4+1,VIDEO_BUFFER_BYTES));
    assert(video_memory_budget(32u<<20)==0 && video_memory_budget(1u<<30)==VIDEO_BUFFER_BYTES);
    assert(video_pixel_order(0x7a123456,1)==0x7a563412 && video_pixel_order(0x7a123456,0)==0x7a123456);
    assert(video_rank(3440,1440,0,0,3440,1440)>video_rank(3840,2160,0,0,3440,1440));
    assert(video_rank(2560,1080,0,0,3440,1440)>video_rank(2560,1440,0,0,3440,1440));
    assert(video_rank(1024,768,1024,768,3440,1440)>video_rank(3440,1440,1024,768,3440,1440));
    assert(video_rank(3840,2160,0,0,0,0)>video_rank(3440,1440,0,0,0,0));
    assert(video_parse_mode("auto\ncursor=sw\n",&w,&h) && !w && !h);
    assert(video_parse_mode(" 3440X1440\n",&w,&h) && w==3440 && h==1440);
    const char *bad[]={"","a","autox","3440x1440trash","4294967296x768","5120x5120","640x0","640x9999"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++)assert(!video_parse_mode(bad[i],&w,&h));
    base(3440,1440);assert(video_edid(edid,128,&w,&h) && w==3440 && h==1440);
    for(unsigned n=0;n<128;n++)assert(!video_edid(edid,n,&w,&h));
    edid[100]^=1;assert(!video_edid(edid,128,&w,&h));
    base(1920,1080);displayid(5120,2880);
    assert(video_edid(edid,256,&w,&h) && w==5120 && h==2880);
    edid[140]^=1;assert(video_edid(edid,256,&w,&h) && w==1920 && h==1080);
    base(0,0);displayid(5120,2160);assert(video_edid(edid,256,&w,&h) && w==5120 && h==2160);
    assert(!video_edid(edid,255,&w,&h));
    edid[130]=127;checksum(edid+128,128);assert(!video_edid(edid,256,&w,&h));
    base(0,0);edid[126]=1;checksum(edid,128);
    unsigned char *e=edid+128;e[0]=2;e[2]=4;e[3]=1;
    e[4]=1;e[6]=0x70;e[8]=0x50;e[9]=0xa0;e[11]=0x50;checksum(e,128);
    assert(video_edid(edid,256,&w,&h) && w==1392 && h==1440);
    /* Все обрезанные и случайные блоки должны оставаться в границах массива. */
    unsigned state=7;
    for(unsigned trial=0;trial<20000;trial++) {
        for(unsigned i=0;i<sizeof(edid);i++){state=state*1664525+1013904223;edid[i]=state>>24;}
        video_edid(edid,trial%1025,&w,&h);
    }
    puts("Video policy: EDID/CTA/DisplayID, native/manual/aspect, pixel order, memory bounds: PASS");
}
