#ifndef VIDEO_MODE_H
#define VIDEO_MODE_H
/* Общие пределы загрузчиков, ядра и окон. Байты учитывают padding строки. */
#define VIDEO_MAX_WIDTH 5120
#define VIDEO_MAX_HEIGHT 5120
#define VIDEO_BUFFER_BYTES 0x04000000u
#define VIDEO_SURFACE_WIDTH 5184
#define VIDEO_SURFACE_HEIGHT 5248
#define VIDEO_EDID_BLOCKS 8u
#define VIDEO_TRIAL_MS 15000u
enum { VIDEO_MODE_TRY=2, VIDEO_MODE_KEEP, VIDEO_MODE_REVERT, VIDEO_MODE_REMAINING };
/* Окно виртуально 64 МиБ, но физический BAR может подходить к границе 4 ГиБ. */
static inline unsigned video_aperture(unsigned base) {
    return base>0u-VIDEO_BUFFER_BYTES?0u-base:VIDEO_BUFFER_BYTES;
}
static inline unsigned video_memory_budget(unsigned available) {
    if(available<=32u*1024*1024)return 0;
    unsigned bytes=(available-32u*1024*1024)/5;
    return bytes<VIDEO_BUFFER_BYTES?bytes:VIDEO_BUFFER_BYTES;
}
static inline unsigned video_pixel_order(unsigned color,unsigned swap) {
    return swap?(color&0xff00ff00u)|((color&255)<<16)|((color>>16)&255):color;
}
static inline int video_geometry(unsigned w,unsigned h,unsigned pitch,unsigned bytes) {
    return w>=640 && h>=480 && w<=VIDEO_MAX_WIDTH && h<=VIDEO_MAX_HEIGHT &&
           !(pitch&3) && pitch>=w*4 && pitch<=bytes/h;
}
/* Порядок: ручной режим, родной, близкий по пропорциям без увеличения, остальные. */
static inline unsigned video_rank(unsigned w,unsigned h,unsigned manual_w,unsigned manual_h,unsigned native_w,unsigned native_h) {
    if(!video_geometry(w,h,w*4,VIDEO_BUFFER_BYTES))return 0;
    unsigned priority=1;
    if(native_w && native_h) {
        if(w<=native_w && h<=native_h) {
            unsigned a=w*native_h,b=h*native_w,error=a>b?a-b:b-a;
            priority=error<=b/100?3:2;
        }
        if(w==native_w && h==native_h)priority=4;
    }
    if(manual_w && w==manual_w && h==manual_h)priority=5;
    return (priority<<24)|(w*h-1);
}
static inline int video_common_mode(unsigned index,unsigned *w,unsigned *h) {
    static const unsigned short modes[][2]={
        {640,480},{800,600},{1024,768},{1152,864},{1280,720},{1280,800},{1280,1024},
        {1360,768},{1366,768},{1440,900},{1600,900},{1600,1200},{1680,1050},
        {1920,1080},{1920,1200},{1920,1440},{2048,1152},{2560,1080},{2560,1440},
        {2560,1600},{2880,1800},{3440,1440},{3840,1600},{3840,2160},{4096,2160},
        {5120,1440},{5120,2160},{5120,2880},{1080,1920},{1440,2560},{2160,3840}};
    if(index>=sizeof(modes)/sizeof(modes[0]))return 0;
    *w=modes[index][0];*h=modes[index][1];return 1;
}
static inline int video_parse_mode(const char *s,unsigned *w,unsigned *h) {
    while(*s==' ' || *s=='\t')s++;
    unsigned a=0,b=0;
    if(s[0]=='a' && s[1]=='u' && s[2]=='t' && s[3]=='o')s+=4;
    else {
        if(*s<'0' || *s>'9')return 0;
        while(*s>='0' && *s<='9'){if(a>VIDEO_MAX_WIDTH/10)return 0;a=a*10+(*s++-'0');}
        if(*s!='x' && *s!='X')return 0;
        s++;
        if(*s<'0' || *s>'9')return 0;
        while(*s>='0' && *s<='9'){if(b>VIDEO_MAX_HEIGHT/10)return 0;b=b*10+(*s++-'0');}
        if(!video_geometry(a,b,a*4,VIDEO_BUFFER_BYTES))return 0;
    }
    while(*s==' ' || *s=='\t')s++;
    if(*s && *s!='\n' && *s!='\r')return 0;
    *w=a;*h=b;return 1;
}
static inline unsigned video_u16(const unsigned char *p){return p[0]|(unsigned)p[1]<<8;}
static inline int video_checksum(const unsigned char *p,unsigned n) {
    unsigned char sum=0;while(n--)sum+=*p++;return !sum;
}
static inline void video_prefer(unsigned w,unsigned h,unsigned *out_w,unsigned *out_h) {
    if(w>=640 && h>=480 && w<=65536 && h<=65536 && (unsigned long long)w*h>(unsigned long long)*out_w * *out_h){*out_w=w;*out_h=h;}
}
static inline void video_dtd(const unsigned char *p,unsigned *w,unsigned *h) {
    if(!video_u16(p) || (p[17]&128))return;
    video_prefer(p[2]|(unsigned)(p[4]&240)<<4,p[5]|(unsigned)(p[7]&240)<<4,w,h);
}
/* Не доверяем размерам блоков прошивки. Повреждённое расширение не портит базовый EDID. */
static inline int video_edid(const unsigned char *edid,unsigned bytes,unsigned *w,unsigned *h) {
    *w=*h=0;
    if(!edid || bytes<128 || edid[0] || edid[7] || edid[18]!=1 || !video_checksum(edid,128))return 0;
    for(unsigned i=1;i<7;i++)if(edid[i]!=255)return 0;
    if((edid[24]&2) || edid[19]>=4)video_dtd(edid+54,w,h);
    unsigned blocks=bytes/128;
    if(blocks>VIDEO_EDID_BLOCKS)blocks=VIDEO_EDID_BLOCKS;
    if(blocks>(unsigned)edid[126]+1)blocks=(unsigned)edid[126]+1;
    for(unsigned i=1;i<blocks;i++) {
        const unsigned char *e=edid+i*128;
        if(!video_checksum(e,128))continue;
        if(e[0]==2 && e[2]>=4 && e[2]<=126) {
            unsigned count=e[3]&15,offset=e[2];
            while(count-- && offset+18<=127){video_dtd(e+offset,w,h);offset+=18;}
        }
        if(e[0]!=0x70 || e[2]>121 || !video_checksum(e+1,(unsigned)e[2]+5))continue;
        unsigned end=5+e[2];
        for(unsigned at=5;at+3<=end;) {
            unsigned size=e[at+2],next=at+3+size;if(next>end)break;
            if((e[at]==3 || e[at]==0x22) && !(size%20))
                for(unsigned t=at+3;t+20<=next;t+=20)if(e[t+3]&128)
                    video_prefer(video_u16(e+t+4)+1,video_u16(e+t+12)+1,w,h);
            at=next;
        }
    }
    return *w && *h;
}
#endif
