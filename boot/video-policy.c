#include "../user/lib/video_mode.h"
/* Вызов из stage2 в коротком защищённом режиме; только переданные низкие адреса. */
__attribute__((section(".entry"))) unsigned boot_video_policy(unsigned operation,unsigned *p) {
    if(!operation)return video_edid((const unsigned char *)p[0],p[1],(unsigned *)p[2],(unsigned *)p[3]);
    if(operation==2) {
        const unsigned short *count=(const void *)0x8000;
        const unsigned char *map=(const void *)0x8004;
        unsigned long long available=0;
        for(unsigned i=0;i<*count && i<128;i++) {
            const unsigned long long *entry=(const void *)(map+i*24);
            if(*(const unsigned *)(map+i*24+16)!=1 || entry[0]>=0x40000000ULL)continue;
            unsigned long long bytes=entry[1];if(bytes>0x40000000ULL-entry[0])bytes=0x40000000ULL-entry[0];
            available+=bytes;
        }
        if(available>0x40000000ULL)available=0x40000000ULL;
        unsigned used=p[0]+p[1]+16u*1024*1024;
        return available>used?video_memory_budget((unsigned)available-used):0;
    }
    return video_rank(p[0],p[1],p[2],p[3],p[4],p[5]);
}
