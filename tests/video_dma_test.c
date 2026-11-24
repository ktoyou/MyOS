/* Проверяем настоящий PMM с картой фрагментированной памяти; IRQ заменены на хосте. */
#include "../kernel/idt.h"
#include "../kernel/spinlock.h"
#define spin_lock_irqsave(p) ((void)(p),0u)
#define spin_unlock_irqrestore(p,f) ((void)(p),(void)(f))
#include "../kernel/pmm.c"
extern int printf(const char *,...);
extern int puts(const char *);
extern void exit(int) __attribute__((noreturn));
void kpanic(const char *message){printf("PMM panic: %s\n",message);exit(1);}
#define CHECK(x) do{if(!(x)){printf("DMA test line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
int main(void) {
    static u8 counts[512];refs=counts;limit_frame=512;
    memset(bitmap,255,sizeof(bitmap));
    for(unsigned f=256;f<512;f++)set_free(f);
    set_used(300);total_frames=255;used_frames=0;next_hint=256;
    CHECK(!pmm_alloc_contiguous(0) && !pmm_alloc_contiguous(0xffffffffu));
    u32 address=pmm_alloc_contiguous(80);
    CHECK(address==301*PAGE_SIZE && used_frames==80);
    for(unsigned f=301;f<381;f++)CHECK(is_used(f) && refs[f]==1);
    CHECK(!pmm_alloc_contiguous(200) && used_frames==80);
    CHECK(pmm_share(address) && pmm_refs(address)==2);
    pmm_free(address);CHECK(pmm_refs(address)==1 && used_frames==80);
    for(unsigned i=0;i<80;i++)pmm_free(address+i*PAGE_SIZE);
    CHECK(used_frames==0 && is_used(300) && !refs[300]);
    CHECK(pmm_alloc_contiguous(211)==301*PAGE_SIZE);
    CHECK(!pmm_alloc_contiguous(45) && used_frames==211);
    CHECK(pmm_alloc_contiguous(44)==256*PAGE_SIZE);
    CHECK(used_frames==255 && !pmm_alloc_contiguous(1));
    puts("Video DMA: contiguous allocation, reserved gaps, failure atomicity, refs and release: PASS");
}
