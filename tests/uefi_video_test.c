/* Вызываем настоящий выбор GOP с отказами firmware, без запуска UEFI. */
#include <efi.h>
#include <efilib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned u32;
typedef unsigned char u8;
#define system firmware_system
static EFI_SYSTEM_TABLE *system;
static EFI_BOOT_SERVICES *services;
static EFI_GUID gop_guid=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
struct boot_info {unsigned fb_phys,width,height,bpp,pitch,pixel_order,native_w,native_h;};
struct config {unsigned width,height;};
static void message(const char *s){(void)s;}
#include "../boot/uefi-video.h"
static EFI_GRAPHICS_OUTPUT_PROTOCOL gop;
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE state;
static EFI_GRAPHICS_OUTPUT_MODE_INFORMATION information[8];
static EFI_EDID_ACTIVE_PROTOCOL edid;
static unsigned char bytes[256];
static int fail_mode,bad_framebuffer,bad_query,edid_available,wrong_monitor;
static unsigned sets,queries,allocations;
static unsigned memory_mb;
static UINT64 framebuffer_base;
static EFI_STATUS EFIAPI allocate_pool(EFI_MEMORY_TYPE type,UINTN size,void **out){(void)type;*out=malloc(size);allocations++;return *out?EFI_SUCCESS:EFI_OUT_OF_RESOURCES;}
static EFI_STATUS EFIAPI memory_map(UINTN *size,EFI_MEMORY_DESCRIPTOR *map,UINTN *key,UINTN *stride,UINT32 *version) {
    if(memory_mb==~0u)return EFI_DEVICE_ERROR;
    assert(*size>=sizeof(*map));memset(map,0,sizeof(*map));
    map->Type=EfiConventionalMemory;map->PhysicalStart=0x100000;map->NumberOfPages=memory_mb*256;
    *size=sizeof(*map);*stride=sizeof(*map);*key=1;*version=1;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI free_pool(void *p){free(p);allocations--;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI locate_handles(EFI_LOCATE_SEARCH_TYPE type,EFI_GUID *guid,void *key,UINTN *count,EFI_HANDLE **handles) {
    (void)type;(void)guid;(void)key;*count=1;*handles=malloc(sizeof(EFI_HANDLE));(*handles)[0]=(void *)1;allocations++;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI handle(EFI_HANDLE h,EFI_GUID *guid,void **out) {
    (void)h;
    if(!memcmp(guid,&gop_guid,sizeof(*guid))){*out=wrong_monitor?NULL:&gop;return wrong_monitor?EFI_NOT_FOUND:EFI_SUCCESS;}
    if(edid_available){*out=&edid;return EFI_SUCCESS;}
    return EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI locate(EFI_GUID *guid,void *registration,void **out) {
    (void)guid;(void)registration;*out=&gop;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI query(EFI_GRAPHICS_OUTPUT_PROTOCOL *p,UINT32 index,UINTN *size,EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **out) {
    (void)p;queries++;
    if(index>=8)return EFI_NOT_FOUND;
    *out=malloc(sizeof(**out));allocations++;**out=information[index];*size=index==(unsigned)bad_query?1:sizeof(**out);
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI set(EFI_GRAPHICS_OUTPUT_PROTOCOL *p,UINT32 index) {
    (void)p;sets++;
    if(index==(unsigned)fail_mode)return EFI_DEVICE_ERROR;
    state.Mode=index;state.Info=&information[index];state.SizeOfInfo=sizeof(information[index]);
    state.FrameBufferBase=framebuffer_base;state.FrameBufferSize=VIDEO_BUFFER_BYTES;
    if(index==(unsigned)bad_framebuffer)state.FrameBufferSize=1;
    return EFI_SUCCESS;
}
static void checksum(unsigned char *p){p[127]=0;for(unsigned i=0;i<127;i++)p[127]-=p[i];}
static void reset(unsigned w,unsigned h) {
    static EFI_BOOT_SERVICES bs;memset(&bs,0,sizeof(bs));services=&bs;system=NULL;
    bs.FreePool=free_pool;bs.LocateHandleBuffer=locate_handles;bs.HandleProtocol=handle;bs.LocateProtocol=locate;
    memset(&gop,0,sizeof(gop));memset(&state,0,sizeof(state));gop.Mode=&state;gop.QueryMode=query;gop.SetMode=set;
    state.MaxMode=6;state.Mode=0;state.Info=&information[0];
    unsigned widths[]={1024,1920,2560,3440,3840,5120},heights[]={768,1080,1080,1440,2160,2880};
    for(unsigned i=0;i<6;i++)information[i]=(EFI_GRAPHICS_OUTPUT_MODE_INFORMATION){
        .HorizontalResolution=widths[i],.VerticalResolution=heights[i],.PixelsPerScanLine=widths[i],.PixelFormat=PixelBlueGreenRedReserved8BitPerColor};
    memset(bytes,0,sizeof(bytes));memset(bytes+1,255,6);bytes[18]=1;bytes[19]=4;bytes[24]=2;
    if(w){bytes[54]=1;bytes[56]=w;bytes[58]=(w>>8)<<4;bytes[59]=h;bytes[61]=(h>>8)<<4;}
    checksum(bytes);edid.SizeOfEdid=128;edid.Edid=bytes;
    fail_mode=bad_framebuffer=bad_query=-1;edid_available=1;wrong_monitor=0;sets=queries=0;
    memory_mb=0;
    framebuffer_base=0xc0000000;
    assert(!allocations);
}
static struct boot_info choose(unsigned w,unsigned h) {
    struct boot_info boot={0};struct config cfg={w,h};
    assert(graphics(&boot,&cfg)==EFI_SUCCESS);assert(!allocations);return boot;
}
int main(void) {
    struct boot_info b;
    reset(3440,1440);b=choose(0,0);assert(b.width==3440 && b.height==1440 && b.native_w==3440 && sets==1);
    reset(3440,1440);b=choose(1024,768);assert(b.width==1024);
    reset(3440,1440);b=choose(2000,1000);assert(b.width==3440);
    reset(3440,1440);fail_mode=3;b=choose(0,0);assert(b.width==2560 && b.height==1080 && sets==2);
    reset(3440,1440);bad_framebuffer=3;b=choose(0,0);assert(b.width==2560 && sets==2);
    reset(3440,1440);bad_query=3;b=choose(0,0);assert(b.width==2560);
    reset(3440,1440);information[3].PixelsPerScanLine=1;b=choose(0,0);assert(b.width==2560);
    reset(3440,1440);information[3].PixelFormat=PixelBltOnly;b=choose(0,0);assert(b.width==2560);
    reset(3440,1440);information[3].PixelFormat=PixelRedGreenBlueReserved8BitPerColor;b=choose(0,0);assert(b.width==3440 && b.pixel_order==1);
    reset(3440,1440);information[3].PixelsPerScanLine=3584;b=choose(0,0);assert(b.width==3440 && b.pitch==14336);
    reset(3440,1440);edid_available=0;b=choose(0,0);assert(b.width==5120);
    reset(3440,1440);wrong_monitor=1;b=choose(0,0);assert(b.width==5120 && !b.native_w);
    reset(3440,1440);bytes[100]^=1;b=choose(0,0);assert(b.width==5120 && !b.native_w);
    reset(3440,1440);state.MaxMode=0;struct config cfg={0};assert(graphics(&b,&cfg)==EFI_UNSUPPORTED && !allocations);
    UINT64 invalid_bases[]={0,0xc0000001,0x100000000ULL,0xfffff000};
    for(unsigned i=0;i<sizeof(invalid_bases)/sizeof(*invalid_bases);i++) {
        reset(3440,1440);framebuffer_base=invalid_bases[i];
        assert(graphics(&b,&cfg)==EFI_UNSUPPORTED && !allocations);
    }
    reset(3440,1440);state.MaxMode=100000;b=choose(0,0);assert(queries==256 && b.width==3440);
    reset(3440,1440);services->AllocatePool=allocate_pool;services->GetMemoryMap=memory_map;
    memory_mb=120;b=choose(0,0);assert(b.width==2560 && b.height==1080);
    reset(3440,1440);services->AllocatePool=allocate_pool;services->GetMemoryMap=memory_map;
    memory_mb=~0u;b=choose(0,0);assert(b.width==1024);
    reset(3440,1440);information[3].PixelFormat=PixelBitMask;
    information[3].PixelInformation=(EFI_PIXEL_BITMASK){0xff,0xff00,0xff0000,0xff000000};
    b=choose(0,0);assert(b.pixel_order==1 && b.width==3440);
    reset(0,0);bytes[126]=1;checksum(bytes);unsigned char *e=bytes+128;
    e[0]=0x70;e[1]=0x20;e[2]=23;e[5]=0x22;e[7]=20;e[11]=128;
    e[12]=5119&255;e[13]=5119>>8;e[20]=2879&255;e[21]=2879>>8;
    for(unsigned i=1;i<28;i++)e[28]-=e[i];checksum(e);edid.SizeOfEdid=256;
    b=choose(0,0);assert(b.width==5120 && b.native_w==5120 && b.native_h==2880);
    puts("UEFI GOP: native/manual/no EDID, failed SetMode, invalid scanout/query, RGB, bounded catalogue: PASS");
}
