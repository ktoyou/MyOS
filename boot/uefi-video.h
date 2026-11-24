#include "../user/lib/video_mode.h"
#define GOP_MODE_LIMIT 256u
static EFI_GUID active_edid_guid=EFI_EDID_ACTIVE_PROTOCOL_GUID;
static EFI_GUID discovered_edid_guid=EFI_EDID_DISCOVERED_PROTOCOL_GUID;
struct gop_candidate {unsigned id,w,h,rank;};
static unsigned gop_budget=VIDEO_BUFFER_BYTES;
static unsigned gop_memory_budget(void) {
    if(!services->GetMemoryMap)return VIDEO_BUFFER_BYTES;
    UINTN capacity=65536,key,stride=0;UINT32 version;void *map=NULL;
    if(EFI_ERROR(services->AllocatePool(EfiLoaderData,capacity,&map)))return video_memory_budget(64u*1024*1024);
    EFI_STATUS r=services->GetMemoryMap(&capacity,map,&key,&stride,&version);
    UINT64 available=0;
    BOOLEAN valid=!EFI_ERROR(r) && capacity<=65536 && stride>=sizeof(EFI_MEMORY_DESCRIPTOR) && !(capacity%stride);
    if(valid)
        for(UINTN off=0;off<capacity;off+=stride) {
            EFI_MEMORY_DESCRIPTOR *m=(void *)((u8 *)map+off);
            if(m->Type!=EfiConventionalMemory || m->PhysicalStart>=0x40000000ULL)continue;
            UINT64 pages=(0x40000000ULL-m->PhysicalStart)/4096;
            if(pages>m->NumberOfPages)pages=m->NumberOfPages;
            available+=pages*4096;
        }
    services->FreePool(map);
    if(!valid)return video_memory_budget(64u*1024*1024);
    if(available>0x40000000ULL)available=0x40000000ULL;
    return video_memory_budget((unsigned)available);
}
static unsigned gop_order(const EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *m) {
    if(m->PixelFormat==PixelBlueGreenRedReserved8BitPerColor)return 0;
    if(m->PixelFormat==PixelRedGreenBlueReserved8BitPerColor)return 1;
    if(m->PixelFormat!=PixelBitMask || m->PixelInformation.GreenMask!=0xff00 || (m->PixelInformation.ReservedMask&0xffffff))return 2;
    if(m->PixelInformation.RedMask==0xff0000 && m->PixelInformation.BlueMask==0xff)return 0;
    if(m->PixelInformation.RedMask==0xff && m->PixelInformation.BlueMask==0xff0000)return 1;
    return 2;
}
static BOOLEAN usable_mode(const EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *m) {
    return m && m->HorizontalResolution>=640 && m->HorizontalResolution<=VIDEO_MAX_WIDTH &&
        m->VerticalResolution>=480 && m->VerticalResolution<=VIDEO_MAX_HEIGHT &&
        m->PixelsPerScanLine>=m->HorizontalResolution &&
        m->PixelsPerScanLine<=gop_budget/(m->VerticalResolution*4) && gop_order(m)<2;
}
static void gop_native(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop,unsigned *w,unsigned *h) {
    *w=*h=0;UINTN count=0;EFI_HANDLE *handles=NULL;
    if(EFI_ERROR(services->LocateHandleBuffer(ByProtocol,&gop_guid,NULL,&count,&handles)))return;
    if(count>256)count=256;
    for(UINTN i=0;i<count;i++) {
        EFI_GRAPHICS_OUTPUT_PROTOCOL *other=NULL;
        if(EFI_ERROR(services->HandleProtocol(handles[i],&gop_guid,(void **)&other)) || other!=gop)continue;
        /* EDID другого видеовыхода нельзя применять к выбранному GOP. */
        for(unsigned kind=0;kind<2;kind++) {
            EFI_EDID_ACTIVE_PROTOCOL *edid=NULL;
            if(!EFI_ERROR(services->HandleProtocol(handles[i],kind?&discovered_edid_guid:&active_edid_guid,(void **)&edid)) &&
                edid && video_edid(edid->Edid,edid->SizeOfEdid,w,h))break;
        }
        if(*w)break;
    }
    if(handles)services->FreePool(handles);
}
static char *gop_decimal(char *at,unsigned value) {
    char reversed[12];unsigned n=0;do{reversed[n++]='0'+value%10;value/=10;}while(value);
    while(n)*at++=reversed[--n];
    return at;
}
static void gop_log(const char *prefix,unsigned w,unsigned h) {
    char text[100],*at=text;while(*prefix && at<text+64)*at++=*prefix++;
    at=gop_decimal(at,w);*at++='x';at=gop_decimal(at,h);*at++='\r';*at++='\n';*at=0;message(text);
}
static void gop_menu(struct gop_candidate *modes,unsigned count,unsigned *manual_w,unsigned *manual_h) {
    if(!system || !system->ConIn || !services->Stall)return;
    message("UEFI video: V=mode menu, S=safe 1024x768 (3 seconds)\r\n");
    EFI_INPUT_KEY key;
    for(unsigned i=0;i<300;i++) {
        if(!EFI_ERROR(system->ConIn->ReadKeyStroke(system->ConIn,&key))) {
            if(key.UnicodeChar=='s' || key.UnicodeChar=='S'){*manual_w=1024;*manual_h=768;return;}
            if(key.UnicodeChar=='v' || key.UnicodeChar=='V')break;
            if(key.UnicodeChar=='\r')return;
        }
        services->Stall(10000);
        if(i==299)return;
    }
    message("0=Auto/native, Space=safe, Esc=build default. Choose a mode:\r\n");
    unsigned shown=count<35?count:35;
    for(unsigned i=0;i<shown;i++) {
        char prefix[5]={(char)(i<9?'1'+i:'A'+i-9),':',' ',0};gop_log(prefix,modes[i].w,modes[i].h);
    }
    for(unsigned i=0;i<1000;i++) {
        if(!EFI_ERROR(system->ConIn->ReadKeyStroke(system->ConIn,&key))) {
            unsigned c=key.UnicodeChar;
            if(c=='0'){*manual_w=*manual_h=0;return;}
            if(c==' '){*manual_w=1024;*manual_h=768;return;}
            if(c==27 || key.ScanCode==SCAN_ESC)return;
            if(c>='a' && c<='z')c-=32;
            unsigned selected=c>='1' && c<='9'?c-'1':c>='A' && c<='Z'?c-'A'+9:35;
            if(selected<shown){*manual_w=modes[selected].w;*manual_h=modes[selected].h;return;}
        }
        services->Stall(10000);
    }
}
static EFI_STATUS graphics(struct boot_info *boot,const struct config *cfg) {
    gop_budget=gop_memory_budget();
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop=NULL;
    EFI_STATUS r=EFI_NOT_FOUND;
    if(system && system->ConsoleOutHandle)r=services->HandleProtocol(system->ConsoleOutHandle,&gop_guid,(void **)&gop);
    if(EFI_ERROR(r) || !gop)r=services->LocateProtocol(&gop_guid,NULL,(void **)&gop);
    if(EFI_ERROR(r) || !gop || !gop->Mode)return EFI_UNSUPPORTED;
    unsigned native_w=0,native_h=0;gop_native(gop,&native_w,&native_h);
    if(native_w)gop_log("UEFI EDID preferred: ",native_w,native_h);
    struct gop_candidate modes[GOP_MODE_LIMIT];unsigned count=0;
    unsigned limit=gop->Mode->MaxMode<GOP_MODE_LIMIT?gop->Mode->MaxMode:GOP_MODE_LIMIT;
    for(unsigned i=0;i<limit;i++) {
        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info=NULL;UINTN size=0;
        r=gop->QueryMode(gop,i,&size,&info);
        if(!EFI_ERROR(r) && info && size>=sizeof(*info) && usable_mode(info))
            modes[count++]=(struct gop_candidate){i,info->HorizontalResolution,info->VerticalResolution,0};
        if(info)services->FreePool(info);
    }
    unsigned manual_w=cfg->width,manual_h=cfg->height;
    gop_menu(modes,count,&manual_w,&manual_h);
    for(unsigned i=0;i<count;i++)modes[i].rank=video_rank(modes[i].w,modes[i].h,manual_w,manual_h,native_w,native_h);
    for(unsigned attempt=0;attempt<count;attempt++) {
        unsigned choice=~0u,score=0;
        for(unsigned i=0;i<count;i++)if(modes[i].rank>score){choice=i;score=modes[i].rank;}
        if(choice==~0u)break;
        struct gop_candidate candidate=modes[choice];modes[choice].rank=0;
        r=gop->SetMode(gop,candidate.id);
        if(EFI_ERROR(r)){gop_log("UEFI GOP SetMode failed: ",candidate.w,candidate.h);continue;}
        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *m=gop->Mode->Info;
        if(gop->Mode->SizeOfInfo<sizeof(*m) || !usable_mode(m) ||
           m->HorizontalResolution!=candidate.w || m->VerticalResolution!=candidate.h)continue;
        UINT64 bytes=(UINT64)m->PixelsPerScanLine*4*m->VerticalResolution,base=gop->Mode->FrameBufferBase;
        if(!base || (base&4095) || base>0xffffffffULL || bytes>0xffffffffULL-base || bytes>gop->Mode->FrameBufferSize)continue;
        boot->fb_phys=base;boot->width=m->HorizontalResolution;boot->height=m->VerticalResolution;
        boot->bpp=32;boot->pitch=m->PixelsPerScanLine*4;boot->pixel_order=gop_order(m);
        boot->native_w=native_w;boot->native_h=native_h;
        gop_log("UEFI GOP selected: ",boot->width,boot->height);
        return EFI_SUCCESS;
    }
    return EFI_UNSUPPORTED;
}
