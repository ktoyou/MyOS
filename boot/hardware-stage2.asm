; Second stage stays below 64 KiB. BIOS reads into a 32 KiB bounce buffer;
; protected-mode copies load the kernel and root image above 1 MiB.
[bits 16]
[org 0x9000]
%include "build/video-policy/limits.inc"
%ifndef VIDEO_WIDTH
%define VIDEO_WIDTH 0
%define VIDEO_HEIGHT 0
%endif
INFO equ 0x6000
FONT equ 0x5000
BOUNCE equ 0x70000
KERNEL equ 0x100000
; Layout limits are passed from kernel/bootinfo.h by the image builder.
ROOT equ ROOT_PHYS
%ifndef INSTALLED_ROOT
%if ROOT_SECTORS*512 < ROOT_MIN_BYTES || ROOT_SECTORS*512 > ROOT_MAX_BYTES
%error "Live root size is outside the supported range"
%endif
%endif
start:
    cli
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov sp,0x7c00
    sti
    cld
    mov [drive],dl
    mov si,loading
    call print
    ; Build an explicit, versioned boot contract (see kernel/bootinfo.h).
    xor ax,ax                  ; print оставляет AH=0x0e, а не ноль
    mov di,INFO
    mov cx,100/2
    rep stosw
    mov dword [INFO],0x534f594d
    mov dword [INFO+4],5
    mov dword [INFO+44],ROOT_LBA
    mov dword [INFO+48],ROOT_DISK_ID
    mov dword [INFO+8],ROOT
    mov dword [INFO+12],ROOT_SECTORS*512
    mov dword [INFO+16],FONT
%ifdef INSTALLED_ROOT
    mov dword [INFO+4],5
    mov dword [INFO+8],0
    mov dword [INFO+12],0
    mov eax,[0x7c00+454] ; first MBR partition, selected by the installer
    mov [INFO+44],eax
    mov eax,[0x7c00+440]
    mov [INFO+48],eax
    mov dword [INFO+52],1 ; BOOT_DISK_ROOT
    mov eax,[0x7c00+458]
    mov [INFO+56],eax
%endif
    ; E820 records remain in the legacy ABI at 0x8000.
    mov di,0x8004
    xor ebx,ebx
    xor bp,bp
.map:
    mov eax,0xe820
    mov edx,0x534d4150
    mov ecx,24
    mov dword [di+20],1
    int 0x15
    jc .mapped
    cmp eax,0x534d4150
    jne .mapped
    jcxz .skip
    inc bp
    add di,24
.skip:
    test ebx,ebx
    jz .mapped
    cmp bp,128
    jb .map
.mapped:
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov [0x8000],bp
    mov word [0x8002],0
    ; Require usable E820 memory for every byte written above 1 MiB.
    mov eax,KERNEL
    mov edx,KERNEL_END
    call usable
%ifdef INSTALLED_ROOT
    mov eax,KERNEL
    mov edx,KERNEL_END+ROOT_RESERVE_BYTES
%else
    mov eax,ROOT
    mov edx,ROOT+ROOT_SECTORS*512+ROOT_RESERVE_BYTES
%endif
    call usable
    in al,0x92
    or al,2
    and al,0xfe
    out 0x92,al
    ; Verify A20 before copying into high memory.
    push ds
    mov ax,0xffff
    mov es,ax
    xor ax,ax
    mov ds,ax
    mov al,[0x500]
    mov ah,[es:0x510]
    push ax
    mov byte [0x500],0
    mov byte [es:0x510],0xff
    cmp byte [0x500],0xff
    pop ax
    mov [es:0x510],ah
    mov [0x500],al
    pop ds
    je a20_error
    xor ax,ax
    mov es,ax
    mov dword [destination],KERNEL
    mov dword [dap_lba],KERNEL_LBA
    mov dword [remaining],KERNEL_SECTORS
    call load
%ifndef INSTALLED_ROOT
    mov dword [destination],ROOT
    mov dword [dap_lba],ROOT_LBA
    mov dword [remaining],ROOT_SECTORS
    call load
%endif
    ; Capture the BIOS font before switching out of VGA text mode.
    mov ax,0x1130
    mov bh,6
    int 0x10
    push ds
    mov ax,es
    mov ds,ax
    mov si,bp
    xor ax,ax
    mov es,ax
    mov di,FONT
    mov cx,4096
    cld
    rep movsb
    pop ds
    call video_select
    ; Firmware display path for real GPUs, including NVIDIA legacy VBIOS.
    mov dword [0x1000],0x32454256
    mov ax,0x4f00
    mov di,0x1000
    call video_bios
    cmp ax,0x004f
    jne no_video
    cmp dword [0x1000],0x41534556 ; 'VESA'
    jne no_video
    cmp word [0x1004],0x200
    jb no_video
    mov eax,[0x100e]
    mov [mode_list],eax
    call select_video
    jnc video_done
no_video:
    mov si,video_error
    call print
video_done:
    ; Preserve IVT/BDA for the runtime interpreter before page zero is unmapped.
    xor ax,ax
    mov ds,ax
    mov es,ax
    xor si,si
    mov di,0x2000
    mov cx,4096/2
    cld
    rep movsw
    mov dword [INFO+40],0x49564256 ; optional runtime snapshot contract
    cli
    lgdt [gdt_desc]
    mov eax,cr0
    or al,1
    mov cr0,eax
    jmp 8:enter_kernel
; EAX=start, EDX=end; a single usable E820 region must contain the range,
; and no non-usable record may overlap it.
usable:
    mov si,0x8004
    mov cx,[0x8000]
    xor bx,bx
.region:
    test cx,cx
    jz .done
    cmp dword [si+4],0
    jne .next
    mov edi,[si]
    mov ebp,[si+8]
    add ebp,edi
    jc .high_end
    cmp dword [si+12],0
    je .end_known
.high_end:
    mov ebp,0xffffffff
.end_known:
    cmp dword [si+16],1
    jne .reserved
    cmp edi,eax
    ja .next
    cmp ebp,edx
    jb .next
    mov bx,1
    jmp .next
.reserved:
    cmp edi,edx
    jae .next
    cmp ebp,eax
    ja memory_error
.next:
    add si,24
    dec cx
    jmp .region
.done:
    test bx,bx
    jz memory_error
    ret
video_select:
    mov word [want_w],VIDEO_WIDTH
    mov word [want_h],VIDEO_HEIGHT
    mov si,video_hint
    call print
    mov ax,[0x46c]
    mov [video_start],ax
.wait:
    mov ah,1
    int 0x16
    jz .time
    xor ah,ah
    int 0x16
    cmp al,'v'
    je .menu
    cmp al,'V'
    je .menu
    cmp al,'s'
    je .safe
    cmp al,'S'
    je .safe
    cmp al,13
    je .done
.time:
    mov ax,[0x46c]
    sub ax,[video_start]
    cmp ax,54                  ; about three seconds
    jb .wait
    ret
.safe:
    mov word [want_w],1024
    mov word [want_h],768
    ret
.menu:
    mov si,video_choices
    call print
.key:
    xor ah,ah
    int 0x16
    cmp al,13
    je .done
    cmp al,'a'
    jb .upper
    cmp al,'d'
    ja .upper
    sub al,32
.upper:
    cmp al,'A'
    jb .number
    cmp al,'D'
    ja .key
    sub al,'A'-10
    jmp .index
.number:
    cmp al,'0'
    jb .key
    cmp al,'9'
    ja .key
    sub al,'0'
.index:
    xor ah,ah
    shl ax,2
    mov si,select_modes
    add si,ax
    lodsw
    mov [want_w],ax
    lodsw
    mov [want_h],ax
.done:
    ret

; Firmware may change segment registers and the direction flag.
video_bios:
    push ds
    push es
    push fs
    int 0x10
    pop fs
    pop es
    pop ds
    cld
    ret

select_video:
    ; Копия списка переживает перезапись scratch-буферов прошивкой.
    mov eax,[mode_list]
    mov [cursor],eax
    mov word [mode_count],0
.ids:
    mov si,[cursor]
    mov ax,[cursor+2]
    mov fs,ax
    movzx eax,ax
    shl eax,4
    movzx edx,si
    add eax,edx
    cmp eax,0xffffe
    ja .copied
    mov ax,[fs:si]
    cmp ax,0xffff
    je .copied
    mov bx,[mode_count]
    shl bx,1
    mov [bx+0x1a00],ax
    inc word [mode_count]
    add word [cursor],2
    jnc .advance
    add word [cursor+2],0x1000
.advance:
    cmp word [mode_count],256
    jb .ids
.copied:
    mov word [edid_block],0
    mov word [edid_count],1
.edid:
    mov ax,[edid_block]
    shl ax,7
    add ax,0x1400
    mov di,ax
    mov ax,0x4f15
    mov bx,1
    xor cx,cx
    mov dx,[edid_block]
    call video_bios
    cmp ax,0x004f
    jne .parse
    inc word [edid_block]
    cmp word [edid_block],1
    jne .extension
    movzx ax,byte [0x147e]
    inc ax
    cmp ax,8
    jbe .count
    mov ax,8
.count:
    mov [edid_count],ax
.extension:
    mov ax,[edid_block]
    cmp ax,[edid_count]
    jb .edid
.parse:
    movzx eax,word [edid_block]
    shl eax,7
    mov [policy_args+4],eax
    mov dword [policy_args],0x1400
    mov dword [policy_args+8],INFO+92
    mov dword [policy_args+12],INFO+96
    xor eax,eax
    call policy_call
%ifdef INSTALLED_ROOT
    mov dword [policy_args],0
%else
    mov dword [policy_args],ROOT_SECTORS*512
%endif
    mov dword [policy_args+4],KERNEL_END
    mov eax,2
    call policy_call
    mov [video_budget],eax
    mov word [mode_index],0
    mov word [candidate_count],0
.query:
    mov bx,[mode_index]
    cmp bx,[mode_count]
    jae .select
    inc word [mode_index]
    shl bx,1
    mov cx,[bx+0x1a00]
    mov [mode],cx
    call query_video
    jc .query
    movzx eax,word [0x1212]
    mov [policy_args],eax
    movzx eax,word [0x1214]
    mov [policy_args+4],eax
    movzx eax,word [want_w]
    mov [policy_args+8],eax
    movzx eax,word [want_h]
    mov [policy_args+12],eax
    mov eax,[INFO+92]
    mov [policy_args+16],eax
    mov eax,[INFO+96]
    mov [policy_args+20],eax
    mov eax,1
    call policy_call
    movzx ebx,word [candidate_count]
    imul bx,20
    add bx,0x2000
    mov [bx+16],eax
    mov ax,[mode]
    mov [bx],ax
    mov eax,[0x1212]
    mov [bx+2],eax
    mov ax,[candidate_order]
    mov [bx+6],ax
    mov eax,[candidate_pitch]
    mov [bx+8],eax
    mov eax,[0x1228]
    mov [bx+12],eax
    inc word [candidate_count]
    jmp .query
.select:
    mov cx,[candidate_count]
    mov si,0x2000
    xor eax,eax
    xor di,di
.best:
    jcxz .chosen
    cmp [si+16],eax
    jbe .skip
    mov eax,[si+16]
    mov di,si
.skip:
    add si,20
    dec cx
    jmp .best
.chosen:
    test di,di
    jz .fail
    mov [candidate_ptr],di
    mov dword [di+16],0
    mov bx,[di]
    mov [mode],bx
    or bx,0x4000
    mov ax,0x4f02
    call video_bios
    cmp ax,0x004f
    jne .select
    mov ax,0x4f03
    call video_bios
    cmp ax,0x004f
    jne .select
    and bx,0x3fff
    cmp bx,[mode]
    jne .select
    mov cx,[mode]
    call query_video
    jc .select
    mov di,[candidate_ptr]
    mov eax,[0x1212]
    cmp eax,[di+2]
    jne .select
    mov eax,[0x1228]
    mov [INFO+20],eax
    movzx eax,word [0x1212]
    mov [INFO+24],eax
    movzx eax,word [0x1214]
    mov [INFO+28],eax
    mov dword [INFO+32],32
    mov eax,[candidate_pitch]
    mov [INFO+36],eax
    movzx eax,word [candidate_order]
    mov [INFO+88],eax
    clc
    ret
.fail:
    stc
    ret

query_video:
    xor ax,ax
    mov es,ax
    mov di,0x1200
    mov ax,0x4f01
    call video_bios
    cmp ax,0x004f
    jne .fail
    mov ax,[0x1200]
    and ax,0x99
    cmp ax,0x99
    jne .fail
    cmp word [0x1212],640
    jb .fail
    cmp word [0x1212],VIDEO_MAX_W
    ja .fail
    cmp word [0x1214],480
    jb .fail
    cmp word [0x1214],VIDEO_MAX_H
    ja .fail
    cmp byte [0x1219],32
    jne .fail
    cmp byte [0x121b],6
    jne .fail
    mov si,0x121f
    mov ax,[0x1210]
    cmp word [0x1004],0x300
    jb .masks
    mov si,0x1236
    mov ax,[0x1232]
.masks:
    movzx eax,ax
    test eax,3
    jnz .fail
    movzx edx,word [0x1212]
    shl edx,2
    cmp eax,edx
    jb .fail
    mov [candidate_pitch],eax
    cmp word [si+2],0x0808
    jne .fail
    mov word [candidate_order],0
    cmp word [si],0x1008
    jne .rgb
    cmp word [si+4],0x0008
    jne .fail
    jmp .geometry
.rgb:
    cmp word [si],0x0008
    jne .fail
    cmp word [si+4],0x1008
    jne .fail
    mov word [candidate_order],1
.geometry:
    cmp byte [si+6],0
    je .reserved_ok
    movzx ax,byte [si+6]
    movzx dx,byte [si+7]
    cmp dx,24
    jb .fail
    add ax,dx
    cmp ax,32
    ja .fail
.reserved_ok:
    ; Padding входит и в лимит отображения, и в оценку доступной памяти.
    mov eax,[candidate_pitch]
    movzx edx,word [0x1214]
    imul edx,eax
    cmp edx,VIDEO_BYTES
    ja .fail
    cmp edx,[video_budget]
    ja .fail
    movzx eax,word [0x1012]
    test eax,eax
    jz .address
    shl eax,16
    cmp edx,eax
    ja .fail
.address:
    mov eax,[0x1228]
    test eax,eax
    jz .fail
    test eax,4095
    jnz .fail
    add edx,eax
    jc .fail
    clc
    ret
.fail:
    stc
    ret

policy_call:
    ; C работает с отдельным стеком: возврат BIOS остаётся ниже 0x7c00.
    pushfd
    pushad
    push ds
    push es
    push fs
    push gs
    mov [policy_sp],sp
    mov [policy_op],eax
    cli
    lgdt [gdt_desc]
    mov eax,cr0
    or al,1
    mov cr0,eax
    jmp 8:policy32
[bits 32]
policy32:
    mov ax,16
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov esp,0x7000
    cld
    push dword policy_args
    push dword [policy_op]
    mov eax,0xc000
    call eax
    mov [policy_result],eax
    jmp 24:policy16
[bits 16]
policy16:
    mov ax,32
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov eax,cr0
    and al,0xfe
    mov cr0,eax
    jmp 0:policy_return
policy_return:
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov sp,[policy_sp]
    pop gs
    pop fs
    pop es
    pop ds
    popad
    popfd
    mov eax,[policy_result]
    ret

load:
    mov eax,[remaining]
    test eax,eax
    jz load_done
    cmp eax,64
    jbe .count
    mov eax,64
.count:
    mov [chunk],ax
    mov [dap_count],ax
    mov byte [retries],3
.read:
    mov ax,[chunk]
    mov [dap_count],ax
    mov si,dap
    mov dl,[drive]
    mov ah,0x42
    int 0x13
    jnc .copy
    xor ah,ah
    mov dl,[drive]
    int 0x13
    dec byte [retries]
    jnz .read
    mov si,disk_error
    jmp fatal
.copy:
    cli
    lgdt [gdt_desc]
    mov eax,cr0
    or al,1
    mov cr0,eax
    jmp 8:copy32
[bits 32]
copy32:
    mov ax,16
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov esi,BOUNCE
    mov edi,[destination]
    movzx ecx,word [chunk]
    shl ecx,7
    cld
    rep movsd
    mov [destination],edi
    jmp 24:copy16
[bits 16]
copy16:
    mov ax,32
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov eax,cr0
    and al,0xfe
    mov cr0,eax
    jmp 0:real_return
real_return:
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov ss,ax
    sti
    movzx eax,word [chunk]
    add [dap_lba],eax
    sub [remaining],eax
    jmp load
load_done:
    ret
print:
    lodsb
    test al,al
    jz .done
    mov ah,0x0e
    int 0x10
    jmp print
.done:
    ret
memory_error:
    mov si,mem_error
    jmp fatal
a20_error:
    mov si,a20_msg
fatal:
    call print
.halt:
    cli
    hlt
    jmp .halt
[bits 32]
enter_kernel:
    mov ax,16
    mov ds,ax
    mov es,ax
    mov fs,ax
    mov gs,ax
    mov ss,ax
    mov esp,0x9f000
    jmp KERNEL
[bits 16]
align 8
gdt:
    dq 0,0x00cf9a000000ffff,0x00cf92000000ffff
    dq 0x00009a000000ffff,0x000092000000ffff
gdt_desc: dw $-gdt-1
    dd gdt
drive: db 0
retries: db 0
chunk: dw 0
remaining: dd 0
destination: dd 0
mode_list: dd 0
cursor: dd 0
mode: dw 0
candidate_pitch: dd 0
mode_count: dw 0
mode_index: dw 0
candidate_count: dw 0
candidate_ptr: dw 0
candidate_order: dw 0
edid_block: dw 0
edid_count: dw 0
policy_sp: dw 0
align 4
policy_op: dd 0
policy_result: dd 0
policy_args: times 6 dd 0
video_budget: dd VIDEO_BYTES
want_w: dw 0
want_h: dw 0
video_start: dw 0
select_modes: dw 0,0, 640,480, 800,600, 1024,768, 1280,720
              dw 1280,1024, 1600,900, 1920,1080, 1920,1200, 2560,1440
              dw 3440,1440, 3840,2160, 5120,2160, 2560,1080
video_hint: db 'Press V for resolution menu, S for safe 1024x768, Enter to boot (3 seconds).',13,10,0
video_choices: db 'Resolution (BIOS must support it):',13,10
    db '0 Auto, 1 640x480, 2 800x600, 3 1024x768, 4 1280x720',13,10
    db '5 1280x1024, 6 1600x900, 7 1920x1080, 8 1920x1200, 9 2560x1440',13,10
    db 'A 3440x1440, B 3840x2160, C 5120x2160, D 2560x1080',13,10
    db 'Choose 0-9 / A-D, or Enter for build default: ',0
align 4
dap: db 16,0
dap_count: dw 64
    dw 0,0x7000
dap_lba: dq 0
loading: db 'MyOS USB: loading kernel and live filesystem...',13,10,0
disk_error: db 'MyOS: disk read failed',0
mem_error: db 'MyOS: insufficient usable E820 RAM for live root and working memory',0
a20_msg: db 'MyOS: A20 enable failed',0
video_error: db 'MyOS: no 32-bit RGB VBE mode, using text',13,10,0
times 0x3000-($-$$) db 0
incbin "build/video-policy/policy.bin"
times 16384-($-$$) db 0
