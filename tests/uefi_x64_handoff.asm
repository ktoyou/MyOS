[bits 64]
[org 0x100000]
    cmp esi,0x55454649
    jne fail
    mov rbx,rdi
    test rbx,rbx
    jz fail

    mov ax,cs
    cmp ax,0x08
    jne fail
    mov ecx,0xc0000080
    rdmsr
    test eax,1<<10
    jz fail
    mov rax,cr0
    bt rax,31
    jnc fail
    pushfq
    pop rax
    test eax,0x600              ; IF и DF должны быть сброшены
    jnz fail
    mov rax,rsp
    and eax,15
    cmp eax,8
    jne fail
    cmp qword [rsp],0
    jne fail
    cmp dword [rbx],0x534f594d
    jne fail
    cmp dword [rbx+4],6
    jne fail
    cmp dword [rbx+60],1        ; boot_info.firmware
    jne fail
    mov eax,[rbx+76]            ; boot_info.arena_phys
    cmp rax,rbx
    jne fail
    lea rax,[rbx+16384]
    mov rcx,cr3
    cmp rax,rcx
    jne fail
    cmp dword [rbx+72],0        ; boot_info.map_count
    je fail
    mov eax,[rbx+64]            ; ACPI RSDP
    test eax,eax
    jz fail
    cmp dword [rax],0x20445352
    jne fail
    cmp dword [rbx+20],0        ; GOP framebuffer
    je fail
    cmp qword [rel tail],0
    jne fail
    cmp qword [rel tail+248],0
    jne fail
    lea rsi,[rel passed]
    jmp print
fail:
    lea rsi,[rel failed]
print:
    lodsb
    test al,al
    jz stop
    mov ah,al
    mov dx,0x3fd
.wait:
    in al,dx
    test al,0x20
    jz .wait
    mov al,ah
    mov dx,0x3f8
    out dx,al
    jmp print
stop:
    hlt
    jmp stop
passed: db "UEFI X64 HANDOFF PASS",13,10,0
failed: db "UEFI X64 HANDOFF FAIL",13,10,0
tail:
