.intel_syntax noprefix
.section .text
.global _start
_start:
#ifdef BAD_STACK
    mov rsp,0x800000000000
    mov eax,9999
    syscall
    ud2
#endif
    test rsp,15
    jnz fail
    cmp qword ptr [rsp],1
    jne fail
    cmp qword ptr [rsp+8],0
    je fail
    cmp qword ptr [rsp+16],0
    jne fail
    lea rbx,[rsp+24]
env:
    mov rax,[rbx]
    add rbx,8
    test rax,rax
    jnz env
    xor r12d,r12d
aux:
    mov rax,[rbx]
    mov rdx,[rbx+8]
    add rbx,16
    test rax,rax
    jz aux_done
    cmp eax,3
    jne pagesize
    cmp dword ptr [rdx],1
    jne fail
    or r12d,1
pagesize:
    cmp eax,4
    jne phnum
    cmp rdx,56
    jne fail
    or r12d,8
phnum:
    cmp eax,5
    jne compare_pagesize
    cmp rdx,3
    jb fail
    or r12d,16
compare_pagesize:
    cmp eax,6
    jne entry
    cmp rdx,4096
    jne fail
    or r12d,2
entry:
    cmp eax,9
    jne aux
    lea rcx,[rip+_start]
    cmp rdx,rcx
    jne fail
    or r12d,4
    jmp aux
aux_done:
    cmp r12d,31
    jne fail
    cmp byte ptr [rip+data_byte],0x5a
    jne fail
    cmp byte ptr [rip+buffer+4095],0
    jne fail
    cmp byte ptr [rip+buffer+8191],0
    jne fail

    mov eax,1
    mov edi,7
    xor esi,esi
    xor edx,edx
    syscall
    cmp rax,-9
    jne fail
    mov eax,1
    mov edi,1
    mov esi,0x100000
    mov edx,1
    syscall
    cmp rax,-14
    jne fail
    mov eax,1
    mov edi,1
    mov rsi,0xffff800000100000
    syscall
    cmp rax,-14
    jne fail
    mov eax,9999
    syscall
    cmp rax,-38
    jne fail

    mov byte ptr [rip+buffer+4095],'O'
    mov byte ptr [rip+buffer+4096],'K'
    mov eax,1
    mov edi,1
    lea rsi,[rip+buffer+4095]
    mov edx,2
    mov r10d,0x12345678
    syscall
    cmp rax,2
    jne fail
    cmp r10d,0x12345678
    jne fail
    mov eax,1
    mov edi,2
    lea rsi,[rip+message]
    mov edx,message_end-message
    syscall
    cmp rax,message_end-message
    jne fail
    mov eax,60
    mov edi,42
    syscall
fail:
    mov eax,60
    mov edi,1
    syscall
    ud2

.global guard_probe
guard_probe:
    mov rax,0x00007fffffefb000
    mov al,[rax]
    ud2

.section .rodata
message: .ascii " Linux ELF64 syscall probe\n"
message_end:
.section .data
data_byte: .byte 0x5a
.section .bss
.balign 4096
buffer: .skip 8192
.section .note.GNU-stack,"",@progbits
