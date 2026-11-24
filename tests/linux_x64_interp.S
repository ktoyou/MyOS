.intel_syntax noprefix
.section .text
.global _start
.hidden __ehdr_start
_start:
    lea rbx,[rsp+8]
    mov rax,[rsp]
    lea rbx,[rbx+rax*8+8]
env:
    mov rax,[rbx]
    add rbx,8
    test rax,rax
    jnz env
    xor r12d,r12d
    xor r13d,r13d
    xor r14d,r14d
aux:
    mov rax,[rbx]
    mov rdx,[rbx+8]
    add rbx,16
    test rax,rax
    jz aux_done
    cmp eax,3
    cmove r12,rdx
    cmp eax,7
    cmove r13,rdx
    cmp eax,9
    cmove r14,rdx
    jmp aux
aux_done:
    lea rax,[rip+__ehdr_start]
    cmp r13,rax
    jne fail
    test r12,r12
    jz fail
    cmp dword ptr [r12],6
    jne fail
    /* AT_PHDR и AT_ENTRY относятся к PIE, а AT_BASE — к интерпретатору. */
    mov rax,r12
    sub rax,[r12+16]
    cmp rax,r13
    je fail
    cmp dword ptr [rax],0x464c457f
    jne fail
    add rax,[rax+24]
    cmp rax,r14
    jne fail
    mov eax,1
    mov edi,1
    lea rsi,[rip+message]
    mov edx,message_end-message
    syscall
    cmp rax,message_end-message
    jne fail
    xor edx,edx
    jmp r14
fail:
    mov eax,60
    mov edi,2
    syscall
    ud2

.section .rodata
message: .ascii "Linux ELF64 interpreter\n"
message_end:
.section .note.GNU-stack,"",@progbits
