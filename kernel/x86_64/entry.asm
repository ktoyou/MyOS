[bits 64]
default rel

section .text.entry
global _start
extern kernel64_main
_start:
    jmp kernel64_main

section .text
extern kernel64_exception

%macro exception 1
exception_%+%1:
    %if %1 != 8 && %1 != 10 && %1 != 11 && %1 != 12 && %1 != 13 && %1 != 14 && %1 != 17 && %1 != 21 && %1 != 29 && %1 != 30
        push qword 0
    %endif
    push qword %1
    jmp exception_entry
%endmacro

%assign vector 0
%rep 32
    exception vector
    %assign vector vector+1
%endrep

exception_entry:
    ; Для C кадр унифицирован до номера, кода ошибки и RIP.
    cld
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov rcx,[rsp+24]
    mov r8,rsp
    mov r9,[rsp+40]
    and rsp,-16
    call kernel64_exception

global segments64_enter_user
segments64_enter_user:
    ; SS:RSP и CS:RIP берутся из кадра IRETQ, IOPL и IF сброшены.
    push qword 0x1b
    push rsi
    push qword 2
    push qword 0x23
    push rdi
    mov ax,0x1b
    mov ds,ax
    mov es,ax
    xor eax,eax
    xor ebx,ebx
    xor ecx,ecx
    xor edx,edx
    xor ebp,ebp
    xor esi,esi
    xor edi,edi
    xor r8d,r8d
    xor r9d,r9d
    xor r10d,r10d
    xor r11d,r11d
    xor r12d,r12d
    xor r13d,r13d
    xor r14d,r14d
    xor r15d,r15d
    iretq

section .rodata
global kernel64_vectors
align 8
kernel64_vectors:
%assign vector 0
%rep 32
    dq exception_%+vector
    %assign vector vector+1
%endrep

section .note.GNU-stack noalloc noexec nowrite progbits
