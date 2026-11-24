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
    and rsp,-16
    call kernel64_exception

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
