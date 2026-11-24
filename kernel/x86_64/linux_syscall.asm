[bits 64]
default rel

section .text
global linux64_syscall_entry
extern linux64_syscall
extern linux64_invalid_return
linux64_syscall_entry:
    ; SYSCALL не загружает RSP0. До смены стека нельзя делать push.
    mov [user_rsp],rsp
    lea rsp,[kernel_stack_end]
    push qword 0x1b
    push qword [user_rsp]
    and r11,0x240dd5
    or r11,2
    push r11
    push qword 0x23
    push rcx

    ; IRETQ не должен получать адрес за пределами нижней половины.
    shr rcx,47
    jnz .bad_return
    mov rcx,[rsp+24]
    shr rcx,47
    jnz .bad_return
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push rdx
    push r10
    push r8
    push r9
    ; Шестой аргумент Linux переходит из R9 в первый стековый аргумент C.
    push r9
    mov r9,r8
    mov r8,r10
    mov rcx,rdx
    mov rdx,rsi
    mov rsi,rdi
    mov rdi,rax
    call linux64_syscall
    add rsp,8
    pop r9
    pop r8
    pop r10
    pop rdx
    pop rsi
    pop rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    mov rcx,[rsp]
    mov r11,[rsp+16]
    iretq
.bad_return:
    and rsp,-16
    call linux64_invalid_return

section .bss
alignb 16
user_rsp: resq 1
alignb 16
kernel_stack: resb 16384
kernel_stack_end:

section .note.GNU-stack noalloc noexec nowrite progbits
