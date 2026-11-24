[bits 64]
default rel

section .text
global linux64_syscall_entry
extern linux64_task_syscall
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
    push rax
    push qword [rsp+15*8]       ; r11: пользовательские флаги
    push qword [rsp+14*8]       ; rcx: пользовательский RIP
    ; Планировщик может заменить весь кадр перед возвратом в ring 3.
    mov rdi,rsp
    call linux64_task_syscall
.restore_frame:
    pop rcx
    pop r11
    pop rax
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
    iretq
.bad_return:
    and rsp,-16
    call linux64_invalid_return

global linux64_task_resume
linux64_task_resume:
    mov rsp,rdi
    jmp linux64_syscall_entry.restore_frame

section .bss
alignb 16
user_rsp: resq 1
alignb 16
kernel_stack: resb 16384
kernel_stack_end:

section .note.GNU-stack noalloc noexec nowrite progbits
