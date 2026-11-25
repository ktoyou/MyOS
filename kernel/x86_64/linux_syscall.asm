[bits 64]
default rel

section .text
global linux64_syscall_entry
extern linux64_task_syscall
extern linux64_invalid_return
extern linux64_user_rflags
extern linux64_task_timer
extern linux64_timer_ack

%macro push_context 0
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
%endmacro

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

    ; До исполнения системного вызова проверяем исходные RIP и RSP.
    shr rcx,47
    jnz .bad_return
    mov rcx,[rsp+24]
    shr rcx,47
    jnz .bad_return
    push_context
    push qword [rsp+15*8]       ; r11: пользовательские флаги
    push qword [rsp+14*8]       ; rcx: пользовательский RIP
    ; Планировщик может заменить весь кадр перед возвратом в ring 3.
    mov rdi,rsp
    call linux64_task_syscall
.restore_frame:
    mov rax,[linux64_user_rflags]
    or [rsp+17*8],rax
.restore_registers:
    ; IRQ захватывает RSP даже у кода, который никогда не вызывал ядро.
    test byte [rsp+16*8],3
    jz .pop_registers
    mov rax,[rsp+15*8]
    shr rax,47
    jnz .bad_return
    mov rax,[rsp+18*8]
    shr rax,47
    jnz .bad_return
.pop_registers:
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
    cld
    and rsp,-16
    call linux64_invalid_return

global linux64_task_resume
linux64_task_resume:
    mov rsp,rdi
    jmp linux64_syscall_entry.restore_frame

global linux64_timer_entry
linux64_timer_entry:
    test byte [rsp+8],3
    jz linux64_external_irq_entry
    ; В отличие от SYSCALL, IRQ сохраняет исходные RCX и R11.
    push_context
    push r11
    push rcx
    cld
    mov rdi,rsp
    call linux64_task_timer
    jmp linux64_syscall_entry.restore_frame

global linux64_external_irq_entry
linux64_external_irq_entry:
    push_context
    push r11
    push rcx
    cld
    mov rbx,rsp
    and rsp,-16
    call linux64_timer_ack
    mov rsp,rbx
    jmp linux64_syscall_entry.restore_registers

global linux64_spurious_entry
linux64_spurious_entry:
    test byte [rsp+8],3
    jz .kernel
    push_context
    push r11
    push rcx
    jmp linux64_syscall_entry.restore_registers
.kernel:
    iretq

section .bss
alignb 16
user_rsp: resq 1
alignb 16
; На одном стеке остаются пути renameat и вложенные буферы MyFS.
kernel_stack: resb 32768
kernel_stack_end:

section .note.GNU-stack noalloc noexec nowrite progbits
