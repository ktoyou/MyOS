[bits 64]
section .rodata

global ring3_stack_start, ring3_stack_end
ring3_stack_start:
    push qword 0x12345678
    pop rax
    cmp eax,0x12345678
    jne .bad_stack
    ud2
.bad_stack:
    hlt
ring3_stack_end:

global ring3_kernel_start, ring3_kernel_end
ring3_kernel_start:
    mov eax,0x100000
    mov al,[rax]
    hlt
ring3_kernel_end:

global ring3_nx_start, ring3_nx_end
ring3_nx_start:
    push qword 0xc3
    jmp rsp
ring3_nx_end:

global ring3_write_start, ring3_write_end
ring3_write_start:
    mov eax,0x400000
    mov byte [rax],0x90
    hlt
ring3_write_end:

section .note.GNU-stack noalloc noexec nowrite progbits
