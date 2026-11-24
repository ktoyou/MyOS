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
    je phdr_ok
    cmp dword ptr [rdx],6
    jne fail
phdr_ok:
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
    jne random
    lea rcx,[rip+_start]
    cmp rdx,rcx
    jne fail
    or r12d,4
    jmp aux
random:
    cmp eax,25
    jne aux
    test r12d,32
    jnz fail
    mov r13,rdx
    or r12d,32
    jmp aux
aux_done:
    cmp r12d,63
    jne fail
    cmp r13,rbx
    jb fail
    lea rdx,[r13+16]
    cmp rdx,[rsp+8]
    ja fail
    mov r8,[r13]
    mov r9,[r13+8]
    cmp byte ptr [rip+data_byte],0x5a
    jne fail
    cmp byte ptr [rip+buffer+4095],0
    jne fail
    cmp byte ptr [rip+buffer+8191],0
    jne fail

    call check_fs

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

check_fs:
    lea rsi,[rip+buffer+4093]
    mov qword ptr [rsi],-1
    mov eax,158
    mov edi,0x1003
    syscall
    test rax,rax
    jne fs_fail
    cmp qword ptr [rsi],0
    jne fs_fail

    mov ax,ss
    mov fs,ax
    lea rsi,[rip+tls_data]
    mov r12,rsi
    mov eax,158
    mov edi,0x1002
    syscall
    test rax,rax
    jne fs_fail
    mov ax,fs
    test ax,ax
    jne fs_fail
    cmp dword ptr fs:[0],0x1234abcd
    jne fs_fail

    mov eax,158
    mov edi,0x1002
    mov rsi,0xffff800000000000
    syscall
    cmp rax,-1
    jne fs_fail
    cmp dword ptr fs:[0],0x1234abcd
    jne fs_fail

    mov eax,158
    mov edi,0x1003
    lea rsi,[rip+message]
    syscall
    cmp rax,-14
    jne fs_fail
    lea rsi,[rip+buffer+8191]
    mov byte ptr [rsi],0x5a
    mov eax,158
    mov edi,0x1003
    syscall
    cmp rax,-14
    jne fs_fail
    cmp byte ptr [rsi],0x5a
    jne fs_fail
    mov eax,158
    mov edi,0x1003
    lea rsi,[rip+buffer+4093]
    syscall
    test rax,rax
    jne fs_fail
    cmp qword ptr [rsi],r12
    jne fs_fail
    mov dword ptr fs:[4],0x4321dcba
    cmp dword ptr [rip+tls_data+4],0x4321dcba
    jne fs_fail

    mov eax,158
    mov edi,0x1002
    mov esi,3
    syscall
    test rax,rax
    jne fs_fail
    mov eax,158
    mov edi,0x1003
    lea rsi,[rip+buffer+4093]
    syscall
    test rax,rax
    jne fs_fail
    cmp qword ptr [rsi],3
    jne fs_fail
    mov eax,158
    mov edi,0x1002
    xor esi,esi
    syscall
    test rax,rax
    jne fs_fail
    ret
fs_fail:
    mov eax,60
    mov edi,13
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
.balign 8
tls_data: .long 0x1234abcd, 0
.section .bss
.balign 4096
buffer: .skip 8192
.section .note.GNU-stack,"",@progbits
