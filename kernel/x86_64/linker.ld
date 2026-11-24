ENTRY(_start)

PHDRS {
    code PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS {
    . = 0x100000;
    .text : { KEEP(*(.text.entry)) *(.text .text.*) } :code
    . = ALIGN(0x1000);
    __text_end = .;
    .rodata : { *(.rodata .rodata.*) } :code
    . = ALIGN(0x1000);
    __rodata_end = .;
    .data : { *(.data .data.*) } :data
    .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
    __kernel_end = .;
    ASSERT(_start == 0x100000, "x86-64 entry must match the UEFI load address")
    ASSERT(__kernel_end <= 0x1000000, "x86-64 image exceeds the UEFI kernel arena")
    /DISCARD/ : { *(.comment) *(.eh_frame*) *(.note*) }
}
