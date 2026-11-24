ENTRY(boot_video_policy)
SECTIONS {
    . = 0xc000;
    .text : { *(.entry) *(.text*) *(.rodata*) }
    /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
}
