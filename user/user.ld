/* Раскладка программы MyOS: код с адреса 0x40000000 (начало памяти программ),
 * данные — с новой страницы, чтобы у кода и данных были разные права. */
ENTRY(_start)

PHDRS {
    text PT_LOAD FLAGS(5);      /* R-X: только чтение и выполнение */
    data PT_LOAD FLAGS(6);      /* RW-: чтение и запись */
    tls  PT_TLS  FLAGS(4);
}

SECTIONS {
    . = 0x40000000;
    .text   : { KEEP(*(.text.start)) *(.text*) } :text
    .rodata : { *(.rodata*) }              :text

    . = ALIGN(4096);
    .data   : { *(.data*) }                :data
    .tdata  : { *(.tdata .tdata.*) }       :data :tls
    .tbss   : { *(.tbss .tbss.*) }         :data :tls
    .bss    : { *(.bss*) *(COMMON) }       :data

    /DISCARD/ : { *(.comment) *(.eh_frame*) *(.note*) }
}
