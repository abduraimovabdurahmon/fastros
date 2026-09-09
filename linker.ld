ENTRY(_start)

PHDRS {
    boot PT_LOAD  FLAGS(5);   /* r-x: code + read-only */
    data PT_LOAD  FLAGS(6);   /* rw-: writable data    */
    note PT_NOTE  FLAGS(0);   /* PVH ELF note for QEMU */
}

SECTIONS {
    /* Load at 1 MB — standard for bare metal x86 kernels */
    . = 1M;

    /* Multiboot2 header must appear within first 32 KB of the file */
    .boot : { KEEP(*(.multiboot_header)) } :boot

    /* PVH note — emitted in PT_NOTE segment so QEMU can find it */
    .note.Xen : { KEEP(*(.note.Xen)) } :note :boot

    .text   : { *(.text .text.*)     } :boot
    .rodata : { *(.rodata .rodata.*) } :boot

    .data   : { *(.data .data.*)     } :data
    .bss    : { *(.bss .bss.*) *(COMMON) } :data
}
