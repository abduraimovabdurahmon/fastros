ENTRY(_start)

SECTIONS {
    /* Load at 1 MB - standard for bare metal x86 kernels */
    . = 1M;

    /* Multiboot2 header must appear within first 32 KB of the file */
    .boot :
    {
        KEEP(*(.multiboot_header))
    }

    .text :
    {
        *(.text .text.*)
    }

    .rodata :
    {
        *(.rodata .rodata.*)
    }

    .data :
    {
        *(.data .data.*)
    }

    .bss :
    {
        *(.bss .bss.*)
        *(COMMON)
    }
}
