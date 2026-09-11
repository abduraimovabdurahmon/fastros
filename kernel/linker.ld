/*
 * FastROS kernel layout.
 *
 * The boot stub (.boot.*) runs at its physical address (1 MiB) in 32-bit mode,
 * builds the early page tables and jumps to the kernel proper, which is linked
 * in the top 2 GiB of the address space (code-model=kernel) and loaded right
 * after the stub: virtual = physical + KERNEL_VMA.
 *
 * Every section of the kernel proper is page aligned so the final page tables
 * can map text read-only+executable, rodata read-only+NX and data NX.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_pvh_start)

KERNEL_PHYS = 0x100000;
KERNEL_VMA  = 0xFFFFFFFF80000000;

PHDRS {
    boot   PT_LOAD FLAGS(7);
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
    note   PT_NOTE FLAGS(4);
}

SECTIONS {
    . = KERNEL_PHYS;
    __boot_start = .;
    .boot.text : { KEEP(*(.boot.text)) } :boot
    .boot.data : { KEEP(*(.boot.data)) } :boot
    .boot.bss (NOLOAD) : { *(.boot.bss) } :boot
    . = ALIGN(4096);
    __boot_end = .;

    . += KERNEL_VMA;

    .text ALIGN(4096) : AT(ADDR(.text) - KERNEL_VMA) {
        __text_start = .;
        *(.text .text.*)
        . = ALIGN(4096);
        __text_end = .;
    } :text

    .rodata ALIGN(4096) : AT(ADDR(.rodata) - KERNEL_VMA) {
        __rodata_start = .;
        *(.rodata .rodata.*)
    } :rodata
    .note.Xen : AT(ADDR(.note.Xen) - KERNEL_VMA) { KEEP(*(.note.Xen)) } :rodata :note
    .rodata.end : AT(ADDR(.rodata.end) - KERNEL_VMA) {
        . = ALIGN(4096);
        __rodata_end = .;
    } :rodata

    .data ALIGN(4096) : AT(ADDR(.data) - KERNEL_VMA) {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
    } :data
    .bss : AT(ADDR(.bss) - KERNEL_VMA) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);
        __bss_end = .;
    } :data
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment .note.GNU-stack .note.gnu.* )
    }
}
