//! 32-bit PVH entry → 64-bit higher-half kernel.
//!
//! QEMU (`-kernel fastros`) finds `XEN_ELFNOTE_PHYS32_ENTRY` and enters
//! `_pvh_start` in 32-bit protected mode with paging off and `ebx` holding the
//! physical address of the `hvm_start_info` structure.
//!
//! The stub builds throw-away page tables that map the first 4 GiB three
//! times — identity (so the stub survives enabling paging), at the direct-map
//! base `0xFFFF_8000_0000_0000`, and the first 2 GiB at `KERNEL_VMA` — enables
//! long mode (with NX when the CPU has it) and jumps to `kernel_main` in the
//! higher half. `mm::init` later replaces these tables with the final ones.

core::arch::global_asm!(
    r#"
    .set KERNEL_VMA, 0xFFFFFFFF80000000

    .section .note.Xen, "a"
    .balign 4
    .long 4                     /* namesz */
    .long 4                     /* descsz */
    .long 18                    /* XEN_ELFNOTE_PHYS32_ENTRY */
    .asciz "Xen"
    .long _pvh_start

    .section .boot.bss, "aw", @nobits
    .balign 4096
boot_pml4:      .skip 4096
boot_pdpt_low:  .skip 4096
boot_pdpt_high: .skip 4096
boot_pd:        .skip 4096 * 4
boot_stack:     .skip 4096
boot_stack_top:

    .section .boot.data, "aw"
    .balign 16
boot_gdt:
    .quad 0
    .quad 0x00AF9A000000FFFF    /* 0x08: 64-bit kernel code */
    .quad 0x00CF92000000FFFF    /* 0x10: kernel data */
boot_gdt_end:
boot_gdt_ptr:
    .word boot_gdt_end - boot_gdt - 1
    .long boot_gdt
    .balign 8
    .global boot_start_info
boot_start_info: .quad 0

    .section .boot.text, "ax"
    .code32
    .global _pvh_start
_pvh_start:
    cli
    cld
    mov esp, offset boot_stack_top
    mov dword ptr [boot_start_info], ebx

    /* Long mode is mandatory; remember EDX of leaf 0x80000001 for NX. */
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb 9f
    mov eax, 0x80000001
    cpuid
    test edx, (1 << 29)
    jz 9f
    mov esi, edx

    /* 2048 x 2 MiB = 4 GiB, present + writable + huge. */
    xor ecx, ecx
1:
    mov eax, ecx
    shl eax, 21
    or eax, 0x83
    mov dword ptr [boot_pd + ecx * 8], eax
    mov dword ptr [boot_pd + ecx * 8 + 4], 0
    inc ecx
    cmp ecx, 2048
    jne 1b

    mov eax, offset boot_pd
    or eax, 3
    mov dword ptr [boot_pdpt_low + 0], eax
    mov dword ptr [boot_pdpt_high + 510 * 8], eax
    add eax, 4096
    mov dword ptr [boot_pdpt_low + 8], eax
    mov dword ptr [boot_pdpt_high + 511 * 8], eax
    add eax, 4096
    mov dword ptr [boot_pdpt_low + 16], eax
    add eax, 4096
    mov dword ptr [boot_pdpt_low + 24], eax

    mov eax, offset boot_pdpt_low
    or eax, 3
    mov dword ptr [boot_pml4 + 0], eax          /* identity */
    mov dword ptr [boot_pml4 + 256 * 8], eax    /* direct map */
    mov eax, offset boot_pdpt_high
    or eax, 3
    mov dword ptr [boot_pml4 + 511 * 8], eax    /* kernel image */

    /* CR4: PAE | PGE */
    mov eax, cr4
    or eax, (1 << 5) | (1 << 7)
    mov cr4, eax
    mov eax, offset boot_pml4
    mov cr3, eax

    /* EFER: LME | SCE, plus NXE when supported. */
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8) | (1 << 0)
    test esi, (1 << 20)
    jz 2f
    or eax, (1 << 11)
2:
    wrmsr

    /* CR0: PE | MP | WP | PG */
    mov eax, cr0
    or eax, (1 << 31) | (1 << 16) | (1 << 1) | 1
    mov cr0, eax

    lgdt [boot_gdt_ptr]
    push 0x08
    mov eax, offset boot_long_mode
    push eax
    retf

9:  /* No long mode: "NOLM" on the first VGA line, then stop. */
    mov dword ptr [0xB8000], 0x4F4F4F4E
    mov dword ptr [0xB8004], 0x4F4D4F4C
8:  hlt
    jmp 8b

    .code64
boot_long_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov rax, offset boot_high
    jmp rax

    .section .text.boot_high, "ax"
    .code64
boot_high:
    mov rsp, offset kernel_boot_stack_top
    xor ebp, ebp
    mov rax, offset boot_start_info
    mov edi, dword ptr [rax]
    call kernel_main
    ud2

    .section .bss.kernel_boot_stack, "aw", @nobits
    .balign 4096
    .global kernel_boot_stack_bottom
kernel_boot_stack_bottom:
    .skip 65536
    .global kernel_boot_stack_top
kernel_boot_stack_top:
"#
);

extern "C" {
    static kernel_boot_stack_bottom: u8;
    static kernel_boot_stack_top: u8;
}

/// Bounds of the boot stack, which becomes the idle task's stack.
pub fn boot_stack() -> (usize, usize) {
    unsafe {
        (
            core::ptr::addr_of!(kernel_boot_stack_bottom) as usize,
            core::ptr::addr_of!(kernel_boot_stack_top) as usize,
        )
    }
}
