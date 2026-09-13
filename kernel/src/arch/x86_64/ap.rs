//! Application-processor bringup (SMP step 3).
//!
//! Each AP starts (via SIPI) in 16-bit real mode at a page-aligned physical
//! address below 1 MiB. This trampoline takes it real → protected → long mode on
//! the *live* kernel page tables, then calls [`ap_entry`]. For now an AP only
//! marks itself online and parks (`cli; hlt`) — it does no scheduling and takes
//! no interrupts, so it cannot perturb the running system. Putting APs to work
//! (per-CPU GDT/IDT/TSS, an SMP scheduler, TLB-shootdown IPIs) is the next step.
//!
//! The trampoline runs at a fixed physical address, so every memory reference is
//! written as `TRAMP_PA + (label - ap_tramp_start)` (build-time constants) and
//! the entry point, CR3 and stack are read from a parameter block the BSP fills.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Where the trampoline is copied and where SIPI vectors the AP (page 8).
pub const TRAMP_PA: usize = 0x8000;
pub const SIPI_VECTOR: u8 = (TRAMP_PA >> 12) as u8;

/// Count of APs that have reached [`ap_entry`].
pub static ONLINE: AtomicUsize = AtomicUsize::new(0);

core::arch::global_asm!(
    r#"
    .set TRAMP, 0x8000
    .section .text.ap_tramp, "ax"
    .code16
    .global ap_tramp_start
ap_tramp_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movb $1, (TRAMP + (ap_status - ap_tramp_start))
    lgdtl (TRAMP + (gdt32_ptr - ap_tramp_start))
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $(TRAMP + (ap_pm32 - ap_tramp_start))

    .code32
ap_pm32:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movb $2, (TRAMP + (ap_status - ap_tramp_start))
    /* CR4: PAE | PGE */
    movl %cr4, %eax
    orl $0xA0, %eax
    movl %eax, %cr4
    /* CR3 = live kernel PML4 (from the parameter block) */
    movl (TRAMP + (ap_cr3 - ap_tramp_start)), %eax
    movl %eax, %cr3
    /* EFER: LME | SCE | NXE */
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x901, %eax
    wrmsr
    /* CR0: PG | WP | MP | PE */
    movl %cr0, %eax
    orl $0x80010003, %eax
    movl %eax, %cr0
    movb $3, (TRAMP + (ap_status - ap_tramp_start))
    lgdtl (TRAMP + (gdt64_ptr - ap_tramp_start))
    ljmpl $0x08, $(TRAMP + (ap_lm64 - ap_tramp_start))

    .code64
ap_lm64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs
    movb $4, (TRAMP + (ap_status - ap_tramp_start))
    movq (TRAMP + (ap_stack - ap_tramp_start)), %rsp
    movq (TRAMP + (ap_entry - ap_tramp_start)), %rax
    callq *%rax
1:  hlt
    jmp 1b

    .balign 16
gdt32:
    .quad 0
    .quad 0x00CF9A000000FFFF    /* 32-bit code */
    .quad 0x00CF92000000FFFF    /* 32-bit data */
gdt32_end:
gdt32_ptr:
    .word gdt32_end - gdt32 - 1
    .long TRAMP + (gdt32 - ap_tramp_start)
    .balign 16
gdt64:
    .quad 0
    .quad 0x00AF9A000000FFFF    /* 64-bit code */
    .quad 0x00CF92000000FFFF    /* data */
gdt64_end:
gdt64_ptr:
    .word gdt64_end - gdt64 - 1
    .quad TRAMP + (gdt64 - ap_tramp_start)
    .balign 8
    .global ap_cr3
ap_cr3:    .quad 0
    .global ap_stack
ap_stack:  .quad 0
    .global ap_entry
ap_entry:  .quad 0
    .global ap_status
ap_status: .byte 0
    .global ap_tramp_end
ap_tramp_end:
"#,
    options(att_syntax)
);

extern "C" {
    static ap_tramp_start: u8;
    static ap_tramp_end: u8;
    static ap_cr3: u8;
    static ap_stack: u8;
    static ap_entry: u8;
    static ap_status: u8;
}

/// Offset of a trampoline label within the copied page.
fn off(sym: &u8) -> usize {
    (sym as *const u8 as usize) - (unsafe { &ap_tramp_start } as *const u8 as usize)
}

/// Physical address inside the copied trampoline for a label.
fn tramp_field(sym: &u8) -> usize {
    crate::mm::phys_to_virt((TRAMP_PA + off(sym)) as u64)
}

/// Copy the trampoline to its fixed low physical page and set the parameter
/// block (live CR3, the AP's stack, and the entry point).
pub fn install(cr3: u64, stack_top: u64) {
    unsafe {
        let start = &ap_tramp_start as *const u8;
        let len = (&ap_tramp_end as *const u8 as usize) - (start as usize);
        let dst = crate::mm::phys_to_virt(TRAMP_PA as u64) as *mut u8;
        core::ptr::copy_nonoverlapping(start, dst, len);
        core::ptr::write_volatile(tramp_field(&ap_cr3) as *mut u64, cr3);
        core::ptr::write_volatile(tramp_field(&ap_stack) as *mut u64, stack_top);
        core::ptr::write_volatile(tramp_field(&ap_entry) as *mut u64, ap_entry_rust as usize as u64);
        core::ptr::write_volatile(tramp_field(&ap_status) as *mut u8, 0);
    }
}

/// The trampoline's progress marker (1..=4 through the mode switches; the AP
/// sets it past that once it reaches Rust). For bringup diagnostics.
pub fn status() -> u8 {
    unsafe { core::ptr::read_volatile(tramp_field(&ap_status) as *const u8) }
}

/// First Rust code on an application processor. Minimal and self-contained: mark
/// online, then park with interrupts disabled (no scheduling, no interrupts yet).
extern "C" fn ap_entry_rust() -> ! {
    unsafe { core::ptr::write_volatile(tramp_field(&ap_status) as *mut u8, 9) };
    ONLINE.fetch_add(1, Ordering::SeqCst);
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
