//! Global Descriptor Table and Task State Segment.
//!
//! Selector layout is the one `SYSCALL`/`SYSRET` require (STAR[63:48] = 0x18
//! makes SYSRET load CS = 0x28|3 and SS = 0x20|3):
//!
//! | selector | descriptor                         |
//! |----------|------------------------------------|
//! | 0x00     | null                               |
//! | 0x08     | kernel code (64-bit)               |
//! | 0x10     | kernel data                        |
//! | 0x18     | user code (32-bit, unused)         |
//! | 0x20     | user data                          |
//! | 0x28     | user code (64-bit)                 |
//! | 0x30     | TSS (16-byte system descriptor)    |
//!
//! The TSS supplies RSP0 (kernel stack for ring 3 → ring 0 transitions) and
//! three interrupt stacks: #DF, NMI and #MC always run on a known-good stack,
//! so even a kernel stack overflow produces a readable report.

use core::mem::size_of;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x20 | 3;
pub const USER_CS: u16 = 0x28 | 3;
pub const TSS_SEL: u16 = 0x30;
/// STAR[63:48]: base for SYSRET selector computation.
pub const SYSRET_BASE: u16 = 0x18 | 3;

pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;

const IST_STACK_SIZE: usize = 16 * 1024;

#[repr(C, packed(4))]
pub struct Tss {
    _r0: u32,
    pub rsp: [u64; 3],
    _r1: u64,
    pub ist: [u64; 7],
    _r2: u64,
    _r3: u16,
    pub iomap_base: u16,
}

#[repr(C, align(16))]
struct IstStacks([[u8; IST_STACK_SIZE]; 3]);

static mut IST_STACKS: IstStacks = IstStacks([[0; IST_STACK_SIZE]; 3]);

static mut TSS: Tss = Tss {
    _r0: 0,
    rsp: [0; 3],
    _r1: 0,
    ist: [0; 7],
    _r2: 0,
    _r3: 0,
    // No I/O permission bitmap: user mode can never touch ports.
    iomap_base: size_of::<Tss>() as u16,
};

static mut GDT: [u64; 8] = [
    0,
    0x00AF_9A00_0000_FFFF, // kernel code: P, DPL0, code, readable, L
    0x00CF_9200_0000_FFFF, // kernel data: P, DPL0, writable
    0x00CF_FA00_0000_FFFF, // user code 32 (placeholder for SYSRET layout)
    0x00CF_F200_0000_FFFF, // user data: P, DPL3, writable
    0x00AF_FA00_0000_FFFF, // user code 64: P, DPL3, L
    0,                     // TSS low
    0,                     // TSS high
];

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

pub fn init() {
    unsafe {
        let stacks = &raw mut IST_STACKS;
        // Packed fields cannot be borrowed: copy the array out and back.
        let mut ist = TSS.ist;
        for (i, slot) in ist.iter_mut().take(3).enumerate() {
            *slot = ((*stacks).0[i].as_ptr() as u64 + IST_STACK_SIZE as u64) & !15;
        }
        TSS.ist = ist;
        let tss = &raw const TSS as u64;
        let limit = (size_of::<Tss>() - 1) as u64;
        GDT[6] = (limit & 0xFFFF)
            | ((tss & 0xFF_FFFF) << 16)
            | (0x89 << 40) // present, 64-bit available TSS
            | (((limit >> 16) & 0xF) << 48)
            | (((tss >> 24) & 0xFF) << 56);
        GDT[7] = tss >> 32;

        let ptr = Pointer { limit: (size_of::<[u64; 8]>() - 1) as u16, base: &raw const GDT as u64 };
        core::arch::asm!(
            "lgdt [{ptr}]",
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov {tmp:x}, {ds}",
            "mov ds, {tmp:x}",
            "mov es, {tmp:x}",
            "mov ss, {tmp:x}",
            "xor {tmp:e}, {tmp:e}",
            "mov fs, {tmp:x}",
            "mov gs, {tmp:x}",
            "ltr {tss:x}",
            ptr = in(reg) &ptr,
            cs = const KERNEL_CS as u64,
            ds = const KERNEL_DS as u64,
            tss = in(reg) TSS_SEL as u64,
            tmp = out(reg) _,
        );
    }
}

/// Kernel stack used when the CPU enters ring 0 from ring 3.
pub fn set_kernel_stack(top: u64) {
    unsafe {
        let mut rsp = TSS.rsp;
        rsp[0] = top;
        TSS.rsp = rsp;
    }
}
