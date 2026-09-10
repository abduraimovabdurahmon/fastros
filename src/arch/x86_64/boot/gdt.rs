//! Global Descriptor Table (GDT) + Task State Segment (TSS)
//!
//! GDT layout (index → selector):
//!   0 → 0x00  Null descriptor
//!   1 → 0x08  Kernel Code  (ring 0, 64-bit)
//!   2 → 0x10  Kernel Data  (ring 0)
//!   3 → 0x18  User Data    (ring 3)
//!   4 → 0x20  User Code    (ring 3, 64-bit)
//!   5 → 0x28  TSS low      (64-bit TSS, 2 × 8-byte entries)
//!   6 → 0x30  TSS high
//!
//! TSS is required for:
//!   - rsp0: kernel stack on ring3→ring0 transition (interrupts/syscalls)
//!   - IST:  dedicated stacks for NMI, double fault, etc.

use core::mem::size_of;

pub const KERNEL_CODE_SEL: u16 = 0x08;
pub const KERNEL_DATA_SEL: u16 = 0x10;
pub const USER_DATA_SEL:   u16 = 0x1B; // 0x18 | 3
pub const USER_CODE_SEL:   u16 = 0x23; // 0x20 | 3
pub const TSS_SEL:         u16 = 0x28;

/// Hardcoded 64-bit descriptor values for standard segments.
/// Format: [base_high|flags|limit_high|access|base_mid|base_low|limit_low]
const GDT_NULL:        u64 = 0x0000_0000_0000_0000;
const GDT_KERNEL_CODE: u64 = 0x00AF_9A00_0000_FFFF; // P,DPL=0,S,X,R,G,L
const GDT_KERNEL_DATA: u64 = 0x00CF_9200_0000_FFFF; // P,DPL=0,S,W,G,D/B
const GDT_USER_DATA:   u64 = 0x00CF_F200_0000_FFFF; // P,DPL=3,S,W,G,D/B
const GDT_USER_CODE:   u64 = 0x00AF_FA00_0000_FFFF; // P,DPL=3,S,X,R,G,L

/// Task State Segment — one per CPU core.
#[repr(C, packed)]
pub struct Tss {
    _reserved0: u32,
    /// Kernel stack pointers for privilege level transitions.
    pub rsp: [u64; 3],
    _reserved1: u64,
    /// Interrupt Stack Table — dedicated stacks for critical exceptions.
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// Offset of I/O permission bitmap from TSS base.  Point past TSS → no I/O bitmap.
    pub iobase: u16,
}

impl Tss {
    pub const fn new() -> Self {
        Self {
            _reserved0: 0,
            rsp: [0; 3],
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iobase: size_of::<Tss>() as u16,
        }
    }
}

/// GDT: 7 entries (null + 4 segments + 2 for TSS).
static mut GDT: [u64; 7] = [0; 7];
pub static mut TSS: Tss = Tss::new();

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base:  u64,
}

/// Build the 2 × 64-bit TSS descriptor from the TSS address and size.
fn make_tss_descriptor(addr: u64, limit: u16) -> (u64, u64) {
    let lim = limit as u64;
    let lo = (lim & 0xFFFF)
        | ((addr & 0xFFFF) << 16)
        | (((addr >> 16) & 0xFF) << 32)
        | (0x89u64 << 40)                       // P=1, DPL=0, Type=9 (available 64-bit TSS)
        | (((lim >> 16) & 0xF) << 48)
        | (((addr >> 24) & 0xFF) << 56);
    let hi = addr >> 32;
    (lo, hi)
}

/// Install the final GDT and TSS, then reload all segment registers.
pub fn load() {
    unsafe {
        GDT[0] = GDT_NULL;
        GDT[1] = GDT_KERNEL_CODE;
        GDT[2] = GDT_KERNEL_DATA;
        GDT[3] = GDT_USER_DATA;
        GDT[4] = GDT_USER_CODE;

        let tss_addr  = &TSS as *const Tss as u64;
        let tss_limit = (size_of::<Tss>() - 1) as u16;
        let (tss_lo, tss_hi) = make_tss_descriptor(tss_addr, tss_limit);
        GDT[5] = tss_lo;
        GDT[6] = tss_hi;

        let ptr = GdtPtr {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base:  GDT.as_ptr() as u64,
        };

        core::arch::asm!(
            // Load new GDT
            "lgdt [{ptr}]",
            // Far-return trick: push CS:RIP pair then retfq → reloads CS
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            // Reload data segment registers (16 = KERNEL_DATA_SEL = 0x10)
            "mov ax, {ds}",
            "mov ss, ax",
            "mov ds, ax",
            "mov es, ax",
            // FS and GS = 0 (will be used for per-CPU data later)
            "xor ax, ax",
            "mov fs, ax",
            "mov gs, ax",
            ptr = in(reg) &ptr,
            cs  = const KERNEL_CODE_SEL as u64,
            tmp = lateout(reg) _,
            ds  = const KERNEL_DATA_SEL as u64,
            lateout("ax") _,
            options(nostack),
        );

        // Load TSS
        core::arch::asm!("ltr ax", in("ax") TSS_SEL, options(nostack));
    }
}

/// Update RSP0 in TSS — called on every context switch.
/// RSP0 is the kernel stack pointer loaded when an interrupt/syscall fires
/// while running in user mode (ring 3 → ring 0 transition).
pub unsafe fn set_kernel_stack(rsp0: u64) {
    TSS.rsp[0] = rsp0;
}
