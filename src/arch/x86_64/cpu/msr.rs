//! Model Specific Registers (MSR)
//!
//! Used for SYSCALL/SYSRET setup, EFER (long mode), APIC base, etc.

/// Read a 64-bit MSR.
///
/// # Safety
/// The MSR number must be valid on the current CPU.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a 64-bit MSR.
///
/// # Safety
/// The MSR number and value must be valid on the current CPU.
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
    );
}

/// Well-known MSR addresses.
pub mod registers {
    pub const EFER:     u32 = 0xC000_0080;
    pub const STAR:     u32 = 0xC000_0081; // SYSCALL segment selectors
    pub const LSTAR:    u32 = 0xC000_0082; // SYSCALL 64-bit handler address
    pub const SFMASK:   u32 = 0xC000_0084; // SYSCALL RFLAGS mask
    pub const APIC_BASE: u32 = 0x0000_001B;
    pub const FS_BASE:  u32 = 0xC000_0100;
    pub const GS_BASE:  u32 = 0xC000_0101;
}
