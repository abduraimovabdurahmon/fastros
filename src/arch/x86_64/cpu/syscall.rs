//! SYSCALL / SYSRET — x86_64 fast system call mechanism
//!
//! Faster than `int 0x80` — no privilege-level stack switch via TSS.
//! SYSCALL saves RIP→RCX, RFLAGS→R11, loads kernel CS+SS from MSR_STAR.
//! SYSRET restores them on return.
//!
//! MSRs used:
//!   EFER   (0xC000_0080) — bit 0 (SCE) enables SYSCALL
//!   STAR   (0xC000_0081) — [63:48]=user CS/SS, [47:32]=kernel CS/SS
//!   LSTAR  (0xC000_0082) — 64-bit handler address (our syscall_entry)
//!   SFMASK (0xC000_0084) — RFLAGS bits to clear on SYSCALL (we clear IF)

use crate::arch::x86_64::cpu::msr::{rdmsr, wrmsr, registers};
use crate::arch::x86_64::boot::gdt::{KERNEL_CODE_SEL, KERNEL_DATA_SEL,
                                      USER_CODE_SEL, USER_DATA_SEL};

extern "C" {
    /// Assembly SYSCALL entry point in boot.s.
    fn syscall_entry();
}

/// Enable SYSCALL instruction and point LSTAR at our assembly entry stub.
pub fn init() {
    unsafe {
        // Enable SCE bit in EFER
        let efer = rdmsr(registers::EFER);
        wrmsr(registers::EFER, efer | 1);

        // STAR layout:
        //   [47:32] = kernel CS (SYSCALL loads this into CS, CS+8 into SS)
        //   [63:48] = user CS-16 (SYSRET loads this+16 into CS, this+8 into SS)
        // Kernel: CS=0x08 (KERNEL_CODE_SEL), SS=0x10 (KERNEL_DATA_SEL = CS+8)  ✓
        // User:   CS=0x23 (USER_CODE_SEL), SS=0x1B (USER_DATA_SEL)
        //         SYSRET loads (star[63:48]+16) into CS → need star[63:48]=0x13 ? No.
        //         Actually: SYSRETQ loads star[63:48] into CS, star[63:48]+8 into SS.
        //         user CS=0x23 → star[63:48] must be 0x23? No, SYSRETQ adds 16 to get CS.
        //         Star[63:48] = USER_CODE_SEL - 16 = 0x23 - 0x10 = 0x13.
        //         Then SYSRETQ CS = 0x13 + 16 = 0x23 ✓, SS = 0x13 + 8 = 0x1B ✓
        let star: u64 = ((KERNEL_CODE_SEL as u64) << 32)
            | (((USER_CODE_SEL as u64) - 16) << 48);
        wrmsr(registers::STAR, star);

        // LSTAR: handler address
        wrmsr(registers::LSTAR, syscall_entry as u64);

        // SFMASK: clear IF (bit 9) on SYSCALL so interrupts are disabled in kernel
        wrmsr(registers::SFMASK, 1 << 9);
    }

    let _ = KERNEL_DATA_SEL; // suppress unused import
    let _ = USER_DATA_SEL;
}
