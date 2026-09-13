//! Local APIC: the per-CPU interrupt controller and preemption timer.
//!
//! Step 2 of SMP enables the boot CPU's local APIC and drives the scheduler tick
//! from its timer instead of the legacy PIT. The legacy 8259 PIC is *kept* for
//! external interrupts (keyboard, NIC, disk, RTC): the LAPIC's LINT0 is set to
//! ExtINT (virtual-wire mode) so those still reach the CPU. This avoids the
//! riskier IO-APIC re-routing while giving every CPU its own local timer — the
//! prerequisite for preempting application processors once they come online.

use crate::mm::phys_to_virt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// IDT vector the LAPIC timer fires on (outside the PIC range, below spurious).
pub const TIMER_VECTOR: u8 = 0xEC;

// LAPIC register offsets (memory-mapped at the LAPIC base).
const SVR: usize = 0x0F0; // Spurious Interrupt Vector Register
const EOI: usize = 0x0B0; // End Of Interrupt
const LVT_TIMER: usize = 0x320;
const LVT_LINT0: usize = 0x350;
const LVT_LINT1: usize = 0x360;
const TIMER_INIT: usize = 0x380; // initial count
const TIMER_CUR: usize = 0x390; // current count
const TIMER_DIV: usize = 0x3E0; // divide configuration
const LVT_MASKED: u32 = 1 << 16;
const TIMER_PERIODIC: u32 = 1 << 17;

/// LAPIC MMIO base (virtual, through the uncached direct map); 0 = disabled.
static LAPIC: AtomicUsize = AtomicUsize::new(0);

fn base() -> usize {
    LAPIC.load(Ordering::Relaxed)
}

unsafe fn read(reg: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base() + reg) as *const u32) }
}

unsafe fn write(reg: usize, v: u32) {
    unsafe { core::ptr::write_volatile((base() + reg) as *mut u32, v) }
}

/// Signal end-of-interrupt to the local APIC (for LAPIC-delivered interrupts,
/// e.g. the timer — distinct from the PIC's EOI for legacy lines).
pub fn eoi() {
    if base() != 0 {
        unsafe { write(EOI, 0) };
    }
}

pub fn enabled() -> bool {
    base() != 0
}

/// Bring up the boot CPU's local APIC and start its periodic timer at `hz`.
/// Returns false (caller keeps the PIT tick) if there is no LAPIC or the timer
/// could not be calibrated.
pub fn init_bsp(hz: u32) -> bool {
    let paddr = crate::smp::topology().map(|t| t.lapic_addr).filter(|&a| a != 0).unwrap_or(0xFEE0_0000);
    let vaddr = phys_to_virt(paddr);
    LAPIC.store(vaddr, Ordering::Relaxed);

    unsafe {
        // Software-enable the LAPIC with a spurious vector.
        write(SVR, 0xFF | 0x100);
        // Keep legacy 8259 interrupts flowing to this CPU (virtual-wire mode):
        // LINT0 delivers ExtINT (the PIC), LINT1 is NMI.
        write(LVT_LINT0, 0x700);
        write(LVT_LINT1, 0x400);

        // Calibrate the timer against the PIT: count down from max for a known
        // interval and see how far it got.
        write(TIMER_DIV, 0x3); // divide bus clock by 16
        write(LVT_TIMER, LVT_MASKED);
        write(TIMER_INIT, 0xFFFF_FFFF);
        let ok = crate::arch::pit::busy_wait_ms(50);
        let elapsed = 0xFFFF_FFFFu32.wrapping_sub(read(TIMER_CUR));
        write(TIMER_INIT, 0); // stop
        if !ok || elapsed < 10_000 {
            LAPIC.store(0, Ordering::Relaxed);
            return false;
        }
        let ticks_per_sec = elapsed as u64 * 20; // 50 ms window → ×20
        let count = (ticks_per_sec / hz as u64).max(1) as u32;

        // Arm the periodic timer on our dedicated vector.
        write(LVT_TIMER, TIMER_VECTOR as u32 | TIMER_PERIODIC);
        write(TIMER_INIT, count);
    }
    true
}
