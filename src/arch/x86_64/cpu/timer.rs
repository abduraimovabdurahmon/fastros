//! PIT 8253/8254 — Programmable Interval Timer
//!
//! PIT oscillates at 1,193,182 Hz.
//! We configure Channel 0 (connected to IRQ 0) for periodic mode.
//!
//! Formula: divisor = 1_193_182 / desired_hz
//! At 100 Hz → divisor = 11931 → tick every 10 ms.

use crate::arch::x86_64::io::outb;

const PIT_CHANNEL0: u16 = 0x40;
const PIT_CMD:      u16 = 0x43;
const PIT_HZ:       u32 = 1_193_182;

/// Configure PIT for `hz` ticks per second and enable IRQ 0.
pub fn init(hz: u32) {
    let divisor = (PIT_HZ / hz) as u16;

    unsafe {
        // Command: channel 0, lo/hi byte access, mode 2 (rate generator), binary
        outb(PIT_CMD, 0x34);
        // Divisor low byte then high byte
        outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
        outb(PIT_CHANNEL0, (divisor >> 8) as u8);
    }
}

/// Global kernel tick counter — incremented by the timer IRQ handler.
/// Wraps at u64::MAX (~584 years at 100 Hz).
pub static mut TICK_COUNT: u64 = 0;

/// Called from the IRQ 0 handler (timer interrupt).
#[inline]
pub fn on_tick() {
    unsafe { TICK_COUNT = TICK_COUNT.wrapping_add(1); }
}

/// Read the current tick count.
#[inline]
pub fn ticks() -> u64 {
    unsafe { TICK_COUNT }
}
