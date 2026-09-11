//! 8254 Programmable Interval Timer: channel 0 drives the scheduler tick,
//! channel 2 (gated, speaker off) is a one-shot reference for TSC calibration.

use super::port::{inb, outb};

pub const PIT_HZ: u64 = 1_193_182;

pub fn start_periodic(hz: u32) {
    let div = (PIT_HZ / hz as u64).clamp(1, 0xFFFF) as u16;
    unsafe {
        outb(0x43, 0x34); // ch0, lo/hi, mode 2 (rate generator)
        outb(0x40, div as u8);
        outb(0x40, (div >> 8) as u8);
    }
}

/// Busy-wait `ms` milliseconds on channel 2 (interrupt-free, used before the
/// scheduler tick exists). Returns false if the channel never counted down.
pub fn busy_wait_ms(ms: u16) -> bool {
    let count = (PIT_HZ * ms as u64 / 1000).min(0xFFFF) as u16;
    unsafe {
        let gate = inb(0x61);
        outb(0x61, (gate & !0x02) | 0x01); // gate on, speaker off
        outb(0x43, 0xB0); // ch2, lo/hi, mode 0 (interrupt on terminal count)
        outb(0x42, count as u8);
        outb(0x42, (count >> 8) as u8);
        // Restart the count by toggling the gate.
        let g = inb(0x61);
        outb(0x61, g & !0x01);
        outb(0x61, g | 0x01);
        let mut spins: u64 = 0;
        while inb(0x61) & 0x20 == 0 {
            spins += 1;
            if spins > 200_000_000 {
                return false;
            }
            core::hint::spin_loop();
        }
        outb(0x61, gate);
    }
    true
}
