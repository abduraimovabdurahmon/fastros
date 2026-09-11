//! CMOS real-time clock: wall-clock time at boot.

use super::port::{inb, outb};

fn read(reg: u8) -> u8 {
    unsafe {
        outb(0x70, 0x80 | reg); // bit 7: keep NMI disabled while selecting
        inb(0x71)
    }
}

fn updating() -> bool {
    read(0x0A) & 0x80 != 0
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Raw {
    sec: u8,
    min: u8,
    hour: u8,
    day: u8,
    mon: u8,
    year: u8,
    century: u8,
}

fn snapshot() -> Raw {
    while updating() {
        core::hint::spin_loop();
    }
    Raw { sec: read(0), min: read(2), hour: read(4), day: read(7), mon: read(8), year: read(9), century: read(0x32) }
}

/// Seconds since the Unix epoch, read twice until two reads agree.
pub fn unix_time() -> u64 {
    let mut a = snapshot();
    loop {
        let b = snapshot();
        if a == b {
            break;
        }
        a = b;
    }
    let status_b = read(0x0B);
    let bcd = status_b & 0x04 == 0;
    let h24 = status_b & 0x02 != 0;
    let conv = |v: u8| if bcd { (v & 0x0F) + (v >> 4) * 10 } else { v };
    let sec = conv(a.sec) as u64;
    let min = conv(a.min) as u64;
    let pm = a.hour & 0x80 != 0;
    let mut hour = conv(a.hour & 0x7F) as u64;
    if !h24 {
        hour %= 12;
        if pm {
            hour += 12;
        }
    }
    let day = conv(a.day) as u64;
    let mon = conv(a.mon) as u64;
    let century = if a.century != 0 && a.century != 0xFF { conv(a.century) as u64 } else { 20 };
    let year = century * 100 + conv(a.year) as u64;
    crate::time::civil::days_from_civil(year as i64, mon as u32, day as u32) as u64 * 86400
        + hour * 3600
        + min * 60
        + sec
}
