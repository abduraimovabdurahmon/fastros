//! Timekeeping: scheduler tick, monotonic clock (TSC), wall clock (RTC).

use crate::arch::{cpu, pit, rtc};
use core::sync::atomic::{AtomicU64, Ordering};

/// Scheduler tick frequency.
pub const HZ: u32 = 250;
pub const NS_PER_TICK: u64 = 1_000_000_000 / HZ as u64;

static JIFFIES: AtomicU64 = AtomicU64::new(0);
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_BASE: AtomicU64 = AtomicU64::new(0);
/// Unix time (ns) corresponding to monotonic 0.
static EPOCH_OFFSET_NS: AtomicU64 = AtomicU64::new(0);

/// Calibrate the TSC against the PIT and read the RTC. Interrupts may be off.
pub fn init() {
    let t0 = cpu::rdtsc();
    if pit::busy_wait_ms(50) {
        let t1 = cpu::rdtsc();
        let hz = (t1 - t0) * 20;
        if hz > 1_000_000 {
            TSC_HZ.store(hz, Ordering::Relaxed);
        }
    }
    TSC_BASE.store(cpu::rdtsc(), Ordering::Relaxed);
    let unix = rtc::unix_time();
    EPOCH_OFFSET_NS.store(unix * 1_000_000_000, Ordering::Relaxed);
}

pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

/// Called from the timer IRQ.
pub fn tick() {
    JIFFIES.fetch_add(1, Ordering::Relaxed);
}

pub fn jiffies() -> u64 {
    JIFFIES.load(Ordering::Relaxed)
}

/// Nanoseconds since boot (monotonic).
pub fn now_ns() -> u64 {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    if hz == 0 {
        return JIFFIES.load(Ordering::Relaxed) * NS_PER_TICK;
    }
    let delta = cpu::rdtsc().wrapping_sub(TSC_BASE.load(Ordering::Relaxed));
    ((delta as u128 * 1_000_000_000) / hz as u128) as u64
}

pub fn uptime_secs() -> u64 {
    now_ns() / 1_000_000_000
}

/// Wall-clock time as (seconds, nanoseconds) since the Unix epoch.
pub fn wall_clock() -> (u64, u32) {
    let ns = EPOCH_OFFSET_NS.load(Ordering::Relaxed) + now_ns();
    (ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
}

pub fn unix_now() -> u64 {
    wall_clock().0
}

/// Set the wall clock (e.g. `date -s`).
pub fn set_wall_clock(unix_secs: u64) {
    let now = now_ns();
    EPOCH_OFFSET_NS.store((unix_secs * 1_000_000_000).saturating_sub(now), Ordering::Relaxed);
}

/// Proleptic Gregorian calendar conversions (Howard Hinnant's algorithms).
pub mod civil {
    /// Days since 1970-01-01 for a civil date.
    pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = (m as i64 + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    }

    /// Civil date (year, month 1-12, day 1-31) for days since 1970-01-01.
    pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        (if m <= 2 { y + 1 } else { y }, m, d)
    }

    /// Broken-down UTC time.
    #[derive(Clone, Copy, Debug)]
    pub struct Tm {
        pub year: i64,
        pub month: u32,
        pub day: u32,
        pub hour: u32,
        pub min: u32,
        pub sec: u32,
        /// 0 = Sunday
        pub weekday: u32,
        /// 0-based day of the year
        pub yday: u32,
    }

    pub fn from_unix(t: i64) -> Tm {
        let days = t.div_euclid(86400);
        let rem = t.rem_euclid(86400) as u32;
        let (year, month, day) = civil_from_days(days);
        let weekday = (days + 4).rem_euclid(7) as u32;
        let yday = (days - days_from_civil(year, 1, 1)) as u32;
        Tm { year, month, day, hour: rem / 3600, min: rem % 3600 / 60, sec: rem % 60, weekday, yday }
    }

    pub const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    pub const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
}
