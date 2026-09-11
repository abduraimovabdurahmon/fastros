//! Calendar conversions needed by the formats (all UTC).

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// (year, month 1-12, day 1-31) for days since the epoch.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// MS-DOS (date, time) for a Unix time; clamped to 1980-01-01..2107-12-31.
pub fn unix_to_dos(t: i64) -> (u16, u16) {
    let min = days_from_civil(1980, 1, 1) * 86_400;
    let max = days_from_civil(2107, 12, 31) * 86_400 + 86_399;
    let t = t.clamp(min, max);
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let date = (((y - 1980) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let time = ((secs / 3600) as u16) << 11 | (((secs / 60) % 60) as u16) << 5 | ((secs % 60) / 2) as u16;
    (date, time)
}

/// Unix time of an MS-DOS (date, time); invalid fields are clamped.
pub fn dos_to_unix(date: u16, time: u16) -> i64 {
    let y = 1980 + (date >> 9) as i64;
    let m = ((date >> 5) & 0xF).clamp(1, 12) as u32;
    let d = (date & 0x1F).max(1) as u32;
    let h = ((time >> 11) & 0x1F).min(23) as i64;
    let mi = ((time >> 5) & 0x3F).min(59) as i64;
    let s = ((time & 0x1F) * 2).min(59) as i64;
    days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip() {
        for z in [-800_000i64, -1, 0, 1, 10_957, 20_707, 2_932_896] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        assert_eq!(days_from_civil(2026, 9, 11), 20_707);
    }

    #[test]
    fn dos_time() {
        // 2026-09-11 07:14:06 UTC
        let t = days_from_civil(2026, 9, 11) * 86_400 + 7 * 3600 + 14 * 60 + 6;
        let (d, tm) = unix_to_dos(t);
        assert_eq!(dos_to_unix(d, tm), t);
        // Odd seconds round down to the 2-second resolution.
        assert_eq!(dos_to_unix(d, unix_to_dos(t + 1).1), t);
        // Before 1980 clamps.
        assert_eq!(dos_to_unix(unix_to_dos(0).0, unix_to_dos(0).1), days_from_civil(1980, 1, 1) * 86_400);
    }
}
