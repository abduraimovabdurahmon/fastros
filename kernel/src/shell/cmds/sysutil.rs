//! System administration and information commands: date, df, mount, umount,
//! lsblk, dmesg, id, whoami, groups, hostname, tty, stty, lscpu, lspci,
//! sysctl, shutdown/reboot/poweroff/halt, wall.

use super::fmtutil;
use crate::errno::Errno;
use crate::fs::mount::MountFlags;
use crate::fs::ops;
use crate::shell::ctx::{human, parse_opts, Ctx, OptSpec};
use crate::time::civil;
use crate::{out, outln};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

fn usage_err(ctx: &mut Ctx, e: String) -> i32 {
    ctx.fail(e);
    let s = alloc::format!("Try '{} --help' for more information.\n", ctx.name());
    ctx.eprint(&s);
    1
}

// ── date ───────────────────────────────────────────────────────────────────

const LONG_DAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const LONG_MONTHS: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/// ISO 8601 week-based (year, week) of a date.
fn iso_week(tm: &civil::Tm) -> (i64, u32) {
    let wday = (tm.weekday + 6) % 7; // Monday = 0
    let yday = tm.yday as i64;
    let mut year = tm.year;
    let mut week = (yday - wday as i64 + 10) / 7;
    let weeks_in = |y: i64| -> i64 {
        let jan1 = (civil::days_from_civil(y, 1, 1) + 4).rem_euclid(7); // 0 = Sunday
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        if jan1 == 4 || (leap && jan1 == 3) {
            53
        } else {
            52
        }
    };
    if week < 1 {
        year -= 1;
        week = weeks_in(year);
    } else if week > weeks_in(year) {
        year += 1;
        week = 1;
    }
    (year, week as u32)
}

/// `strftime` for UTC times, GNU `date` flavour (`%-d`, `%_H`, `%^a`,
/// `%N`, `%s`, `%:z`...).
pub fn strftime(fmt: &str, t: i64, nanos: u32) -> String {
    let tm = civil::from_unix(t);
    let mut out = String::new();
    let c: Vec<char> = fmt.chars().collect();
    let mut i = 0;
    while i < c.len() {
        if c[i] != '%' || i + 1 >= c.len() {
            out.push(c[i]);
            i += 1;
            continue;
        }
        i += 1;
        // Flags: `-` no padding, `_` space padding, `0` zero padding, `^` upper case.
        let mut pad: Option<char> = None;
        let mut upper = false;
        while i < c.len() && matches!(c[i], '-' | '_' | '0' | '^' | '#') {
            match c[i] {
                '-' => pad = Some('\0'),
                '_' => pad = Some(' '),
                '0' => pad = Some('0'),
                '^' => upper = true,
                _ => {}
            }
            i += 1;
        }
        let mut width = 0usize;
        while i < c.len() && c[i].is_ascii_digit() {
            width = width * 10 + c[i].to_digit(10).unwrap_or(0) as usize;
            i += 1;
        }
        let mut colons = 0;
        while i < c.len() && c[i] == ':' {
            colons += 1;
            i += 1;
        }
        if i >= c.len() {
            out.push('%');
            break;
        }
        let conv = c[i];
        i += 1;
        let num = |v: i64, w: usize, default_pad: char| -> String {
            let p = pad.unwrap_or(default_pad);
            let w = if width > 0 { width } else { w };
            match p {
                '\0' => v.to_string(),
                ' ' => alloc::format!("{v:>w$}"),
                _ => alloc::format!("{v:0>w$}"),
            }
        };
        let hour12 = if tm.hour % 12 == 0 { 12 } else { tm.hour % 12 } as i64;
        let s: String = match conv {
            'a' => civil::WEEKDAYS[tm.weekday as usize].to_string(),
            'A' => LONG_DAYS[tm.weekday as usize].to_string(),
            'b' | 'h' => civil::MONTHS[(tm.month - 1) as usize].to_string(),
            'B' => LONG_MONTHS[(tm.month - 1) as usize].to_string(),
            'c' => strftime("%a %b %e %H:%M:%S %Y", t, nanos),
            'C' => num(tm.year / 100, 2, '0'),
            'd' => num(tm.day as i64, 2, '0'),
            'D' => strftime("%m/%d/%y", t, nanos),
            'e' => num(tm.day as i64, 2, ' '),
            'F' => strftime("%Y-%m-%d", t, nanos),
            'g' => num(iso_week(&tm).0 % 100, 2, '0'),
            'G' => num(iso_week(&tm).0, 4, '0'),
            'H' => num(tm.hour as i64, 2, '0'),
            'I' => num(hour12, 2, '0'),
            'j' => num(tm.yday as i64 + 1, 3, '0'),
            'k' => num(tm.hour as i64, 2, ' '),
            'l' => num(hour12, 2, ' '),
            'm' => num(tm.month as i64, 2, '0'),
            'M' => num(tm.min as i64, 2, '0'),
            'n' => String::from("\n"),
            'N' => {
                let digits = if width > 0 { width.min(9) } else { 9 };
                let s = alloc::format!("{nanos:09}");
                s[..digits].to_string()
            }
            'p' => String::from(if tm.hour < 12 { "AM" } else { "PM" }),
            'P' => String::from(if tm.hour < 12 { "am" } else { "pm" }),
            'r' => strftime("%I:%M:%S %p", t, nanos),
            'R' => strftime("%H:%M", t, nanos),
            's' => t.to_string(),
            'S' => num(tm.sec as i64, 2, '0'),
            't' => String::from("\t"),
            'T' => strftime("%H:%M:%S", t, nanos),
            'u' => (if tm.weekday == 0 { 7 } else { tm.weekday }).to_string(),
            'U' => num(((tm.yday + 7 - tm.weekday) / 7) as i64, 2, '0'),
            'V' => num(iso_week(&tm).1 as i64, 2, '0'),
            'w' => tm.weekday.to_string(),
            'W' => num(((tm.yday + 7 - (tm.weekday + 6) % 7) / 7) as i64, 2, '0'),
            'x' => strftime("%m/%d/%y", t, nanos),
            'X' => strftime("%H:%M:%S", t, nanos),
            'y' => num(tm.year % 100, 2, '0'),
            'Y' => num(tm.year, 0, '0'),
            'z' => match colons {
                0 => String::from("+0000"),
                1 => String::from("+00:00"),
                _ => String::from("+00:00:00"),
            },
            'Z' => String::from("UTC"),
            '%' => String::from("%"),
            other => alloc::format!("%{other}"),
        };
        if upper {
            out.push_str(&s.to_uppercase());
        } else {
            out.push_str(&s);
        }
    }
    out
}

/// Parse `date -d` strings: `@EPOCH`, `now`, `today`, `yesterday`,
/// `tomorrow`, `YYYY-MM-DD[ T]HH:MM[:SS]`, `HH:MM[:SS]`, `N unit[s] [ago]`,
/// `+N unit`, and combinations like `2026-09-11 +1 day`.
fn parse_date(s: &str, now: i64) -> Option<i64> {
    let s = s.trim();
    if let Some(e) = s.strip_prefix('@') {
        return e.parse().ok();
    }
    let lower = s.to_ascii_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let mut t = now;
    let mut i = 0;
    let midnight = |t: i64| t - t.rem_euclid(86400);
    while i < words.len() {
        let w = words[i];
        match w {
            "now" => {}
            "today" => t = midnight(t) + t.rem_euclid(86400),
            "yesterday" => t -= 86400,
            "tomorrow" => t += 86400,
            "midnight" => t = midnight(t),
            "noon" => t = midnight(t) + 12 * 3600,
            "utc" | "z" | "gmt" => {}
            _ => {
                // Date and/or time.
                let (date_part, time_part) = match w.split_once('t') {
                    Some((d, tt)) if d.contains('-') => (Some(d), Some(tt)),
                    _ if w.contains('-') && w.len() >= 8 => (Some(w), None),
                    _ if w.contains(':') => (None, Some(w)),
                    _ => (None, None),
                };
                if date_part.is_some() || time_part.is_some() {
                    let mut day_start = midnight(t);
                    if let Some(d) = date_part {
                        let f: Vec<&str> = d.split('-').collect();
                        if f.len() != 3 {
                            return None;
                        }
                        let (y, m, dd) = (f[0].parse::<i64>().ok()?, f[1].parse::<u32>().ok()?, f[2].parse::<u32>().ok()?);
                        if !(1..=12).contains(&m) || !(1..=31).contains(&dd) {
                            return None;
                        }
                        day_start = civil::days_from_civil(y, m, dd) * 86400;
                        t = day_start;
                    }
                    let tp = time_part.or_else(|| words.get(i + 1).filter(|x| x.contains(':')).map(|x| {
                        i += 1;
                        *x
                    }));
                    if let Some(tt) = tp {
                        let tt = tt.trim_end_matches('z');
                        let f: Vec<&str> = tt.split(':').collect();
                        let h: i64 = f.first()?.parse().ok()?;
                        let m: i64 = f.get(1).map(|x| x.parse().ok()).unwrap_or(Some(0))?;
                        let sec: i64 = f.get(2).map(|x| x.split('.').next().unwrap_or("0").parse().ok()).unwrap_or(Some(0))?;
                        if h > 23 || m > 59 || sec > 60 {
                            return None;
                        }
                        t = day_start + h * 3600 + m * 60 + sec;
                    }
                } else {
                    // Relative: `[+-]N unit[s] [ago]`, `next unit`, `last unit`.
                    let (n, unit_idx) = match w {
                        "next" => (1i64, i + 1),
                        "last" => (-1i64, i + 1),
                        _ => match w.trim_start_matches('+').parse::<i64>() {
                            Ok(n) => (n, i + 1),
                            Err(_) => (1, i),
                        },
                    };
                    let unit = words.get(unit_idx)?.trim_end_matches('s');
                    let secs = match unit {
                        "sec" | "second" => 1,
                        "min" | "minute" => 60,
                        "hour" => 3600,
                        "day" => 86400,
                        "week" => 7 * 86400,
                        "fortnight" => 14 * 86400,
                        "month" => 30 * 86400,
                        "year" => 365 * 86400,
                        _ => return None,
                    };
                    let mut delta = n * secs;
                    i = unit_idx;
                    if words.get(i + 1) == Some(&"ago") {
                        delta = -delta;
                        i += 1;
                    }
                    t += delta;
                }
            }
        }
        i += 1;
    }
    Some(t)
}

pub fn date(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "uRr",
        values: "dsIrf",
        long: &[
            ("utc", 'u', false),
            ("universal", 'u', false),
            ("date", 'd', true),
            ("set", 's', true),
            ("rfc-email", 'R', false),
            ("rfc-2822", 'R', false),
            ("reference", 'r', true),
            ("iso-8601", 'I', true),
            ("rfc-3339", 'T', true),
            ("file", 'f', true),
        ],
    };
    // `-I` takes an optional attached value: normalize `-I` to `-Idate`.
    let args: Vec<String> = ctx.args.iter().map(|a| if a == "-I" || a == "--iso-8601" { String::from("-Idate") } else { a.clone() }).collect();
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    let (now_s, now_ns) = crate::time::wall_clock();
    let mut t = now_s as i64;
    let mut nanos = now_ns;
    if let Some(d) = p.value('d') {
        match parse_date(d, t) {
            Some(v) => {
                t = v;
                nanos = 0;
            }
            None => return ctx.fail(alloc::format!("invalid date '{d}'")),
        }
    }
    if let Some(f) = p.value('r') {
        match ops::stat(&ctx.fs(), f, true) {
            Ok(m) => {
                t = m.mtime.sec;
                nanos = m.mtime.nsec;
            }
            Err(e) => return ctx.fail_errno(f, e),
        }
    }
    if let Some(s) = p.value('s') {
        if !ctx.cred().is_root() {
            return ctx.fail("cannot set date: Operation not permitted");
        }
        match parse_date(s, t) {
            Some(v) if v >= 0 => {
                crate::time::set_wall_clock(v as u64);
                crate::knotice!("time", "clock set to {} by uid {}", v, ctx.cred().uid);
                t = v;
                nanos = 0;
            }
            _ => return ctx.fail(alloc::format!("invalid date '{s}'")),
        }
    }
    let fmt = if let Some(f) = p.operands.first() {
        match f.strip_prefix('+') {
            Some(f) => f.to_string(),
            None => return ctx.fail(alloc::format!("invalid date '{f}'")),
        }
    } else if p.has('R') {
        String::from("%a, %d %b %Y %H:%M:%S %z")
    } else if let Some(i) = p.value('I') {
        match i {
            "date" => String::from("%Y-%m-%d"),
            "hours" => String::from("%Y-%m-%dT%H%:z"),
            "minutes" => String::from("%Y-%m-%dT%H:%M%:z"),
            "seconds" => String::from("%Y-%m-%dT%H:%M:%S%:z"),
            "ns" => String::from("%Y-%m-%dT%H:%M:%S,%N%:z"),
            _ => return ctx.fail(alloc::format!("invalid argument '{i}' for '--iso-8601'")),
        }
    } else if let Some(i) = p.value('T') {
        match i {
            "date" => String::from("%Y-%m-%d"),
            "seconds" => String::from("%Y-%m-%d %H:%M:%S%:z"),
            "ns" => String::from("%Y-%m-%d %H:%M:%S.%N%:z"),
            _ => return ctx.fail(alloc::format!("invalid argument '{i}' for '--rfc-3339'")),
        }
    } else {
        String::from("%a %b %e %H:%M:%S %Z %Y")
    };
    let s = strftime(&fmt, t, nanos);
    outln!(ctx, "{s}");
    0
}

// ── df ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum SizeMode {
    Kib,
    Human,
    Si,
    Block(u64),
}

fn df_size(bytes: u64, mode: SizeMode) -> String {
    match mode {
        SizeMode::Kib => bytes.div_ceil(1024).to_string(),
        SizeMode::Block(b) => bytes.div_ceil(b).to_string(),
        SizeMode::Human => {
            if bytes == 0 {
                String::from("0")
            } else {
                human(bytes)
            }
        }
        SizeMode::Si => {
            let units = ["", "k", "M", "G", "T", "P"];
            let mut v = bytes;
            let mut u = 0;
            let mut rem = 0;
            while v >= 1000 && u < units.len() - 1 {
                rem = v % 1000;
                v /= 1000;
                u += 1;
            }
            if u > 0 && v < 10 {
                let tenths = (v * 10 + rem.div_ceil(100)).max(1);
                alloc::format!("{}.{}{}", tenths / 10, tenths % 10, units[u])
            } else {
                alloc::format!("{}{}", v + (rem > 0) as u64, units[u])
            }
        }
    }
}

/// Filesystems `df` hides without `-a` (no blocks: pseudo filesystems).
fn is_dummy(fs_type: &str) -> bool {
    matches!(fs_type, "proc" | "sysfs" | "binfs" | "devpts" | "cgroup" | "cgroup2" | "securityfs" | "debugfs")
}

pub fn df(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "ahHikmlPTx",
        values: "Btx",
        long: &[
            ("all", 'a', false),
            ("human-readable", 'h', false),
            ("si", 'H', false),
            ("inodes", 'i', false),
            ("local", 'l', false),
            ("portability", 'P', false),
            ("print-type", 'T', false),
            ("type", 't', true),
            ("exclude-type", 'x', true),
            ("block-size", 'B', true),
            ("total", 'o', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    let mode = if p.has('h') {
        SizeMode::Human
    } else if p.has('H') {
        SizeMode::Si
    } else if p.has('m') {
        SizeMode::Block(1 << 20)
    } else if let Some(b) = p.value('B') {
        match fmtutil::parse_size(b) {
            Some(n) if n > 0 => SizeMode::Block(n),
            _ => return ctx.fail(alloc::format!("invalid --block-size argument '{b}'")),
        }
    } else {
        SizeMode::Kib
    };
    let inodes = p.has('i');
    let ns = ctx.proc.fs.lock().ns.clone();
    let mut mounts = ns.list();
    // Operands: the filesystem containing each file.
    if !p.operands.is_empty() {
        let mut picked = Vec::new();
        for f in p.operands.clone() {
            match ops::statfs(&ctx.fs(), &f) {
                Ok((_, at)) => {
                    let id = at.mount.id;
                    if let Some(m) = mounts.iter().find(|(_, m)| m.id == id) {
                        picked.push(m.clone());
                    }
                }
                Err(e) => {
                    ctx.fail_errno(&f, e);
                }
            }
        }
        mounts = picked;
        if mounts.is_empty() {
            return 1;
        }
    }
    let size_header = match mode {
        SizeMode::Human | SizeMode::Si => String::from("Size"),
        SizeMode::Kib => String::from(if p.has('P') { "1024-blocks" } else { "1K-blocks" }),
        SizeMode::Block(b) if b == 1 << 20 => String::from("1M-blocks"),
        SizeMode::Block(b) => alloc::format!("{}-blocks", fmtutil::human_block_size(b)),
    };
    let mut header: Vec<String> = alloc::vec![String::from("Filesystem")];
    if p.has('T') {
        header.push(String::from("Type"));
    }
    if inodes {
        header.extend(["Inodes", "IUsed", "IFree", "IUse%"].map(String::from));
    } else {
        header.push(size_header);
        header.push(String::from("Used"));
        header.push(String::from(if p.has('P') { "Available" } else { "Avail" }).replace("Avail", if matches!(mode, SizeMode::Human | SizeMode::Si) { "Avail" } else { "Available" }));
        header.push(String::from(if p.has('P') { "Capacity" } else { "Use%" }));
    }
    header.push(String::from("Mounted on"));
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut seen_all = p.has('a');
    let (mut tot_size, mut tot_used, mut tot_avail) = (0u64, 0u64, 0u64);
    let types: Vec<&String> = p.values('t').iter().collect();
    let excl: Vec<&String> = p.values('x').iter().collect();
    for (path, m) in &mounts {
        let ty = m.fs.fs_type();
        if !types.is_empty() && !types.iter().any(|t| *t == ty) {
            continue;
        }
        if excl.iter().any(|t| *t == ty) {
            continue;
        }
        let st = m.fs.statfs();
        if !seen_all && p.operands.is_empty() && (is_dummy(ty) || st.blocks == 0) {
            continue;
        }
        let mut r = alloc::vec![m.source.clone()];
        if p.has('T') {
            r.push(ty.to_string());
        }
        if inodes {
            let used = st.files.saturating_sub(st.files_free);
            let pct = if st.files == 0 { String::from("-") } else { alloc::format!("{}%", (used * 100).div_ceil(st.files)) };
            let fmt_n = |n: u64| match mode {
                SizeMode::Human | SizeMode::Si => {
                    if n < 1000 {
                        n.to_string()
                    } else {
                        human(n * 1024).replace('K', "K").trim_end_matches('B').to_string()
                    }
                }
                _ => n.to_string(),
            };
            r.push(fmt_n(st.files));
            r.push(fmt_n(used));
            r.push(fmt_n(st.files_free));
            r.push(pct);
        } else {
            let bs = st.block_size.max(1);
            let size = st.blocks * bs;
            let used = st.blocks.saturating_sub(st.blocks_free) * bs;
            let avail = st.blocks_avail * bs;
            tot_size += size;
            tot_used += used;
            tot_avail += avail;
            let denom = used + avail;
            let pct = if denom == 0 { String::from("-") } else { alloc::format!("{}%", (used * 100).div_ceil(denom)) };
            r.push(df_size(size, mode));
            r.push(df_size(used, mode));
            r.push(df_size(avail, mode));
            r.push(pct);
        }
        r.push(path.clone());
        rows.push(r);
    }
    seen_all = true;
    let _ = seen_all;
    if ctx.args.iter().any(|a| a == "--total") && !inodes {
        let mut r = alloc::vec![String::from("total")];
        if p.has('T') {
            r.push(String::from("-"));
        }
        let denom = tot_used + tot_avail;
        r.push(df_size(tot_size, mode));
        r.push(df_size(tot_used, mode));
        r.push(df_size(tot_avail, mode));
        r.push(if denom == 0 { String::from("-") } else { alloc::format!("{}%", (tot_used * 100).div_ceil(denom)) });
        r.push(String::from("-"));
        rows.push(r);
    }
    // GNU df: column widths from the widest cell (Filesystem at least 14,
    // numbers at least 5); text left-aligned, numbers right-aligned.
    let ncol = header.len();
    let mut widths = alloc::vec![0usize; ncol];
    for (i, w) in widths.iter_mut().enumerate() {
        // GNU minimums: source 14, type 4, counts 5, percentages 4.
        let min = match header[i].as_str() {
            _ if i == 0 => 14,
            _ if i + 1 == ncol => 0,
            "Type" => 4,
            "Use%" | "IUse%" | "Capacity" => 4,
            _ => 5,
        };
        *w = rows.iter().map(|r| fmtutil::width(&r[i])).chain(core::iter::once(fmtutil::width(&header[i]))).max().unwrap_or(0).max(min);
    }
    let type_col = if p.has('T') { Some(1) } else { None };
    let mut all_rows = alloc::vec![header];
    all_rows.extend(rows);
    for (ri, r) in all_rows.iter().enumerate() {
        let mut line = String::new();
        for (i, cellv) in r.iter().enumerate() {
            if i > 0 {
                line.push(' ');
            }
            let left = i == 0 || Some(i) == type_col || i + 1 == ncol;
            if i + 1 == ncol {
                line.push_str(cellv);
            } else if left {
                line.push_str(&fmtutil::pad_right(cellv, widths[i]));
            } else if ri == 0 && !matches!(cellv.as_str(), "Use%" | "IUse%" | "Capacity") {
                // Headers of numeric columns are right-aligned too (GNU).
                line.push_str(&fmtutil::pad_left(cellv, widths[i]));
            } else {
                line.push_str(&fmtutil::pad_left(cellv, widths[i]));
            }
        }
        outln!(ctx, "{}", line.trim_end());
    }
    0
}

// ── mount / umount ─────────────────────────────────────────────────────────

fn print_mounts(ctx: &mut Ctx, only_type: Option<&str>) {
    let ns = ctx.proc.fs.lock().ns.clone();
    for (path, m) in ns.list() {
        if only_type.is_some_and(|t| t != m.fs.fs_type()) {
            continue;
        }
        outln!(ctx, "{} on {} type {} ({})", m.source, path, m.fs.fs_type(), m.flags.lock().describe());
    }
}

/// `-o` options → (flags, remount, bind, tmpfs size).
fn parse_mount_opts(opts: &str, base: MountFlags) -> Result<(MountFlags, bool, bool, Option<u64>), String> {
    let mut f = base;
    let mut remount = false;
    let mut bind = false;
    let mut size = None;
    for o in opts.split(',').filter(|s| !s.is_empty()) {
        match o {
            "ro" => f.read_only = true,
            "rw" => f.read_only = false,
            "nosuid" => f.nosuid = true,
            "suid" => f.nosuid = false,
            "nodev" => f.nodev = true,
            "dev" => f.nodev = false,
            "noexec" => f.noexec = true,
            "exec" => f.noexec = false,
            "remount" => remount = true,
            "bind" | "rbind" => bind = true,
            "defaults" | "relatime" | "noatime" | "strictatime" | "async" | "sync" | "auto" | "noauto" | "user" | "nouser" => {}
            o if o.starts_with("size=") => {
                let v = &o[5..];
                size = Some(if let Some(pct) = v.strip_suffix('%') {
                    let pct: u64 = pct.parse().map_err(|_| alloc::format!("bad size '{v}'"))?;
                    crate::mm::stats().total_bytes * pct.min(100) / 100
                } else {
                    fmtutil::parse_size(v).ok_or_else(|| alloc::format!("bad size '{v}'"))?
                });
            }
            o if o.starts_with("mode=") || o.starts_with("uid=") || o.starts_with("gid=") || o.starts_with("nr_inodes=") => {}
            o => return Err(alloc::format!("unsupported option '{o}'")),
        }
    }
    Ok((f, remount, bind, size))
}

pub fn mount(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "arwvnfB",
        values: "to",
        long: &[("types", 't', true), ("options", 'o', true), ("read-only", 'r', false), ("rw", 'w', false), ("bind", 'B', false), ("all", 'a', false), ("verbose", 'v', false)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    if p.operands.is_empty() {
        print_mounts(ctx, p.value('t'));
        return 0;
    }
    if !ctx.cred().is_root() {
        return ctx.fail("only root can do that");
    }
    let opts = p.values('o').join(",");
    let base = if p.has('r') { MountFlags::RO } else { MountFlags::RW };
    let (flags, remount, bind, size) = match parse_mount_opts(&opts, base) {
        Ok(v) => v,
        Err(e) => return ctx.fail(e),
    };
    let bind = bind || p.has('B');
    let fs = ctx.fs();
    let ns = ctx.proc.fs.lock().ns.clone();
    if remount {
        let target = p.operands.last().cloned().unwrap_or_default();
        let at = match fs.resolve(&target, true) {
            Ok(a) => a,
            Err(e) => return ctx.fail_errno(&target, e),
        };
        if !Arc::ptr_eq(&at.mount.root, &at.inode) {
            return ctx.fail(alloc::format!("{target}: mount point not mounted or bad option"));
        }
        let mut f = at.mount.flags.lock();
        // Only the options named change on a remount.
        let (nf, _, _, _) = match parse_mount_opts(&opts, *f) {
            Ok(v) => v,
            Err(e) => {
                drop(f);
                return ctx.fail(e);
            }
        };
        *f = nf;
        return 0;
    }
    let (source, target) = match p.operands.as_slice() {
        [s, t] => (s.clone(), t.clone()),
        [t] => {
            return ctx.fail(alloc::format!("{t}: can't find in /etc/fstab."));
        }
        _ => return usage_err(ctx, String::from("bad usage")),
    };
    let at = match fs.resolve(&target, true) {
        Ok(a) => a,
        Err(e) => return ctx.fail(alloc::format!("{target}: mount point does not exist ({e})")),
    };
    if !at.inode.is_dir() {
        return ctx.fail(alloc::format!("{target}: mount point is not a directory"));
    }
    let r = if bind {
        match fs.resolve(&source, true) {
            Ok(src) => ns.bind(&at, &src, flags),
            Err(e) => return ctx.fail(alloc::format!("{source}: special device does not exist ({e})")),
        }
    } else {
        let ty = p.value('t').unwrap_or(if source.starts_with("/dev/") { "ext2" } else { &source }).to_string();
        let new_fs: Arc<dyn crate::fs::FileSystem> = match ty.as_str() {
            "tmpfs" => crate::fs::tmpfs::TmpFs::new(size.unwrap_or(0)),
            "proc" => crate::fs::procfs::ProcFs::new(),
            "sysfs" => crate::sysfs::SysFs::new(),
            "devtmpfs" => crate::fs::devfs::create(),
            "ext2" => {
                let dev = source.strip_prefix("/dev/").unwrap_or(&source);
                let Some(disk) = crate::drivers::block::get(dev) else {
                    return ctx.fail(alloc::format!("{source}: special device does not exist"));
                };
                if ns.list().iter().any(|(_, m)| m.source == source) {
                    return ctx.fail(alloc::format!("{source}: already mounted"));
                }
                let rdev = crate::device::disk_rdev(dev).unwrap_or(0);
                match crate::fs::ext2fs::Ext2Fs::mount(disk, rdev) {
                    crate::fs::ext2fs::Probe::Mounted(f) => {
                        crate::fs::bcache::register_syncable(&(f.clone() as Arc<dyn crate::fs::FileSystem>));
                        f
                    }
                    crate::fs::ext2fs::Probe::NotExt2 => return ctx.fail(alloc::format!("{target}: wrong fs type, bad option, bad superblock on {source}")),
                    crate::fs::ext2fs::Probe::Failed(e) => return ctx.fail(alloc::format!("{source}: {e}")),
                }
            }
            other => return ctx.fail(alloc::format!("unknown filesystem type '{other}'.")),
        };
        ns.mount(&at, new_fs, &source, flags)
    };
    match r {
        Ok(()) => {
            crate::kinfo!("fs", "mounted {} on {} by uid {}", source, target, ctx.cred().uid);
            0
        }
        Err(e) => ctx.fail(alloc::format!("{target}: {e}")),
    }
}

pub fn umount(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "flnrvaR", values: "t", long: &[("force", 'f', false), ("lazy", 'l', false), ("verbose", 'v', false), ("recursive", 'R', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    if p.operands.is_empty() {
        return usage_err(ctx, String::from("bad usage"));
    }
    if !ctx.cred().is_root() {
        return ctx.fail("must be superuser to unmount.");
    }
    let ns = ctx.proc.fs.lock().ns.clone();
    let mut st = 0;
    for t in p.operands.clone() {
        // A device name unmounts where it is mounted.
        let path = match ns.list().into_iter().rev().find(|(_, m)| m.source == t) {
            Some((path, _)) if t.starts_with("/dev/") => path,
            _ => t.clone(),
        };
        let at = match ctx.fs().resolve(&path, true) {
            Ok(a) => a,
            Err(e) => {
                st = ctx.fail(alloc::format!("{t}: {e}"));
                continue;
            }
        };
        match ns.umount(&at) {
            Ok(m) => {
                let _ = m.fs.sync();
                if p.has('v') {
                    outln!(ctx, "umount: {} unmounted", path);
                }
            }
            Err(Errno::EINVAL) => st = ctx.fail(alloc::format!("{t}: not mounted.")),
            Err(Errno::EBUSY) => st = ctx.fail(alloc::format!("{t}: target is busy.")),
            Err(e) => st = ctx.fail(alloc::format!("{t}: {e}")),
        }
    }
    st
}

// ── lsblk ──────────────────────────────────────────────────────────────────

/// lsblk sizes: `8G`, `19.9G`, `512M` (binary units, one decimal if needed).
fn lsblk_size(bytes: u64) -> String {
    let units = ["B", "K", "M", "G", "T", "P"];
    let mut u = 0;
    let mut div = 1u64;
    while bytes / div >= 1024 && u < units.len() - 1 {
        div *= 1024;
        u += 1;
    }
    let tenths = (bytes * 10 + div / 2) / div;
    if tenths % 10 == 0 || u == 0 {
        alloc::format!("{}{}", tenths / 10, units[u])
    } else {
        alloc::format!("{}.{}{}", tenths / 10, tenths % 10, units[u])
    }
}

pub fn lsblk(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "bdfnlaS", values: "o", long: &[("bytes", 'b', false), ("fs", 'f', false), ("noheadings", 'n', false), ("list", 'l', false), ("all", 'a', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    let ns = ctx.proc.fs.lock().ns.clone();
    let mounts = ns.list();
    let mut rows: Vec<[String; 7]> = Vec::new();
    for d in crate::drivers::block::all() {
        let name = d.name().to_string();
        let rdev = crate::device::disk_rdev(&name).unwrap_or(0);
        let src = alloc::format!("/dev/{name}");
        let points: Vec<String> = mounts.iter().filter(|(_, m)| m.source == src).map(|(p, _)| p.clone()).collect();
        let ro = points.first().and_then(|pt| mounts.iter().find(|(p2, _)| p2 == pt)).is_some_and(|(_, m)| m.read_only());
        let bytes = d.sectors() * d.sector_size() as u64;
        rows.push([
            name,
            alloc::format!("{}:{}", crate::fs::major(rdev), crate::fs::minor(rdev)),
            String::from("0"),
            if p.has('b') { bytes.to_string() } else { lsblk_size(bytes) },
            String::from(if ro { "1" } else { "0" }),
            String::from("disk"),
            points.join("\n"),
        ]);
    }
    let header = ["NAME", "MAJ:MIN", "RM", "SIZE", "RO", "TYPE", "MOUNTPOINTS"];
    let w = |i: usize| rows.iter().map(|r| r[i].len()).max().unwrap_or(0).max(header[i].len());
    let (wn, wsz, wt) = (w(0), w(3), w(5));
    // MAJ:MIN is aligned on the colon: major right in 3, minor left in 3.
    let majmin = |s: &str| -> String {
        let (a, b) = s.split_once(':').unwrap_or((s, ""));
        alloc::format!("{a:>3}:{b:<3}")
    };
    if !p.has('n') {
        outln!(ctx, "{:<wn$} {} {:>2} {:>wsz$} {:>2} {:<wt$} {}", header[0], header[1], header[2], header[3], header[4], header[5], header[6]);
    }
    for r in rows {
        let line = alloc::format!("{:<wn$} {} {:>2} {:>wsz$} {:>2} {:<wt$} {}", r[0], majmin(&r[1]), r[2], r[3], r[4], r[5], r[6]);
        outln!(ctx, "{}", line.trim_end());
    }
    0
}

// ── dmesg ──────────────────────────────────────────────────────────────────

const FACILITY_LEVELS: [&str; 8] = ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"];

pub fn dmesg(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "cCTxrkuwWtHL",
        values: "ln",
        long: &[
            ("read-clear", 'c', false),
            ("clear", 'C', false),
            ("ctime", 'T', false),
            ("decode", 'x', false),
            ("raw", 'r', false),
            ("level", 'l', true),
            ("follow", 'w', false),
            ("follow-new", 'W', false),
            ("notime", 't', false),
            ("kernel", 'k', false),
            ("human", 'H', false),
            ("color", 'L', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    // kernel.dmesg_restrict=1: the kernel log is for root only.
    if !ctx.cred().is_root() {
        ctx.eprint("dmesg: read kernel buffer failed: Operation not permitted\n");
        return 1;
    }
    let mut levels: Option<Vec<u8>> = None;
    if let Some(l) = p.value('l') {
        let mut v = Vec::new();
        for name in l.split(',') {
            match FACILITY_LEVELS.iter().position(|x| *x == name) {
                Some(i) => v.push(i as u8),
                None => return ctx.fail(alloc::format!("unknown level '{name}'")),
            }
        }
        levels = Some(v);
    }
    if p.has('C') {
        crate::log::clear();
        return 0;
    }
    let boot = crate::time::unix_now() as i64 - crate::time::uptime_secs() as i64;
    let print = |ctx: &mut Ctx, r: &crate::log::Record| {
        let lvl = r.level as u8;
        if levels.as_ref().is_some_and(|v| !v.contains(&lvl)) {
            return;
        }
        let text = alloc::format!("{}: {}", r.facility, r.text);
        let stamp = if p.has('t') {
            String::new()
        } else if p.has('T') {
            let t = boot + (r.time_ns / 1_000_000_000) as i64;
            alloc::format!("[{}] ", strftime("%a %b %e %H:%M:%S %Y", t, 0))
        } else {
            alloc::format!("[{:5}.{:06}] ", r.time_ns / 1_000_000_000, r.time_ns / 1000 % 1_000_000)
        };
        if p.has('r') {
            outln!(ctx, "<{}>{}{}", lvl, stamp, text);
        } else if p.has('x') {
            outln!(ctx, "kern  :{:<6}: {}{}", FACILITY_LEVELS[lvl as usize & 7], stamp, text);
        } else {
            outln!(ctx, "{}{}", stamp, text);
        }
    };
    let mut last_seq = None;
    if !p.has('W') {
        for r in crate::log::records() {
            print(ctx, &r);
            last_seq = Some(r.seq);
        }
    } else {
        last_seq = crate::log::records().last().map(|r| r.seq);
    }
    if p.has('c') {
        crate::log::clear();
    }
    if p.has('w') || p.has('W') {
        loop {
            if !ctx.sleep_ms(250) {
                return 0;
            }
            for r in crate::log::records() {
                if last_seq.is_none_or(|s| r.seq > s) {
                    print(ctx, &r);
                    last_seq = Some(r.seq);
                }
            }
            if !ctx.flush() {
                return 0;
            }
        }
    }
    0
}

// ── id / whoami / groups ───────────────────────────────────────────────────

pub fn whoami(ctx: &mut Ctx) -> i32 {
    if ctx.args.len() > 1 {
        return usage_err(ctx, alloc::format!("extra operand '{}'", ctx.args[1]));
    }
    let uid = ctx.cred().euid;
    match crate::users::by_uid(uid) {
        Some(u) => {
            outln!(ctx, "{}", u.name);
            0
        }
        None => ctx.fail(alloc::format!("cannot find name for user ID {uid}")),
    }
}

pub fn id(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "ugGnrza", values: "", long: &[("user", 'u', false), ("group", 'g', false), ("groups", 'G', false), ("name", 'n', false), ("real", 'r', false), ("zero", 'z', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    let (uid, euid, gid, egid, mut groups) = match p.operands.first() {
        Some(name) => {
            let u = match name.parse::<u32>().ok().and_then(crate::users::by_uid).or_else(|| crate::users::by_name(name)) {
                Some(u) => u,
                None => return ctx.fail(alloc::format!("'{name}': no such user")),
            };
            let g = crate::users::supplementary(&u.name);
            (u.uid, u.uid, u.gid, u.gid, g)
        }
        None => {
            let c = ctx.cred();
            (c.uid, c.euid, c.gid, c.egid, c.groups.clone())
        }
    };
    // The primary group leads the list, without duplicates.
    groups.retain(|&g| g != egid);
    groups.insert(0, egid);
    let uname = |u: u32| crate::users::by_uid(u).map(|x| x.name);
    let gname = |g: u32| crate::users::group_by_gid(g).map(|x| x.name);
    let sep = if p.has('z') { "\0" } else { " " };
    let end = if p.has('z') { "\0" } else { "\n" };
    if p.has('u') || p.has('g') || p.has('G') {
        let items: Vec<String> = if p.has('u') {
            let u = if p.has('r') { uid } else { euid };
            alloc::vec![if p.has('n') { uname(u).unwrap_or_else(|| u.to_string()) } else { u.to_string() }]
        } else if p.has('g') {
            let g = if p.has('r') { gid } else { egid };
            alloc::vec![if p.has('n') { gname(g).unwrap_or_else(|| g.to_string()) } else { g.to_string() }]
        } else {
            groups.iter().map(|&g| if p.has('n') { gname(g).unwrap_or_else(|| g.to_string()) } else { g.to_string() }).collect()
        };
        out!(ctx, "{}{}", items.join(sep), end);
        return 0;
    }
    let named = |n: u32, name: Option<String>| match name {
        Some(s) => alloc::format!("{n}({s})"),
        None => n.to_string(),
    };
    let mut s = alloc::format!("uid={} gid={}", named(uid, uname(uid)), named(gid, gname(gid)));
    if euid != uid {
        s.push_str(&alloc::format!(" euid={}", named(euid, uname(euid))));
    }
    if egid != gid {
        s.push_str(&alloc::format!(" egid={}", named(egid, gname(egid))));
    }
    let g: Vec<String> = groups.iter().map(|&g| named(g, gname(g))).collect();
    s.push_str(&alloc::format!(" groups={}", g.join(",")));
    outln!(ctx, "{s}");
    0
}

pub fn groups(ctx: &mut Ctx) -> i32 {
    let names: Vec<String> = ctx.args[1..].to_vec();
    let gname = |g: u32| crate::users::group_by_gid(g).map(|x| x.name).unwrap_or_else(|| g.to_string());
    if names.is_empty() {
        let c = ctx.cred();
        let mut gs = c.groups.clone();
        gs.retain(|&g| g != c.egid);
        gs.insert(0, c.egid);
        let v: Vec<String> = gs.into_iter().map(gname).collect();
        outln!(ctx, "{}", v.join(" "));
        return 0;
    }
    let mut st = 0;
    for n in names {
        match crate::users::by_name(&n) {
            Some(u) => {
                let mut gs = crate::users::supplementary(&u.name);
                gs.retain(|&g| g != u.gid);
                gs.insert(0, u.gid);
                let v: Vec<String> = gs.into_iter().map(gname).collect();
                outln!(ctx, "{} : {}", n, v.join(" "));
            }
            None => st = ctx.fail(alloc::format!("'{n}': no such user")),
        }
    }
    st
}

// ── hostname / tty / stty ──────────────────────────────────────────────────

pub fn hostname(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "sfdiIAbF", values: "", long: &[("short", 's', false), ("fqdn", 'f', false), ("long", 'f', false), ("domain", 'd', false), ("ip-address", 'i', false), ("all-ip-addresses", 'I', false), ("boot", 'b', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    let current = ctx.proc.uts.hostname.lock().clone();
    if let Some(new) = p.operands.first().cloned() {
        if !ctx.cred().is_root() {
            return ctx.fail("you must be root to change the host name");
        }
        let valid = !new.is_empty() && new.len() <= 64 && new.split('.').all(|l| !l.is_empty() && !l.starts_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !valid {
            return ctx.fail("the specified hostname is invalid");
        }
        *ctx.proc.uts.hostname.lock() = new.clone();
        if p.has('b') {
            let _ = ops::write_file(&ctx.fs(), "/etc/hostname", alloc::format!("{new}\n").as_bytes(), 0o644);
        }
        return 0;
    }
    if p.has('I') {
        let ips: Vec<String> = crate::net::config().addr.map(|c| c.address().to_string()).into_iter().collect();
        outln!(ctx, "{} ", ips.join(" "));
        return 0;
    }
    if p.has('i') {
        let hosts = ops::read_file(&ctx.fs(), "/etc/hosts").map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
        let ip = hosts.lines().filter(|l| !l.trim_start().starts_with('#')).find_map(|l| {
            let mut f = l.split_whitespace();
            let ip = f.next()?;
            f.any(|n| n == current).then(|| ip.to_string())
        });
        return match ip {
            Some(ip) => {
                outln!(ctx, "{ip}");
                0
            }
            None => ctx.fail("Name or service not known"),
        };
    }
    let short = current.split('.').next().unwrap_or(&current).to_string();
    if p.has('s') {
        outln!(ctx, "{short}");
    } else if p.has('d') {
        outln!(ctx, "{}", current.split_once('.').map(|(_, d)| d).unwrap_or(""));
    } else {
        outln!(ctx, "{current}");
    }
    0
}

pub fn tty(ctx: &mut Ctx) -> i32 {
    let silent = ctx.args.iter().any(|a| a == "-s" || a == "--silent" || a == "--quiet");
    match ctx.stdin_tty() {
        Some(t) => {
            if !silent {
                outln!(ctx, "/dev/{}", t.name);
            }
            0
        }
        None => {
            if !silent {
                outln!(ctx, "not a tty");
            }
            1
        }
    }
}

pub fn stty(ctx: &mut Ctx) -> i32 {
    use crate::tty::consts::*;
    let Some(t) = ctx.stdin_tty() else {
        ctx.eprint("stty: 'standard input': Inappropriate ioctl for device\n");
        return 1;
    };
    let args = ctx.args[1..].to_vec();
    let mut tio = t.termios();
    let ws = t.winsize();
    if args.is_empty() || args[0] == "-a" || args[0] == "--all" {
        let all = !args.is_empty();
        let cc = |i: usize| -> String {
            match tio.cc[i] {
                0 => String::from("<undef>"),
                0x7F => String::from("^?"),
                c if c < 0x20 => alloc::format!("^{}", (c + b'@') as char),
                c => (c as char).to_string(),
            }
        };
        outln!(ctx, "speed 38400 baud; rows {}; columns {}; line = 0;", ws.rows, ws.cols);
        if all {
            outln!(ctx, "intr = {}; quit = {}; erase = {}; kill = {}; eof = {}; eol = <undef>; eol2 = <undef>; swtch = <undef>;", cc(VINTR), cc(VQUIT), cc(VERASE), cc(VKILL), cc(VEOF));
            outln!(ctx, "start = ^Q; stop = ^S; susp = {}; rprnt = {}; werase = {}; lnext = {}; discard = ^O; min = {}; time = {};", cc(VSUSP), cc(VREPRINT), cc(VWERASE), cc(VLNEXT), tio.cc[VMIN], tio.cc[VTIME]);
        }
        let flag = |on: bool, name: &str| if on { name.to_string() } else { alloc::format!("-{name}") };
        let l = tio.lflag;
        let lflags = [
            flag(l & ISIG != 0, "isig"),
            flag(l & ICANON != 0, "icanon"),
            flag(l & IEXTEN != 0, "iexten"),
            flag(l & ECHO != 0, "echo"),
            flag(l & ECHOE != 0, "echoe"),
            flag(l & ECHOK != 0, "echok"),
            flag(l & ECHONL != 0, "echonl"),
            flag(l & ECHOCTL != 0, "echoctl"),
            flag(l & ECHOKE != 0, "echoke"),
        ];
        let iflags = [flag(tio.iflag & ICRNL != 0, "icrnl"), flag(tio.iflag & IXON != 0, "ixon"), flag(tio.iflag & IUTF8 != 0, "iutf8")];
        let oflags = [flag(tio.oflag & OPOST != 0, "opost"), flag(tio.oflag & ONLCR != 0, "onlcr")];
        if all {
            outln!(ctx, "{}", iflags.join(" "));
            outln!(ctx, "{}", oflags.join(" "));
            outln!(ctx, "{}", lflags.join(" "));
        }
        return 0;
    }
    let mut i = 0;
    let mut new_ws = ws;
    while i < args.len() {
        let a = args[i].as_str();
        let (neg, name) = match a.strip_prefix('-') {
            Some(n) => (true, n),
            None => (false, a),
        };
        let set = |field: &mut u32, bit: u32| {
            if neg {
                *field &= !bit;
            } else {
                *field |= bit;
            }
        };
        match name {
            "size" => {
                outln!(ctx, "{} {}", ws.rows, ws.cols);
                return 0;
            }
            "echo" => set(&mut tio.lflag, ECHO),
            "icanon" => set(&mut tio.lflag, ICANON),
            "isig" => set(&mut tio.lflag, ISIG),
            "iexten" => set(&mut tio.lflag, IEXTEN),
            "echoe" => set(&mut tio.lflag, ECHOE),
            "echoctl" => set(&mut tio.lflag, ECHOCTL),
            "icrnl" => set(&mut tio.iflag, ICRNL),
            "ixon" => set(&mut tio.iflag, IXON),
            "opost" => set(&mut tio.oflag, OPOST),
            "onlcr" => set(&mut tio.oflag, ONLCR),
            "raw" => {
                if neg {
                    tio = crate::tty::Termios::default();
                } else {
                    tio.make_raw();
                }
            }
            "cooked" | "sane" => {
                let d = crate::tty::Termios::default();
                tio.iflag = d.iflag;
                tio.oflag = d.oflag;
                tio.lflag = d.lflag;
                tio.cc = d.cc;
            }
            "rows" | "cols" | "columns" => {
                i += 1;
                let Some(v) = args.get(i).and_then(|v| v.parse::<u16>().ok()) else {
                    return ctx.fail(alloc::format!("missing argument to '{name}'"));
                };
                if name == "rows" {
                    new_ws.rows = v;
                } else {
                    new_ws.cols = v;
                }
            }
            _ => return ctx.fail(alloc::format!("invalid argument '{a}'")),
        }
        i += 1;
    }
    t.set_termios(tio);
    if new_ws != ws {
        t.set_winsize(new_ws);
    }
    0
}

// ── lscpu / lspci ──────────────────────────────────────────────────────────

pub fn lscpu(ctx: &mut Ctx) -> i32 {
    let text = ops::read_file(&ctx.fs(), "/proc/cpuinfo").map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
    let get = |k: &str| text.lines().find_map(|l| {
        let (key, v) = l.split_once(':')?;
        (key.trim() == k).then(|| v.trim().to_string())
    }).unwrap_or_default();
    let ncpu = text.lines().filter(|l| l.starts_with("processor")).count().max(1);
    let row = |ctx: &mut Ctx, indent: usize, k: &str, v: &str| {
        let key = alloc::format!("{}{}:", " ".repeat(indent), k);
        outln!(ctx, "{:<34}{}", key, v);
    };
    row(ctx, 0, "Architecture", "x86_64");
    row(ctx, 2, "CPU op-mode(s)", "32-bit, 64-bit");
    row(ctx, 2, "Address sizes", &get("address sizes"));
    row(ctx, 2, "Byte Order", "Little Endian");
    row(ctx, 0, "CPU(s)", &ncpu.to_string());
    row(ctx, 2, "On-line CPU(s) list", &if ncpu == 1 { String::from("0") } else { alloc::format!("0-{}", ncpu - 1) });
    row(ctx, 0, "Vendor ID", &get("vendor_id"));
    row(ctx, 2, "Model name", &get("model name"));
    row(ctx, 4, "CPU family", &get("cpu family"));
    row(ctx, 4, "Model", &get("model"));
    row(ctx, 4, "Thread(s) per core", "1");
    row(ctx, 4, "Core(s) per socket", &get("cpu cores"));
    row(ctx, 4, "Socket(s)", "1");
    row(ctx, 4, "Stepping", &get("stepping"));
    row(ctx, 4, "BogoMIPS", &get("bogomips"));
    row(ctx, 4, "Flags", &get("flags"));
    row(ctx, 0, "Virtualization features", "");
    row(ctx, 2, "Hypervisor vendor", "KVM/QEMU");
    row(ctx, 2, "Virtualization type", "full");
    0
}

pub fn lspci(ctx: &mut Ctx) -> i32 {
    let numeric = ctx.args.iter().filter(|a| a.starts_with('-') && a.contains('n')).map(|a| a.matches('n').count()).sum::<usize>();
    let verbose = ctx.args.iter().any(|a| a.starts_with('-') && a.contains('v'));
    for d in crate::drivers::pci::devices() {
        let slot = alloc::format!("{:02x}:{:02x}.{}", d.addr.bus, d.addr.dev, d.addr.func);
        let class_code = alloc::format!("{:02x}{:02x}", d.class, d.subclass);
        let rev = if d.revision != 0 { alloc::format!(" (rev {:02x})", d.revision) } else { String::new() };
        match numeric {
            0 => outln!(ctx, "{} {}: {} {}{}", slot, d.class_name(), d.vendor_name(), d.device_name(), rev),
            1 => outln!(ctx, "{} {}: {:04x}:{:04x}{}", slot, class_code, d.vendor, d.device, rev),
            _ => outln!(ctx, "{} {} [{}]: {} {} [{:04x}:{:04x}]{}", slot, d.class_name(), class_code, d.vendor_name(), d.device_name(), d.vendor, d.device, rev),
        }
        if verbose {
            if d.irq_line != 0 && d.irq_line != 0xFF {
                outln!(ctx, "\tFlags: bus master, fast devsel, latency 0, IRQ {}", d.irq_line);
            }
            for (i, b) in d.bars.iter().enumerate() {
                match b {
                    crate::drivers::pci::Bar::Io(p) => outln!(ctx, "\tI/O ports at {:04x} [BAR{}]", p, i),
                    crate::drivers::pci::Bar::Mem { addr, size, prefetchable } => {
                        outln!(ctx, "\tMemory at {:08x} ({}-bit, {}) [size={}] [BAR{}]", addr, if *addr > u32::MAX as u64 { 64 } else { 32 }, if *prefetchable { "prefetchable" } else { "non-prefetchable" }, lsblk_size(*size), i)
                    }
                    crate::drivers::pci::Bar::None => {}
                }
            }
            outln!(ctx);
        }
    }
    0
}

// ── sysctl ─────────────────────────────────────────────────────────────────

fn sysctl_walk(ctx: &Ctx, dir: &str, out: &mut Vec<String>) {
    let Ok(entries) = ops::list_dir(&ctx.fs(), dir) else { return };
    let mut names: Vec<(String, bool)> = entries.into_iter().map(|e| (e.name, e.kind == crate::fs::FileType::Directory)).collect();
    names.sort();
    for (n, is_dir) in names {
        let path = alloc::format!("{dir}/{n}");
        if is_dir {
            sysctl_walk(ctx, &path, out);
        } else {
            out.push(path);
        }
    }
}

pub fn sysctl(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "anweqpNb", values: "", long: &[("all", 'a', false), ("values", 'n', false), ("names", 'N', false), ("write", 'w', false), ("quiet", 'q', false), ("ignore", 'e', false), ("load", 'p', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    let to_path = |k: &str| alloc::format!("/proc/sys/{}", k.replace('.', "/"));
    let to_key = |path: &str| path.trim_start_matches("/proc/sys/").replace('/', ".");
    let show = |ctx: &mut Ctx, key: &str| -> i32 {
        let path = to_path(key);
        match ops::read_file(&ctx.fs(), &path) {
            Ok(v) => {
                let v = String::from_utf8_lossy(&v).trim_end().to_string();
                if p.has('n') {
                    outln!(ctx, "{v}");
                } else if p.has('N') {
                    outln!(ctx, "{key}");
                } else {
                    outln!(ctx, "{key} = {v}");
                }
                0
            }
            Err(Errno::ENOENT) => {
                if !p.has('e') {
                    ctx.eprint(&alloc::format!("sysctl: cannot stat {path}: No such file or directory\n"));
                }
                255
            }
            Err(e) => ctx.fail(alloc::format!("permission denied on key \"{key}\" ({e})")),
        }
    };
    if p.has('a') || p.operands.is_empty() && !p.has('p') {
        let mut paths = Vec::new();
        sysctl_walk(ctx, "/proc/sys", &mut paths);
        for path in paths {
            let k = to_key(&path);
            show(ctx, &k);
        }
        return 0;
    }
    let mut st = 0;
    for a in p.operands.clone() {
        if let Some((k, v)) = a.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            match ops::open(&ctx.fs(), &to_path(k), crate::fs::file::flags::O_WRONLY | crate::fs::file::flags::O_TRUNC, 0) {
                Ok(f) => match f.write_all(alloc::format!("{v}\n").as_bytes()) {
                    Ok(()) => {
                        if !p.has('q') {
                            outln!(ctx, "{k} = {v}");
                        }
                    }
                    Err(e) => st = ctx.fail(alloc::format!("setting key \"{k}\": {e}")),
                },
                Err(Errno::ENOENT) => st = ctx.fail(alloc::format!("cannot stat {}: No such file or directory", to_path(k))),
                Err(e) => st = ctx.fail(alloc::format!("permission denied on key \"{k}\" ({e})")),
            }
        } else {
            let r = show(ctx, &a);
            if r != 0 {
                st = r;
            }
        }
    }
    st
}

// ── wall / shutdown / reboot / poweroff / halt ─────────────────────────────

/// Write a broadcast to every terminal, as `wall` does.
fn broadcast(ctx: &Ctx, msg: &str) {
    let user = crate::users::user_name(ctx.cred().uid);
    let host = ctx.proc.uts.hostname.lock().clone();
    let tty = ctx.proc.ctty.lock().as_ref().map(|t| t.name.clone()).unwrap_or_else(|| String::from("somewhere"));
    let now = crate::time::unix_now() as i64;
    let text = alloc::format!(
        "\nBroadcast message from {}@{} ({}) ({}):\n\n{}\n\n",
        user,
        host,
        tty,
        strftime("%a %b %e %H:%M:%S %Y", now, 0),
        msg.trim_end()
    );
    for t in crate::tty::all() {
        let _ = t.write(text.as_bytes());
    }
}

pub fn wall(ctx: &mut Ctx) -> i32 {
    let msg = if ctx.args.len() > 1 {
        ctx.args[1..].join(" ")
    } else {
        match ctx.read_input("-") {
            Ok(d) => String::from_utf8_lossy(&d).into_owned(),
            Err(e) => return ctx.fail_errno("stdin", e),
        }
    };
    broadcast(ctx, &msg);
    0
}

fn power_command(ctx: &mut Ctx, action: crate::power::Action, verb: &str) -> i32 {
    if !ctx.cred().is_root() {
        return ctx.fail("must be superuser.");
    }
    broadcast(ctx, &alloc::format!("The system will {verb} now!"));
    crate::knotice!("power", "{} requested by uid {} ({})", verb, ctx.cred().uid, ctx.name());
    crate::power::request(action);
    0
}

pub fn reboot(ctx: &mut Ctx) -> i32 {
    power_command(ctx, crate::power::Action::Reboot, "reboot")
}

pub fn poweroff(ctx: &mut Ctx) -> i32 {
    power_command(ctx, crate::power::Action::PowerOff, "power off")
}

pub fn halt(ctx: &mut Ctx) -> i32 {
    if ctx.args.iter().any(|a| a == "-p" || a == "--poweroff") {
        return poweroff(ctx);
    }
    power_command(ctx, crate::power::Action::Halt, "halt")
}

pub fn shutdown(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "hPrHck", values: "", long: &[("halt", 'H', false), ("poweroff", 'P', false), ("reboot", 'r', false), ("no-wall", 'W', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage_err(ctx, e),
    };
    if !ctx.cred().is_root() {
        return ctx.fail("must be superuser.");
    }
    if p.has('c') {
        return if crate::power::cancel_scheduled() {
            broadcast(ctx, "The system shutdown has been cancelled");
            0
        } else {
            ctx.fail("no shutdown scheduled")
        };
    }
    let action = if p.has('r') {
        crate::power::Action::Reboot
    } else if p.has('H') {
        crate::power::Action::Halt
    } else {
        crate::power::Action::PowerOff
    };
    let when = p.operands.first().map(|s| s.as_str()).unwrap_or("+1");
    let delay_secs = match when {
        "now" => 0,
        w if w.starts_with('+') => match w[1..].parse::<u64>() {
            Ok(m) => m * 60,
            Err(_) => return ctx.fail(alloc::format!("Failed to parse time specification: {w}")),
        },
        w if w.contains(':') => {
            let (h, m) = w.split_once(':').unwrap_or(("0", "0"));
            let (Ok(h), Ok(m)) = (h.parse::<u64>(), m.parse::<u64>()) else {
                return ctx.fail(alloc::format!("Failed to parse time specification: {w}"));
            };
            if h > 23 || m > 59 {
                return ctx.fail(alloc::format!("Failed to parse time specification: {w}"));
            }
            let now = crate::time::unix_now();
            let day = now - now % 86400;
            let mut target = day + h * 3600 + m * 60;
            if target <= now {
                target += 86400;
            }
            target - now
        }
        w => return ctx.fail(alloc::format!("Failed to parse time specification: {w}")),
    };
    let verb = match action {
        crate::power::Action::Reboot => "reboot",
        crate::power::Action::Halt => "halt",
        crate::power::Action::PowerOff => "power off",
    };
    let extra = if p.operands.len() > 1 { alloc::format!("\n{}", p.operands[1..].join(" ")) } else { String::new() };
    if delay_secs == 0 {
        broadcast(ctx, &alloc::format!("The system will {verb} now!{extra}"));
        crate::power::request(action);
    } else {
        let at = crate::time::unix_now() + delay_secs;
        let when_s = strftime("%a %Y-%m-%d %H:%M:%S %Z", at as i64, 0);
        broadcast(ctx, &alloc::format!("The system will {verb} at {when_s}!{extra}"));
        crate::power::schedule(action, delay_secs);
        outln!(ctx, "Shutdown scheduled for {when_s}, use 'shutdown -c' to cancel.");
    }
    0
}
