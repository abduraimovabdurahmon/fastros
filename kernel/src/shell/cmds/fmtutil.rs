//! Formatting shared by commands: permission strings, dates, colours,
//! column layout — all matching GNU coreutils output byte for byte.

use crate::fs::{FileType, Metadata};
use crate::time::civil;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// `-rwxr-xr-x` (with setuid/setgid/sticky letters).
pub fn mode_string(m: &Metadata) -> String {
    let p = m.perm as u32;
    let mut s = String::with_capacity(10);
    s.push(m.kind.letter());
    let bit = |b: u32, c: char| if p & b != 0 { c } else { '-' };
    s.push(bit(0o400, 'r'));
    s.push(bit(0o200, 'w'));
    s.push(match (p & 0o100 != 0, p & 0o4000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s.push(bit(0o040, 'r'));
    s.push(bit(0o020, 'w'));
    s.push(match (p & 0o010 != 0, p & 0o2000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s.push(bit(0o004, 'r'));
    s.push(bit(0o002, 'w'));
    s.push(match (p & 0o001 != 0, p & 0o1000 != 0) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s
}

/// `ls -l` time: `Sep 11 07:14` within six months, `Sep 11  2025` otherwise.
pub fn ls_time(t: i64) -> String {
    let now = crate::time::unix_now() as i64;
    let tm = civil::from_unix(t);
    let mon = civil::MONTHS[(tm.month - 1) as usize];
    if (now - t).abs() < 15_552_000 {
        alloc::format!("{} {:>2} {:02}:{:02}", mon, tm.day, tm.hour, tm.min)
    } else {
        alloc::format!("{} {:>2}  {}", mon, tm.day, tm.year)
    }
}

/// `2026-09-11 07:14:05` (UTC).
pub fn iso_time(t: i64) -> String {
    let tm = civil::from_unix(t);
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec)
}

/// `date`'s default format: `Fri Sep 11 07:14:05 UTC 2026`.
pub fn date_string(t: i64) -> String {
    let tm = civil::from_unix(t);
    alloc::format!(
        "{} {} {:>2} {:02}:{:02}:{:02} UTC {}",
        civil::WEEKDAYS[tm.weekday as usize],
        civil::MONTHS[(tm.month - 1) as usize],
        tm.day,
        tm.hour,
        tm.min,
        tm.sec,
        tm.year
    )
}

/// Width of a string in terminal cells.
pub fn width(s: &str) -> usize {
    s.chars().count()
}

pub fn pad_right(s: &str, w: usize) -> String {
    let n = width(s);
    let mut o = s.to_string();
    for _ in n..w {
        o.push(' ');
    }
    o
}

pub fn pad_left(s: &str, w: usize) -> String {
    let n = width(s);
    let mut o = String::new();
    for _ in n..w {
        o.push(' ');
    }
    o.push_str(s);
    o
}

/// GNU `ls` colour for an entry (default LS_COLORS).
pub fn ls_color(name: &str, m: &Metadata, target_ok: bool) -> Option<&'static str> {
    Some(match m.kind {
        FileType::Directory => {
            let p = m.perm;
            if p & 0o1000 != 0 && p & 0o002 != 0 {
                "30;42"
            } else if p & 0o002 != 0 {
                "34;42"
            } else {
                "01;34"
            }
        }
        FileType::Symlink => {
            if target_ok {
                "01;36"
            } else {
                "40;31;01"
            }
        }
        FileType::Fifo => "40;33",
        FileType::Socket => "01;35",
        FileType::CharDevice | FileType::BlockDevice => "40;33;01",
        FileType::Regular => {
            if m.perm & 0o4000 != 0 {
                "37;41"
            } else if m.perm & 0o2000 != 0 {
                "30;43"
            } else if m.perm & 0o111 != 0 {
                "01;32"
            } else {
                let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
                match ext.as_str() {
                    "tar" | "tgz" | "gz" | "zip" | "bz2" | "xz" | "zst" | "7z" | "rar" | "deb" | "rpm" | "jar" => "01;31",
                    "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" | "webp" | "ico" | "tif" | "tiff" => "01;35",
                    "mp3" | "flac" | "ogg" | "wav" | "m4a" | "aac" => "00;36",
                    "mp4" | "mkv" | "avi" | "mov" | "webm" => "01;35",
                    _ => return None,
                }
            }
        }
    })
}

pub fn colorize(name: &str, code: Option<&str>) -> String {
    match code {
        Some(c) => alloc::format!("\x1b[{c}m{name}\x1b[0m"),
        None => name.to_string(),
    }
}

/// `ls -C` layout: as few rows as possible, columns filled top to bottom,
/// each column as wide as its longest entry plus two spaces.
/// `items` are (display text, visible width).
pub fn columns(items: &[(String, usize)], term_width: usize) -> Vec<String> {
    if items.is_empty() {
        return Vec::new();
    }
    let n = items.len();
    let mut best_rows = n;
    let mut best_widths = alloc::vec![items.iter().map(|i| i.1).max().unwrap_or(0)];
    for cols in (1..=n).rev() {
        let rows = n.div_ceil(cols);
        let cols = n.div_ceil(rows); // actual columns used
        let mut widths = alloc::vec![0usize; cols];
        for (i, it) in items.iter().enumerate() {
            let c = i / rows;
            widths[c] = widths[c].max(it.1);
        }
        let total: usize = widths.iter().sum::<usize>() + 2 * (cols - 1);
        if total <= term_width {
            best_rows = rows;
            best_widths = widths;
            break;
        }
    }
    let rows = best_rows;
    let mut lines = Vec::with_capacity(rows);
    for r in 0..rows {
        let mut line = String::new();
        let mut c = 0;
        loop {
            let i = c * rows + r;
            if i >= n {
                break;
            }
            let (text, w) = &items[i];
            line.push_str(text);
            let last_in_row = (c + 1) * rows + r >= n;
            if !last_in_row {
                for _ in *w..best_widths[c] + 2 {
                    line.push(' ');
                }
            }
            c += 1;
        }
        lines.push(line);
    }
    lines
}

/// Cache uid/gid → name lookups for listings.
pub struct NameCache {
    users: Vec<(u32, String)>,
    groups: Vec<(u32, String)>,
}

impl NameCache {
    pub fn new() -> NameCache {
        let users = crate::users::users().into_iter().map(|u| (u.uid, u.name)).collect();
        let groups = crate::users::groups().into_iter().map(|g| (g.gid, g.name)).collect();
        NameCache { users, groups }
    }
    pub fn user(&self, uid: u32) -> String {
        self.users.iter().find(|(u, _)| *u == uid).map(|(_, n)| n.clone()).unwrap_or_else(|| uid.to_string())
    }
    pub fn group(&self, gid: u32) -> String {
        self.groups.iter().find(|(g, _)| *g == gid).map(|(_, n)| n.clone()).unwrap_or_else(|| gid.to_string())
    }
}

/// Parse an unsigned size with an optional suffix (`10`, `4K`, `2M`, `1G`).
pub fn parse_size(s: &str) -> Option<u64> {
    let (num, mult) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1024),
        'm' | 'M' => (&s[..s.len() - 1], 1024 * 1024),
        'g' | 'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        'b' => (&s[..s.len() - 1], 512),
        _ => (s, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// A block size as `df -B` prints it in its header: `4K`, `1M`, `512`.
pub fn human_block_size(b: u64) -> String {
    const U: [(u64, &str); 4] = [(1 << 40, "T"), (1 << 30, "G"), (1 << 20, "M"), (1 << 10, "K")];
    for (size, u) in U {
        if b >= size && b % size == 0 {
            return alloc::format!("{}{}", b / size, u);
        }
    }
    b.to_string()
}

/// Process C-style escapes (`echo -e`, `printf %b`). Returns (text, stop):
/// `\c` stops all further output.
pub fn unescape(s: &str) -> (String, bool) {
    let mut out = String::new();
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < c.len() {
        if c[i] != '\\' || i + 1 >= c.len() {
            out.push(c[i]);
            i += 1;
            continue;
        }
        i += 1;
        match c[i] {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            'e' | 'E' => out.push('\x1b'),
            '\\' => out.push('\\'),
            'c' => return (out, true),
            '0' => {
                let mut v = 0u32;
                let mut n = 0;
                while n < 3 && i + 1 < c.len() && ('0'..='7').contains(&c[i + 1]) {
                    i += 1;
                    v = v * 8 + c[i].to_digit(8).unwrap_or(0);
                    n += 1;
                }
                out.push(char::from_u32(v).unwrap_or('?'));
            }
            'x' => {
                let mut v = 0u32;
                let mut n = 0;
                while n < 2 && i + 1 < c.len() && c[i + 1].is_ascii_hexdigit() {
                    i += 1;
                    v = v * 16 + c[i].to_digit(16).unwrap_or(0);
                    n += 1;
                }
                if n == 0 {
                    out.push_str("\\x");
                } else {
                    out.push(char::from_u32(v).unwrap_or('?'));
                }
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
        i += 1;
    }
    (out, false)
}
