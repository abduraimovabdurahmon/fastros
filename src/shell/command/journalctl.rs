//! journalctl — display kernel log entries.
//!
//! Usage:
//!   journalctl          — show all log entries (newest last)
//!   journalctl -e       — jump to end (last 20 entries)
//!   journalctl -p err   — show only errors and above
//!   journalctl -n N     — show last N entries
//!   journalctl -f       — follow (tail) mode (press Ctrl-C to exit)
//!
//! Linux equivalent: systemd's journalctl reading /run/log/journal/

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::log::{self, Level};
use crate::libs::fmt;

pub struct JournalCtl;
pub static JOURNALCTL: JournalCtl = JournalCtl;

impl Command for JournalCtl {
    fn name(&self) -> &'static str { "journalctl" }
    fn description(&self) -> &'static str { "Show kernel log (like Linux journalctl)" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let count = log::count();
        if count == 0 {
            io.write_bytes(b"-- No journal entries --\n");
            return 0;
        }

        // Parse flags
        let mut max_level = Level::Debug;   // show all by default
        let mut tail: Option<usize> = None;
        let mut follow = false;

        let mut i = 0;
        while i < args.len() {
            match args[i] {
                b"-e"    => { tail = Some(20); }
                b"-f"    => { follow = true; tail = Some(20); }
                b"-p"    => {
                    i += 1;
                    if i < args.len() {
                        max_level = parse_level(args[i]);
                    }
                }
                b"-n"    => {
                    i += 1;
                    if i < args.len() {
                        let mut n = 0usize;
                        for &b in args[i] {
                            if b >= b'0' && b <= b'9' { n = n * 10 + (b - b'0') as usize; }
                        }
                        tail = Some(n);
                    }
                }
                _ => {}
            }
            i += 1;
        }

        let start = if let Some(n) = tail {
            count.saturating_sub(n)
        } else {
            0
        };

        print_entries(io, start, count, max_level);

        if follow {
            io.write_bytes(b"-- Waiting for new entries (press Enter to stop) --\n");
            let mut last = count;
            loop {
                // Check for keyboard input to break
                if io.read_byte().is_some() { break; }
                let new_count = log::count();
                if new_count > last {
                    print_entries(io, last, new_count, max_level);
                    last = new_count;
                }
                crate::kernel::net::poll_drivers();
            }
        }

        0
    }
}

fn print_entries(io: &mut dyn ShellIo, start: usize, end: usize, max_level: Level) {
    for pos in start..end {
        let e = match log::get(pos) { Some(e) => e, None => break };
        if e.level as u8 > max_level as u8 { continue; }

        // Format: "  <seq> [LEVEL ] msg"
        // Sequence number (6 digits)
        let mut buf = [0u8; 20];
        let s = fmt::u64_to_dec(e.seq, &mut buf);
        // Pad to 6 chars
        for _ in s.len()..6 { io.write_byte(b' '); }
        io.write_bytes(s);
        io.write_byte(b' ');

        // Level tag with color codes (ANSI)
        let (color, tag) = level_display(e.level);
        io.write_bytes(color);
        io.write_bytes(tag);
        io.write_bytes(b"\x1b[0m ");  // reset

        io.write_bytes(&e.msg[..e.msg_len]);
        io.write_bytes(b"\r\n");
    }
}

fn level_display(level: Level) -> (&'static [u8], &'static [u8]) {
    match level {
        Level::Emergency | Level::Alert | Level::Critical
            => (b"\x1b[1;31m", b"[CRIT  ]"),
        Level::Error
            => (b"\x1b[31m",   b"[ERROR ]"),
        Level::Warning
            => (b"\x1b[33m",   b"[WARN  ]"),
        Level::Notice
            => (b"\x1b[36m",   b"[NOTICE]"),
        Level::Info
            => (b"\x1b[0m",    b"[INFO  ]"),
        Level::Debug
            => (b"\x1b[2m",    b"[DEBUG ]"),
    }
}

fn parse_level(s: &[u8]) -> Level {
    match s {
        b"emerg" | b"0"  => Level::Emergency,
        b"alert" | b"1"  => Level::Alert,
        b"crit"  | b"2"  => Level::Critical,
        b"err"   | b"3"  => Level::Error,
        b"warn"  | b"4"  => Level::Warning,
        b"notice"| b"5"  => Level::Notice,
        b"info"  | b"6"  => Level::Info,
        b"debug" | b"7"  => Level::Debug,
        _                => Level::Debug,
    }
}
