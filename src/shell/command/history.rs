//! `history` — display command history.
//!
//! Usage:
//!   history        — show all stored commands (oldest first, numbered)
//!   history <N>    — show only the last N commands

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct HistoryCommand;
pub static HISTORY: HistoryCommand = HistoryCommand;

impl Command for HistoryCommand {
    fn name(&self) -> &'static str { "history" }
    fn description(&self) -> &'static str { "Show command history (history [N])" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        // Parse optional count argument
        let limit: usize = if let Some(&arg) = args.first() {
            parse_usize(arg).unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };

        let total = crate::shell::history::count();
        let start = if limit < total { total - limit } else { 0 };
        let mut shown = 0;

        crate::shell::history::with(|hist| {
            for (i, entry) in hist.iter_oldest_first().enumerate() {
                if i < start { continue; }
                // Print "  N  command\n"
                let n = i + 1;
                io.write_bytes(b"  ");
                io.write_u64(n as u64);
                io.write_bytes(b"  ");
                io.write_bytes(entry);
                io.newline();
                shown += 1;
            }
        });

        if shown == 0 {
            io.write_bytes(b"(no history)\n");
        }

        0
    }
}

fn parse_usize(s: &[u8]) -> Option<usize> {
    if s.is_empty() { return None; }
    let mut n: usize = 0;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        n = n * 10 + (b - b'0') as usize;
    }
    Some(n)
}
