//! `ls` — list directory contents.
//!
//! Flags:
//!   -a   show all entries including hidden (dot-files)
//!   -l   long listing (one entry per line)
//!
//! Paging: if the number of visible entries exceeds PAGE_SIZE (20),
//! ls pauses and shows "-- More --" after each page.
//! Press Enter/Space to continue, 'q' to stop.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct LsCommand;
pub static LS: LsCommand = LsCommand;

/// How many entries to show before pausing.
const PAGE_SIZE: usize = 20;

impl Command for LsCommand {
    fn name(&self) -> &'static str { "ls" }
    fn description(&self) -> &'static str { "List directory contents (-a hidden, -l long)" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut show_all  = false;
        let mut long_fmt  = false;
        let mut target: &[u8] = env.cwd();

        for &arg in args {
            if arg.starts_with(b"-") {
                if arg.contains(&b'a') { show_all = true; }
                if arg.contains(&b'l') { long_fmt  = true; }
            } else {
                target = arg;
            }
        }

        let children = match super::virt_fs::lookup(target) {
            None => {
                io.write_bytes(b"ls: ");
                io.write_bytes(target);
                io.write_bytes(b": No such directory\n");
                return 1;
            }
            Some(c) => c,
        };

        // Collect visible entries
        let mut visible: [&[u8]; 256] = [b""; 256];
        let mut count = 0;
        for &name in children {
            if !show_all && name.first() == Some(&b'.') { continue; }
            if count < 256 { visible[count] = name; count += 1; }
        }

        if count == 0 {
            if show_all { io.write_bytes(b"(empty)\n"); }
            return 0;
        }

        // Total pages needed
        let needs_paging = count > PAGE_SIZE;

        let mut shown = 0;
        for i in 0..count {
            let name = visible[i];

            if long_fmt {
                // One per line
                io.write_bytes(name);
                io.newline();
            } else {
                // Space-separated, wrapping at ~80 cols (4 per row of 20 chars each)
                io.write_bytes(name);
                io.write_bytes(b"  ");
                // Newline every 4 entries to keep lines tidy
                if (i + 1) % 4 == 0 { io.newline(); }
            }

            shown += 1;

            // Pause after every PAGE_SIZE entries (only if paging is needed)
            if needs_paging && shown % PAGE_SIZE == 0 && i + 1 < count {
                // Make sure current line is closed
                if !long_fmt && shown % 4 != 0 { io.newline(); }

                io.write_bytes(b"-- More -- (Enter/Space: continue, q: quit) ");
                loop {
                    let key = io.read_byte_blocking();
                    match key {
                        b'q' | b'Q' => {
                            io.newline();
                            return 0;
                        }
                        b' ' | b'\n' | b'\r' => {
                            // Erase the "-- More --" line with spaces then CR
                            io.write_bytes(b"\r                                             \r");
                            break;
                        }
                        _ => {}  // ignore other keys, keep waiting
                    }
                }
            }
        }

        // Final newline if last row wasn't closed
        if !long_fmt && shown % 4 != 0 { io.newline(); }

        0
    }
}
