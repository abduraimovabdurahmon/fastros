//! `ls` — list directory contents.
//!
//! Flags:
//!   -a   show all entries including hidden (dot-files)
//!   -l   long listing (one entry per line with type indicator)
//!
//! Default display: auto-sized columns aligned to the widest entry name,
//! filling 80 columns.  Pagination kicks in after PAGE_LINES visible lines.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::shell::memfs;
use crate::shell::memdir;

pub struct LsCommand;
pub static LS: LsCommand = LsCommand;

const SCREEN_COLS: usize = 80;
const PAGE_LINES:  usize = 20;

impl Command for LsCommand {
    fn name(&self) -> &'static str { "ls" }
    fn description(&self) -> &'static str { "List directory contents (-a hidden, -l long)" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut show_all = false;
        let mut long_fmt = false;
        let mut target: &[u8] = env.cwd();

        for &arg in args {
            if arg.starts_with(b"-") {
                if arg.contains(&b'a') { show_all = true; }
                if arg.contains(&b'l') { long_fmt  = true; }
            } else {
                target = arg;
            }
        }

        // Look up children from static tree first; if this is a user-created
        // directory (memdir) it won't be in the static tree but is still valid.
        let static_children: &[&[u8]] = match super::virt_fs::lookup(target) {
            Some(c) => c,
            None => {
                // Not in static tree — check if it's a user-created directory
                if !super::virt_fs::is_dir(target) {
                    io.write_bytes(b"ls: ");
                    io.write_bytes(target);
                    io.write_bytes(b": No such directory\n");
                    return 1;
                }
                // It's a memdir — no static children, memfs/memdir will fill it
                &[]
            }
        };

        // ── Filter visible entries (virt_fs + memfs + memdir) ─────────────────
        let mut visible: [&[u8]; 256] = [b""; 256];
        let mut count = 0usize;
        for &name in static_children {
            if !show_all && name.first() == Some(&b'.') { continue; }
            if count < 256 { visible[count] = name; count += 1; }
        }

        // Also include user-created files from memfs under this directory
        let mut memfs_paths: [&'static [u8]; memfs::MAX_FILES] = [b""; memfs::MAX_FILES];
        let mcount = memfs::list(&mut memfs_paths);
        'mf: for i in 0..mcount {
            let path = memfs_paths[i];
            if !memfs_path_parent_is(path, target) { continue; }
            let name = memfs_path_name(path);
            if !show_all && name.first() == Some(&b'.') { continue; }
            for j in 0..count { if visible[j] == name { continue 'mf; } }
            if count < 256 { visible[count] = name; count += 1; }
        }

        // Also include user-created directories from memdir under this directory
        let mut memdir_paths: [&'static [u8]; memdir::MAX_DIRS] = [b""; memdir::MAX_DIRS];
        let dcount = memdir::list(&mut memdir_paths);
        'md: for i in 0..dcount {
            let path = memdir_paths[i];
            if !memfs_path_parent_is(path, target) { continue; }
            let name = memfs_path_name(path);
            if !show_all && name.first() == Some(&b'.') { continue; }
            for j in 0..count { if visible[j] == name { continue 'md; } }
            if count < 256 { visible[count] = name; count += 1; }
        }

        if count == 0 {
            if show_all { io.write_bytes(b"(empty)\n"); }
            return 0;
        }

        // ── Long format: one entry per line ───────────────────────────────────
        if long_fmt {
            let mut lines_shown = 0usize;
            for i in 0..count {
                let full_path = make_abs_path(target, visible[i]);
                let fp = full_path.as_slice();
                let is_dir = super::virt_fs::is_dir(fp);
                let (uid, gid, mode) = super::virt_fs::get_stat(fp);

                // Mode string: drwxr-xr-x
                let mut mode_str = [0u8; 10];
                crate::kernel::users::permission::fmt_mode_str(is_dir, mode, &mut mode_str);
                io.write_bytes(&mode_str);

                // Owner name
                io.write_byte(b' ');
                let mut uname = [0u8; 32];
                let un = crate::kernel::users::uid_to_name(uid, &mut uname);
                io.write_bytes(&uname[..un]);

                // Group name
                io.write_byte(b' ');
                let mut gname = [0u8; 32];
                let gn = crate::kernel::users::gid_to_name(gid, &mut gname);
                io.write_bytes(&gname[..gn]);

                // Size
                io.write_bytes(b" ");
                let size = crate::shell::memfs::get_size(fp).unwrap_or(0);
                write_padded_u32(io, size as u32, 6);

                // Date (static — no RTC)
                io.write_bytes(b" Jan  1 00:00 ");

                // Name
                io.write_bytes(visible[i]);
                io.newline();
                lines_shown += 1;
                if lines_shown % PAGE_LINES == 0 && i + 1 < count {
                    if prompt_more(io) { return 0; }
                }
            }
            return 0;
        }

        // ── Column format ─────────────────────────────────────────────────────
        // Find the widest name
        let mut max_len = 1usize;
        for i in 0..count {
            if visible[i].len() > max_len { max_len = visible[i].len(); }
        }

        // Column width = name width + 2 spaces gap
        let col_width = (max_len + 2).min(SCREEN_COLS);
        let cols = (SCREEN_COLS / col_width).max(1);
        let rows = (count + cols - 1) / cols;

        let mut lines_shown = 0usize;
        for row in 0..rows {
            for col in 0..cols {
                let idx = col * rows + row;   // column-major order (like ls)
                if idx >= count { break; }
                let name = visible[idx];
                io.write_bytes(name);
                // Pad to col_width (unless it's the last column on this row)
                let next_idx = (col + 1) * rows + row;
                if col + 1 < cols && next_idx < count {
                    let pad = col_width.saturating_sub(name.len());
                    for _ in 0..pad { io.write_byte(b' '); }
                }
            }
            io.newline();
            lines_shown += 1;

            if lines_shown % PAGE_LINES == 0 && row + 1 < rows {
                if prompt_more(io) { return 0; }
            }
        }

        0
    }
}

fn write_padded_u32(io: &mut dyn ShellIo, mut n: u32, width: usize) {
    let mut buf = [b' '; 10];
    let mut len = 0;
    if n == 0 { buf[0] = b'0'; len = 1; }
    else { while n > 0 { buf[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; } }
    // Right-align in `width`
    let pad = width.saturating_sub(len);
    for _ in 0..pad { io.write_byte(b' '); }
    for i in (0..len).rev() { io.write_byte(buf[i]); }
}

/// Show "-- More --" and wait for input. Returns true if user quit.
fn prompt_more(io: &mut dyn ShellIo) -> bool {
    io.write_bytes(b"-- More -- (Space/Enter: continue, q: quit) ");
    loop {
        match io.read_byte_blocking() {
            b'q' | b'Q' => {
                io.newline();
                return true;
            }
            b' ' | b'\n' | b'\r' => {
                io.write_bytes(b"\r                                              \r");
                return false;
            }
            _ => {}
        }
    }
}

/// Build "/parent/name" path string into a fixed buffer.
struct PathBuf { data: [u8; 256], len: usize }
impl PathBuf {
    fn new() -> Self { Self { data: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) { if self.len < 255 { self.data[self.len] = b; self.len += 1; } }
    fn push_bytes(&mut self, s: &[u8]) { for &b in s { self.push(b); } }
    fn as_slice(&self) -> &[u8] { &self.data[..self.len] }
}
/// True if `path` is directly inside `dir` (no further slashes in the tail).
fn memfs_path_parent_is(path: &[u8], dir: &[u8]) -> bool {
    if path.len() <= dir.len() { return false; }
    if !path.starts_with(dir) { return false; }
    let rest = &path[dir.len()..];
    if dir == b"/" {
        // dir is root: rest must be just "name" with no slash
        !rest.contains(&b'/')
    } else {
        // rest should be "/name" with no further slashes
        rest.first() == Some(&b'/') && !rest[1..].contains(&b'/')
    }
}

/// Extract the last path component.
fn memfs_path_name(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        None    => path,
        Some(i) => &path[i + 1..],
    }
}

fn make_abs_path(parent: &[u8], name: &[u8]) -> PathBuf {
    let mut p = PathBuf::new();
    p.push_bytes(parent);
    if parent != b"/" { p.push(b'/'); }
    p.push_bytes(name);
    p
}
