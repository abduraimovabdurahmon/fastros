//! `chmod` — change file/directory permissions.
//!
//! Usage:
//!   chmod 755 file        — octal mode
//!   chmod u+x file        — symbolic (user add execute)
//!   chmod a-w file        — symbolic (all remove write)
//!   chmod -R 644 dir/     — recursive
//!
//! Only root or the file owner can chmod (mirrors Linux).

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::shell::memfs;
use crate::shell::memdir;

pub struct ChmodCommand;
pub static CHMOD: ChmodCommand = ChmodCommand;

impl Command for ChmodCommand {
    fn name(&self) -> &'static str { "chmod" }
    fn description(&self) -> &'static str { "Change file permissions" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut recursive = false;
        let mut mode_str:  &[u8] = b"";
        let mut paths: [&[u8]; 16] = [b""; 16];
        let mut path_count = 0usize;
        let mut mode_set = false;

        for &arg in args {
            if arg == b"-R" || arg == b"-r" { recursive = true; continue; }
            if !mode_set {
                mode_str = arg;
                mode_set = true;
            } else if path_count < 16 {
                paths[path_count] = arg;
                path_count += 1;
            }
        }

        if !mode_set || path_count == 0 {
            io.write_bytes(b"Usage: chmod [-R] <mode> <file>...\n");
            return 1;
        }

        let mut exit_code = 0;
        for i in 0..path_count {
            let mut buf = [0u8; 256];
            let abs = resolve(env.cwd(), paths[i], &mut buf);
            let code = do_chmod(abs, paths[i], mode_str, env, io, recursive);
            if code != 0 { exit_code = code; }
        }
        exit_code
    }
}

fn do_chmod(abs: &[u8], display: &[u8], mode_str: &[u8], env: &ShellEnv,
            io: &mut dyn ShellIo, recursive: bool) -> i32 {
    // Get current metadata
    let (uid, gid, old_mode) = super::virt_fs::get_stat(abs);
    let _ = gid;

    // Permission check: must be root or owner
    if env.euid() != 0 && env.euid() != uid {
        io.write_bytes(b"chmod: changing permissions of '");
        io.write_bytes(display);
        io.write_bytes(b"': Operation not permitted\n");
        return 1;
    }

    let new_mode = match parse_mode(mode_str, old_mode) {
        Some(m) => m,
        None => {
            io.write_bytes(b"chmod: invalid mode: '");
            io.write_bytes(mode_str);
            io.write_bytes(b"'\n");
            return 1;
        }
    };

    // Apply to memfs file or memdir entry
    let is_dir = super::virt_fs::is_dir(abs);
    let changed = if is_dir {
        memdir::set_mode(abs, new_mode)
    } else {
        memfs::set_mode(abs, new_mode)
    };

    if !changed {
        // Static virt_fs entry — can't chmod (read-only)
        if super::virt_fs::get_content(abs).is_some() || super::virt_fs::lookup(abs).is_some() {
            io.write_bytes(b"chmod: cannot change permissions of read-only file '");
            io.write_bytes(display);
            io.write_bytes(b"'\n");
            return 1;
        }
        io.write_bytes(b"chmod: cannot access '");
        io.write_bytes(display);
        io.write_bytes(b"': No such file or directory\n");
        return 1;
    }

    // Recursive: chmod all memdir entries and memfs files under this dir
    if recursive && is_dir {
        let mut dir_paths = [b"" as &'static [u8]; 32];
        let dc = memdir::list(&mut dir_paths);
        for i in 0..dc {
            if dir_paths[i].starts_with(abs) && dir_paths[i] != abs {
                memdir::set_mode(dir_paths[i], new_mode);
            }
        }
        let mut file_paths = [b"" as &'static [u8]; 16];
        let fc = memfs::list(&mut file_paths);
        for i in 0..fc {
            if file_paths[i].starts_with(abs) {
                memfs::set_mode(file_paths[i], new_mode);
            }
        }
    }

    0
}

/// Parse mode string. Supports:
///   octal: "755", "644", "0755"
///   symbolic: "u+x", "a-w", "go+r", etc.
fn parse_mode(s: &[u8], current: u16) -> Option<u16> {
    // Octal: all digits
    if s.iter().all(|&b| b >= b'0' && b <= b'7') {
        let mut v = 0u32;
        for &b in s { v = v * 8 + (b - b'0') as u32; }
        return Some((v & 0o7777) as u16);
    }
    // Symbolic: [ugoa][+-=][rwxXst],...
    parse_symbolic(s, current)
}

fn parse_symbolic(s: &[u8], mut mode: u16) -> Option<u16> {
    // Split by ','
    let mut i = 0;
    loop {
        let end = s[i..].iter().position(|&b| b == b',').map(|p| i + p).unwrap_or(s.len());
        let clause = &s[i..end];
        if clause.is_empty() { break; }

        // who: u g o a (default = a)
        let mut who_mask: u16 = 0;
        let mut ci = 0;
        loop {
            if ci >= clause.len() { break; }
            match clause[ci] {
                b'u' => { who_mask |= 0o700; ci += 1; }
                b'g' => { who_mask |= 0o070; ci += 1; }
                b'o' => { who_mask |= 0o007; ci += 1; }
                b'a' => { who_mask |= 0o777; ci += 1; }
                _    => break,
            }
        }
        if who_mask == 0 { who_mask = 0o777; } // default = all

        if ci >= clause.len() { return None; }
        let op = clause[ci]; ci += 1;
        if op != b'+' && op != b'-' && op != b'=' { return None; }

        // perms: r w x
        let mut perm_bits: u16 = 0;
        while ci < clause.len() {
            match clause[ci] {
                b'r' => { perm_bits |= 0o444 & who_mask; }
                b'w' => { perm_bits |= 0o222 & who_mask; }
                b'x' => { perm_bits |= 0o111 & who_mask; }
                b'X' => { perm_bits |= 0o111 & who_mask; } // conditional exec
                b's' => {}  // setuid/setgid — accept, ignore for now
                b't' => {}  // sticky — accept, ignore
                _    => return None,
            }
            ci += 1;
        }

        match op {
            b'+' => mode |=  perm_bits,
            b'-' => mode &= !perm_bits,
            b'=' => { mode &= !who_mask; mode |= perm_bits; }
            _    => {}
        }

        i = end + 1;
        if i >= s.len() { break; }
    }
    Some(mode)
}

fn resolve<'a>(cwd: &[u8], path: &[u8], buf: &'a mut [u8; 256]) -> &'a [u8] {
    if path.first() == Some(&b'/') {
        let n = path.len().min(255); buf[..n].copy_from_slice(&path[..n]); return &buf[..n];
    }
    let mut n = 0;
    for &b in cwd  { if n < 255 { buf[n] = b; n += 1; } }
    if cwd != b"/" && n < 255 { buf[n] = b'/'; n += 1; }
    for &b in path { if n < 255 { buf[n] = b; n += 1; } }
    &buf[..n]
}
