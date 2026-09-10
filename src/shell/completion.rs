//! Tab completion for the shell readline.
//!
//! Provides two kinds of completion:
//!   • Command names  — when completing the first token on the line
//!   • Paths          — when completing arguments (virt_fs dirs/files + memfs)
//!
//! Usage:
//!   `complete(partial, ctx)` → CompletionList
//!
//! The readline feeds back a single unique completion, or cycles through
//! multiple matches on repeated Tab presses.

use crate::shell::memfs;

/// Static list of all registered command names.
/// Must be kept in sync with CommandRegistry::init().
const COMMANDS: &[&[u8]] = &[
    b"cat", b"cd", b"chmod", b"chown", b"clear", b"echo", b"exit",
    b"groups", b"help", b"history", b"htop", b"id", b"ifconfig",
    b"ls", b"mem", b"mkdir", b"nano", b"netstat",
    b"passwd", b"ping", b"ps", b"reboot", b"rm",
    b"sshd", b"su", b"sudo", b"uname", b"uptime",
    b"useradd", b"userdel", b"vim", b"whoami",
];

/// Maximum completions returned for a single Tab press.
pub const MAX_COMPLETIONS: usize = 64;

/// Result of a completion query.
pub struct CompletionList {
    pub items: [[u8; 128]; MAX_COMPLETIONS],
    pub lens:  [usize; MAX_COMPLETIONS],
    pub count: usize,
}

impl CompletionList {
    pub const fn empty() -> Self {
        Self {
            items: [[0u8; 128]; MAX_COMPLETIONS],
            lens:  [0usize; MAX_COMPLETIONS],
            count: 0,
        }
    }

    fn push(&mut self, s: &[u8]) {
        if self.count >= MAX_COMPLETIONS { return; }
        let n = s.len().min(128);
        self.items[self.count][..n].copy_from_slice(&s[..n]);
        self.lens[self.count] = n;
        self.count += 1;
    }

    pub fn get(&self, idx: usize) -> &[u8] {
        if idx >= self.count { return b""; }
        &self.items[idx][..self.lens[idx]]
    }
}

/// Complete a partial word.
///
/// `partial`    — the incomplete word the cursor is on/after
/// `is_command` — true when completing the first token (command name)
/// `cwd`        — current working directory (for path resolution)
pub fn complete(partial: &[u8], is_command: bool, cwd: &[u8]) -> CompletionList {
    let mut list = CompletionList::empty();

    // Never complete on empty input (Linux behaviour)
    if partial.is_empty() { return list; }

    if is_command {
        // Complete command names
        for &cmd in COMMANDS {
            if cmd.starts_with(partial) {
                list.push(cmd);
            }
        }
    } else {
        // Complete paths: try both absolute and cwd-relative
        complete_paths(partial, cwd, &mut list);
    }

    list
}

/// Populate `list` with path completions matching `partial`.
fn complete_paths(partial: &[u8], cwd: &[u8], list: &mut CompletionList) {
    // Split partial into directory prefix and name fragment
    // e.g. "/etc/host"  → dir="/etc", frag="host"
    //      "host"       → dir=cwd,    frag="host"
    //      "/etc/"      → dir="/etc", frag=""
    let (dir, frag) = split_dir_frag(partial, cwd);

    // The "typed prefix" is everything the user typed up to and including
    // the last '/'.  We prepend this to each child name so the completion
    // replaces only the fragment, not the whole path.
    //   ""        → typed_prefix = ""      (no slash typed)
    //   "f"       → typed_prefix = ""
    //   "/etc/h"  → typed_prefix = "/etc/"
    //   "sub/h"   → typed_prefix = "sub/"
    let typed_prefix: &[u8] = match partial.iter().rposition(|&b| b == b'/') {
        None    => b"",
        Some(i) => &partial[..i + 1],
    };

    // Iterate virtual FS directory entries
    if let Some(children) = crate::shell::command::virt_fs::lookup(dir) {
        for &child in children {
            if child.starts_with(frag) {
                let entry = build_prefixed(typed_prefix, child);
                list.push(entry.as_slice());
            }
        }
    }

    // Also check memfs for user-created files under `dir`
    let mut memfs_paths: [&'static [u8]; memfs::MAX_FILES] = [b""; memfs::MAX_FILES];
    let n = memfs::list(&mut memfs_paths);
    for i in 0..n {
        let path = memfs_paths[i];
        if path_parent_is(path, dir) {
            let name = path_name(path);
            if name.starts_with(frag) {
                let entry = build_prefixed(typed_prefix, name);
                list.push(entry.as_slice());
            }
        }
    }

    // Also check memdir for user-created subdirectories under `dir`
    let mut memdir_paths: [&'static [u8]; crate::shell::memdir::MAX_DIRS] =
        [b""; crate::shell::memdir::MAX_DIRS];
    let nd = crate::shell::memdir::list(&mut memdir_paths);
    for i in 0..nd {
        let path = memdir_paths[i];
        if path_parent_is(path, dir) {
            let name = path_name(path);
            if name.starts_with(frag) {
                let entry = build_prefixed(typed_prefix, name);
                list.push(entry.as_slice());
            }
        }
    }
}

/// Split "prefix/frag" into ("/prefix", "frag").
/// If no slash, dir = cwd, frag = partial.
fn split_dir_frag<'a>(partial: &'a [u8], cwd: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    // Find last '/'
    let last_slash = partial.iter().rposition(|&b| b == b'/');
    match last_slash {
        None => (cwd, partial),
        Some(0) => (b"/", &partial[1..]),          // "/frag"
        Some(i) => (&partial[..i], &partial[i+1..]) // "/dir/frag"
    }
}

/// True if `path` is directly inside `dir` (i.e. parent directory is `dir`).
fn path_parent_is(path: &[u8], dir: &[u8]) -> bool {
    if path.len() <= dir.len() { return false; }
    if !path.starts_with(dir) { return false; }
    let rest = &path[dir.len()..];
    // rest should be "/name" with no further slashes
    if rest.first() != Some(&b'/') { return false; }
    !rest[1..].contains(&b'/')
}

/// Extract the last component of a path.
fn path_name(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        None    => path,
        Some(i) => &path[i + 1..],
    }
}

struct PathBuf { data: [u8; 256], len: usize }
impl PathBuf {
    fn new() -> Self { Self { data: [0u8; 256], len: 0 } }
    fn push(&mut self, b: u8) { if self.len < 255 { self.data[self.len] = b; self.len += 1; } }
    fn push_bytes(&mut self, s: &[u8]) { for &b in s { self.push(b); } }
    fn as_slice(&self) -> &[u8] { &self.data[..self.len] }
}

/// Build `prefix + name` — preserves whatever the user actually typed before
/// the fragment so we never expand a bare name into an absolute path.
fn build_prefixed(prefix: &[u8], name: &[u8]) -> PathBuf {
    let mut p = PathBuf::new();
    p.push_bytes(prefix);
    p.push_bytes(name);
    p
}
