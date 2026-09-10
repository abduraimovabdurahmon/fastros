//! In-memory directory store — tracks user-created directories.
//!
//! Mirrors the design of `memfs` but for directories instead of files.
//! Directories persist within a session and are lost on reboot.
//!
//! Used by:
//!   mkdir          — creates entries here
//!   virt_fs::is_dir — checks here after checking the static tree
//!   ls             — lists entries here alongside virt_fs children
//!   cd             — navigates here (via virt_fs::is_dir)
//!   tab completion — completes into these directories

use crate::kernel::sync::spinlock::SpinLock;

pub const MAX_DIRS: usize = 32;
const PATH_CAP:    usize = 256;

struct MemDirEntry {
    path:     [u8; PATH_CAP],
    path_len: usize,
    used:     bool,
}

impl MemDirEntry {
    const fn empty() -> Self {
        Self { path: [0u8; PATH_CAP], path_len: 0, used: false }
    }
}

static     DIR_LOCK: SpinLock = SpinLock::new();
static mut STORE: [MemDirEntry; MAX_DIRS] = [
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
    MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(), MemDirEntry::empty(),
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Create a directory.  Returns false if the store is full or path is too long.
/// Does NOT check whether the path already exists — callers must do that.
pub fn create(path: &[u8]) -> bool {
    if path.len() >= PATH_CAP { return false; }
    DIR_LOCK.lock();
    let result = unsafe { store_create(path) };
    DIR_LOCK.unlock();
    result
}

/// True if `path` is a user-created directory in this store.
pub fn exists(path: &[u8]) -> bool {
    DIR_LOCK.lock();
    let result = unsafe { store_find(path).is_some() };
    DIR_LOCK.unlock();
    result
}

/// List all stored directory absolute paths into `out`. Returns count.
pub fn list(out: &mut [&'static [u8]; MAX_DIRS]) -> usize {
    DIR_LOCK.lock();
    let mut n = 0;
    unsafe {
        for entry in STORE.iter() {
            if entry.used && n < MAX_DIRS {
                out[n] = core::slice::from_raw_parts(entry.path.as_ptr(), entry.path_len);
                n += 1;
            }
        }
    }
    DIR_LOCK.unlock();
    n
}

// ── Internals ─────────────────────────────────────────────────────────────────

unsafe fn store_find(path: &[u8]) -> Option<usize> {
    for (i, e) in STORE.iter().enumerate() {
        if e.used && &e.path[..e.path_len] == path {
            return Some(i);
        }
    }
    None
}

unsafe fn store_create(path: &[u8]) -> bool {
    // Already exists — idempotent (caller decides whether to error)
    if store_find(path).is_some() { return false; }
    for e in STORE.iter_mut() {
        if !e.used {
            let n = path.len().min(PATH_CAP - 1);
            e.path[..n].copy_from_slice(&path[..n]);
            e.path_len = n;
            e.used = true;
            return true;
        }
    }
    false // store full
}
