//! In-memory directory store — tracks user-created directories.
//!
//! Each directory carries Unix-style metadata: uid, gid, mode.
//! Default: uid=0, gid=0, mode=0o755 (drwxr-xr-x).

use crate::kernel::sync::spinlock::SpinLock;

pub const MAX_DIRS: usize = 32;
const PATH_CAP:    usize = 256;

struct MemDirEntry {
    path:     [u8; PATH_CAP],
    path_len: usize,
    uid:      u32,
    gid:      u32,
    mode:     u16,
    used:     bool,
}

impl MemDirEntry {
    const fn empty() -> Self {
        Self { path: [0u8; PATH_CAP], path_len: 0, uid: 0, gid: 0, mode: 0o755, used: false }
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

/// Create a directory with default ownership (uid=0 gid=0 mode=0o755).
pub fn create(path: &[u8]) -> bool {
    create_owned(path, 0, 0, 0o755)
}

/// Create a directory with explicit uid/gid/mode.
pub fn create_owned(path: &[u8], uid: u32, gid: u32, mode: u16) -> bool {
    if path.len() >= PATH_CAP { return false; }
    DIR_LOCK.lock();
    let result = unsafe { store_create(path, uid, gid, mode) };
    DIR_LOCK.unlock();
    result
}

/// True if path is a user-created directory.
pub fn exists(path: &[u8]) -> bool {
    DIR_LOCK.lock();
    let result = unsafe { store_find(path).is_some() };
    DIR_LOCK.unlock();
    result
}

/// Get directory metadata (uid, gid, mode).
pub fn get_meta(path: &[u8]) -> Option<(u32, u32, u16)> {
    DIR_LOCK.lock();
    let result = unsafe {
        store_find(path).map(|i| {
            let e = &STORE[i];
            (e.uid, e.gid, e.mode)
        })
    };
    DIR_LOCK.unlock();
    result
}

/// Update only mode bits.
pub fn set_mode(path: &[u8], mode: u16) -> bool {
    DIR_LOCK.lock();
    let result = unsafe {
        match store_find(path) {
            Some(i) => { STORE[i].mode = mode; true }
            None    => false,
        }
    };
    DIR_LOCK.unlock();
    result
}

/// Update only owner (uid, gid).
pub fn set_owner(path: &[u8], uid: u32, gid: u32) -> bool {
    DIR_LOCK.lock();
    let result = unsafe {
        match store_find(path) {
            Some(i) => { STORE[i].uid = uid; STORE[i].gid = gid; true }
            None    => false,
        }
    };
    DIR_LOCK.unlock();
    result
}

/// Remove a directory entry. Returns true if found.
pub fn remove(path: &[u8]) -> bool {
    DIR_LOCK.lock();
    let result = unsafe {
        match store_find(path) {
            Some(i) => { STORE[i] = MemDirEntry::empty(); true }
            None    => false,
        }
    };
    DIR_LOCK.unlock();
    result
}

/// Remove all entries whose path starts with `prefix` (for recursive removal).
pub fn remove_recursive(prefix: &[u8]) -> usize {
    DIR_LOCK.lock();
    let mut count = 0;
    unsafe {
        for e in STORE.iter_mut() {
            if e.used && e.path[..e.path_len].starts_with(prefix) {
                *e = MemDirEntry::empty();
                count += 1;
            }
        }
    }
    DIR_LOCK.unlock();
    count
}

/// List all stored directory absolute paths. Returns count.
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

unsafe fn store_create(path: &[u8], uid: u32, gid: u32, mode: u16) -> bool {
    if store_find(path).is_some() { return false; }
    for e in STORE.iter_mut() {
        if !e.used {
            let n = path.len().min(PATH_CAP - 1);
            e.path[..n].copy_from_slice(&path[..n]);
            e.path_len = n;
            e.uid  = uid;
            e.gid  = gid;
            e.mode = mode;
            e.used = true;
            return true;
        }
    }
    false
}
