//! In-memory file store — persists files between commands within one session.
//!
//! Backed by a fixed static array (no heap).
//! Capacity: MAX_FILES files, each up to FILE_CAP bytes.
//!
//! Used by:
//!   echo > file   — writes captured command output
//!   nano Ctrl+O   — saves editor buffer
//!   vim :w        — saves editor buffer
//!   cat / vim     — reads previously written files
//!   virt_fs       — overlay: memfs is checked FIRST, then static content

use crate::kernel::sync::spinlock::SpinLock;

pub const MAX_FILES: usize = 16;
pub const PATH_CAP:  usize = 128;
pub const FILE_CAP:  usize = 4096;

struct MemFile {
    path:     [u8; PATH_CAP],
    path_len: usize,
    data:     [u8; FILE_CAP],
    data_len: usize,
    used:     bool,
}

impl MemFile {
    const fn empty() -> Self {
        Self {
            path:     [0u8; PATH_CAP],
            path_len: 0,
            data:     [0u8; FILE_CAP],
            data_len: 0,
            used:     false,
        }
    }
}

// ── Global store ──────────────────────────────────────────────────────────────

static     FS_LOCK: SpinLock                     = SpinLock::new();
static mut STORE:   [MemFile; MAX_FILES]          = [
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Write (create or overwrite) a file.
/// Returns false if the store is full or data is too large.
pub fn write(path: &[u8], data: &[u8]) -> bool {
    if path.len() > PATH_CAP || data.len() > FILE_CAP { return false; }
    FS_LOCK.lock();
    let result = unsafe { store_write(path, data) };
    FS_LOCK.unlock();
    result
}

/// Append data to an existing file, or create it.
pub fn append(path: &[u8], data: &[u8]) -> bool {
    FS_LOCK.lock();
    let result = unsafe { store_append(path, data) };
    FS_LOCK.unlock();
    result
}

/// Return a slice into the file's data, or None if not found.
///
/// Safety: caller must not hold the lock when calling this, and must
/// finish using the slice before the next write (which would change data).
/// In our single-threaded kernel this is safe.
pub fn read(path: &[u8]) -> Option<&'static [u8]> {
    FS_LOCK.lock();
    let result = unsafe { store_read(path) };
    FS_LOCK.unlock();
    result
}

/// True if the path exists in memfs.
pub fn exists(path: &[u8]) -> bool {
    FS_LOCK.lock();
    let result = unsafe { store_find(path).is_some() };
    FS_LOCK.unlock();
    result
}

/// List all stored file paths into `out`. Returns count.
pub fn list(out: &mut [&'static [u8]; MAX_FILES]) -> usize {
    FS_LOCK.lock();
    let mut n = 0;
    unsafe {
        for f in STORE.iter() {
            if f.used && n < MAX_FILES {
                // SAFETY: static lifetime, single-threaded
                out[n] = core::slice::from_raw_parts(f.path.as_ptr(), f.path_len);
                n += 1;
            }
        }
    }
    FS_LOCK.unlock();
    n
}

// ── Internals (called while lock is held) ────────────────────────────────────

unsafe fn store_find(path: &[u8]) -> Option<usize> {
    for (i, f) in STORE.iter().enumerate() {
        if f.used && &f.path[..f.path_len] == path {
            return Some(i);
        }
    }
    None
}

unsafe fn store_write(path: &[u8], data: &[u8]) -> bool {
    // Update existing slot if found
    if let Some(i) = store_find(path) {
        let f = &mut STORE[i];
        let n = data.len().min(FILE_CAP);
        f.data[..n].copy_from_slice(&data[..n]);
        f.data_len = n;
        return true;
    }
    // Find an empty slot
    for f in STORE.iter_mut() {
        if !f.used {
            let pn = path.len().min(PATH_CAP);
            let dn = data.len().min(FILE_CAP);
            f.path[..pn].copy_from_slice(&path[..pn]);
            f.path_len = pn;
            f.data[..dn].copy_from_slice(&data[..dn]);
            f.data_len = dn;
            f.used = true;
            return true;
        }
    }
    false // store full
}

unsafe fn store_append(path: &[u8], data: &[u8]) -> bool {
    if let Some(i) = store_find(path) {
        let f = &mut STORE[i];
        let space = FILE_CAP - f.data_len;
        let n = data.len().min(space);
        let start = f.data_len;
        f.data[start..start + n].copy_from_slice(&data[..n]);
        f.data_len += n;
        return true;
    }
    store_write(path, data)
}

unsafe fn store_read(path: &[u8]) -> Option<&'static [u8]> {
    if let Some(i) = store_find(path) {
        let f = &STORE[i];
        return Some(core::slice::from_raw_parts(f.data.as_ptr(), f.data_len));
    }
    None
}
