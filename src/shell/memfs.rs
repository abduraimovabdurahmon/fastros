//! In-memory file store — persists files between commands within one session.
//!
//! Backed by a fixed static array (no heap).
//! Capacity: MAX_FILES files, each up to FILE_CAP bytes.
//!
//! Each file carries Unix-style metadata: uid, gid, mode (permission bits).
//! Default for new files: uid=0, gid=0, mode=0o644 (rw-r--r--).

use crate::kernel::sync::spinlock::SpinLock;

pub const MAX_FILES: usize = 16;
pub const PATH_CAP:  usize = 128;
pub const FILE_CAP:  usize = 4096;

struct MemFile {
    path:     [u8; PATH_CAP],
    path_len: usize,
    data:     [u8; FILE_CAP],
    data_len: usize,
    uid:      u32,
    gid:      u32,
    mode:     u16,   // lower 9 bits = rwxrwxrwx
    used:     bool,
}

impl MemFile {
    const fn empty() -> Self {
        Self {
            path: [0u8; PATH_CAP], path_len: 0,
            data: [0u8; FILE_CAP], data_len: 0,
            uid: 0, gid: 0,
            mode: 0o644,
            used: false,
        }
    }
}

static     FS_LOCK: SpinLock                     = SpinLock::new();
static mut STORE:   [MemFile; MAX_FILES]          = [
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
    MemFile::empty(), MemFile::empty(), MemFile::empty(), MemFile::empty(),
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Write (create or overwrite) a file with default ownership (uid=0 gid=0 mode=0o644).
/// Returns false if the store is full or data is too large.
pub fn write(path: &[u8], data: &[u8]) -> bool {
    write_owned(path, data, 0, 0, 0o644)
}

/// Write a file with explicit uid/gid/mode metadata.
pub fn write_owned(path: &[u8], data: &[u8], uid: u32, gid: u32, mode: u16) -> bool {
    if path.len() > PATH_CAP || data.len() > FILE_CAP { return false; }
    FS_LOCK.lock();
    let result = unsafe { store_write(path, data, uid, gid, mode) };
    FS_LOCK.unlock();
    // Persist to disk (no-op if ATA disk not present)
    if result {
        crate::fs::diskfs::persist_file(path, data);
    }
    result
}

/// Append data to an existing file, or create it (uid=0 gid=0 mode=0o644).
pub fn append(path: &[u8], data: &[u8]) -> bool {
    FS_LOCK.lock();
    let result = unsafe { store_append(path, data) };
    FS_LOCK.unlock();
    result
}

/// Return a slice into the file's data, or None if not found.
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

/// Get file metadata (uid, gid, mode). Returns None if not found.
pub fn get_meta(path: &[u8]) -> Option<(u32, u32, u16)> {
    FS_LOCK.lock();
    let result = unsafe {
        store_find(path).map(|i| {
            let f = &STORE[i];
            (f.uid, f.gid, f.mode)
        })
    };
    FS_LOCK.unlock();
    result
}

/// Get file size in bytes. Returns None if not found.
pub fn get_size(path: &[u8]) -> Option<usize> {
    FS_LOCK.lock();
    let result = unsafe {
        store_find(path).map(|i| STORE[i].data_len)
    };
    FS_LOCK.unlock();
    result
}

/// Update metadata (uid, gid, mode) of an existing file.
pub fn set_meta(path: &[u8], uid: u32, gid: u32, mode: u16) -> bool {
    FS_LOCK.lock();
    let result = unsafe {
        match store_find(path) {
            Some(i) => { STORE[i].uid = uid; STORE[i].gid = gid; STORE[i].mode = mode; true }
            None    => false,
        }
    };
    FS_LOCK.unlock();
    result
}

/// Update only the mode bits of an existing file.
pub fn set_mode(path: &[u8], mode: u16) -> bool {
    FS_LOCK.lock();
    let result = unsafe {
        match store_find(path) {
            Some(i) => { STORE[i].mode = mode; true }
            None    => false,
        }
    };
    FS_LOCK.unlock();
    result
}

/// Update only the owner (uid, gid) of an existing file.
pub fn set_owner(path: &[u8], uid: u32, gid: u32) -> bool {
    FS_LOCK.lock();
    let result = unsafe {
        match store_find(path) {
            Some(i) => { STORE[i].uid = uid; STORE[i].gid = gid; true }
            None    => false,
        }
    };
    FS_LOCK.unlock();
    result
}

/// Remove a file from the store. Returns true if found and removed.
pub fn remove(path: &[u8]) -> bool {
    FS_LOCK.lock();
    let result = unsafe {
        match store_find(path) {
            Some(i) => { STORE[i] = MemFile::empty(); true }
            None    => false,
        }
    };
    FS_LOCK.unlock();
    if result {
        crate::fs::diskfs::remove(path);
    }
    result
}

/// List all stored file paths into `out`. Returns count.
pub fn list(out: &mut [&'static [u8]; MAX_FILES]) -> usize {
    FS_LOCK.lock();
    let mut n = 0;
    unsafe {
        for f in STORE.iter() {
            if f.used && n < MAX_FILES {
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

unsafe fn store_write(path: &[u8], data: &[u8], uid: u32, gid: u32, mode: u16) -> bool {
    if let Some(i) = store_find(path) {
        let f = &mut STORE[i];
        let n = data.len().min(FILE_CAP);
        f.data[..n].copy_from_slice(&data[..n]);
        f.data_len = n;
        // Don't change ownership on overwrite (only chmod/chown does that)
        return true;
    }
    for f in STORE.iter_mut() {
        if !f.used {
            let pn = path.len().min(PATH_CAP);
            let dn = data.len().min(FILE_CAP);
            f.path[..pn].copy_from_slice(&path[..pn]);
            f.path_len = pn;
            f.data[..dn].copy_from_slice(&data[..dn]);
            f.data_len = dn;
            f.uid  = uid;
            f.gid  = gid;
            f.mode = mode;
            f.used = true;
            return true;
        }
    }
    false
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
    store_write(path, data, 0, 0, 0o644)
}

unsafe fn store_read(path: &[u8]) -> Option<&'static [u8]> {
    if let Some(i) = store_find(path) {
        let f = &STORE[i];
        return Some(core::slice::from_raw_parts(f.data.as_ptr(), f.data_len));
    }
    None
}
