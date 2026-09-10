//! File Descriptor Table
//!
//! Each process has one FdTable with up to MAX_FDS open descriptors.
//! FD 0 = stdin, 1 = stdout, 2 = stderr (set up by default for init).

pub const MAX_FDS: usize = 256;

#[derive(Clone, Copy)]
pub enum FdKind {
    Closed,
    Stdin,
    Stdout,
    Stderr,
    /// Regular file — index into the global inode table.
    File { inode_idx: u32, read: bool, write: bool },
    /// Pipe — index into the global pipe table + which end.
    Pipe { pipe_idx: u32, is_read_end: bool },
}

#[derive(Clone, Copy)]
pub struct FdEntry {
    pub kind:   FdKind,
    pub offset: u64,
    pub flags:  u32,
}

impl FdEntry {
    const fn closed() -> Self {
        Self { kind: FdKind::Closed, offset: 0, flags: 0 }
    }
}

#[derive(Clone, Copy)]
pub struct FdTable {
    entries: [FdEntry; MAX_FDS],
}

impl FdTable {
    /// New table with stdin/stdout/stderr pre-opened.
    pub const fn new_init() -> Self {
        let mut t = Self { entries: [FdEntry::closed(); MAX_FDS] };
        t.entries[0] = FdEntry { kind: FdKind::Stdin,  offset: 0, flags: 0 };
        t.entries[1] = FdEntry { kind: FdKind::Stdout, offset: 0, flags: 0 };
        t.entries[2] = FdEntry { kind: FdKind::Stderr, offset: 0, flags: 0 };
        t
    }

    /// Empty table (all closed).
    pub const fn new_empty() -> Self {
        Self { entries: [FdEntry::closed(); MAX_FDS] }
    }

    /// Allocate the lowest free FD.  Returns the FD number or None if table is full.
    pub fn alloc(&mut self, kind: FdKind) -> Option<usize> {
        for (i, e) in self.entries.iter_mut().enumerate() {
            if matches!(e.kind, FdKind::Closed) {
                *e = FdEntry { kind, offset: 0, flags: 0 };
                return Some(i);
            }
        }
        None
    }

    /// Close a file descriptor.  Returns false if it was already closed.
    pub fn close(&mut self, fd: usize) -> bool {
        if fd >= MAX_FDS { return false; }
        if matches!(self.entries[fd].kind, FdKind::Closed) { return false; }
        self.entries[fd] = FdEntry::closed();
        true
    }

    /// Get a reference to a descriptor.
    pub fn get(&self, fd: usize) -> Option<&FdEntry> {
        if fd >= MAX_FDS { return None; }
        match self.entries[fd].kind {
            FdKind::Closed => None,
            _ => Some(&self.entries[fd]),
        }
    }

    /// Get a mutable reference to a descriptor.
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FdEntry> {
        if fd >= MAX_FDS { return None; }
        match self.entries[fd].kind {
            FdKind::Closed => None,
            _ => Some(&mut self.entries[fd]),
        }
    }

    /// Duplicate (clone) this table for fork().
    pub fn fork_copy(&self) -> Self {
        *self
    }
}
