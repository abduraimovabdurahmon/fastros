//! Per-process file descriptor tables.

use crate::errno::{Errno, KResult};
use crate::fs::file::File;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub const MAX_FDS: usize = 1024;

#[derive(Clone)]
pub struct FdEntry {
    pub file: Arc<dyn File>,
    pub cloexec: bool,
}

#[derive(Clone, Default)]
pub struct FdTable {
    slots: Vec<Option<FdEntry>>,
}

impl FdTable {
    pub fn new() -> FdTable {
        FdTable { slots: Vec::new() }
    }

    /// Lowest free descriptor ≥ `min`.
    pub fn alloc(&mut self, file: Arc<dyn File>, cloexec: bool, min: usize) -> KResult<i32> {
        let fd = (min..MAX_FDS).find(|&i| self.slots.get(i).is_none_or(|s| s.is_none())).ok_or(Errno::EMFILE)?;
        self.set(fd, file, cloexec);
        Ok(fd as i32)
    }

    pub fn set(&mut self, fd: usize, file: Arc<dyn File>, cloexec: bool) {
        if self.slots.len() <= fd {
            self.slots.resize(fd + 1, None);
        }
        self.slots[fd] = Some(FdEntry { file, cloexec });
    }

    pub fn get(&self, fd: i32) -> KResult<Arc<dyn File>> {
        self.entry(fd).map(|e| e.file.clone())
    }

    pub fn entry(&self, fd: i32) -> KResult<&FdEntry> {
        if fd < 0 {
            return Err(Errno::EBADF);
        }
        self.slots.get(fd as usize).and_then(|s| s.as_ref()).ok_or(Errno::EBADF)
    }

    pub fn set_cloexec(&mut self, fd: i32, on: bool) -> KResult<()> {
        if fd < 0 {
            return Err(Errno::EBADF);
        }
        match self.slots.get_mut(fd as usize).and_then(|s| s.as_mut()) {
            Some(e) => {
                e.cloexec = on;
                Ok(())
            }
            None => Err(Errno::EBADF),
        }
    }

    pub fn close(&mut self, fd: i32) -> KResult<Arc<dyn File>> {
        if fd < 0 {
            return Err(Errno::EBADF);
        }
        let e = self.slots.get_mut(fd as usize).and_then(|s| s.take()).ok_or(Errno::EBADF)?;
        Ok(e.file)
    }

    /// `dup2(old, new)`.
    pub fn dup2(&mut self, old: i32, new: i32) -> KResult<i32> {
        let f = self.get(old)?;
        if new < 0 || new as usize >= MAX_FDS {
            return Err(Errno::EBADF);
        }
        if old != new {
            self.set(new as usize, f, false);
        }
        Ok(new)
    }

    /// Drop descriptors marked close-on-exec.
    pub fn close_on_exec(&mut self) {
        for s in self.slots.iter_mut() {
            if s.as_ref().is_some_and(|e| e.cloexec) {
                *s = None;
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (i32, &FdEntry)> {
        self.slots.iter().enumerate().filter_map(|(i, s)| s.as_ref().map(|e| (i as i32, e)))
    }

    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn clear(&mut self) {
        self.slots.clear();
    }
}
