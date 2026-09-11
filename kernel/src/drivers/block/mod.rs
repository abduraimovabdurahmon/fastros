//! Block devices: the contract filesystems use, a registry, and I/O stats.

pub mod ata;

use crate::sync::SpinLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    /// The device reported an error for this request.
    Device,
    /// The device did not respond in time.
    Timeout,
    /// Request outside the device or misaligned buffer.
    Invalid,
}

/// Per-device counters in the layout of `/proc/diskstats`.
#[derive(Default)]
pub struct IoStats {
    pub reads: AtomicU64,
    pub sectors_read: AtomicU64,
    pub read_ns: AtomicU64,
    pub writes: AtomicU64,
    pub sectors_written: AtomicU64,
    pub write_ns: AtomicU64,
    pub flushes: AtomicU64,
    pub busy_ns: AtomicU64,
}

impl IoStats {
    pub fn account(&self, write: bool, sectors: u64, ns: u64) {
        if write {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.sectors_written.fetch_add(sectors, Ordering::Relaxed);
            self.write_ns.fetch_add(ns, Ordering::Relaxed);
        } else {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.sectors_read.fetch_add(sectors, Ordering::Relaxed);
            self.read_ns.fetch_add(ns, Ordering::Relaxed);
        }
        self.busy_ns.fetch_add(ns, Ordering::Relaxed);
    }
}

pub trait BlockDevice: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    /// Always 512 for the devices we drive.
    fn sector_size(&self) -> usize {
        512
    }
    fn sectors(&self) -> u64;
    /// Read `buf.len() / 512` sectors starting at `lba`.
    fn read(&self, lba: u64, buf: &mut [u8]) -> Result<(), IoError>;
    fn write(&self, lba: u64, buf: &[u8]) -> Result<(), IoError>;
    /// Make every completed write durable.
    fn flush(&self) -> Result<(), IoError>;
    fn stats(&self) -> &IoStats;
}

static DEVICES: SpinLock<Vec<Arc<dyn BlockDevice>>> = SpinLock::new(Vec::new());

pub fn register(d: Arc<dyn BlockDevice>) {
    crate::kinfo!("block", "{}: {} ({} MiB)", d.name(), d.model(), d.sectors() * 512 >> 20);
    DEVICES.lock().push(d);
}

pub fn get(name: &str) -> Option<Arc<dyn BlockDevice>> {
    DEVICES.lock().iter().find(|d| d.name() == name).cloned()
}

pub fn all() -> Vec<Arc<dyn BlockDevice>> {
    DEVICES.lock().clone()
}

pub fn names() -> Vec<String> {
    DEVICES.lock().iter().map(|d| String::from(d.name())).collect()
}
