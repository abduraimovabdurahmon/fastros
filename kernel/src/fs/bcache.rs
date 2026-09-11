//! Block cache: 4 KiB pages of a block device with read-ahead, LRU
//! eviction and write-back (dirty pages are flushed in sorted, coalesced
//! runs — by `sync`, by the periodic flusher, or under memory pressure).

use crate::drivers::block::BlockDevice;
use crate::sync::SpinLock;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const PAGE: usize = 4096;
const SECTORS_PER_PAGE: u64 = (PAGE / 512) as u64;
/// Pages fetched at once on a miss (128 KiB).
const READ_AHEAD: u64 = 32;
/// Longest run written in one device command (256 KiB).
const MAX_RUN: usize = 64;

static CACHED: AtomicUsize = AtomicUsize::new(0);
static DIRTY: AtomicUsize = AtomicUsize::new(0);

pub fn cached_bytes() -> u64 {
    (CACHED.load(Ordering::Relaxed) * PAGE) as u64
}
pub fn dirty_bytes() -> u64 {
    (DIRTY.load(Ordering::Relaxed) * PAGE) as u64
}

struct Page {
    data: Box<[u8; PAGE]>,
    dirty: bool,
    last_use: u64,
}

pub struct BlockCache {
    dev: Arc<dyn BlockDevice>,
    pages: BTreeMap<u64, Page>,
    capacity: usize,
    tick: u64,
    pages_total: u64,
}

#[derive(Debug)]
pub struct CacheError;

impl BlockCache {
    /// `capacity` in pages.
    pub fn new(dev: Arc<dyn BlockDevice>, capacity: usize) -> BlockCache {
        let pages_total = dev.sectors() / SECTORS_PER_PAGE;
        BlockCache { dev, pages: BTreeMap::new(), capacity: capacity.max(64), tick: 0, pages_total }
    }

    pub fn device(&self) -> &Arc<dyn BlockDevice> {
        &self.dev
    }

    pub fn size_bytes(&self) -> u64 {
        self.pages_total * PAGE as u64
    }

    fn touch(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Make sure page `idx` is cached (reading ahead on a miss).
    fn load(&mut self, idx: u64, need_data: bool) -> Result<(), CacheError> {
        if self.pages.contains_key(&idx) {
            return Ok(());
        }
        self.make_room(READ_AHEAD as usize)?;
        let t = self.touch();
        if !need_data {
            // Whole-page overwrite: no need to read the old contents.
            self.insert(idx, Box::new([0u8; PAGE]), t);
            return Ok(());
        }
        let mut n = 1;
        while n < READ_AHEAD && idx + n < self.pages_total && !self.pages.contains_key(&(idx + n)) {
            n += 1;
        }
        let mut buf = vec![0u8; n as usize * PAGE];
        self.dev.read(idx * SECTORS_PER_PAGE, &mut buf).map_err(|_| CacheError)?;
        for i in 0..n {
            let mut page = Box::new([0u8; PAGE]);
            page.copy_from_slice(&buf[i as usize * PAGE..(i as usize + 1) * PAGE]);
            // Read-ahead pages start "older" so they are evicted first if unused.
            self.insert(idx + i, page, if i == 0 { t } else { t.saturating_sub(1_000_000) });
        }
        Ok(())
    }

    fn insert(&mut self, idx: u64, data: Box<[u8; PAGE]>, last_use: u64) {
        if self.pages.insert(idx, Page { data, dirty: false, last_use }).is_none() {
            CACHED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Evict clean LRU pages (writing back dirty ones if needed) until
    /// `want` free slots exist.
    fn make_room(&mut self, want: usize) -> Result<(), CacheError> {
        if self.pages.len() + want <= self.capacity {
            return Ok(());
        }
        let excess = self.pages.len() + want - self.capacity;
        if self.pages.values().filter(|p| !p.dirty).count() < excess {
            self.writeback()?;
        }
        let mut clean: Vec<(u64, u64)> = self.pages.iter().filter(|(_, p)| !p.dirty).map(|(&k, p)| (p.last_use, k)).collect();
        clean.sort_unstable();
        for (_, k) in clean.into_iter().take(excess) {
            self.pages.remove(&k);
            CACHED.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), CacheError> {
        let mut done = 0;
        while done < buf.len() {
            let pos = offset + done as u64;
            let idx = pos / PAGE as u64;
            let po = (pos % PAGE as u64) as usize;
            let n = (PAGE - po).min(buf.len() - done);
            self.load(idx, true)?;
            let t = self.touch();
            let p = self.pages.get_mut(&idx).expect("loaded");
            p.last_use = t;
            buf[done..done + n].copy_from_slice(&p.data[po..po + n]);
            done += n;
        }
        Ok(())
    }

    pub fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), CacheError> {
        let mut done = 0;
        while done < buf.len() {
            let pos = offset + done as u64;
            let idx = pos / PAGE as u64;
            let po = (pos % PAGE as u64) as usize;
            let n = (PAGE - po).min(buf.len() - done);
            self.load(idx, n != PAGE)?;
            let t = self.touch();
            let p = self.pages.get_mut(&idx).expect("loaded");
            p.last_use = t;
            p.data[po..po + n].copy_from_slice(&buf[done..done + n]);
            if !p.dirty {
                p.dirty = true;
                DIRTY.fetch_add(1, Ordering::Relaxed);
            }
            done += n;
        }
        Ok(())
    }

    /// Write every dirty page back, in ascending order, coalescing runs.
    pub fn writeback(&mut self) -> Result<(), CacheError> {
        let dirty: Vec<u64> = self.pages.iter().filter(|(_, p)| p.dirty).map(|(&k, _)| k).collect();
        let mut i = 0;
        while i < dirty.len() {
            let start = dirty[i];
            let mut len = 1;
            while i + len < dirty.len() && dirty[i + len] == start + len as u64 && len < MAX_RUN {
                len += 1;
            }
            let mut buf = vec![0u8; len * PAGE];
            for j in 0..len {
                buf[j * PAGE..(j + 1) * PAGE].copy_from_slice(&self.pages[&(start + j as u64)].data[..]);
            }
            self.dev.write(start * SECTORS_PER_PAGE, &buf).map_err(|_| CacheError)?;
            for j in 0..len {
                if let Some(p) = self.pages.get_mut(&(start + j as u64)) {
                    p.dirty = false;
                    DIRTY.fetch_sub(1, Ordering::Relaxed);
                }
            }
            i += len;
            crate::sched::cond_resched();
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), CacheError> {
        self.writeback()?;
        self.dev.flush().map_err(|_| CacheError)
    }

    pub fn dirty_pages(&self) -> usize {
        self.pages.values().filter(|p| p.dirty).count()
    }

    /// Drop every clean page (after `sync`, or `echo 3 > drop_caches`).
    pub fn drop_clean(&mut self) {
        let before = self.pages.len();
        self.pages.retain(|_, p| p.dirty);
        CACHED.fetch_sub(before - self.pages.len(), Ordering::Relaxed);
    }
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        let dirty = self.dirty_pages();
        CACHED.fetch_sub(self.pages.len(), Ordering::Relaxed);
        DIRTY.fetch_sub(dirty, Ordering::Relaxed);
    }
}

/// Cache size for a new mount: an eighth of RAM, at least 4 MiB.
pub fn default_capacity() -> usize {
    let (managed, _) = crate::mm::frame::counts();
    (managed / 8).max(1024)
}

/// `fastros_ext2::Device` over a cache.
pub struct CachedDevice(pub BlockCache);

impl fastros_ext2::Device for CachedDevice {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> fastros_ext2::Result<()> {
        self.0.read(offset, buf).map_err(|_| fastros_ext2::Error::Io)
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> fastros_ext2::Result<()> {
        self.0.write(offset, buf).map_err(|_| fastros_ext2::Error::Io)
    }
    fn flush(&mut self) -> fastros_ext2::Result<()> {
        self.0.flush().map_err(|_| fastros_ext2::Error::Io)
    }
    fn size(&self) -> u64 {
        self.0.size_bytes()
    }
}

/// Every mounted filesystem registers here so `sync` and the flusher reach it.
static SYNCABLE: SpinLock<Vec<alloc::sync::Weak<dyn crate::fs::FileSystem>>> = SpinLock::new(Vec::new());

pub fn register_syncable(fs: &Arc<dyn crate::fs::FileSystem>) {
    SYNCABLE.lock().push(Arc::downgrade(fs));
}

/// `sync(2)`: write back every filesystem.
pub fn sync_all() {
    let list: Vec<Arc<dyn crate::fs::FileSystem>> = {
        let mut l = SYNCABLE.lock();
        l.retain(|w| w.strong_count() > 0);
        l.iter().filter_map(|w| w.upgrade()).collect()
    };
    for fs in list {
        if let Err(e) = fs.sync() {
            crate::kerr!("fs", "sync of {} failed: {}", fs.fs_type(), e);
        }
    }
}

/// Background writeback: dirty data reaches the disk within ~2 s.
pub fn start_flusher() {
    crate::sched::spawn("kflushd", || loop {
        crate::sched::sleep_ms(2000);
        if DIRTY.load(Ordering::Relaxed) > 0 {
            sync_all();
        }
    });
}
