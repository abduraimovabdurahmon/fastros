//! ATA/IDE disks (LBA28 and LBA48) on the legacy primary and secondary
//! channels, with PCI bus-master DMA where the controller offers it and PIO
//! as the fallback.
//!
//! Interrupts are masked at the drive (nIEN); every command polls status with
//! a deadline and checks ERR/DF. The two drives of a channel share its task
//! file, so all I/O on a channel is serialized by the channel's lock. Long
//! transfers are split into chunks with a reschedule point between them.
//!
//! DMA goes through one physically contiguous 128 KiB bounce buffer per
//! channel: QEMU (and real hardware) then moves a whole chunk per command
//! instead of one 512-byte PIO block per DRQ, which is ~20x faster under TCG.

use super::{BlockDevice, IoError, IoStats};
use crate::arch::port::{inb, insw, outb, outl, outsw};
use crate::mm::dma::DmaBuffer;
use crate::sync::Mutex;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

const SR_ERR: u8 = 0x01;
const SR_DRQ: u8 = 0x08;
const SR_DF: u8 = 0x20;
const SR_BSY: u8 = 0x80;

const CMD_READ_PIO: u8 = 0x20;
const CMD_READ_PIO_EXT: u8 = 0x24;
const CMD_WRITE_PIO: u8 = 0x30;
const CMD_WRITE_PIO_EXT: u8 = 0x34;
const CMD_READ_DMA: u8 = 0xC8;
const CMD_READ_DMA_EXT: u8 = 0x25;
const CMD_WRITE_DMA: u8 = 0xCA;
const CMD_WRITE_DMA_EXT: u8 = 0x35;
const CMD_FLUSH: u8 = 0xE7;
const CMD_FLUSH_EXT: u8 = 0xEA;
const CMD_IDENTIFY: u8 = 0xEC;

/// Sectors per command: 128 KiB, the size of the DMA bounce buffer.
const CHUNK: u64 = 256;
const CHUNK_BYTES: usize = CHUNK as usize * 512;
/// Longest a single command may take before we call the device dead.
const TIMEOUT_NS: u64 = 10_000_000_000;

// Bus-master IDE registers (offsets from the channel's BMIBA).
const BM_CMD: u16 = 0;
const BM_STATUS: u16 = 2;
const BM_PRDT: u16 = 4;
const BM_CMD_START: u8 = 0x01;
/// Direction bit: set = device to memory (a disk read).
const BM_CMD_READ: u8 = 0x08;
const BM_ST_ACTIVE: u8 = 0x01;
const BM_ST_ERR: u8 = 0x02;
const BM_ST_IRQ: u8 = 0x04;

/// Bus-master DMA resources of one channel.
struct BusMaster {
    base: u16,
    /// Physical Region Descriptor table (one page, 4-byte aligned).
    prdt: DmaBuffer,
    /// Bounce buffer, naturally aligned so no 64 KiB PRD boundary is crossed.
    buf: DmaBuffer,
}

/// One IDE channel: task-file ports, its lock, optional bus master.
struct Channel {
    io: u16,
    ctrl: u16,
    lock: Mutex<()>,
    bm: Option<BusMaster>,
}

pub struct AtaDisk {
    name: String,
    model: String,
    chan: Arc<Channel>,
    slave: bool,
    lba48: bool,
    sectors: u64,
    /// DMA is used while this is set; cleared after a DMA failure.
    dma: AtomicBool,
    stats: IoStats,
}

impl Channel {
    fn status(&self) -> u8 {
        unsafe { inb(self.io + 7) }
    }
    fn alt_status(&self) -> u8 {
        unsafe { inb(self.ctrl) }
    }
    /// ~400 ns: four reads of the alternate status register.
    fn delay(&self) {
        for _ in 0..4 {
            self.alt_status();
        }
    }
    fn wait_not_busy(&self) -> Result<u8, IoError> {
        let deadline = crate::time::now_ns() + TIMEOUT_NS;
        let mut spins = 0u32;
        loop {
            let s = self.alt_status();
            if s & SR_BSY == 0 {
                return Ok(s);
            }
            spins += 1;
            if spins % 1024 == 0 && crate::time::now_ns() > deadline {
                return Err(IoError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
    fn wait_drq(&self) -> Result<(), IoError> {
        let deadline = crate::time::now_ns() + TIMEOUT_NS;
        let mut spins = 0u32;
        loop {
            let s = self.alt_status();
            if s & SR_BSY == 0 {
                if s & (SR_ERR | SR_DF) != 0 {
                    return Err(IoError::Device);
                }
                if s & SR_DRQ != 0 {
                    return Ok(());
                }
            }
            spins += 1;
            if spins % 1024 == 0 && crate::time::now_ns() > deadline {
                return Err(IoError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
}

impl BusMaster {
    fn new(base: u16) -> Option<BusMaster> {
        let prdt = DmaBuffer::new(4096)?;
        let buf = DmaBuffer::new(CHUNK_BYTES)?;
        // PRD entries hold 32-bit physical addresses.
        let end = buf.phys() + buf.len() as u64;
        if end > u32::MAX as u64 || prdt.phys() + 4096 > u32::MAX as u64 {
            return None;
        }
        Some(BusMaster { base, prdt, buf })
    }

    /// Describe the first `bytes` of the bounce buffer, in ≤64 KiB pieces.
    fn fill_prdt(&self, bytes: usize) {
        let table = self.prdt.as_ptr() as *mut u32;
        let mut off = 0usize;
        let mut i = 0usize;
        while off < bytes {
            let n = (bytes - off).min(65536);
            let last = off + n >= bytes;
            unsafe {
                table.add(2 * i).write_volatile((self.buf.phys() + off as u64) as u32);
                // A count of 0 means 64 KiB; bit 31 marks the last entry.
                table.add(2 * i + 1).write_volatile((n as u32 & 0xFFFF) | if last { 0x8000_0000 } else { 0 });
            }
            off += n;
            i += 1;
        }
    }
    fn reg(&self, r: u16) -> u8 {
        unsafe { inb(self.base + r) }
    }
    fn set(&self, r: u16, v: u8) {
        unsafe { outb(self.base + r, v) }
    }
}

impl AtaDisk {
    fn probe(chan: &Arc<Channel>, slave: bool, name: &str) -> Option<AtaDisk> {
        let io = chan.io;
        unsafe {
            if inb(io + 7) == 0xFF {
                return None; // floating bus: no controller
            }
            outb(chan.ctrl, 0x02); // nIEN: no interrupts from this channel
            outb(io + 6, if slave { 0xB0 } else { 0xA0 });
            chan.delay();
            outb(io + 2, 0);
            outb(io + 3, 0);
            outb(io + 4, 0);
            outb(io + 5, 0);
            outb(io + 7, CMD_IDENTIFY);
            chan.delay();
            if chan.status() == 0 {
                return None; // no drive
            }
            chan.wait_not_busy().ok()?;
            // ATAPI/SATA signatures: not an ATA disk.
            if inb(io + 4) != 0 || inb(io + 5) != 0 {
                return None;
            }
            chan.wait_drq().ok()?;
            let mut id = [0u16; 256];
            insw(io, &mut id);
            let lba48 = id[83] & (1 << 10) != 0;
            let sectors = if lba48 {
                id[100] as u64 | (id[101] as u64) << 16 | (id[102] as u64) << 32 | (id[103] as u64) << 48
            } else {
                id[60] as u64 | (id[61] as u64) << 16
            };
            let mut model = String::new();
            for w in &id[27..47] {
                model.push((w >> 8) as u8 as char);
                model.push((w & 0xFF) as u8 as char);
            }
            let model = String::from(model.trim());
            let dma_capable = id[49] & (1 << 8) != 0 && chan.bm.is_some();
            Some(AtaDisk {
                name: String::from(name),
                model,
                chan: chan.clone(),
                slave,
                lba48,
                sectors,
                dma: AtomicBool::new(dma_capable),
                stats: IoStats::default(),
            })
        }
    }

    /// Load the task file and issue `cmd` (LBA48 `ext` or LBA28 form).
    fn command(&self, lba: u64, count: u64, cmd28: u8, cmd48: u8) {
        let io = self.chan.io;
        unsafe {
            if self.lba48 {
                outb(io + 6, 0x40 | if self.slave { 0x10 } else { 0 });
                outb(io + 2, (count >> 8) as u8);
                outb(io + 3, (lba >> 24) as u8);
                outb(io + 4, (lba >> 32) as u8);
                outb(io + 5, (lba >> 40) as u8);
                outb(io + 2, count as u8);
                outb(io + 3, lba as u8);
                outb(io + 4, (lba >> 8) as u8);
                outb(io + 5, (lba >> 16) as u8);
                outb(io + 7, cmd48);
            } else {
                outb(io + 6, 0xE0 | if self.slave { 0x10 } else { 0 } | ((lba >> 24) & 0x0F) as u8);
                outb(io + 2, count as u8);
                outb(io + 3, lba as u8);
                outb(io + 4, (lba >> 8) as u8);
                outb(io + 5, (lba >> 16) as u8);
                outb(io + 7, cmd28);
            }
        }
    }

    fn transfer_pio(&self, lba: u64, sectors: u64, buf: *mut u8, write: bool) -> Result<(), IoError> {
        self.chan.wait_not_busy()?;
        if write {
            self.command(lba, sectors, CMD_WRITE_PIO, CMD_WRITE_PIO_EXT);
        } else {
            self.command(lba, sectors, CMD_READ_PIO, CMD_READ_PIO_EXT);
        }
        self.chan.delay();
        for s in 0..sectors as usize {
            self.chan.wait_drq()?;
            let words = unsafe { core::slice::from_raw_parts_mut(buf.add(s * 512) as *mut u16, 256) };
            unsafe {
                if write {
                    outsw(self.chan.io, words);
                } else {
                    insw(self.chan.io, words);
                }
            }
            self.chan.delay();
        }
        let st = self.chan.wait_not_busy()?;
        if st & (SR_ERR | SR_DF) != 0 {
            return Err(IoError::Device);
        }
        Ok(())
    }

    fn transfer_dma(&self, bm: &BusMaster, lba: u64, sectors: u64, buf: *mut u8, write: bool) -> Result<(), IoError> {
        let bytes = sectors as usize * 512;
        debug_assert!(bytes <= bm.buf.len());
        if write {
            unsafe { core::ptr::copy_nonoverlapping(buf, bm.buf.as_ptr(), bytes) };
        }
        bm.fill_prdt(bytes);
        let dir = if write { 0 } else { BM_CMD_READ };
        bm.set(BM_CMD, dir); // stopped, direction set
        unsafe { outl(bm.base + BM_PRDT, bm.prdt.phys() as u32) };
        bm.set(BM_STATUS, bm.reg(BM_STATUS) | BM_ST_ERR | BM_ST_IRQ); // write-1-to-clear
        self.chan.wait_not_busy()?;
        if write {
            self.command(lba, sectors, CMD_WRITE_DMA, CMD_WRITE_DMA_EXT);
        } else {
            self.command(lba, sectors, CMD_READ_DMA, CMD_READ_DMA_EXT);
        }
        bm.set(BM_CMD, dir | BM_CMD_START);
        let deadline = crate::time::now_ns() + TIMEOUT_NS;
        let mut spins = 0u32;
        let result = loop {
            let s = bm.reg(BM_STATUS);
            if s & BM_ST_ERR != 0 {
                break Err(IoError::Device);
            }
            if s & BM_ST_ACTIVE == 0 {
                break Ok(());
            }
            spins += 1;
            if spins % 256 == 0 {
                if crate::time::now_ns() > deadline {
                    break Err(IoError::Timeout);
                }
                // The transfer runs without the CPU: let others use it.
                crate::sched::cond_resched();
            }
            core::hint::spin_loop();
        };
        bm.set(BM_CMD, dir); // clear START (also on error)
        let st = self.chan.wait_not_busy()?;
        result?;
        if st & (SR_ERR | SR_DF) != 0 {
            return Err(IoError::Device);
        }
        if !write {
            unsafe { core::ptr::copy_nonoverlapping(bm.buf.as_ptr(), buf, bytes) };
        }
        Ok(())
    }

    fn transfer(&self, lba: u64, sectors: u64, buf: *mut u8, write: bool) -> Result<(), IoError> {
        if let (true, Some(bm)) = (self.dma.load(Ordering::Relaxed), self.chan.bm.as_ref()) {
            match self.transfer_dma(bm, lba, sectors, buf, write) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // Never trust DMA again on this disk; retry the chunk by PIO.
                    crate::kerr!("ata", "{}: DMA {:?} at lba {}; falling back to PIO", self.name, e, lba);
                    self.dma.store(false, Ordering::Relaxed);
                }
            }
        }
        self.transfer_pio(lba, sectors, buf, write)
    }

    fn rw(&self, lba: u64, buf: *mut u8, len: usize, write: bool) -> Result<(), IoError> {
        if len % 512 != 0 || buf as usize % 2 != 0 {
            return Err(IoError::Invalid);
        }
        let total = (len / 512) as u64;
        if lba.checked_add(total).is_none_or(|end| end > self.sectors) {
            return Err(IoError::Invalid);
        }
        if !self.lba48 && lba + total > (1 << 28) {
            return Err(IoError::Invalid);
        }
        let start = crate::time::now_ns();
        let mut done = 0u64;
        while done < total {
            let n = (total - done).min(CHUNK);
            let p = unsafe { buf.add(done as usize * 512) };
            let r = {
                let _g = self.chan.lock.lock();
                self.transfer(lba + done, n, p, write)
            };
            if r.is_err() {
                crate::kerr!("ata", "{}: {} error at lba {} (+{})", self.name, if write { "write" } else { "read" }, lba + done, n);
                return r;
            }
            done += n;
            crate::sched::cond_resched();
        }
        self.stats.account(write, total, crate::time::now_ns() - start);
        Ok(())
    }
}

impl BlockDevice for AtaDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.rw(lba, buf.as_mut_ptr(), buf.len(), false)
    }
    fn write(&self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        self.rw(lba, buf.as_ptr() as *mut u8, buf.len(), true)
    }
    fn flush(&self) -> Result<(), IoError> {
        let _g = self.chan.lock.lock();
        self.chan.wait_not_busy()?;
        unsafe {
            outb(self.chan.io + 6, if self.slave { 0xB0 } else { 0xA0 });
            outb(self.chan.io + 7, if self.lba48 { CMD_FLUSH_EXT } else { CMD_FLUSH });
        }
        self.chan.delay();
        let st = self.chan.wait_not_busy()?;
        self.stats.flushes.fetch_add(1, Ordering::Relaxed);
        if st & (SR_ERR | SR_DF) != 0 {
            return Err(IoError::Device);
        }
        Ok(())
    }
    fn stats(&self) -> &IoStats {
        &self.stats
    }
}

/// Bus-master base of the PCI IDE controller (BAR4), with bus mastering on.
fn bus_master_base() -> Option<u16> {
    let dev = crate::drivers::pci::find_class(0x01, 0x01)?;
    if dev.prog_if & 0x80 == 0 {
        return None; // not bus-master capable
    }
    match dev.bars[4] {
        crate::drivers::pci::Bar::Io(base) if base != 0 => {
            dev.enable();
            Some(base)
        }
        _ => None,
    }
}

/// Probe the four legacy positions and register the disks found.
pub fn init() {
    let bmiba = bus_master_base();
    for (idx, (io, ctrl)) in [(0x1F0u16, 0x3F6u16), (0x170, 0x376)].into_iter().enumerate() {
        let bm = bmiba.and_then(|b| BusMaster::new(b + 8 * idx as u16));
        let chan = Arc::new(Channel { io, ctrl, lock: Mutex::new(()), bm });
        for (slave, name) in [(false, 2 * idx), (true, 2 * idx + 1)] {
            let dev_name = alloc::format!("sd{}", (b'a' + name as u8) as char);
            if let Some(d) = AtaDisk::probe(&chan, slave, &dev_name) {
                let mode = if d.dma.load(Ordering::Relaxed) { "DMA" } else { "PIO" };
                crate::kinfo!("ata", "{}: {} mode, {} sectors{}", d.name, mode, d.sectors, if d.lba48 { ", LBA48" } else { "" });
                super::register(Arc::new(d));
            }
        }
    }
}
