//! ATA/IDE disks in PIO mode (LBA28 and LBA48), primary and secondary channel.
//!
//! Interrupts are masked at the drive (nIEN); every command polls status with
//! a deadline, checks ERR/DF, and long transfers are split into chunks with a
//! reschedule point between them so other tasks keep running.

use super::{BlockDevice, IoError, IoStats};
use crate::arch::port::{inb, insw, outb, outsw};
use crate::sync::Mutex;
use alloc::string::String;
use alloc::sync::Arc;

const SR_ERR: u8 = 0x01;
const SR_DRQ: u8 = 0x08;
const SR_DF: u8 = 0x20;
const SR_BSY: u8 = 0x80;

const CMD_READ_PIO: u8 = 0x20;
const CMD_READ_PIO_EXT: u8 = 0x24;
const CMD_WRITE_PIO: u8 = 0x30;
const CMD_WRITE_PIO_EXT: u8 = 0x34;
const CMD_FLUSH: u8 = 0xE7;
const CMD_FLUSH_EXT: u8 = 0xEA;
const CMD_IDENTIFY: u8 = 0xEC;

/// Sectors per command (keeps one transfer ≤ 128 KiB between resched points).
const CHUNK: u64 = 256;

struct Channel {
    io: u16,
    ctrl: u16,
}

pub struct AtaDisk {
    name: String,
    model: String,
    chan: Channel,
    slave: bool,
    lba48: bool,
    sectors: u64,
    lock: Mutex<()>,
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
        for _ in 0..2_000_000 {
            let s = self.alt_status();
            if s & SR_BSY == 0 {
                return Ok(s);
            }
            core::hint::spin_loop();
        }
        Err(IoError::Timeout)
    }
    fn wait_drq(&self) -> Result<(), IoError> {
        for _ in 0..2_000_000 {
            let s = self.alt_status();
            if s & SR_BSY == 0 {
                if s & (SR_ERR | SR_DF) != 0 {
                    return Err(IoError::Device);
                }
                if s & SR_DRQ != 0 {
                    return Ok(());
                }
            }
            core::hint::spin_loop();
        }
        Err(IoError::Timeout)
    }
}

impl AtaDisk {
    fn probe(io: u16, ctrl: u16, slave: bool, name: &str) -> Option<AtaDisk> {
        let chan = Channel { io, ctrl };
        unsafe {
            if inb(io + 7) == 0xFF {
                return None; // floating bus: no controller
            }
            outb(ctrl, 0x02); // nIEN: no interrupts from this channel
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
            Some(AtaDisk {
                name: String::from(name),
                model,
                chan,
                slave,
                lba48,
                sectors,
                lock: Mutex::new(()),
                stats: IoStats::default(),
            })
        }
    }

    fn command(&self, lba: u64, count: u64, write: bool) {
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
                outb(io + 7, if write { CMD_WRITE_PIO_EXT } else { CMD_READ_PIO_EXT });
            } else {
                outb(io + 6, 0xE0 | if self.slave { 0x10 } else { 0 } | ((lba >> 24) & 0x0F) as u8);
                outb(io + 2, count as u8);
                outb(io + 3, lba as u8);
                outb(io + 4, (lba >> 8) as u8);
                outb(io + 5, (lba >> 16) as u8);
                outb(io + 7, if write { CMD_WRITE_PIO } else { CMD_READ_PIO });
            }
        }
    }

    fn transfer(&self, lba: u64, sectors: u64, buf: *mut u8, write: bool) -> Result<(), IoError> {
        self.chan.wait_not_busy()?;
        self.command(lba, sectors, write);
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
        let _g = self.lock.lock();
        let start = crate::time::now_ns();
        let mut done = 0u64;
        while done < total {
            let n = (total - done).min(CHUNK);
            let p = unsafe { buf.add(done as usize * 512) };
            let r = self.transfer(lba + done, n, p, write);
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
        let _g = self.lock.lock();
        self.chan.wait_not_busy()?;
        unsafe {
            outb(self.chan.io + 6, if self.slave { 0xB0 } else { 0xA0 });
            outb(self.chan.io + 7, if self.lba48 { CMD_FLUSH_EXT } else { CMD_FLUSH });
        }
        self.chan.delay();
        let st = self.chan.wait_not_busy()?;
        self.stats.flushes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if st & (SR_ERR | SR_DF) != 0 {
            return Err(IoError::Device);
        }
        Ok(())
    }
    fn stats(&self) -> &IoStats {
        &self.stats
    }
}

/// Probe the four legacy positions and register the disks found.
pub fn init() {
    let positions = [
        (0x1F0, 0x3F6, false, "sda"),
        (0x1F0, 0x3F6, true, "sdb"),
        (0x170, 0x376, false, "sdc"),
        (0x170, 0x376, true, "sdd"),
    ];
    for (io, ctrl, slave, name) in positions {
        if let Some(d) = AtaDisk::probe(io, ctrl, slave, name) {
            super::register(Arc::new(d));
        }
    }
}
