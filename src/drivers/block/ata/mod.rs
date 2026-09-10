//! ATA/IDE PIO driver — primary channel only.
//!
//! Implements LBA28 sector read/write in polling (PIO) mode.
//! Used for the persistent data disk attached as IDE drive 0.
//!
//! Primary channel I/O ports:
//!   0x1F0 — data (16-bit r/w)
//!   0x1F1 — error (r) / features (w)
//!   0x1F2 — sector count
//!   0x1F3 — LBA low  [7:0]
//!   0x1F4 — LBA mid  [15:8]
//!   0x1F5 — LBA high [23:16]
//!   0x1F6 — drive/head (LBA mode bit + drive select + LBA[27:24])
//!   0x1F7 — status (r) / command (w)
//!
//! Linux equivalent: drivers/ata/libata-core.c  drivers/ide/ide-io.c

use crate::arch::x86_64::io::{inb, inw, outb, outw};

// ── I/O port base ─────────────────────────────────────────────────────────────

const DATA:    u16 = 0x1F0;
const SEC_CNT: u16 = 0x1F2;
const LBA_LO:  u16 = 0x1F3;
const LBA_MI:  u16 = 0x1F4;
const LBA_HI:  u16 = 0x1F5;
const DRIVE:   u16 = 0x1F6;
const STATUS:  u16 = 0x1F7;
const CMD:     u16 = 0x1F7;

// ── Status register bits ──────────────────────────────────────────────────────

const SR_BSY: u8 = 0x80;
const SR_DRQ: u8 = 0x08;
const SR_ERR: u8 = 0x01;

// ── ATA commands ──────────────────────────────────────────────────────────────

const CMD_READ:  u8 = 0x20;
const CMD_WRITE: u8 = 0x30;
const CMD_FLUSH: u8 = 0xE7;
const CMD_IDENT: u8 = 0xEC;

pub const SECTOR_SIZE: usize = 512;

static mut DISK_PRESENT: bool = false;

// ── Internal helpers ──────────────────────────────────────────────────────────

unsafe fn wait_not_busy(timeout: u32) -> bool {
    let mut t = timeout;
    while inb(STATUS) & SR_BSY != 0 {
        t = t.wrapping_sub(1);
        if t == 0 { return false; }
        core::hint::spin_loop();
    }
    true
}

unsafe fn wait_drq(timeout: u32) -> bool {
    let mut t = timeout;
    loop {
        let s = inb(STATUS);
        if s & SR_ERR != 0 { return false; }
        if s & SR_DRQ != 0 { return true; }
        t = t.wrapping_sub(1);
        if t == 0 { return false; }
        core::hint::spin_loop();
    }
}

unsafe fn select_lba28(lba: u32, sector_count: u8) {
    outb(DRIVE,   0xE0 | ((lba >> 24) & 0x0F) as u8);
    outb(SEC_CNT, sector_count);
    outb(LBA_LO,  (lba & 0xFF) as u8);
    outb(LBA_MI,  ((lba >> 8) & 0xFF) as u8);
    outb(LBA_HI,  ((lba >> 16) & 0xFF) as u8);
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Detect whether a disk is present on the primary IDE channel.
pub fn init() -> bool {
    unsafe {
        outb(DRIVE, 0xA0); // select master drive
        if !wait_not_busy(100_000) { return false; }
        outb(CMD, CMD_IDENT);
        let status = inb(STATUS);
        if status == 0 || status == 0xFF { return false; } // no drive
        if !wait_drq(100_000) { return false; }
        for _ in 0..256 { let _ = inw(DATA); } // consume IDENTIFY data
        DISK_PRESENT = true;
        true
    }
}

pub fn is_present() -> bool { unsafe { DISK_PRESENT } }

/// Read `count` sectors starting at LBA `lba` into `buf`.
pub fn read_sectors(lba: u32, count: u8, buf: &mut [u8]) -> bool {
    if !unsafe { DISK_PRESENT } { return false; }
    if buf.len() < count as usize * SECTOR_SIZE { return false; }
    unsafe {
        if !wait_not_busy(100_000) { return false; }
        select_lba28(lba, count);
        outb(CMD, CMD_READ);
        for s in 0..count as usize {
            if !wait_drq(100_000) { return false; }
            let off = s * SECTOR_SIZE;
            for i in 0..(SECTOR_SIZE / 2) {
                let w = inw(DATA);
                buf[off + i * 2]     = (w & 0xFF) as u8;
                buf[off + i * 2 + 1] = (w >> 8)   as u8;
            }
        }
    }
    true
}

/// Write `count` sectors starting at LBA `lba` from `buf`.
pub fn write_sectors(lba: u32, count: u8, buf: &[u8]) -> bool {
    if !unsafe { DISK_PRESENT } { return false; }
    if buf.len() < count as usize * SECTOR_SIZE { return false; }
    unsafe {
        if !wait_not_busy(100_000) { return false; }
        select_lba28(lba, count);
        outb(CMD, CMD_WRITE);
        for s in 0..count as usize {
            if !wait_drq(100_000) { return false; }
            let off = s * SECTOR_SIZE;
            for i in 0..(SECTOR_SIZE / 2) {
                let lo = buf[off + i * 2] as u16;
                let hi = buf[off + i * 2 + 1] as u16;
                outw(DATA, lo | (hi << 8));
            }
        }
        // Cache flush
        if !wait_not_busy(100_000) { return false; }
        outb(CMD, CMD_FLUSH);
        wait_not_busy(100_000);
    }
    true
}

/// Write zeros to a range of sectors.
pub fn zero_sectors(lba: u32, count: u32) -> bool {
    let buf = [0u8; SECTOR_SIZE];
    for i in 0..count {
        if !write_sectors(lba + i, 1, &buf) { return false; }
    }
    true
}
