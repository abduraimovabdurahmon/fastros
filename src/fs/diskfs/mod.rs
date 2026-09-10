//! DiskFS — simple flat filesystem on the ATA data disk.
//!
//! Layout (1 MB disk, 2048 sectors × 512 bytes):
//!
//!   Sector 0:       Superblock  (magic, version, entry count)
//!   Sectors 1–64:   Directory table (64 entries, 1 sector each)
//!   Sectors 65+:    File data  (variable length, 8-sector pages)
//!
//! Each directory entry (512 bytes):
//!   [0..4]   magic  u32  = 0xFADE_CAFE
//!   [4]      flags  u8   = 0x01 valid | 0x02 directory
//!   [5..9]   size   u32  = byte count of file data
//!   [9..13]  start  u32  = first data sector
//!   [13]     nlen   u8   = length of name
//!   [14..78] name   [u8; 64]
//!
//! On boot: scan directory → populate shell::memfs and shell::memdir.
//! On write: persist new/updated entries and data back to disk.
//!
//! Max files: 64.  Max file size: ~960 KB.

use crate::drivers::block::ata;

// ── On-disk constants ─────────────────────────────────────────────────────────

const MAGIC_SUPER: u32 = 0xFA57_0500; // "FAST OS"
const MAGIC_ENTRY: u32 = 0xFADE_CAFE;
const VERSION: u8 = 1;

const SUPER_SECTOR:   u32 = 0;
const DIR_START:      u32 = 1;         // sectors 1..64
const DIR_ENTRIES:    usize = 64;
const DATA_START:     u32 = 65;        // sectors 65+
const PAGE_SECTORS:   u32 = 8;         // 8 sectors = 4 KB per file page
const MAX_FILE_BYTES: usize = 128 * 4096; // 512 KB per file

pub const FLAG_VALID: u8 = 0x01;
pub const FLAG_DIR:   u8 = 0x02;

// ── Sector scratch buffers ────────────────────────────────────────────────────

static mut SECTOR_BUF: [u8; ata::SECTOR_SIZE] = [0u8; ata::SECTOR_SIZE];

// ── On-disk structures (parsed from raw bytes) ────────────────────────────────

#[derive(Copy, Clone)]
pub struct DirEntry {
    pub flags: u8,
    pub size:  u32,
    pub start: u32,     // first data sector
    pub nlen:  u8,
    pub name:  [u8; 64],
}

impl DirEntry {
    pub fn name_bytes(&self) -> &[u8] { &self.name[..self.nlen as usize] }
    pub fn is_valid(&self)     -> bool { self.flags & FLAG_VALID != 0 }
    pub fn is_dir(&self)       -> bool { self.flags & FLAG_DIR   != 0 }
}

fn parse_entry(buf: &[u8]) -> Option<DirEntry> {
    if buf.len() < 78 { return None; }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != MAGIC_ENTRY { return None; }
    let flags = buf[4];
    if flags & FLAG_VALID == 0 { return None; }
    let size  = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
    let start = u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]);
    let nlen  = buf[13].min(64);
    let mut name = [0u8; 64];
    name[..nlen as usize].copy_from_slice(&buf[14..14 + nlen as usize]);
    Some(DirEntry { flags, size, start, nlen, name })
}

fn write_entry_to_buf(buf: &mut [u8; ata::SECTOR_SIZE], e: &DirEntry) {
    buf.fill(0);
    buf[0..4].copy_from_slice(&MAGIC_ENTRY.to_le_bytes());
    buf[4]   = e.flags;
    buf[5..9].copy_from_slice(&e.size.to_le_bytes());
    buf[9..13].copy_from_slice(&e.start.to_le_bytes());
    buf[13]  = e.nlen;
    let n = e.nlen as usize;
    buf[14..14 + n].copy_from_slice(&e.name[..n]);
}

// ── Superblock ────────────────────────────────────────────────────────────────

fn read_superblock() -> (bool, u32) {
    let mut buf = [0u8; ata::SECTOR_SIZE];
    if !ata::read_sectors(SUPER_SECTOR, 1, &mut buf) { return (false, 0); }
    let magic   = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let version = buf[4];
    let count   = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
    if magic == MAGIC_SUPER && version == VERSION {
        (true, count)
    } else {
        (false, 0)
    }
}

fn write_superblock(count: u32) {
    let mut buf = [0u8; ata::SECTOR_SIZE];
    buf[0..4].copy_from_slice(&MAGIC_SUPER.to_le_bytes());
    buf[4] = VERSION;
    buf[5..9].copy_from_slice(&count.to_le_bytes());
    ata::write_sectors(SUPER_SECTOR, 1, &buf);
}

// ── Next free data sector tracking ────────────────────────────────────────────

static mut NEXT_DATA_SECTOR: u32 = DATA_START;

fn scan_next_data_sector() -> u32 {
    let mut max_end = DATA_START;
    let mut buf = [0u8; ata::SECTOR_SIZE];
    for i in 0..DIR_ENTRIES as u32 {
        if !ata::read_sectors(DIR_START + i, 1, &mut buf) { continue; }
        if let Some(e) = parse_entry(&buf) {
            let pages = (e.size as u32 + PAGE_SECTORS * ata::SECTOR_SIZE as u32 - 1)
                        / (PAGE_SECTORS * ata::SECTOR_SIZE as u32);
            let end = e.start + pages.max(1) * PAGE_SECTORS;
            if end > max_end { max_end = end; }
        }
    }
    max_end
}

// ── Init — format or mount ────────────────────────────────────────────────────

/// Initialize diskfs. If the disk has a valid superblock, mount it.
/// Otherwise format (write superblock, zero directory sectors).
/// Returns true if disk is usable.
pub fn init() -> bool {
    if !ata::is_present() { return false; }

    let (valid, _count) = read_superblock();
    if valid {
        unsafe { NEXT_DATA_SECTOR = scan_next_data_sector(); }
    } else {
        // Format: write superblock and zero directory table
        write_superblock(0);
        for i in 0..DIR_ENTRIES as u32 {
            ata::zero_sectors(DIR_START + i, 1);
        }
        unsafe { NEXT_DATA_SECTOR = DATA_START; }
    }

    // Load all entries into memfs/memdir
    load_into_memfs();
    true
}

/// Scan directory table and populate shell::memfs and shell::memdir.
fn load_into_memfs() {
    let mut buf = [0u8; ata::SECTOR_SIZE];
    for i in 0..DIR_ENTRIES as u32 {
        if !ata::read_sectors(DIR_START + i, 1, &mut buf) { continue; }
        let e = match parse_entry(&buf) {
            Some(e) => e,
            None    => continue,
        };
        let name = e.name_bytes();

        if e.is_dir() {
            // Create directory in memdir
            crate::shell::memdir::create(name);
        } else {
            // Read file data from disk and load into memfs
            let size = e.size as usize;
            if size == 0 || size > MAX_FILE_BYTES { continue; }

            // Read up to 8 sectors of data
            let sectors_needed = ((size + ata::SECTOR_SIZE - 1) / ata::SECTOR_SIZE).min(8) as u8;
            let mut data_buf = [0u8; 8 * ata::SECTOR_SIZE];
            if !ata::read_sectors(e.start, sectors_needed, &mut data_buf) { continue; }

            crate::shell::memfs::write(name, &data_buf[..size]);
        }
    }
}

// ── Write file to disk ────────────────────────────────────────────────────────

/// Find an existing directory entry by name, or allocate a new slot.
/// Returns the slot index, or None if full.
fn find_or_alloc_slot(name: &[u8]) -> Option<u32> {
    let mut buf = [0u8; ata::SECTOR_SIZE];
    let mut free_slot: Option<u32> = None;

    for i in 0..DIR_ENTRIES as u32 {
        if !ata::read_sectors(DIR_START + i, 1, &mut buf) { continue; }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic == MAGIC_ENTRY {
            let nlen = buf[13].min(64) as usize;
            if &buf[14..14 + nlen] == name {
                return Some(i); // existing entry
            }
        } else if free_slot.is_none() {
            free_slot = Some(i); // remember first free slot
        }
    }
    free_slot
}

/// Persist a file (from memfs write) to disk.
pub fn persist_file(name: &[u8], data: &[u8]) {
    if !ata::is_present() { return; }
    let slot = match find_or_alloc_slot(name) { Some(s) => s, None => return };

    // Determine data sector
    let mut buf = [0u8; ata::SECTOR_SIZE];
    let _ = ata::read_sectors(DIR_START + slot, 1, &mut buf);
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let start_sector = if magic == MAGIC_ENTRY {
        // Reuse existing data area
        u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]])
    } else {
        // Allocate new data pages
        let s = unsafe { NEXT_DATA_SECTOR };
        let pages = ((data.len() + PAGE_SECTORS as usize * ata::SECTOR_SIZE - 1)
                    / (PAGE_SECTORS as usize * ata::SECTOR_SIZE)).max(1) as u32;
        unsafe { NEXT_DATA_SECTOR += pages * PAGE_SECTORS; }
        s
    };

    // Write data sectors (up to 8)
    let sectors = ((data.len() + ata::SECTOR_SIZE - 1) / ata::SECTOR_SIZE).min(8) as u8;
    let mut data_buf = [0u8; 8 * ata::SECTOR_SIZE];
    data_buf[..data.len()].copy_from_slice(data);
    ata::write_sectors(start_sector, sectors, &data_buf);

    // Write directory entry
    let nlen = name.len().min(64) as u8;
    let mut name_arr = [0u8; 64];
    name_arr[..nlen as usize].copy_from_slice(&name[..nlen as usize]);
    let entry = DirEntry {
        flags: FLAG_VALID,
        size:  data.len() as u32,
        start: start_sector,
        nlen,
        name:  name_arr,
    };
    let mut ebuf = [0u8; ata::SECTOR_SIZE];
    write_entry_to_buf(&mut ebuf, &entry);
    ata::write_sectors(DIR_START + slot, 1, &ebuf);

    // Update superblock count
    let (_, old_count) = read_superblock();
    write_superblock(old_count + 1);
}

/// Persist a directory entry to disk.
pub fn persist_dir(name: &[u8]) {
    if !ata::is_present() { return; }
    let slot = match find_or_alloc_slot(name) { Some(s) => s, None => return };

    let nlen = name.len().min(64) as u8;
    let mut name_arr = [0u8; 64];
    name_arr[..nlen as usize].copy_from_slice(&name[..nlen as usize]);
    let entry = DirEntry {
        flags: FLAG_VALID | FLAG_DIR,
        size:  0,
        start: 0,
        nlen,
        name:  name_arr,
    };
    let mut ebuf = [0u8; ata::SECTOR_SIZE];
    write_entry_to_buf(&mut ebuf, &entry);
    ata::write_sectors(DIR_START + slot, 1, &ebuf);
}

/// Remove a file or directory from disk (mark entry invalid).
pub fn remove(name: &[u8]) {
    if !ata::is_present() { return; }
    let mut buf = [0u8; ata::SECTOR_SIZE];
    for i in 0..DIR_ENTRIES as u32 {
        if !ata::read_sectors(DIR_START + i, 1, &mut buf) { continue; }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != MAGIC_ENTRY { continue; }
        let nlen = buf[13].min(64) as usize;
        if &buf[14..14 + nlen] != name { continue; }
        // Zero-out the entry to mark it free
        ata::zero_sectors(DIR_START + i, 1);
        return;
    }
}

/// List all entries: call `cb(name, is_dir)` for each.
pub fn list(cb: &mut dyn FnMut(&[u8], bool)) {
    if !ata::is_present() { return; }
    let mut buf = [0u8; ata::SECTOR_SIZE];
    for i in 0..DIR_ENTRIES as u32 {
        if !ata::read_sectors(DIR_START + i, 1, &mut buf) { continue; }
        if let Some(e) = parse_entry(&buf) {
            cb(e.name_bytes(), e.is_dir());
        }
    }
}
