//! ext2 (revision 1) — read, write and mkfs.
//!
//! Compatible with Linux and e2fsprogs: images made here pass `e2fsck -f`,
//! and images made by `mke2fs -t ext2` mount here. Supported features:
//! `filetype` (incompat), `sparse_super` + `large_file` (ro-compat). A
//! filesystem with other incompatible features is refused; with unknown
//! ro-compat features it is opened read-only.
//!
//! The implementation is synchronous and single-threaded (`&mut self`); the
//! kernel serialises access with one lock per mounted filesystem and supplies
//! a cached [`Device`]. Every on-disk structure is decoded/encoded explicitly
//! (little-endian, no `repr(C)` punning).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const ROOT_INO: u32 = 2;
const MAGIC: u16 = 0xEF53;
const INCOMPAT_FILETYPE: u32 = 0x0002;
const RO_SPARSE_SUPER: u32 = 0x0001;
const RO_LARGE_FILE: u32 = 0x0002;
const RO_SUPPORTED: u32 = RO_SPARSE_SUPER | RO_LARGE_FILE;
const STATE_VALID: u16 = 1;

pub const S_IFMT: u16 = 0o170000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFIFO: u16 = 0o010000;

/// Directory entry file types (`filetype` feature).
pub mod ft {
    pub const UNKNOWN: u8 = 0;
    pub const REG: u8 = 1;
    pub const DIR: u8 = 2;
    pub const CHR: u8 = 3;
    pub const BLK: u8 = 4;
    pub const FIFO: u8 = 5;
    pub const SOCK: u8 = 6;
    pub const SYMLINK: u8 = 7;
}

pub fn ft_from_mode(mode: u16) -> u8 {
    match mode & S_IFMT {
        S_IFREG => ft::REG,
        S_IFDIR => ft::DIR,
        S_IFCHR => ft::CHR,
        S_IFBLK => ft::BLK,
        S_IFIFO => ft::FIFO,
        S_IFSOCK => ft::SOCK,
        S_IFLNK => ft::SYMLINK,
        _ => ft::UNKNOWN,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    /// Not an ext2 filesystem, or a structure is inconsistent.
    Corrupt,
    Unsupported,
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpace,
    NameTooLong,
    TooManyLinks,
    ReadOnly,
    Invalid,
    FileTooBig,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Byte-addressed storage. Offsets and lengths used by this crate are
/// always multiples of 512 (usually whole filesystem blocks).
pub trait Device {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
    /// Total size in bytes.
    fn size(&self) -> u64;
}

// ── little-endian helpers ───────────────────────────────────────────────────

fn r16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn r32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn w16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

// ── on-disk structures ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Superblock {
    raw: Vec<u8>, // 1024 bytes; unknown fields are preserved
}

impl Superblock {
    fn inodes_count(&self) -> u32 {
        r32(&self.raw, 0)
    }
    fn blocks_count(&self) -> u32 {
        r32(&self.raw, 4)
    }
    fn r_blocks_count(&self) -> u32 {
        r32(&self.raw, 8)
    }
    fn free_blocks(&self) -> u32 {
        r32(&self.raw, 12)
    }
    fn set_free_blocks(&mut self, v: u32) {
        w32(&mut self.raw, 12, v)
    }
    fn free_inodes(&self) -> u32 {
        r32(&self.raw, 16)
    }
    fn set_free_inodes(&mut self, v: u32) {
        w32(&mut self.raw, 16, v)
    }
    fn first_data_block(&self) -> u32 {
        r32(&self.raw, 20)
    }
    fn log_block_size(&self) -> u32 {
        r32(&self.raw, 24)
    }
    fn blocks_per_group(&self) -> u32 {
        r32(&self.raw, 32)
    }
    fn inodes_per_group(&self) -> u32 {
        r32(&self.raw, 40)
    }
    fn magic(&self) -> u16 {
        r16(&self.raw, 56)
    }
    fn state(&self) -> u16 {
        r16(&self.raw, 58)
    }
    fn set_state(&mut self, v: u16) {
        w16(&mut self.raw, 58, v)
    }
    fn rev_level(&self) -> u32 {
        r32(&self.raw, 76)
    }
    fn first_ino(&self) -> u32 {
        if self.rev_level() == 0 {
            11
        } else {
            r32(&self.raw, 84)
        }
    }
    fn inode_size(&self) -> u16 {
        if self.rev_level() == 0 {
            128
        } else {
            r16(&self.raw, 88)
        }
    }
    fn feature_incompat(&self) -> u32 {
        r32(&self.raw, 96)
    }
    fn feature_ro_compat(&self) -> u32 {
        r32(&self.raw, 100)
    }
    fn volume_name(&self) -> String {
        let n = &self.raw[120..136];
        let end = n.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&n[..end]).into_owned()
    }
    fn uuid(&self) -> [u8; 16] {
        let mut u = [0u8; 16];
        u.copy_from_slice(&self.raw[104..120]);
        u
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct GroupDesc {
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    free_blocks: u16,
    free_inodes: u16,
    used_dirs: u16,
}

impl GroupDesc {
    fn decode(b: &[u8]) -> GroupDesc {
        GroupDesc {
            block_bitmap: r32(b, 0),
            inode_bitmap: r32(b, 4),
            inode_table: r32(b, 8),
            free_blocks: r16(b, 12),
            free_inodes: r16(b, 14),
            used_dirs: r16(b, 16),
        }
    }
    fn encode(&self, b: &mut [u8]) {
        b[..32].fill(0);
        w32(b, 0, self.block_bitmap);
        w32(b, 4, self.inode_bitmap);
        w32(b, 8, self.inode_table);
        w16(b, 12, self.free_blocks);
        w16(b, 14, self.free_inodes);
        w16(b, 16, self.used_dirs);
    }
}

/// An inode as stored on disk (the full record, unknown fields preserved).
#[derive(Clone, Debug)]
pub struct Inode {
    raw: Vec<u8>,
}

impl Inode {
    fn new(size: usize) -> Inode {
        Inode { raw: vec![0; size] }
    }
    pub fn mode(&self) -> u16 {
        r16(&self.raw, 0)
    }
    pub fn set_mode(&mut self, v: u16) {
        w16(&mut self.raw, 0, v)
    }
    pub fn uid(&self) -> u32 {
        r16(&self.raw, 2) as u32 | (r16(&self.raw, 120) as u32) << 16
    }
    pub fn set_uid(&mut self, v: u32) {
        w16(&mut self.raw, 2, v as u16);
        w16(&mut self.raw, 120, (v >> 16) as u16);
    }
    pub fn gid(&self) -> u32 {
        r16(&self.raw, 24) as u32 | (r16(&self.raw, 122) as u32) << 16
    }
    pub fn set_gid(&mut self, v: u32) {
        w16(&mut self.raw, 24, v as u16);
        w16(&mut self.raw, 122, (v >> 16) as u16);
    }
    pub fn size(&self) -> u64 {
        let lo = r32(&self.raw, 4) as u64;
        if self.mode() & S_IFMT == S_IFREG {
            lo | (r32(&self.raw, 108) as u64) << 32
        } else {
            lo
        }
    }
    fn set_size(&mut self, v: u64) {
        w32(&mut self.raw, 4, v as u32);
        if self.mode() & S_IFMT == S_IFREG {
            w32(&mut self.raw, 108, (v >> 32) as u32);
        }
    }
    pub fn atime(&self) -> u32 {
        r32(&self.raw, 8)
    }
    pub fn ctime(&self) -> u32 {
        r32(&self.raw, 12)
    }
    pub fn mtime(&self) -> u32 {
        r32(&self.raw, 16)
    }
    pub fn set_atime(&mut self, v: u32) {
        w32(&mut self.raw, 8, v)
    }
    pub fn set_ctime(&mut self, v: u32) {
        w32(&mut self.raw, 12, v)
    }
    pub fn set_mtime(&mut self, v: u32) {
        w32(&mut self.raw, 16, v)
    }
    fn set_dtime(&mut self, v: u32) {
        w32(&mut self.raw, 20, v)
    }
    pub fn links(&self) -> u16 {
        r16(&self.raw, 26)
    }
    fn set_links(&mut self, v: u16) {
        w16(&mut self.raw, 26, v)
    }
    /// Allocated 512-byte sectors (data + indirect blocks).
    pub fn sectors(&self) -> u32 {
        r32(&self.raw, 28)
    }
    fn set_sectors(&mut self, v: u32) {
        w32(&mut self.raw, 28, v)
    }
    fn block(&self, i: usize) -> u32 {
        r32(&self.raw, 40 + i * 4)
    }
    fn set_block(&mut self, i: usize, v: u32) {
        w32(&mut self.raw, 40 + i * 4, v)
    }
    pub fn is_dir(&self) -> bool {
        self.mode() & S_IFMT == S_IFDIR
    }
    pub fn is_symlink(&self) -> bool {
        self.mode() & S_IFMT == S_IFLNK
    }
    /// Device number of a device node (old 16-bit or new 32-bit encoding).
    pub fn rdev(&self) -> u32 {
        let old = self.block(0);
        if old != 0 {
            old
        } else {
            self.block(1)
        }
    }
    fn set_rdev(&mut self, v: u32) {
        if v < 0x10000 && (v & 0xFF00) >> 8 < 256 {
            self.set_block(0, v);
        } else {
            self.set_block(1, v);
        }
    }
    /// Symlink target stored inside the inode ("fast" symlink).
    fn is_fast_symlink(&self) -> bool {
        self.is_symlink() && self.sectors() == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u32,
    pub name: String,
    pub file_type: u8,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub block_size: u32,
    pub blocks: u64,
    pub free_blocks: u64,
    pub reserved_blocks: u64,
    pub inodes: u64,
    pub free_inodes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Attr {
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub ctime: Option<u32>,
}

pub struct Ext2<D: Device> {
    dev: D,
    sb: Superblock,
    bs: usize,
    groups: Vec<GroupDesc>,
    gdt_dirty: bool,
    sb_dirty: bool,
    read_only: bool,
    /// Current time source for timestamps (seconds since the epoch).
    clock: fn() -> u32,
    /// The superblock said "cleanly unmounted" when we opened it.
    clean_at_mount: bool,
}

fn has_super_backup(group: u32, sparse: bool) -> bool {
    if !sparse || group <= 1 {
        return true;
    }
    for p in [3u32, 5, 7] {
        let mut x = p;
        while x < group {
            x *= p;
        }
        if x == group {
            return true;
        }
    }
    false
}

impl<D: Device> Ext2<D> {
    /// Mount an existing filesystem.
    pub fn open(mut dev: D, clock: fn() -> u32) -> Result<Self> {
        let mut raw = vec![0u8; 1024];
        dev.read(1024, &mut raw)?;
        let sb = Superblock { raw };
        if sb.magic() != MAGIC {
            return Err(Error::Corrupt);
        }
        if sb.feature_incompat() & !INCOMPAT_FILETYPE != 0 {
            return Err(Error::Unsupported);
        }
        let read_only = sb.feature_ro_compat() & !RO_SUPPORTED != 0;
        let bs = 1024usize << sb.log_block_size();
        if !(1024..=65536).contains(&bs) || sb.blocks_per_group() == 0 || sb.inodes_per_group() == 0 {
            return Err(Error::Corrupt);
        }
        let ngroups = (sb.blocks_count() - sb.first_data_block()).div_ceil(sb.blocks_per_group()) as usize;
        let gdt_block = sb.first_data_block() as u64 + 1;
        let gdt_bytes = (ngroups * 32).div_ceil(bs) * bs;
        let mut gdt = vec![0u8; gdt_bytes];
        dev.read(gdt_block * bs as u64, &mut gdt)?;
        let groups = (0..ngroups).map(|g| GroupDesc::decode(&gdt[g * 32..g * 32 + 32])).collect();
        let clean_at_mount = sb.state() & STATE_VALID != 0;
        let mut fs = Ext2 { dev, sb, bs, groups, gdt_dirty: false, sb_dirty: false, read_only, clock, clean_at_mount };
        if !fs.read_only {
            // Mark "mounted / not cleanly unmounted" until `unmount`.
            let st = fs.sb.state();
            fs.sb.set_state(st & !STATE_VALID);
            fs.sb_dirty = true;
            fs.sync()?;
        }
        Ok(fs)
    }

    pub fn device(&mut self) -> &mut D {
        &mut self.dev
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    pub fn block_size(&self) -> usize {
        self.bs
    }
    pub fn label(&self) -> String {
        self.sb.volume_name()
    }
    pub fn uuid(&self) -> [u8; 16] {
        self.sb.uuid()
    }
    /// Was the filesystem cleanly unmounted before this mount?
    pub fn was_clean(&self) -> bool {
        self.clean_at_mount
    }

    pub fn stats(&self) -> Stats {
        Stats {
            block_size: self.bs as u32,
            blocks: self.sb.blocks_count() as u64,
            free_blocks: self.sb.free_blocks() as u64,
            reserved_blocks: self.sb.r_blocks_count() as u64,
            inodes: self.sb.inodes_count() as u64,
            free_inodes: self.sb.free_inodes() as u64,
        }
    }

    fn now(&self) -> u32 {
        (self.clock)()
    }

    fn check_rw(&self) -> Result<()> {
        if self.read_only {
            Err(Error::ReadOnly)
        } else {
            Ok(())
        }
    }

    // ── raw block I/O ───────────────────────────────────────────────────────

    fn read_block(&mut self, blk: u32, buf: &mut [u8]) -> Result<()> {
        if blk == 0 || blk >= self.sb.blocks_count() {
            return Err(Error::Corrupt);
        }
        self.dev.read(blk as u64 * self.bs as u64, &mut buf[..self.bs])
    }
    fn write_block(&mut self, blk: u32, buf: &[u8]) -> Result<()> {
        if blk == 0 || blk >= self.sb.blocks_count() {
            return Err(Error::Corrupt);
        }
        self.dev.write(blk as u64 * self.bs as u64, &buf[..self.bs])
    }
    fn zero_block(&mut self, blk: u32) -> Result<()> {
        let z = vec![0u8; self.bs];
        self.write_block(blk, &z)
    }

    /// Write superblock and group descriptors (primary copies) and flush.
    pub fn sync(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        if self.gdt_dirty {
            let gdt_bytes = (self.groups.len() * 32).div_ceil(self.bs) * self.bs;
            let mut gdt = vec![0u8; gdt_bytes];
            for (i, g) in self.groups.iter().enumerate() {
                g.encode(&mut gdt[i * 32..i * 32 + 32]);
            }
            let blk = self.sb.first_data_block() as u64 + 1;
            self.dev.write(blk * self.bs as u64, &gdt)?;
            self.gdt_dirty = false;
            self.sb_dirty = true;
        }
        if self.sb_dirty {
            let now = self.now();
            w32(&mut self.sb.raw, 48, now); // s_wtime
            let raw = self.sb.raw.clone();
            self.dev.write(1024, &raw)?;
            self.sb_dirty = false;
        }
        self.dev.flush()
    }

    /// Mark the filesystem clean and flush everything.
    pub fn unmount(&mut self) -> Result<()> {
        if !self.read_only {
            let st = self.sb.state();
            self.sb.set_state(st | STATE_VALID);
            self.sb_dirty = true;
        }
        self.sync()
    }

    // ── inodes ──────────────────────────────────────────────────────────────

    fn inode_location(&self, ino: u32) -> Result<(u64, usize)> {
        if ino == 0 || ino > self.sb.inodes_count() {
            return Err(Error::Invalid);
        }
        let ipg = self.sb.inodes_per_group();
        let g = ((ino - 1) / ipg) as usize;
        let idx = ((ino - 1) % ipg) as u64;
        let isz = self.sb.inode_size() as u64;
        let off = self.groups[g].inode_table as u64 * self.bs as u64 + idx * isz;
        Ok((off, isz as usize))
    }

    pub fn read_inode(&mut self, ino: u32) -> Result<Inode> {
        let (off, isz) = self.inode_location(ino)?;
        // Read the whole enclosing 512-byte sector(s) (devices are sector-addressed).
        let sec = off & !511;
        let span = ((off + isz as u64 - sec) as usize).div_ceil(512) * 512;
        let mut buf = vec![0u8; span];
        self.dev.read(sec, &mut buf)?;
        let start = (off - sec) as usize;
        Ok(Inode { raw: buf[start..start + isz].to_vec() })
    }

    fn write_inode(&mut self, ino: u32, inode: &Inode) -> Result<()> {
        let (off, isz) = self.inode_location(ino)?;
        let sec = off & !511;
        let span = ((off + isz as u64 - sec) as usize).div_ceil(512) * 512;
        let mut buf = vec![0u8; span];
        self.dev.read(sec, &mut buf)?;
        let start = (off - sec) as usize;
        buf[start..start + isz].copy_from_slice(&inode.raw[..isz]);
        self.dev.write(sec, &buf)
    }

    // ── bitmaps / allocation ────────────────────────────────────────────────

    fn group_blocks(&self, g: usize) -> u32 {
        let bpg = self.sb.blocks_per_group();
        let start = self.sb.first_data_block() + g as u32 * bpg;
        (self.sb.blocks_count() - start).min(bpg)
    }

    fn alloc_block(&mut self, goal: u32) -> Result<u32> {
        self.check_rw()?;
        if self.sb.free_blocks() == 0 {
            return Err(Error::NoSpace);
        }
        let bpg = self.sb.blocks_per_group();
        let first = self.sb.first_data_block();
        let ng = self.groups.len();
        let goal = goal.max(first).min(self.sb.blocks_count() - 1);
        let goal_group = ((goal - first) / bpg) as usize;
        let mut bitmap = vec![0u8; self.bs];
        for step in 0..ng {
            let g = (goal_group + step) % ng;
            if self.groups[g].free_blocks == 0 {
                continue;
            }
            let bb = self.groups[g].block_bitmap;
            self.read_block(bb, &mut bitmap)?;
            let nbits = self.group_blocks(g) as usize;
            let start_bit = if step == 0 { ((goal - first) % bpg) as usize } else { 0 };
            let found = (start_bit..nbits).chain(0..start_bit).find(|&i| bitmap[i / 8] & (1 << (i % 8)) == 0);
            let Some(bit) = found else {
                // Descriptor said free but the bitmap is full: trust the bitmap.
                self.groups[g].free_blocks = 0;
                self.gdt_dirty = true;
                continue;
            };
            bitmap[bit / 8] |= 1 << (bit % 8);
            self.write_block(bb, &bitmap)?;
            self.groups[g].free_blocks -= 1;
            self.gdt_dirty = true;
            let fb = self.sb.free_blocks();
            self.sb.set_free_blocks(fb - 1);
            self.sb_dirty = true;
            return Ok(first + g as u32 * bpg + bit as u32);
        }
        Err(Error::NoSpace)
    }

    fn free_block(&mut self, blk: u32) -> Result<()> {
        let first = self.sb.first_data_block();
        if blk < first || blk >= self.sb.blocks_count() {
            return Err(Error::Corrupt);
        }
        let bpg = self.sb.blocks_per_group();
        let g = ((blk - first) / bpg) as usize;
        let bit = ((blk - first) % bpg) as usize;
        let mut bitmap = vec![0u8; self.bs];
        let bb = self.groups[g].block_bitmap;
        self.read_block(bb, &mut bitmap)?;
        if bitmap[bit / 8] & (1 << (bit % 8)) == 0 {
            return Err(Error::Corrupt); // double free
        }
        bitmap[bit / 8] &= !(1 << (bit % 8));
        self.write_block(bb, &bitmap)?;
        self.groups[g].free_blocks += 1;
        self.gdt_dirty = true;
        let fb = self.sb.free_blocks();
        self.sb.set_free_blocks(fb + 1);
        self.sb_dirty = true;
        Ok(())
    }

    fn alloc_inode(&mut self, parent: u32, dir: bool) -> Result<u32> {
        self.check_rw()?;
        if self.sb.free_inodes() == 0 {
            return Err(Error::NoSpace);
        }
        let ipg = self.sb.inodes_per_group();
        let ng = self.groups.len();
        let pg = ((parent.max(1) - 1) / ipg) as usize;
        // Directories go to the emptiest group (spreads the tree, like
        // Linux's Orlov allocator); files stay near their directory.
        let start = if dir {
            (0..ng).max_by_key(|&g| (self.groups[g].free_inodes as u32, self.groups[g].free_blocks as u32)).unwrap_or(0)
        } else {
            pg
        };
        let mut bitmap = vec![0u8; self.bs];
        for step in 0..ng {
            let g = (start + step) % ng;
            if self.groups[g].free_inodes == 0 {
                continue;
            }
            let ib = self.groups[g].inode_bitmap;
            self.read_block(ib, &mut bitmap)?;
            let first_ok = if g == 0 { self.sb.first_ino() as usize - 1 } else { 0 };
            let found = (first_ok..ipg as usize).find(|&i| bitmap[i / 8] & (1 << (i % 8)) == 0);
            let Some(bit) = found else {
                self.groups[g].free_inodes = 0;
                self.gdt_dirty = true;
                continue;
            };
            bitmap[bit / 8] |= 1 << (bit % 8);
            self.write_block(ib, &bitmap)?;
            self.groups[g].free_inodes -= 1;
            if dir {
                self.groups[g].used_dirs += 1;
            }
            self.gdt_dirty = true;
            let fi = self.sb.free_inodes();
            self.sb.set_free_inodes(fi - 1);
            self.sb_dirty = true;
            return Ok(g as u32 * ipg + bit as u32 + 1);
        }
        Err(Error::NoSpace)
    }

    fn free_inode(&mut self, ino: u32, dir: bool) -> Result<()> {
        let ipg = self.sb.inodes_per_group();
        let g = ((ino - 1) / ipg) as usize;
        let bit = ((ino - 1) % ipg) as usize;
        let mut bitmap = vec![0u8; self.bs];
        let ib = self.groups[g].inode_bitmap;
        self.read_block(ib, &mut bitmap)?;
        if bitmap[bit / 8] & (1 << (bit % 8)) == 0 {
            return Err(Error::Corrupt);
        }
        bitmap[bit / 8] &= !(1 << (bit % 8));
        self.write_block(ib, &bitmap)?;
        self.groups[g].free_inodes += 1;
        if dir {
            self.groups[g].used_dirs = self.groups[g].used_dirs.saturating_sub(1);
        }
        self.gdt_dirty = true;
        let fi = self.sb.free_inodes();
        self.sb.set_free_inodes(fi + 1);
        self.sb_dirty = true;
        Ok(())
    }

    // ── block mapping ───────────────────────────────────────────────────────

    fn ptrs_per_block(&self) -> u64 {
        (self.bs / 4) as u64
    }

    fn read_ptr(&mut self, blk: u32, idx: u64) -> Result<u32> {
        let mut b = vec![0u8; self.bs];
        self.read_block(blk, &mut b)?;
        Ok(r32(&b, idx as usize * 4))
    }

    fn write_ptr(&mut self, blk: u32, idx: u64, v: u32) -> Result<()> {
        let mut b = vec![0u8; self.bs];
        self.read_block(blk, &mut b)?;
        w32(&mut b, idx as usize * 4, v);
        self.write_block(blk, &b)
    }

    /// Physical block of file block `fblk`; allocates (with zeroed metadata)
    /// when `alloc` is set. `Ok(0)` is a hole.
    fn bmap(&mut self, inode: &mut Inode, ino: u32, fblk: u64, alloc: bool) -> Result<u32> {
        let p = self.ptrs_per_block();
        let spb = (self.bs / 512) as u32;
        let goal = {
            let g = (ino - 1) / self.sb.inodes_per_group();
            self.sb.first_data_block() + g * self.sb.blocks_per_group()
        };
        // Path of indices through the indirection levels.
        let (root_slot, path): (usize, Vec<u64>) = if fblk < 12 {
            (fblk as usize, Vec::new())
        } else if fblk < 12 + p {
            (12, vec![fblk - 12])
        } else if fblk < 12 + p + p * p {
            let r = fblk - 12 - p;
            (13, vec![r / p, r % p])
        } else if fblk < 12 + p + p * p + p * p * p {
            let r = fblk - 12 - p - p * p;
            (14, vec![r / (p * p), (r / p) % p, r % p])
        } else {
            return Err(Error::FileTooBig);
        };
        let mut cur = inode.block(root_slot);
        if cur == 0 {
            if !alloc {
                return Ok(0);
            }
            cur = self.alloc_block(goal)?;
            if !path.is_empty() {
                self.zero_block(cur)?;
            }
            inode.set_block(root_slot, cur);
            inode.set_sectors(inode.sectors() + spb);
        }
        for &idx in &path {
            let mut next = self.read_ptr(cur, idx)?;
            if next == 0 {
                if !alloc {
                    return Ok(0);
                }
                next = self.alloc_block(cur + 1)?;
                // Interior blocks must start zeroed; data blocks are written by the caller.
                self.zero_block(next)?;
                self.write_ptr(cur, idx, next)?;
                inode.set_sectors(inode.sectors() + spb);
            }
            cur = next;
        }
        Ok(cur)
    }

    /// Free every block of the file at or beyond file block `from`.
    fn free_from(&mut self, inode: &mut Inode, from: u64) -> Result<()> {
        let p = self.ptrs_per_block();
        let spb = (self.bs / 512) as u32;
        for i in (from.min(12) as usize)..12 {
            let b = inode.block(i);
            if b != 0 {
                self.free_block(b)?;
                inode.set_block(i, 0);
                inode.set_sectors(inode.sectors().saturating_sub(spb));
            }
        }
        // Indirect trees: (slot, first file block covered, depth).
        let trees = [(12usize, 12u64, 1u32), (13, 12 + p, 2), (14, 12 + p + p * p, 3)];
        for (slot, base, depth) in trees {
            let root = inode.block(slot);
            if root == 0 {
                continue;
            }
            let span = p.pow(depth);
            if from >= base + span {
                continue;
            }
            let keep_from = from.saturating_sub(base);
            let emptied = self.free_tree(root, depth, keep_from, inode, spb)?;
            if emptied {
                self.free_block(root)?;
                inode.set_block(slot, 0);
                inode.set_sectors(inode.sectors().saturating_sub(spb));
            }
        }
        Ok(())
    }

    /// Free entries ≥ `from` (relative) under indirect block `blk`.
    /// Returns true if the block ended up with no entries.
    fn free_tree(&mut self, blk: u32, depth: u32, from: u64, inode: &mut Inode, spb: u32) -> Result<bool> {
        let p = self.ptrs_per_block();
        let per = p.pow(depth - 1);
        let mut b = vec![0u8; self.bs];
        self.read_block(blk, &mut b)?;
        let mut changed = false;
        for i in 0..p {
            let child = r32(&b, i as usize * 4);
            if child == 0 {
                continue;
            }
            let child_base = i * per;
            if child_base + per <= from {
                continue; // entirely kept
            }
            let child_from = from.saturating_sub(child_base);
            let free_child = if depth == 1 {
                true
            } else {
                self.free_tree(child, depth - 1, child_from, inode, spb)?
            };
            if free_child {
                self.free_block(child)?;
                inode.set_sectors(inode.sectors().saturating_sub(spb));
                w32(&mut b, i as usize * 4, 0);
                changed = true;
            }
        }
        if changed {
            self.write_block(blk, &b)?;
        }
        Ok(b.chunks(4).all(|c| c == [0, 0, 0, 0]))
    }

    // ── file data ───────────────────────────────────────────────────────────

    pub fn read(&mut self, ino: u32, off: u64, buf: &mut [u8]) -> Result<usize> {
        let mut inode = self.read_inode(ino)?;
        if inode.is_dir() {
            return Err(Error::IsDir);
        }
        let size = inode.size();
        if off >= size {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - off) as usize;
        let bs = self.bs as u64;
        let mut done = 0;
        let mut blockbuf = vec![0u8; self.bs];
        while done < n {
            let pos = off + done as u64;
            let fblk = pos / bs;
            let boff = (pos % bs) as usize;
            let chunk = (self.bs - boff).min(n - done);
            let pb = self.bmap(&mut inode, ino, fblk, false)?;
            if pb == 0 {
                buf[done..done + chunk].fill(0);
            } else if boff == 0 && chunk == self.bs {
                self.read_block(pb, &mut buf[done..done + chunk])?;
            } else {
                self.read_block(pb, &mut blockbuf)?;
                buf[done..done + chunk].copy_from_slice(&blockbuf[boff..boff + chunk]);
            }
            done += chunk;
        }
        Ok(n)
    }

    pub fn write(&mut self, ino: u32, off: u64, data: &[u8]) -> Result<usize> {
        self.check_rw()?;
        let mut inode = self.read_inode(ino)?;
        if inode.is_dir() {
            return Err(Error::IsDir);
        }
        let end = off.checked_add(data.len() as u64).ok_or(Error::FileTooBig)?;
        let max = if self.sb.feature_ro_compat() & RO_LARGE_FILE != 0 { 1u64 << 40 } else { u32::MAX as u64 };
        if end > max {
            return Err(Error::FileTooBig);
        }
        let r = self.write_into(&mut inode, ino, off, data);
        // Persist whatever was allocated even when the write stopped early (ENOSPC).
        let written = match r {
            Ok(n) => n,
            Err(Error::NoSpace) => 0,
            Err(e) => {
                self.write_inode(ino, &inode)?;
                return Err(e);
            }
        };
        let now = self.now();
        inode.set_mtime(now);
        inode.set_ctime(now);
        self.write_inode(ino, &inode)?;
        if written == 0 && !data.is_empty() {
            return Err(Error::NoSpace);
        }
        Ok(written)
    }

    fn write_into(&mut self, inode: &mut Inode, ino: u32, off: u64, data: &[u8]) -> Result<usize> {
        let bs = self.bs as u64;
        let mut done = 0;
        let mut blockbuf = vec![0u8; self.bs];
        while done < data.len() {
            let pos = off + done as u64;
            let fblk = pos / bs;
            let boff = (pos % bs) as usize;
            let chunk = (self.bs - boff).min(data.len() - done);
            let existed = self.bmap(inode, ino, fblk, false)? != 0;
            let pb = match self.bmap(inode, ino, fblk, true) {
                Ok(b) => b,
                Err(Error::NoSpace) if done > 0 => break,
                Err(e) => return Err(e),
            };
            if boff == 0 && chunk == self.bs {
                self.write_block(pb, &data[done..done + chunk])?;
            } else {
                if existed {
                    self.read_block(pb, &mut blockbuf)?;
                } else {
                    blockbuf.fill(0);
                }
                blockbuf[boff..boff + chunk].copy_from_slice(&data[done..done + chunk]);
                self.write_block(pb, &blockbuf)?;
            }
            done += chunk;
            if pos + chunk as u64 > inode.size() {
                inode.set_size(pos + chunk as u64);
            }
        }
        Ok(done)
    }

    pub fn truncate(&mut self, ino: u32, size: u64) -> Result<()> {
        self.check_rw()?;
        let mut inode = self.read_inode(ino)?;
        if inode.is_dir() {
            return Err(Error::IsDir);
        }
        self.truncate_inode(&mut inode, ino, size)?;
        let now = self.now();
        inode.set_mtime(now);
        inode.set_ctime(now);
        self.write_inode(ino, &inode)
    }

    fn truncate_inode(&mut self, inode: &mut Inode, ino: u32, size: u64) -> Result<()> {
        let bs = self.bs as u64;
        let old = inode.size();
        if size < old {
            if !inode.is_fast_symlink() {
                self.free_from(inode, size.div_ceil(bs))?;
                // Zero the tail of the last kept block so a later extension reads zeros.
                let tail = (size % bs) as usize;
                if tail != 0 {
                    let pb = self.bmap(inode, ino, size / bs, false)?;
                    if pb != 0 {
                        let mut b = vec![0u8; self.bs];
                        self.read_block(pb, &mut b)?;
                        b[tail..].fill(0);
                        self.write_block(pb, &b)?;
                    }
                }
            }
        }
        inode.set_size(size);
        Ok(())
    }

    // ── directories ─────────────────────────────────────────────────────────

    fn dir_block_count(&self, inode: &Inode) -> u64 {
        inode.size() / self.bs as u64
    }

    fn parse_dir_block(&self, b: &[u8], mut f: impl FnMut(usize, u32, u16, &[u8], u8) -> bool) -> Result<()> {
        let mut off = 0;
        while off + 8 <= self.bs {
            let ino = r32(b, off);
            let rec_len = r16(b, off + 4) as usize;
            let name_len = b[off + 6] as usize;
            let ftype = b[off + 7];
            if rec_len < 8 || off + rec_len > self.bs || 8 + name_len > rec_len || rec_len % 4 != 0 {
                return Err(Error::Corrupt);
            }
            if !f(off, ino, rec_len as u16, &b[off + 8..off + 8 + name_len], ftype) {
                return Ok(());
            }
            off += rec_len;
        }
        Ok(())
    }

    pub fn readdir(&mut self, dir: u32) -> Result<Vec<DirEntry>> {
        let mut inode = self.read_inode(dir)?;
        if !inode.is_dir() {
            return Err(Error::NotDir);
        }
        let mut out = Vec::new();
        let mut b = vec![0u8; self.bs];
        for fblk in 0..self.dir_block_count(&inode) {
            let pb = self.bmap(&mut inode, dir, fblk, false)?;
            if pb == 0 {
                continue;
            }
            self.read_block(pb, &mut b)?;
            self.parse_dir_block(&b, |_, ino, _, name, ft| {
                if ino != 0 {
                    out.push(DirEntry { ino, name: String::from_utf8_lossy(name).into_owned(), file_type: ft });
                }
                true
            })?;
        }
        Ok(out)
    }

    pub fn lookup(&mut self, dir: u32, name: &str) -> Result<u32> {
        let mut inode = self.read_inode(dir)?;
        if !inode.is_dir() {
            return Err(Error::NotDir);
        }
        let mut b = vec![0u8; self.bs];
        for fblk in 0..self.dir_block_count(&inode) {
            let pb = self.bmap(&mut inode, dir, fblk, false)?;
            if pb == 0 {
                continue;
            }
            self.read_block(pb, &mut b)?;
            let mut hit = None;
            self.parse_dir_block(&b, |_, ino, _, n, _| {
                if ino != 0 && n == name.as_bytes() {
                    hit = Some(ino);
                    false
                } else {
                    true
                }
            })?;
            if let Some(i) = hit {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    fn add_entry(&mut self, dir: u32, name: &str, ino: u32, ftype: u8) -> Result<()> {
        if name.is_empty() || name.len() > 255 {
            return Err(Error::NameTooLong);
        }
        let need = (8 + name.len() + 3) & !3;
        let mut dinode = self.read_inode(dir)?;
        let mut b = vec![0u8; self.bs];
        let nblocks = self.dir_block_count(&dinode);
        for fblk in 0..nblocks {
            let pb = self.bmap(&mut dinode, dir, fblk, false)?;
            if pb == 0 {
                continue;
            }
            self.read_block(pb, &mut b)?;
            let mut slot = None;
            self.parse_dir_block(&b, |off, e_ino, rec_len, e_name, _| {
                let used = if e_ino == 0 { 0 } else { (8 + e_name.len() + 3) & !3 };
                if rec_len as usize - used >= need {
                    slot = Some((off, used, rec_len as usize));
                    false
                } else {
                    true
                }
            })?;
            if let Some((off, used, rec_len)) = slot {
                let new_off = if used == 0 { off } else { off + used };
                if used != 0 {
                    w16(&mut b, off + 4, used as u16);
                }
                let new_len = rec_len - (new_off - off);
                write_entry(&mut b, new_off, ino, new_len, name, ftype);
                self.write_block(pb, &b)?;
                let now = self.now();
                dinode.set_mtime(now);
                dinode.set_ctime(now);
                return self.write_inode(dir, &dinode);
            }
        }
        // No room: append a block.
        let pb = self.bmap(&mut dinode, dir, nblocks, true)?;
        b.fill(0);
        write_entry(&mut b, 0, ino, self.bs, name, ftype);
        self.write_block(pb, &b)?;
        let sz = dinode.size();
        dinode.set_size(sz + self.bs as u64);
        let now = self.now();
        dinode.set_mtime(now);
        dinode.set_ctime(now);
        self.write_inode(dir, &dinode)
    }

    /// Remove `name` from `dir`; returns the inode it referred to.
    fn remove_entry(&mut self, dir: u32, name: &str) -> Result<u32> {
        let mut dinode = self.read_inode(dir)?;
        let mut b = vec![0u8; self.bs];
        for fblk in 0..self.dir_block_count(&dinode) {
            let pb = self.bmap(&mut dinode, dir, fblk, false)?;
            if pb == 0 {
                continue;
            }
            self.read_block(pb, &mut b)?;
            let mut prev: Option<usize> = None;
            let mut hit = None;
            self.parse_dir_block(&b, |off, ino, rec_len, n, _| {
                if ino != 0 && n == name.as_bytes() {
                    hit = Some((off, ino, rec_len, prev));
                    return false;
                }
                prev = Some(off);
                true
            })?;
            if let Some((off, ino, rec_len, prev)) = hit {
                match prev {
                    Some(p) => {
                        let plen = r16(&b, p + 4);
                        w16(&mut b, p + 4, plen + rec_len);
                    }
                    None => w32(&mut b, off, 0),
                }
                self.write_block(pb, &b)?;
                let now = self.now();
                dinode.set_mtime(now);
                dinode.set_ctime(now);
                self.write_inode(dir, &dinode)?;
                return Ok(ino);
            }
        }
        Err(Error::NotFound)
    }

    /// Point an existing entry at another inode (rename over, `..` fix-up).
    fn set_entry(&mut self, dir: u32, name: &str, ino: u32, ftype: u8) -> Result<()> {
        let mut dinode = self.read_inode(dir)?;
        let mut b = vec![0u8; self.bs];
        for fblk in 0..self.dir_block_count(&dinode) {
            let pb = self.bmap(&mut dinode, dir, fblk, false)?;
            if pb == 0 {
                continue;
            }
            self.read_block(pb, &mut b)?;
            let mut hit = None;
            self.parse_dir_block(&b, |off, e, _, n, _| {
                if e != 0 && n == name.as_bytes() {
                    hit = Some(off);
                    false
                } else {
                    true
                }
            })?;
            if let Some(off) = hit {
                w32(&mut b, off, ino);
                b[off + 7] = ftype;
                return self.write_block(pb, &b);
            }
        }
        Err(Error::NotFound)
    }

    fn dir_is_empty(&mut self, dir: u32) -> Result<bool> {
        Ok(self.readdir(dir)?.iter().all(|e| e.name == "." || e.name == ".."))
    }

    // ── namespace operations ────────────────────────────────────────────────

    /// Create a regular file, device node, fifo or socket.
    pub fn create(&mut self, dir: u32, name: &str, mode: u16, uid: u32, gid: u32, rdev: u32) -> Result<u32> {
        self.check_rw()?;
        if mode & S_IFMT == S_IFDIR {
            return self.mkdir(dir, name, mode, uid, gid);
        }
        if name.len() > 255 {
            return Err(Error::NameTooLong);
        }
        if !self.read_inode(dir)?.is_dir() {
            return Err(Error::NotDir);
        }
        if self.lookup(dir, name).is_ok() {
            return Err(Error::Exists);
        }
        let ino = self.alloc_inode(dir, false)?;
        let mut inode = Inode::new(self.sb.inode_size() as usize);
        let now = self.now();
        inode.set_mode(mode);
        inode.set_uid(uid);
        inode.set_gid(gid);
        inode.set_links(1);
        inode.set_atime(now);
        inode.set_ctime(now);
        inode.set_mtime(now);
        if matches!(mode & S_IFMT, S_IFCHR | S_IFBLK) {
            inode.set_rdev(rdev);
        }
        self.write_inode(ino, &inode)?;
        if let Err(e) = self.add_entry(dir, name, ino, ft_from_mode(mode)) {
            self.free_inode(ino, false)?;
            return Err(e);
        }
        Ok(ino)
    }

    pub fn mkdir(&mut self, parent: u32, name: &str, mode: u16, uid: u32, gid: u32) -> Result<u32> {
        self.check_rw()?;
        if name.len() > 255 {
            return Err(Error::NameTooLong);
        }
        let mut pinode = self.read_inode(parent)?;
        if !pinode.is_dir() {
            return Err(Error::NotDir);
        }
        if self.lookup(parent, name).is_ok() {
            return Err(Error::Exists);
        }
        if pinode.links() >= 32000 {
            return Err(Error::TooManyLinks);
        }
        let ino = self.alloc_inode(parent, true)?;
        let mut inode = Inode::new(self.sb.inode_size() as usize);
        let now = self.now();
        inode.set_mode(S_IFDIR | (mode & 0o7777));
        inode.set_uid(uid);
        inode.set_gid(gid);
        inode.set_links(2);
        inode.set_atime(now);
        inode.set_ctime(now);
        inode.set_mtime(now);
        let blk = match self.bmap(&mut inode, ino, 0, true) {
            Ok(b) => b,
            Err(e) => {
                self.free_inode(ino, true)?;
                return Err(e);
            }
        };
        let mut b = vec![0u8; self.bs];
        write_entry(&mut b, 0, ino, 12, ".", ft::DIR);
        write_entry(&mut b, 12, parent, self.bs - 12, "..", ft::DIR);
        self.write_block(blk, &b)?;
        inode.set_size(self.bs as u64);
        self.write_inode(ino, &inode)?;
        self.add_entry(parent, name, ino, ft::DIR)?;
        let mut pinode = self.read_inode(parent)?;
        pinode.set_links(pinode.links() + 1);
        self.write_inode(parent, &pinode)?;
        Ok(ino)
    }

    pub fn symlink(&mut self, dir: u32, name: &str, target: &str, uid: u32, gid: u32) -> Result<u32> {
        self.check_rw()?;
        if target.is_empty() || target.len() >= self.bs {
            return Err(Error::NameTooLong);
        }
        if self.lookup(dir, name).is_ok() {
            return Err(Error::Exists);
        }
        let ino = self.alloc_inode(dir, false)?;
        let mut inode = Inode::new(self.sb.inode_size() as usize);
        let now = self.now();
        inode.set_mode(S_IFLNK | 0o777);
        inode.set_uid(uid);
        inode.set_gid(gid);
        inode.set_links(1);
        inode.set_atime(now);
        inode.set_ctime(now);
        inode.set_mtime(now);
        if target.len() < 60 {
            inode.raw[40..40 + target.len()].copy_from_slice(target.as_bytes());
            inode.set_size(target.len() as u64);
            self.write_inode(ino, &inode)?;
        } else {
            let blk = self.bmap(&mut inode, ino, 0, true)?;
            let mut b = vec![0u8; self.bs];
            b[..target.len()].copy_from_slice(target.as_bytes());
            self.write_block(blk, &b)?;
            inode.set_size(target.len() as u64);
            self.write_inode(ino, &inode)?;
        }
        self.add_entry(dir, name, ino, ft::SYMLINK)?;
        Ok(ino)
    }

    pub fn readlink(&mut self, ino: u32) -> Result<String> {
        let mut inode = self.read_inode(ino)?;
        if !inode.is_symlink() {
            return Err(Error::Invalid);
        }
        let len = inode.size() as usize;
        if inode.is_fast_symlink() {
            return Ok(String::from_utf8_lossy(&inode.raw[40..40 + len.min(60)]).into_owned());
        }
        let blk = self.bmap(&mut inode, ino, 0, false)?;
        let mut b = vec![0u8; self.bs];
        self.read_block(blk, &mut b)?;
        Ok(String::from_utf8_lossy(&b[..len.min(self.bs)]).into_owned())
    }

    pub fn link(&mut self, dir: u32, name: &str, ino: u32) -> Result<()> {
        self.check_rw()?;
        let mut inode = self.read_inode(ino)?;
        if inode.is_dir() {
            return Err(Error::IsDir);
        }
        if inode.links() >= 32000 {
            return Err(Error::TooManyLinks);
        }
        if self.lookup(dir, name).is_ok() {
            return Err(Error::Exists);
        }
        self.add_entry(dir, name, ino, ft_from_mode(inode.mode()))?;
        inode.set_links(inode.links() + 1);
        let now = self.now();
        inode.set_ctime(now);
        self.write_inode(ino, &inode)
    }

    /// Remove a non-directory entry. The inode is released when its link
    /// count reaches zero *and* the caller says nobody holds it open
    /// (otherwise call [`Ext2::evict`] on last close).
    pub fn unlink(&mut self, dir: u32, name: &str, in_use: bool) -> Result<u32> {
        self.check_rw()?;
        let ino = self.lookup(dir, name)?;
        let mut inode = self.read_inode(ino)?;
        if inode.is_dir() {
            return Err(Error::IsDir);
        }
        self.remove_entry(dir, name)?;
        inode.set_links(inode.links().saturating_sub(1));
        let now = self.now();
        inode.set_ctime(now);
        self.write_inode(ino, &inode)?;
        if inode.links() == 0 && !in_use {
            self.evict(ino)?;
        }
        Ok(ino)
    }

    pub fn rmdir(&mut self, parent: u32, name: &str) -> Result<()> {
        self.check_rw()?;
        if name == "." || name == ".." {
            return Err(Error::Invalid);
        }
        let ino = self.lookup(parent, name)?;
        let inode = self.read_inode(ino)?;
        if !inode.is_dir() {
            return Err(Error::NotDir);
        }
        if !self.dir_is_empty(ino)? {
            return Err(Error::NotEmpty);
        }
        self.remove_entry(parent, name)?;
        let mut inode = self.read_inode(ino)?;
        inode.set_links(0);
        self.write_inode(ino, &inode)?;
        self.release(ino, true)?;
        let mut p = self.read_inode(parent)?;
        p.set_links(p.links().saturating_sub(1));
        self.write_inode(parent, &p)?;
        Ok(())
    }

    /// Free an unlinked inode's blocks and the inode itself (no-op if it
    /// still has links).
    pub fn evict(&mut self, ino: u32) -> Result<()> {
        let inode = self.read_inode(ino)?;
        if inode.links() > 0 || inode.mode() == 0 {
            return Ok(());
        }
        self.release(ino, inode.is_dir())
    }

    fn release(&mut self, ino: u32, dir: bool) -> Result<()> {
        let mut inode = self.read_inode(ino)?;
        if !inode.is_fast_symlink() && !matches!(inode.mode() & S_IFMT, S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK) {
            self.free_from(&mut inode, 0)?;
        }
        inode.set_size(0);
        let now = self.now();
        inode.set_dtime(now);
        inode.set_mode(0);
        for i in 0..15 {
            inode.set_block(i, 0);
        }
        inode.set_sectors(0);
        self.write_inode(ino, &inode)?;
        self.free_inode(ino, dir)
    }

    /// `rename(2)` within one filesystem. Replacing an existing target is
    /// allowed when types are compatible (and a directory target is empty).
    pub fn rename(&mut self, odir: u32, oname: &str, ndir: u32, nname: &str) -> Result<()> {
        self.check_rw()?;
        if nname.len() > 255 {
            return Err(Error::NameTooLong);
        }
        let ino = self.lookup(odir, oname)?;
        let inode = self.read_inode(ino)?;
        let is_dir = inode.is_dir();
        if let Ok(existing) = self.lookup(ndir, nname) {
            if existing == ino {
                return Ok(());
            }
            let ex = self.read_inode(existing)?;
            match (is_dir, ex.is_dir()) {
                (true, false) => return Err(Error::NotDir),
                (false, true) => return Err(Error::IsDir),
                (true, true) if !self.dir_is_empty(existing)? => return Err(Error::NotEmpty),
                _ => {}
            }
            self.set_entry(ndir, nname, ino, ft_from_mode(inode.mode()))?;
            if ex.is_dir() {
                let mut e = ex;
                e.set_links(0);
                self.write_inode(existing, &e)?;
                self.release(existing, true)?;
                let mut nd = self.read_inode(ndir)?;
                nd.set_links(nd.links().saturating_sub(1));
                self.write_inode(ndir, &nd)?;
            } else {
                let mut e = ex;
                e.set_links(e.links().saturating_sub(1));
                self.write_inode(existing, &e)?;
                if e.links() == 0 {
                    self.release(existing, false)?;
                }
            }
        } else {
            self.add_entry(ndir, nname, ino, ft_from_mode(inode.mode()))?;
        }
        self.remove_entry(odir, oname)?;
        if is_dir && odir != ndir {
            self.set_entry(ino, "..", ndir, ft::DIR)?;
            let mut o = self.read_inode(odir)?;
            o.set_links(o.links().saturating_sub(1));
            self.write_inode(odir, &o)?;
            let mut n = self.read_inode(ndir)?;
            n.set_links(n.links() + 1);
            self.write_inode(ndir, &n)?;
        }
        let mut i = self.read_inode(ino)?;
        let now = self.now();
        i.set_ctime(now);
        self.write_inode(ino, &i)
    }

    pub fn set_attr(&mut self, ino: u32, a: &Attr) -> Result<()> {
        self.check_rw()?;
        let mut inode = self.read_inode(ino)?;
        if let Some(size) = a.size {
            if inode.is_dir() {
                return Err(Error::IsDir);
            }
            self.truncate_inode(&mut inode, ino, size)?;
        }
        if let Some(m) = a.mode {
            inode.set_mode((inode.mode() & S_IFMT) | (m & 0o7777));
        }
        if let Some(u) = a.uid {
            inode.set_uid(u);
        }
        if let Some(g) = a.gid {
            inode.set_gid(g);
        }
        if let Some(t) = a.atime {
            inode.set_atime(t);
        }
        if let Some(t) = a.mtime {
            inode.set_mtime(t);
        }
        let now = self.now();
        inode.set_ctime(a.ctime.unwrap_or(now));
        self.write_inode(ino, &inode)
    }
}

fn write_entry(b: &mut [u8], off: usize, ino: u32, rec_len: usize, name: &str, ftype: u8) {
    w32(b, off, ino);
    w16(b, off + 4, rec_len as u16);
    b[off + 6] = name.len() as u8;
    b[off + 7] = ftype;
    b[off + 8..off + 8 + name.len()].copy_from_slice(name.as_bytes());
}

// ── mkfs ────────────────────────────────────────────────────────────────────

/// Options for [`format`].
pub struct FormatOptions<'a> {
    pub label: &'a str,
    pub uuid: [u8; 16],
    pub now: u32,
    /// Bytes of disk per inode (mke2fs `-i`).
    pub bytes_per_inode: u64,
}

/// Create an empty ext2 filesystem on `dev` (4 KiB blocks, 128-byte inodes,
/// sparse superblock backups, root directory and `lost+found`).
pub fn format<D: Device>(dev: &mut D, o: &FormatOptions) -> Result<()> {
    let bs: usize = 4096;
    let blocks = (dev.size() / bs as u64).min(u32::MAX as u64) as u32;
    if blocks < 64 {
        return Err(Error::NoSpace);
    }
    let bpg: u32 = 8 * bs as u32;
    let ngroups = blocks.div_ceil(bpg);
    let isz: u32 = 128;
    let inodes_per_block = bs as u32 / isz;
    let want = ((blocks as u64 * bs as u64) / o.bytes_per_inode.max(4096)) as u32;
    let mut ipg = want.div_ceil(ngroups).max(inodes_per_block * 2);
    ipg = ipg.div_ceil(inodes_per_block) * inodes_per_block;
    ipg = ipg.min(8 * bs as u32);
    let itable_blocks = ipg / inodes_per_block;
    let gdt_blocks = (ngroups as usize * 32).div_ceil(bs) as u32;

    let mut groups = Vec::new();
    let mut total_free = 0u32;
    for g in 0..ngroups {
        let start = g * bpg;
        let count = (blocks - start).min(bpg);
        let mut meta = 0;
        if has_super_backup(g, true) {
            meta += 1 + gdt_blocks;
        }
        let bb = start + meta;
        let ib = bb + 1;
        let it = ib + 1;
        meta += 2 + itable_blocks;
        if meta + 1 >= count {
            // A tiny trailing group cannot hold its own metadata: drop it.
            break;
        }
        groups.push((start, count, bb, ib, it, meta));
    }
    let ngroups = groups.len() as u32;
    let blocks = groups.last().map(|g| g.0 + g.1).ok_or(Error::NoSpace)?;
    let inodes = ipg * ngroups;

    // Root directory + lost+found data blocks live right after group 0's metadata.
    let (_, _, _, _, _, meta0) = groups[0];
    let root_blk = meta0;
    let lf_blk = meta0 + 1;

    let mut gdt = vec![0u8; (gdt_blocks as usize) * bs];
    let zero = vec![0u8; bs];
    for (gi, &(_, count, bb, ib, it, meta)) in groups.iter().enumerate() {
        let mut used = meta;
        if gi == 0 {
            used += 2; // root + lost+found blocks
        }
        // Block bitmap: metadata (+ the two directory blocks in group 0), and
        // padding past the end of the last group.
        let mut bitmap = vec![0u8; bs];
        for i in 0..used as usize {
            bitmap[i / 8] |= 1 << (i % 8);
        }
        for i in count as usize..(bs * 8) {
            bitmap[i / 8] |= 1 << (i % 8);
        }
        dev.write(bb as u64 * bs as u64, &bitmap)?;
        // Inode bitmap: reserved inodes 1..=11 in group 0; padding past ipg.
        let mut ibm = vec![0u8; bs];
        if gi == 0 {
            for i in 0..11 {
                ibm[i / 8] |= 1 << (i % 8);
            }
        }
        for i in ipg as usize..(bs * 8) {
            ibm[i / 8] |= 1 << (i % 8);
        }
        dev.write(ib as u64 * bs as u64, &ibm)?;
        for t in 0..itable_blocks {
            dev.write((it + t) as u64 * bs as u64, &zero)?;
        }
        let free_blocks = count - used;
        total_free += free_blocks;
        let gd = GroupDesc {
            block_bitmap: bb,
            inode_bitmap: ib,
            inode_table: it,
            free_blocks: free_blocks as u16,
            free_inodes: (if gi == 0 { ipg - 11 } else { ipg }) as u16,
            used_dirs: if gi == 0 { 2 } else { 0 },
        };
        gd.encode(&mut gdt[gi * 32..gi * 32 + 32]);
    }

    let mut sb = vec![0u8; 1024];
    w32(&mut sb, 0, inodes);
    w32(&mut sb, 4, blocks);
    w32(&mut sb, 8, blocks / 20);
    w32(&mut sb, 12, total_free);
    w32(&mut sb, 16, inodes - 11);
    w32(&mut sb, 20, 0); // first data block (bs > 1024)
    w32(&mut sb, 24, 2); // log2(4096) - 10
    w32(&mut sb, 28, 2);
    w32(&mut sb, 32, bpg);
    w32(&mut sb, 36, bpg);
    w32(&mut sb, 40, ipg);
    w32(&mut sb, 44, 0);
    w32(&mut sb, 48, o.now);
    w16(&mut sb, 52, 0);
    w16(&mut sb, 54, 0xFFFF); // max mount count: -1 (no forced checks)
    w16(&mut sb, 56, MAGIC);
    w16(&mut sb, 58, STATE_VALID);
    w16(&mut sb, 60, 1); // errors: continue
    w32(&mut sb, 64, o.now);
    w32(&mut sb, 72, 0); // creator OS: Linux (keeps e2fsck's inode layout)
    w32(&mut sb, 76, 1); // dynamic revision
    w32(&mut sb, 84, 11);
    w16(&mut sb, 88, isz as u16);
    w32(&mut sb, 96, INCOMPAT_FILETYPE);
    w32(&mut sb, 100, RO_SPARSE_SUPER | RO_LARGE_FILE);
    sb[104..120].copy_from_slice(&o.uuid);
    let lbl = o.label.as_bytes();
    sb[120..120 + lbl.len().min(16)].copy_from_slice(&lbl[..lbl.len().min(16)]);
    w32(&mut sb, 264, o.now); // s_mkfs_time

    // Superblock + GDT in group 0 and in every sparse backup group.
    for (gi, &(start, ..)) in groups.iter().enumerate() {
        if !has_super_backup(gi as u32, true) {
            continue;
        }
        let mut copy = sb.clone();
        w16(&mut copy, 90, gi as u16); // s_block_group_nr
        if gi == 0 {
            dev.write(1024, &copy)?;
        } else {
            let mut blk = vec![0u8; bs];
            blk[..1024].copy_from_slice(&copy);
            dev.write(start as u64 * bs as u64, &blk)?;
        }
        dev.write((start as u64 + 1) * bs as u64, &gdt)?;
    }

    // Root (inode 2) and lost+found (inode 11).
    let (_, _, _, _, it0, _) = groups[0];
    let mut table = vec![0u8; bs];
    let mut mk = |slot: usize, mode: u16, links: u16, blk: u32| {
        let o2 = slot * isz as usize;
        let t = &mut table[o2..o2 + isz as usize];
        w16(t, 0, mode);
        w32(t, 4, bs as u32);
        w32(t, 8, o.now);
        w32(t, 12, o.now);
        w32(t, 16, o.now);
        w16(t, 26, links);
        w32(t, 28, (bs / 512) as u32);
        w32(t, 40, blk);
    };
    mk(1, S_IFDIR | 0o755, 3, root_blk);
    mk(10, S_IFDIR | 0o700, 2, lf_blk);
    dev.write(it0 as u64 * bs as u64, &table)?;

    let mut d = vec![0u8; bs];
    write_entry(&mut d, 0, ROOT_INO, 12, ".", ft::DIR);
    write_entry(&mut d, 12, ROOT_INO, 12, "..", ft::DIR);
    write_entry(&mut d, 24, 11, bs - 24, "lost+found", ft::DIR);
    dev.write(root_blk as u64 * bs as u64, &d)?;
    d.fill(0);
    write_entry(&mut d, 0, 11, 12, ".", ft::DIR);
    write_entry(&mut d, 12, ROOT_INO, bs - 12, "..", ft::DIR);
    dev.write(lf_blk as u64 * bs as u64, &d)?;
    dev.flush()
}
