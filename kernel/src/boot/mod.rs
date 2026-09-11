//! Boot information handed over by the loader (QEMU's PVH boot protocol).

use crate::mm::phys_to_virt;
use crate::sync::Once;

pub const MAX_REGIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemKind {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    Bad,
}

#[derive(Clone, Copy, Debug)]
pub struct MemRegion {
    pub start: u64,
    pub end: u64,
    pub kind: MemKind,
}

pub struct BootInfo {
    regions: [MemRegion; MAX_REGIONS],
    region_count: usize,
    cmdline: [u8; 512],
    cmdline_len: usize,
    pub rsdp: u64,
    pub start_info: u64,
}

impl BootInfo {
    pub fn regions(&self) -> &[MemRegion] {
        &self.regions[..self.region_count]
    }
    pub fn usable(&self) -> impl Iterator<Item = &MemRegion> {
        self.regions().iter().filter(|r| r.kind == MemKind::Usable)
    }
    /// Highest usable physical address (exclusive).
    pub fn max_ram(&self) -> u64 {
        self.usable().map(|r| r.end).max().unwrap_or(0)
    }
    pub fn cmdline(&self) -> &str {
        core::str::from_utf8(&self.cmdline[..self.cmdline_len]).unwrap_or("")
    }
    /// Value of `key=value` on the kernel command line.
    pub fn arg(&self, key: &str) -> Option<&str> {
        self.cmdline().split_ascii_whitespace().find_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k == key).then_some(v)
        })
    }
}

static BOOT: Once<BootInfo> = Once::new();

pub fn info() -> &'static BootInfo {
    BOOT.expect_init()
}

#[repr(C)]
struct HvmStartInfo {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    modlist_paddr: u64,
    cmdline_paddr: u64,
    rsdp_paddr: u64,
    memmap_paddr: u64,
    memmap_entries: u32,
    _reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HvmMemmapEntry {
    addr: u64,
    size: u64,
    kind: u32,
    _reserved: u32,
}

const HVM_START_MAGIC: u32 = 0x336e_c578;

/// Parse the PVH `hvm_start_info` (still reachable through the boot page
/// tables' direct map) into a self-contained [`BootInfo`].
pub fn parse_pvh(start_info_phys: u64) -> &'static BootInfo {
    let si = unsafe { &*(phys_to_virt(start_info_phys) as *const HvmStartInfo) };
    if si.magic != HVM_START_MAGIC {
        panic!("boot: bad PVH start_info magic {:#x} at {:#x}", si.magic, start_info_phys);
    }
    let mut info = BootInfo {
        regions: [MemRegion { start: 0, end: 0, kind: MemKind::Reserved }; MAX_REGIONS],
        region_count: 0,
        cmdline: [0; 512],
        cmdline_len: 0,
        rsdp: si.rsdp_paddr,
        start_info: start_info_phys,
    };
    if si.version >= 1 && si.memmap_paddr != 0 {
        let n = (si.memmap_entries as usize).min(MAX_REGIONS);
        let entries =
            unsafe { core::slice::from_raw_parts(phys_to_virt(si.memmap_paddr) as *const HvmMemmapEntry, n) };
        for e in entries {
            let kind = match e.kind {
                1 => MemKind::Usable,
                3 => MemKind::AcpiReclaimable,
                4 => MemKind::AcpiNvs,
                5 => MemKind::Bad,
                _ => MemKind::Reserved,
            };
            info.regions[info.region_count] = MemRegion { start: e.addr, end: e.addr + e.size, kind };
            info.region_count += 1;
        }
    }
    if info.region_count == 0 {
        panic!("boot: the loader provided no memory map");
    }
    if si.cmdline_paddr != 0 {
        let p = phys_to_virt(si.cmdline_paddr) as *const u8;
        let mut n = 0;
        while n < info.cmdline.len() - 1 {
            let b = unsafe { *p.add(n) };
            if b == 0 {
                break;
            }
            info.cmdline[n] = b;
            n += 1;
        }
        info.cmdline_len = n;
    }
    BOOT.call_once(|| info)
}
