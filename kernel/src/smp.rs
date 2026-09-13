//! Multi-processor topology discovery (ACPI MADT).
//!
//! This is the first, deliberately read-only step toward SMP: parse the ACPI
//! tables to learn how many CPUs the platform has, their local-APIC ids, and the
//! LAPIC/IOAPIC addresses. Nothing here changes interrupt routing or scheduling
//! — the application processors stay parked by firmware until a later phase sends
//! them a startup IPI — so discovery cannot destabilise the running system.

use crate::mm::phys_to_virt;
use crate::sync::Once;
use alloc::vec::Vec;

/// One discovered application/boot processor.
#[derive(Clone, Copy, Debug)]
pub struct Cpu {
    pub acpi_id: u32,
    pub apic_id: u32,
    pub enabled: bool,
}

/// An IO-APIC (external interrupt controller) found in the MADT.
#[derive(Clone, Copy, Debug)]
pub struct IoApic {
    pub id: u8,
    pub addr: u32,
    pub gsi_base: u32,
}

#[derive(Default)]
pub struct Topology {
    pub cpus: Vec<Cpu>,
    pub ioapics: Vec<IoApic>,
    pub lapic_addr: u64,
}

impl Topology {
    /// CPUs the firmware reports as usable (enabled).
    pub fn enabled_count(&self) -> usize {
        self.cpus.iter().filter(|c| c.enabled).count().max(1)
    }
}

static TOPO: Once<Topology> = Once::new();

/// Discover the CPU topology from ACPI. Safe to call once, early. Falls back to
/// a single CPU if the tables are absent or malformed (never panics).
pub fn init() {
    let topo = parse().unwrap_or_default();
    let topo = TOPO.call_once(|| topo);
    if topo.cpus.is_empty() {
        crate::knotice!("smp", "no ACPI MADT: assuming 1 CPU");
        return;
    }
    let ids: Vec<u32> = topo.cpus.iter().filter(|c| c.enabled).map(|c| c.apic_id).collect();
    crate::knotice!(
        "smp",
        "{} CPU(s) present (APIC ids {:?}), LAPIC @ {:#x}, {} IOAPIC(s) — running on the BSP only for now",
        topo.enabled_count(),
        ids,
        topo.lapic_addr,
        topo.ioapics.len()
    );
}

/// Number of CPUs the platform has (enabled in the MADT); 1 if unknown.
pub fn present_count() -> usize {
    TOPO.get().map(|t| t.enabled_count()).unwrap_or(1)
}

pub fn topology() -> Option<&'static Topology> {
    TOPO.get()
}

/// Bring the application processors online (SMP step 3). Each AP runs the
/// trampoline into long mode and parks; the BSP keeps doing all the work for
/// now. Best-effort: an AP that does not check in within the timeout is skipped.
pub fn bringup() {
    use crate::arch::paging::{self, flags};
    use crate::arch::{apic, ap, cpu};
    let Some(topo) = TOPO.get() else { return };
    if !apic::enabled() {
        return;
    }
    let bsp = apic::local_id();
    let cr3 = cpu::read_cr3();

    // Identity-map the trampoline pages into the (live) kernel PML4 so the AP
    // keeps fetching instructions right after it turns paging on.
    let pml4 = crate::mm::kspace::pml4();
    for p in [ap::TRAMP_PA, ap::TRAMP_PA + 0x1000] {
        let _ = unsafe { paging::map_4k(pml4, p, p as u64, flags::PRESENT | flags::WRITABLE, &mut || crate::mm::frame::alloc_zeroed(0)) };
    }

    let mut online = 0usize;
    for c in topo.cpus.iter().filter(|c| c.enabled && c.apic_id != bsp) {
        // A per-AP kernel stack (in the direct map, so it is already mapped).
        let Some(stack_phys) = crate::mm::frame::alloc(2) else { continue };
        let stack_top = (crate::mm::phys_to_virt(stack_phys) + (4 * 4096)) as u64 & !15;
        ap::install(cr3, stack_top);

        let before = ap::ONLINE.load(core::sync::atomic::Ordering::SeqCst);
        apic::send_init(c.apic_id);
        crate::arch::pit::busy_wait_ms(10);
        apic::send_sipi(c.apic_id, ap::SIPI_VECTOR);
        crate::arch::pit::busy_wait_ms(1);
        apic::send_sipi(c.apic_id, ap::SIPI_VECTOR);

        // Wait (up to ~200 ms) for the AP to reach ap_entry.
        let mut up = false;
        for _ in 0..200 {
            if ap::ONLINE.load(core::sync::atomic::Ordering::SeqCst) > before {
                up = true;
                break;
            }
            crate::arch::pit::busy_wait_ms(1);
        }
        if up {
            online += 1;
            crate::knotice!("smp", "CPU (APIC {}) online", c.apic_id);
        } else {
            crate::kwarn!("smp", "CPU (APIC {}) did not start (trampoline stage {})", c.apic_id, ap::status());
        }
    }
    crate::knotice!("smp", "{} CPU(s) online (1 BSP + {} AP)", 1 + online, online);
}

// ── ACPI table parsing ───────────────────────────────────────────────────────

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Read `len` bytes of physical memory through the direct map.
unsafe fn phys_slice(paddr: u64, len: usize) -> &'static [u8] {
    unsafe { core::slice::from_raw_parts(phys_to_virt(paddr) as *const u8, len) }
}

/// Map a whole ACPI SDT: read its 36-byte header for the length, then the rest.
/// Returns `None` if the length is implausible.
unsafe fn map_sdt(paddr: u64) -> Option<&'static [u8]> {
    if paddr == 0 {
        return None;
    }
    let hdr = unsafe { phys_slice(paddr, 36) };
    let len = le32(hdr, 4) as usize;
    if !(36..=1 << 20).contains(&len) {
        return None;
    }
    Some(unsafe { phys_slice(paddr, len) })
}

fn parse() -> Option<Topology> {
    let rsdp_paddr = crate::boot::info().rsdp;
    if rsdp_paddr == 0 {
        return None;
    }
    // RSDP: "RSD PTR " signature, then revision selects RSDT (v1) or XSDT (v2).
    let rsdp = unsafe { phys_slice(rsdp_paddr, 36) };
    if &rsdp[0..8] != b"RSD PTR " {
        return None;
    }
    let revision = rsdp[15];
    let (root_paddr, entry_size) = if revision >= 2 && le64(rsdp, 24) != 0 {
        (le64(rsdp, 24), 8usize) // XSDT
    } else {
        (le32(rsdp, 16) as u64, 4usize) // RSDT
    };
    let root = unsafe { map_sdt(root_paddr)? };
    // Iterate the pointer array after the 36-byte header, looking for the MADT.
    let mut off = 36;
    while off + entry_size <= root.len() {
        let sdt_paddr = if entry_size == 8 { le64(root, off) } else { le32(root, off) as u64 };
        off += entry_size;
        let Some(sdt) = (unsafe { map_sdt(sdt_paddr) }) else { continue };
        if &sdt[0..4] == b"APIC" {
            return Some(parse_madt(sdt));
        }
    }
    None
}

fn parse_madt(madt: &[u8]) -> Topology {
    let mut topo = Topology { lapic_addr: le32(madt, 36) as u64, ..Default::default() };
    // Entries begin after the 8-byte MADT-specific header (local APIC addr +
    // flags), i.e. at offset 44.
    let mut off = 44;
    while off + 2 <= madt.len() {
        let etype = madt[off];
        let elen = madt[off + 1] as usize;
        if elen < 2 || off + elen > madt.len() {
            break;
        }
        let e = &madt[off..off + elen];
        match etype {
            // Processor Local APIC: acpi_id(2), apic_id(3), flags(4..8).
            0 if elen >= 8 => {
                topo.cpus.push(Cpu { acpi_id: e[2] as u32, apic_id: e[3] as u32, enabled: le32(e, 4) & 1 != 0 });
            }
            // IO APIC: id(2), addr(4..8), gsi_base(8..12).
            1 if elen >= 12 => {
                topo.ioapics.push(IoApic { id: e[2], addr: le32(e, 4), gsi_base: le32(e, 8) });
            }
            // Local APIC Address Override: addr(4..12).
            5 if elen >= 12 => {
                topo.lapic_addr = le64(e, 4);
            }
            // Processor Local x2APIC: x2apic_id(4..8), flags(8..12), acpi_id(12..16).
            9 if elen >= 16 => {
                topo.cpus.push(Cpu { acpi_id: le32(e, 12), apic_id: le32(e, 4), enabled: le32(e, 8) & 1 != 0 });
            }
            _ => {}
        }
        off += elen;
    }
    topo
}
