//! PCI bus enumeration (configuration mechanism #1, ports 0xCF8/0xCFC).

use crate::arch::port::{inl, outl};
use crate::sync::SpinLock;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

impl Address {
    fn cfg(&self, off: u8) -> u32 {
        0x8000_0000 | (self.bus as u32) << 16 | (self.dev as u32) << 11 | (self.func as u32) << 8 | (off as u32 & 0xFC)
    }
    pub fn read32(&self, off: u8) -> u32 {
        let _g = CFG_LOCK.lock();
        unsafe {
            outl(0xCF8, self.cfg(off));
            inl(0xCFC)
        }
    }
    pub fn write32(&self, off: u8, v: u32) {
        let _g = CFG_LOCK.lock();
        unsafe {
            outl(0xCF8, self.cfg(off));
            outl(0xCFC, v);
        }
    }
    pub fn read16(&self, off: u8) -> u16 {
        (self.read32(off & !3) >> ((off & 2) * 8)) as u16
    }
    pub fn read8(&self, off: u8) -> u8 {
        (self.read32(off & !3) >> ((off & 3) * 8)) as u8
    }
    pub fn write16(&self, off: u8, v: u16) {
        let shift = (off & 2) * 8;
        let old = self.read32(off & !3);
        let new = (old & !(0xFFFF << shift)) | ((v as u32) << shift);
        self.write32(off & !3, new);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Bar {
    None,
    Io(u16),
    Mem { addr: u64, size: u64, prefetchable: bool },
}

#[derive(Clone, Debug)]
pub struct Device {
    pub addr: Address,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub irq_line: u8,
    pub bars: [Bar; 6],
}

impl Device {
    /// Enable memory/IO decoding and bus mastering (DMA).
    pub fn enable(&self) {
        let cmd = self.addr.read16(0x04);
        self.addr.write16(0x04, cmd | 0x0007);
    }
    pub fn class_name(&self) -> &'static str {
        match (self.class, self.subclass) {
            (0x01, 0x01) => "IDE interface",
            (0x01, 0x06) => "SATA controller",
            (0x01, 0x08) => "NVM controller",
            (0x01, _) => "Mass storage controller",
            (0x02, 0x00) => "Ethernet controller",
            (0x02, _) => "Network controller",
            (0x03, 0x00) => "VGA compatible controller",
            (0x03, _) => "Display controller",
            (0x06, 0x00) => "Host bridge",
            (0x06, 0x01) => "ISA bridge",
            (0x06, 0x04) => "PCI bridge",
            (0x06, 0x80) => "Bridge",
            (0x0C, 0x03) => "USB controller",
            (0x0C, 0x05) => "SMBus",
            (0x06, _) => "Bridge",
            (0x08, _) => "System peripheral",
            (0x00, _) => "Unclassified device",
            _ => "Device",
        }
    }
    pub fn vendor_name(&self) -> &'static str {
        match self.vendor {
            0x8086 => "Intel Corporation",
            0x1234 => "QEMU",
            0x1AF4 => "Red Hat, Inc. (virtio)",
            0x1B36 => "Red Hat, Inc.",
            0x10EC => "Realtek",
            _ => "Unknown vendor",
        }
    }
    pub fn device_name(&self) -> &'static str {
        match (self.vendor, self.device) {
            (0x8086, 0x1237) => "440FX - 82441FX PMC [Natoma]",
            (0x8086, 0x7000) => "82371SB PIIX3 ISA [Natoma/Triton II]",
            (0x8086, 0x7010) => "82371SB PIIX3 IDE [Natoma/Triton II]",
            (0x8086, 0x7113) => "82371AB/EB/MB PIIX4 ACPI",
            (0x8086, 0x100E) => "82540EM Gigabit Ethernet Controller",
            (0x8086, 0x10D3) => "82574L Gigabit Network Connection",
            (0x8086, 0x29C0) => "82G33/G31/P35/P31 Express DRAM Controller",
            (0x8086, 0x2918) => "82801IB (ICH9) LPC Interface Controller",
            (0x8086, 0x2922) => "82801IR/IO/IH (ICH9R/DO/DH) 6 port SATA Controller [AHCI mode]",
            (0x8086, 0x2930) => "82801I (ICH9 Family) SMBus Controller",
            (0x1234, 0x1111) => "QEMU Standard VGA",
            (0x1AF4, 0x1000) | (0x1AF4, 0x1041) => "Virtio network device",
            (0x1AF4, 0x1001) | (0x1AF4, 0x1042) => "Virtio block device",
            (0x1AF4, 0x1005) | (0x1AF4, 0x1044) => "Virtio RNG",
            _ => "Device",
        }
    }
}

static CFG_LOCK: SpinLock<()> = SpinLock::new(());
static DEVICES: SpinLock<Vec<Device>> = SpinLock::new(Vec::new());

fn read_bars(a: Address) -> [Bar; 6] {
    let mut bars = [Bar::None; 6];
    let mut i = 0;
    while i < 6 {
        let off = 0x10 + (i as u8) * 4;
        let v = a.read32(off);
        if v == 0 {
            i += 1;
            continue;
        }
        if v & 1 == 1 {
            bars[i] = Bar::Io((v & 0xFFFC) as u16);
            i += 1;
            continue;
        }
        let is64 = (v >> 1) & 3 == 2;
        // Size probe: write all-ones, read back the mask, restore.
        a.write32(off, 0xFFFF_FFFF);
        let mask_lo = a.read32(off) & !0xF;
        a.write32(off, v);
        let mut addr = (v & !0xF) as u64;
        let mut mask = mask_lo as u64 | 0xFFFF_FFFF_0000_0000;
        if is64 && i < 5 {
            let hi = a.read32(off + 4);
            a.write32(off + 4, 0xFFFF_FFFF);
            let mask_hi = a.read32(off + 4);
            a.write32(off + 4, hi);
            addr |= (hi as u64) << 32;
            mask = ((mask_hi as u64) << 32) | mask_lo as u64;
        }
        let size = (!mask).wrapping_add(1);
        bars[i] = Bar::Mem { addr, size, prefetchable: v & 8 != 0 };
        i += if is64 { 2 } else { 1 };
    }
    bars
}

pub fn init() {
    let mut found = Vec::new();
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let a = Address { bus, dev, func };
                let id = a.read32(0);
                if id & 0xFFFF == 0xFFFF {
                    if func == 0 {
                        break;
                    }
                    continue;
                }
                let class = a.read32(0x08);
                let header = a.read8(0x0E);
                let d = Device {
                    addr: a,
                    vendor: id as u16,
                    device: (id >> 16) as u16,
                    class: (class >> 24) as u8,
                    subclass: (class >> 16) as u8,
                    prog_if: (class >> 8) as u8,
                    revision: class as u8,
                    irq_line: a.read8(0x3C),
                    bars: if header & 0x7F == 0 { read_bars(a) } else { [Bar::None; 6] },
                };
                crate::kinfo!(
                    "pci",
                    "{:02x}:{:02x}.{} [{:04x}:{:04x}] {} (irq {})",
                    bus,
                    dev,
                    func,
                    d.vendor,
                    d.device,
                    d.class_name(),
                    d.irq_line
                );
                found.push(d);
                if func == 0 && header & 0x80 == 0 {
                    break; // single-function device
                }
            }
        }
    }
    *DEVICES.lock() = found;
}

pub fn devices() -> Vec<Device> {
    DEVICES.lock().clone()
}

pub fn find(vendor: u16, device: u16) -> Option<Device> {
    DEVICES.lock().iter().find(|d| d.vendor == vendor && d.device == device).cloned()
}

pub fn find_class(class: u8, subclass: u8) -> Option<Device> {
    DEVICES.lock().iter().find(|d| d.class == class && d.subclass == subclass).cloned()
}
