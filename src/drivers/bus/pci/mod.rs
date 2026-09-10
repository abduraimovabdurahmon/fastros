//! PCI Bus Driver
//!
//! Enumerates all PCI devices by scanning bus:device:function combinations.
//! Each device identified by: vendor_id, device_id, class, subclass.
//!
//! Linux equivalent: drivers/pci/probe.c  drivers/pci/bus.c

pub mod config;

// ── PCI device descriptor ─────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct PciDevice {
    pub bus:       u8,
    pub device:    u8,
    pub function:  u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class:     u8,
    pub subclass:  u8,
    pub bar0:      u32,
}

const MAX_DEVICES: usize = 32;
static mut FOUND: [PciDevice; MAX_DEVICES] = [PciDevice {
    bus: 0, device: 0, function: 0,
    vendor_id: 0, device_id: 0, class: 0, subclass: 0, bar0: 0,
}; MAX_DEVICES];
static mut FOUND_COUNT: usize = 0;

// ── Enumeration ───────────────────────────────────────────────────────────────

pub fn init() {
    // Scan bus 0 (QEMU puts all devices on bus 0).
    // A real kernel follows PCI bridge hierarchies recursively.
    for dev in 0u8..32 {
        let vendor = config::vendor_id(0, dev, 0);
        if vendor == 0xFFFF { continue; }   // empty slot

        let is_multifunction =
            (unsafe { config::read_u8(0, dev, 0, 0x0E) } & 0x80) != 0;
        let max_func = if is_multifunction { 8u8 } else { 1u8 };

        for func in 0..max_func {
            let vendor = config::vendor_id(0, dev, func);
            if vendor == 0xFFFF { continue; }

            let did   = config::device_id(0, dev, func);
            let class = unsafe { config::read_u8(0, dev, func, 0x0B) };
            let sub   = unsafe { config::read_u8(0, dev, func, 0x0A) };
            let bar0  = config::bar(0, dev, func, 0);

            unsafe {
                if FOUND_COUNT < MAX_DEVICES {
                    FOUND[FOUND_COUNT] = PciDevice {
                        bus: 0, device: dev, function: func,
                        vendor_id: vendor, device_id: did,
                        class, subclass: sub, bar0,
                    };
                    FOUND_COUNT += 1;
                }
            }
        }
    }
}

/// Find the first PCI device with the given vendor + device ID.
pub fn find(vendor: u16, device: u16) -> Option<PciDevice> {
    unsafe {
        for i in 0..FOUND_COUNT {
            let d = &FOUND[i];
            if d.vendor_id == vendor && d.device_id == device {
                return Some(*d);
            }
        }
    }
    None
}

/// Iterate all found PCI devices.
pub fn iter<F: FnMut(PciDevice)>(mut f: F) {
    unsafe {
        for i in 0..FOUND_COUNT { f(FOUND[i]); }
    }
}

/// Enable MMIO space and Bus Mastering for a device.
/// Must be called before accessing MMIO registers or performing DMA.
pub fn enable_mmio_and_busmaster(bus: u8, device: u8, func: u8) {
    let cmd = config::command(bus, device, func);
    config::set_command(
        bus, device, func,
        cmd | config::CMD_MEM_SPACE | config::CMD_BUS_MASTER,
    );
}
