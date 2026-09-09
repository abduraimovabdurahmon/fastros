//! PCI Configuration Space access
//!
//! PCI config space: 256 bytes per function, accessed via I/O ports.
//! Address register (0xCF8): [31=enable][23:16=bus][15:11=dev][10:8=func][7:2=reg][1:0=0]

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA:    u16 = 0xCFC;

fn make_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

pub unsafe fn read_u32(bus: u8, device: u8, func: u8, offset: u8) -> u32 {
    let addr = make_address(bus, device, func, offset);
    core::arch::asm!("out dx, eax", in("dx") CONFIG_ADDRESS, in("eax") addr, options(nomem, nostack));
    let mut val: u32;
    core::arch::asm!("in eax, dx", out("eax") val, in("dx") CONFIG_DATA, options(nomem, nostack));
    val
}

pub unsafe fn read_u16(bus: u8, device: u8, func: u8, offset: u8) -> u16 {
    (read_u32(bus, device, func, offset) >> ((offset & 2) * 8)) as u16
}

pub fn vendor_id(bus: u8, device: u8, func: u8) -> u16 {
    unsafe { read_u16(bus, device, func, 0x00) }
}

pub fn device_id(bus: u8, device: u8, func: u8) -> u16 {
    unsafe { read_u16(bus, device, func, 0x02) }
}
