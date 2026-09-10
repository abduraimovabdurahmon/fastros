//! Intel 82540EM (e1000) Ethernet driver.
//!
//! QEMU emulates this NIC with `-device e1000,netdev=net0`.
//! PCI vendor = 0x8086 (Intel), device = 0x100E.
//!
//! Init sequence (mirrors Linux e1000_probe):
//!   1. PCI scan + enable MMIO + Bus Mastering
//!   2. Map BAR0 MMIO registers
//!   3. Software reset (CTRL.RST)
//!   4. Read MAC from EEPROM
//!   5. TX descriptor ring (16 slots)
//!   6. RX descriptor ring (16 slots)
//!   7. Configure RCTL + TCTL
//!   8. Enable link (CTRL.SLU)
//!   9. Register with kernel::net
//!
//! Linux equiv: drivers/net/ethernet/intel/e1000/e1000_main.c

use crate::drivers::bus::pci;
use crate::kernel::net;

pub const E1000_VENDOR: u16 = 0x8086;
pub const E1000_DEVICE: u16 = 0x100E;

// MMIO register offsets
const CTRL:  u32 = 0x0000;
const EERD:  u32 = 0x0014;
const ICR:   u32 = 0x00C0;
const IMC:   u32 = 0x00D8;
const RCTL:  u32 = 0x0100;
const TCTL:  u32 = 0x0400;
const TIPG:  u32 = 0x0410;
const RDBAL: u32 = 0x2800;
const RDBAH: u32 = 0x2804;
const RDLEN: u32 = 0x2808;
const RDH:   u32 = 0x2810;
const RDT:   u32 = 0x2818;
const TDBAL: u32 = 0x3800;
const TDBAH: u32 = 0x3804;
const TDLEN: u32 = 0x3808;
const TDH:   u32 = 0x3810;
const TDT:   u32 = 0x3818;
const MTA:   u32 = 0x5200;
const RAL0:  u32 = 0x5400;
const RAH0:  u32 = 0x5404;

const CTRL_FD:   u32 = 1 << 0;
const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU:  u32 = 1 << 6;
const CTRL_RST:  u32 = 1 << 26;

const RCTL_EN:    u32 = 1 << 1;
const RCTL_MPE:   u32 = 1 << 4;
const RCTL_BAM:   u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;

const TCTL_EN:   u32 = 1 << 1;
const TCTL_PSP:  u32 = 1 << 3;
const TCTL_CT:   u32 = 0x10 << 4;
const TCTL_COLD: u32 = 0x40 << 12;

const EERD_START: u32 = 1 << 0;
const EERD_DONE:  u32 = 1 << 4;

const TDESC_CMD_EOP:  u8 = 0x01;
const TDESC_CMD_IFCS: u8 = 0x02;
const TDESC_CMD_RS:   u8 = 0x08;
const TDESC_STA_DD:   u8 = 0x01;
const RDESC_STA_DD:   u8 = 0x01;

#[repr(C, align(16))]
struct TxDesc { buf_addr: u64, length: u16, cso: u8, cmd: u8, status: u8, css: u8, special: u16 }
impl TxDesc { const fn zero() -> Self { Self { buf_addr:0,length:0,cso:0,cmd:0,status:0,css:0,special:0 } } }

#[repr(C, align(16))]
struct RxDesc { buf_addr: u64, length: u16, checksum: u16, status: u8, errors: u8, special: u16 }
impl RxDesc { const fn zero() -> Self { Self { buf_addr:0,length:0,checksum:0,status:0,errors:0,special:0 } } }

const NUM_TX: usize = 16;
const NUM_RX: usize = 16;
const RX_BUF: usize = 2048;

#[repr(C, align(16))] struct TxRing([TxDesc; NUM_TX]);
#[repr(C, align(16))] struct RxRing([RxDesc; NUM_RX]);

static mut TX_RING: TxRing = TxRing([const { TxDesc::zero() }; NUM_TX]);
static mut RX_RING: RxRing = RxRing([const { RxDesc::zero() }; NUM_RX]);
static mut TX_BUFS: [[u8; 1600]; NUM_TX] = [[0; 1600]; NUM_TX];
static mut RX_BUFS: [[u8; RX_BUF]; NUM_RX] = [[0; RX_BUF]; NUM_RX];

static mut MMIO_BASE: u64   = 0;
static mut TX_TAIL:   usize = 0;
static mut RX_TAIL:   usize = NUM_RX - 1;
static mut MAC_ADDR:  [u8; 6] = [0; 6];
static mut READY:     bool  = false;
static mut DEV_IDX:   usize = 0;

#[inline] unsafe fn mmio_r(reg: u32) -> u32 { core::ptr::read_volatile((MMIO_BASE + reg as u64) as *const u32) }
#[inline] unsafe fn mmio_w(reg: u32, v: u32) { core::ptr::write_volatile((MMIO_BASE + reg as u64) as *mut u32, v) }

unsafe fn eeprom_read(word: u16) -> u16 {
    mmio_w(EERD, ((word as u32) << 8) | EERD_START);
    let mut n = 100_000u32;
    loop {
        let v = mmio_r(EERD);
        if v & EERD_DONE != 0 { return (v >> 16) as u16; }
        n -= 1; if n == 0 { return 0; }
        core::hint::spin_loop();
    }
}

pub fn init() -> bool {
    let dev = match pci::find(E1000_VENDOR, E1000_DEVICE) { Some(d) => d, None => return false };
    pci::enable_mmio_and_busmaster(dev.bus, dev.device, dev.function);
    let bar0 = dev.bar0 & !0xFu32;
    if bar0 == 0 { return false; }

    unsafe {
        MMIO_BASE = bar0 as u64;

        // Software reset
        mmio_w(CTRL, mmio_r(CTRL) | CTRL_RST);
        let mut t = 100_000u32;
        while mmio_r(CTRL) & CTRL_RST != 0 { t -= 1; if t == 0 { return false; } core::hint::spin_loop(); }

        // Disable interrupts
        mmio_w(IMC, 0xFFFF_FFFF);
        let _ = mmio_r(ICR);

        // MAC from EEPROM
        let w0 = eeprom_read(0); let w1 = eeprom_read(1); let w2 = eeprom_read(2);
        MAC_ADDR = [(w0&0xFF) as u8,(w0>>8) as u8,(w1&0xFF) as u8,(w1>>8) as u8,(w2&0xFF) as u8,(w2>>8) as u8];

        // Program RAL/RAH
        let ral = (MAC_ADDR[0] as u32)|((MAC_ADDR[1] as u32)<<8)|((MAC_ADDR[2] as u32)<<16)|((MAC_ADDR[3] as u32)<<24);
        let rah = (MAC_ADDR[4] as u32)|((MAC_ADDR[5] as u32)<<8)|(1u32<<31);
        mmio_w(RAL0, ral); mmio_w(RAH0, rah);

        // Clear MTA
        for i in 0..128u32 { mmio_w(MTA + i*4, 0); }

        // RX ring
        for i in 0..NUM_RX { RX_RING.0[i].buf_addr = &RX_BUFS[i][0] as *const u8 as u64; RX_RING.0[i].status = 0; }
        let rx_base = &RX_RING.0[0] as *const RxDesc as u64;
        mmio_w(RDBAL, (rx_base & 0xFFFF_FFFF) as u32);
        mmio_w(RDBAH, (rx_base >> 32) as u32);
        mmio_w(RDLEN, (NUM_RX * core::mem::size_of::<RxDesc>()) as u32);
        mmio_w(RDH, 0); mmio_w(RDT, (NUM_RX - 1) as u32);
        RX_TAIL = NUM_RX - 1;
        mmio_w(RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC | RCTL_MPE);

        // TX ring
        for i in 0..NUM_TX { TX_RING.0[i].buf_addr = &TX_BUFS[i][0] as *const u8 as u64; TX_RING.0[i].status = TDESC_STA_DD; }
        let tx_base = &TX_RING.0[0] as *const TxDesc as u64;
        mmio_w(TDBAL, (tx_base & 0xFFFF_FFFF) as u32);
        mmio_w(TDBAH, (tx_base >> 32) as u32);
        mmio_w(TDLEN, (NUM_TX * core::mem::size_of::<TxDesc>()) as u32);
        mmio_w(TDH, 0); mmio_w(TDT, 0); TX_TAIL = 0;
        mmio_w(TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
        mmio_w(TIPG, 0x0060_200A); // IEEE 802.3 copper Gigabit IPG

        // Link up
        mmio_w(CTRL, (mmio_r(CTRL) | CTRL_SLU | CTRL_ASDE | CTRL_FD) & !CTRL_RST);
        READY = true;
    }

    let mac = unsafe { MAC_ADDR };
    if let Some(idx) = net::register_device(net::DevConfig {
        name: b"eth0", mac,
        ip: [10,0,2,15], netmask: [255,255,255,0], gateway: [10,0,2,2],
        mtu: 1500, loopback: false, send_fn: send_frame,
    }) { unsafe { DEV_IDX = idx; } }

    true
}

/// TX callback — called by kernel::net for every outgoing frame.
pub fn send_frame(frame: &[u8]) -> bool {
    if !unsafe { READY } || frame.len() > 1514 { return false; }
    unsafe {
        let idx = TX_TAIL;
        let desc = &mut TX_RING.0[idx];
        let mut t = 100_000u32;
        while desc.status & TDESC_STA_DD == 0 { t -= 1; if t == 0 { return false; } core::hint::spin_loop(); }
        TX_BUFS[idx][..frame.len()].copy_from_slice(frame);
        desc.length = frame.len() as u16;
        desc.cmd    = TDESC_CMD_EOP | TDESC_CMD_IFCS | TDESC_CMD_RS;
        desc.status = 0;
        TX_TAIL = (TX_TAIL + 1) % NUM_TX;
        mmio_w(TDT, TX_TAIL as u32);
    }
    true
}

/// Poll for received frames (Linux NAPI equivalent — polling mode).
pub fn poll() {
    if !unsafe { READY } { return; }
    unsafe {
        loop {
            let next = (RX_TAIL + 1) % NUM_RX;
            if RX_RING.0[next].status & RDESC_STA_DD == 0 { break; }
            let len = RX_RING.0[next].length as usize;
            if len > 0 && len <= RX_BUF {
                net::receive_frame(&RX_BUFS[next][..len], DEV_IDX);
            }
            RX_RING.0[next].status = 0;
            mmio_w(RDT, next as u32);
            RX_TAIL = next;
        }
    }
}

pub fn mac()      -> [u8; 6] { unsafe { MAC_ADDR } }
pub fn is_ready() -> bool    { unsafe { READY } }
