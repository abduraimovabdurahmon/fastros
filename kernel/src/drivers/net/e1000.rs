//! Intel 8254x (e1000) Gigabit Ethernet — the NIC QEMU emulates by default.
//!
//! Interrupt driven: RX timer/overrun and link-change interrupts wake the
//! network task, with interrupt throttling so a packet flood cannot starve
//! the CPU. 256-entry descriptor rings, 2 KiB DMA buffers.

use super::{NetDevice, NetStats};
use crate::drivers::pci;
use crate::mm::dma::DmaBuffer;
use crate::mm::phys_to_virt;
use core::sync::atomic::{AtomicUsize, Ordering};

const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const ICR: usize = 0x00C0;
const ITR: usize = 0x00C4;
const IMS: usize = 0x00D0;
const IMC: usize = 0x00D8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const RDTR: usize = 0x2820;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const MTA: usize = 0x5200;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const IMS_LSC: u32 = 1 << 2;
const IMS_RXDMT0: u32 = 1 << 4;
const IMS_RXO: u32 = 1 << 6;
const IMS_RXT0: u32 = 1 << 7;

const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;
const DESC_DD: u8 = 1 << 0;
const RX_EOP: u8 = 1 << 1;

const RING: usize = 256;
const BUF: usize = 2048;

#[repr(C)]
#[derive(Clone, Copy)]
struct RxDesc {
    addr: u64,
    len: u16,
    csum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TxDesc {
    addr: u64,
    len: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

pub struct E1000 {
    mmio: usize,
    mac: [u8; 6],
    rx_ring: DmaBuffer,
    tx_ring: DmaBuffer,
    rx_bufs: DmaBuffer,
    tx_bufs: DmaBuffer,
    rx_next: usize,
    tx_next: usize,
    stats: NetStats,
    pub irq: u8,
}

/// MMIO base for the interrupt handler (acknowledges ICR without the device lock).
static IRQ_MMIO: AtomicUsize = AtomicUsize::new(0);

impl E1000 {
    fn r(&self, reg: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio + reg) as *const u32) }
    }
    fn w(&self, reg: usize, v: u32) {
        unsafe { core::ptr::write_volatile((self.mmio + reg) as *mut u32, v) }
    }
    fn rx(&self) -> *mut RxDesc {
        self.rx_ring.as_ptr() as *mut RxDesc
    }
    fn tx(&self) -> *mut TxDesc {
        self.tx_ring.as_ptr() as *mut TxDesc
    }

    pub fn probe() -> Option<E1000> {
        let dev = [0x100E, 0x100F, 0x10D3, 0x153A].iter().find_map(|&id| pci::find(0x8086, id))?;
        dev.enable();
        let base = match dev.bars[0] {
            pci::Bar::Mem { addr, .. } => addr,
            _ => return None,
        };
        let mut nic = E1000 {
            mmio: phys_to_virt(base),
            mac: [0; 6],
            rx_ring: DmaBuffer::new(RING * 16)?,
            tx_ring: DmaBuffer::new(RING * 16)?,
            rx_bufs: DmaBuffer::new(RING * BUF)?,
            tx_bufs: DmaBuffer::new(RING * BUF)?,
            rx_next: 0,
            tx_next: 0,
            stats: NetStats::default(),
            irq: dev.irq_line,
        };
        nic.reset();
        IRQ_MMIO.store(nic.mmio, Ordering::Release);
        crate::kinfo!(
            "e1000",
            "{:02x}:{:02x}.{} mac {} irq {} link {}",
            dev.addr.bus,
            dev.addr.dev,
            dev.addr.func,
            fmt_mac(&nic.mac),
            nic.irq,
            if nic.link_up() { "up" } else { "down" }
        );
        Some(nic)
    }

    fn reset(&mut self) {
        self.w(IMC, 0xFFFF_FFFF);
        self.w(CTRL, self.r(CTRL) | CTRL_RST);
        for _ in 0..100_000 {
            if self.r(CTRL) & CTRL_RST == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        self.w(IMC, 0xFFFF_FFFF);
        let _ = self.r(ICR);

        // QEMU (and the EEPROM autoload on real parts) leaves the MAC in RAL/RAH.
        let lo = self.r(RAL0);
        let hi = self.r(RAH0);
        self.mac = [lo as u8, (lo >> 8) as u8, (lo >> 16) as u8, (lo >> 24) as u8, hi as u8, (hi >> 8) as u8];
        self.w(RAH0, hi | (1 << 31)); // address valid
        for i in 0..128 {
            self.w(MTA + i * 4, 0);
        }

        unsafe {
            for i in 0..RING {
                *self.rx().add(i) = RxDesc {
                    addr: self.rx_bufs.phys() + (i * BUF) as u64,
                    len: 0,
                    csum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                };
                *self.tx().add(i) = TxDesc {
                    addr: self.tx_bufs.phys() + (i * BUF) as u64,
                    len: 0,
                    cso: 0,
                    cmd: 0,
                    status: DESC_DD,
                    css: 0,
                    special: 0,
                };
            }
        }
        self.w(RDBAL, self.rx_ring.phys() as u32);
        self.w(RDBAH, (self.rx_ring.phys() >> 32) as u32);
        self.w(RDLEN, (RING * 16) as u32);
        self.w(RDH, 0);
        self.w(RDT, (RING - 1) as u32);
        self.w(RDTR, 0);
        self.w(RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC); // 2 KiB buffers

        self.w(TDBAL, self.tx_ring.phys() as u32);
        self.w(TDBAH, (self.tx_ring.phys() >> 32) as u32);
        self.w(TDLEN, (RING * 16) as u32);
        self.w(TDH, 0);
        self.w(TDT, 0);
        self.w(TCTL, TCTL_EN | TCTL_PSP | (0x0F << 4) | (0x40 << 12));
        self.w(TIPG, 0x0060_200A);

        self.w(CTRL, (self.r(CTRL) | CTRL_SLU) & !CTRL_RST);
        // ≤ ~8000 interrupts/s (ITR unit: 256 ns).
        self.w(ITR, 500);
        self.w(IMS, IMS_RXT0 | IMS_RXO | IMS_RXDMT0 | IMS_LSC);
        self.rx_next = 0;
        self.tx_next = 0;
    }
}

/// Acknowledge the interrupt (reading ICR clears it). Returns the cause bits.
pub fn ack_irq() -> u32 {
    let mmio = IRQ_MMIO.load(Ordering::Acquire);
    if mmio == 0 {
        return 0;
    }
    unsafe { core::ptr::read_volatile((mmio + ICR) as *const u32) }
}

impl NetDevice for E1000 {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn link_up(&self) -> bool {
        self.r(STATUS) & STATUS_LU != 0
    }
    fn driver(&self) -> &'static str {
        "e1000"
    }
    fn stats(&self) -> NetStats {
        self.stats
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        if frame.len() > BUF {
            self.stats.tx_errors += 1;
            return false;
        }
        let i = self.tx_next;
        let d = unsafe { &mut *self.tx().add(i) };
        if unsafe { core::ptr::read_volatile(&d.status) } & DESC_DD == 0 {
            self.stats.tx_dropped += 1;
            return false; // ring full
        }
        let buf = unsafe { self.tx_bufs.as_ptr().add(i * BUF) };
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), buf, frame.len()) };
        // Pad runt frames to the Ethernet minimum (60 bytes without FCS).
        let len = frame.len().max(60);
        if len > frame.len() {
            unsafe { core::ptr::write_bytes(buf.add(frame.len()), 0, len - frame.len()) };
        }
        d.len = len as u16;
        d.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        unsafe { core::ptr::write_volatile(&mut d.status, 0) };
        self.tx_next = (i + 1) % RING;
        core::sync::atomic::fence(Ordering::SeqCst);
        self.w(TDT, self.tx_next as u32);
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame.len() as u64;
        true
    }

    fn receive(&mut self, out: &mut [u8]) -> Option<usize> {
        loop {
            let i = self.rx_next;
            let d = unsafe { &mut *self.rx().add(i) };
            let status = unsafe { core::ptr::read_volatile(&d.status) };
            if status & DESC_DD == 0 {
                return None;
            }
            core::sync::atomic::fence(Ordering::SeqCst);
            let len = d.len as usize;
            let ok = status & RX_EOP != 0 && d.errors == 0 && len <= out.len();
            if ok {
                let src = unsafe { core::slice::from_raw_parts(self.rx_bufs.as_ptr().add(i * BUF), len) };
                out[..len].copy_from_slice(src);
                self.stats.rx_packets += 1;
                self.stats.rx_bytes += len as u64;
            } else {
                self.stats.rx_errors += 1;
            }
            d.status = 0;
            self.rx_next = (i + 1) % RING;
            // Hand the descriptor back: the tail trails the next one we read.
            self.w(RDT, i as u32);
            if ok {
                return Some(len);
            }
        }
    }
}

pub fn fmt_mac(m: &[u8; 6]) -> alloc::string::String {
    alloc::format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}
