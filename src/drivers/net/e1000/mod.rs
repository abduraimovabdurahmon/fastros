//! Intel E1000 Network Driver
//!
//! The E1000 (82540EM) is the default NIC emulated by QEMU (-nic e1000).
//! PCI vendor=0x8086, device=0x100E.
//!
//! Initialization sequence:
//!   1. Find via PCI scan
//!   2. Map MMIO BAR0
//!   3. Read MAC from EEPROM
//!   4. Initialize TX/RX descriptor rings
//!   5. Enable RX/TX and interrupts

// TODO: Implement E1000 register map (CTRL, STATUS, RCTL, TCTL, etc.)
// TODO: Implement descriptor ring buffers (16 TX + 16 RX descriptors to start)
// TODO: Implement send_packet / receive_packet
// TODO: Register IRQ handler for incoming packets
