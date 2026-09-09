//! ATA/IDE Driver (PIO mode)
//!
//! Supports reading/writing sectors on ATA hard disks and CD-ROMs.
//! PIO mode: CPU transfers data to/from data register (slow but simple).
//! DMA mode: disk DMA controller transfers directly to RAM (faster).
//!
//! Primary channel:   data=0x1F0, control=0x3F6, IRQ=14
//! Secondary channel: data=0x170, control=0x376, IRQ=15

// TODO: Implement identify() — read disk identity block (model, sectors, etc.)
// TODO: Implement read_sectors(lba, count, buf) using LBA28 or LBA48.
// TODO: Implement write_sectors(lba, count, buf).
// TODO: Register IRQ 14/15 handlers for interrupt-driven (non-polling) I/O.
