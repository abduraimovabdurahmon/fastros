//! NVMe Driver (Non-Volatile Memory Express over PCIe)
//!
//! Modern SSD interface. Extremely fast (millions of IOPS).
//! Uses submission/completion queues in memory.
//! Requires PCI driver (bus/pci) to locate and map the NVMe controller.

// TODO: Find NVMe controller via PCI class code 0x01, subclass 0x08.
// TODO: Map BAR0 (NVMe MMIO registers).
// TODO: Initialize Admin Submission/Completion queues.
// TODO: Send Identify Controller command.
// TODO: Create I/O queues for read/write.
