//! Universal Driver trait
//!
//! Every driver (keyboard, disk, NIC, etc.) must implement this.
//! Provides a common lifecycle: probe → init → read/write → shutdown.

pub trait Driver {
    /// Human-readable driver name (e.g. "e1000", "ata-pio", "vga-text").
    fn name(&self) -> &'static str;

    /// Called once to check if this driver can handle the detected hardware.
    /// Returns true if the driver claims this device.
    fn probe(&self) -> bool;

    /// Initialize the hardware. Called after probe() returns true.
    fn init(&mut self) -> Result<(), DriverError>;

    /// Shut down the device cleanly (flush buffers, disable IRQs).
    fn shutdown(&mut self);
}

#[derive(Debug)]
pub enum DriverError {
    HardwareNotFound,
    InitFailed(&'static str),
    Timeout,
    IoError,
}

/// Trait for character (stream) devices: keyboard, serial, TTY.
pub trait CharDevice: Driver {
    fn read_byte(&mut self) -> Option<u8>;
    fn write_byte(&mut self, byte: u8);
}

/// Trait for block devices: ATA, NVMe, virtio-blk.
pub trait BlockDevice: Driver {
    /// Logical block size in bytes (usually 512 or 4096).
    fn block_size(&self) -> u64;

    /// Total number of blocks on the device.
    fn block_count(&self) -> u64;

    /// Read `count` blocks starting at `lba` into `buf`.
    fn read_blocks(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), DriverError>;

    /// Write `count` blocks from `buf` starting at `lba`.
    fn write_blocks(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), DriverError>;
}

/// Trait for network interface cards.
pub trait NetDevice: Driver {
    fn mac_address(&self) -> [u8; 6];
    fn send_packet(&mut self, data: &[u8]) -> Result<(), DriverError>;
    fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, DriverError>;
}
