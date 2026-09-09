//! HAL: CPU interface trait

pub trait CpuInterface {
    /// Halt the CPU until the next interrupt.
    fn halt(&self);

    /// Disable all maskable interrupts.
    fn disable_interrupts(&self);

    /// Enable all maskable interrupts.
    fn enable_interrupts(&self);

    /// Read the current CPU timestamp counter.
    fn read_tsc(&self) -> u64;

    /// Returns the CPU vendor string (e.g. "GenuineIntel").
    fn vendor_string(&self) -> [u8; 12];
}
