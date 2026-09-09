//! HAL: Interrupt controller trait

pub type IrqHandler = fn(irq: u8);

pub trait InterruptController {
    /// Initialize the interrupt controller (IDT, PIC/APIC setup).
    fn init(&mut self);

    /// Register a handler for a hardware IRQ line.
    fn register_irq(&mut self, irq: u8, handler: IrqHandler);

    /// Mask (disable) a specific IRQ line.
    fn mask_irq(&mut self, irq: u8);

    /// Unmask (enable) a specific IRQ line.
    fn unmask_irq(&mut self, irq: u8);

    /// Send End-Of-Interrupt signal to the controller.
    fn end_of_interrupt(&mut self, irq: u8);
}

/// Well-known IRQ numbers for x86 hardware.
pub mod irq {
    pub const TIMER:    u8 = 0;
    pub const KEYBOARD: u8 = 1;
    pub const CASCADE:  u8 = 2;
    pub const COM2:     u8 = 3;
    pub const COM1:     u8 = 4;
    pub const ATA1:     u8 = 14;
    pub const ATA2:     u8 = 15;
}
