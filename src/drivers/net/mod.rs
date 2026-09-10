//! Network Interface Card drivers.
//!
//! Driver init order: loopback first (always present), then hardware NICs.
//! Each driver calls kernel::net::register_device() during init to plug
//! itself into the protocol stack.

pub mod e1000;
pub mod loopback;

/// Initialise all network drivers.
/// Called from kernel_main after PCI enumeration.
pub fn init() {
    // Loopback is always present
    loopback::init();

    // Hardware NIC: try e1000 (QEMU default)
    if e1000::init() {
        crate::drivers::char::serial::write(b"  e1000: eth0 up (10.0.2.15/24 gw 10.0.2.2)\n");
    }

    // Register our poll function with the kernel net stack
    crate::kernel::net::register_poll(poll);
}

/// Poll all hardware NICs for incoming packets.
/// Called from the main shell loop (or could be driven by timer IRQ).
pub fn poll() {
    e1000::poll();
}
