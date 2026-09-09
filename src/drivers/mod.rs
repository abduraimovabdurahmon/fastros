//! LAYER 3 — Hardware Drivers
//!
//! Each driver implements the Driver trait from interface.rs.
//! Drivers communicate with hardware via hal:: traits only.
//! Drivers NEVER call arch:: code directly.
//!
//! CAN IMPORT:   hal/, kernel/, libs/
//! CANNOT IMPORT: arch/, fs/, userspace/

pub mod block;
pub mod bus;
pub mod char;
pub mod display;
pub mod interface;
pub mod net;

pub fn init() {
    display::vga::init();
    char::serial::init();
    bus::pci::init();
}
