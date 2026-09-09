//! HAL: I/O port interface trait
//!
//! Abstracts over raw x86 `in`/`out` instructions.
//! All drivers must use this trait — never raw port instructions directly.

pub trait IoInterface {
    /// Read a byte from an I/O port.
    unsafe fn read_u8(&self, port: u16) -> u8;

    /// Write a byte to an I/O port.
    unsafe fn write_u8(&self, port: u16, value: u8);

    /// Read a 16-bit word from an I/O port.
    unsafe fn read_u16(&self, port: u16) -> u16;

    /// Write a 16-bit word to an I/O port.
    unsafe fn write_u16(&self, port: u16, value: u16);

    /// Read a 32-bit dword from an I/O port.
    unsafe fn read_u32(&self, port: u16) -> u32;

    /// Write a 32-bit dword to an I/O port.
    unsafe fn write_u32(&self, port: u16, value: u32);

    /// Small delay (used after port writes for old hardware to settle).
    unsafe fn io_wait(&self);
}
