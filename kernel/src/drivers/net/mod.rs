//! Network interface drivers and the device contract the stack consumes.

pub mod e1000;

#[derive(Clone, Copy, Debug, Default)]
pub struct NetStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

/// A hardware (or virtual) Ethernet interface.
pub trait NetDevice: Send {
    fn mac(&self) -> [u8; 6];
    fn mtu(&self) -> usize {
        1500
    }
    fn link_up(&self) -> bool;
    /// Queue one Ethernet frame (without FCS). False if the TX ring is full.
    fn transmit(&mut self, frame: &[u8]) -> bool;
    /// Copy the next received frame into `buf`; returns its length.
    fn receive(&mut self, buf: &mut [u8]) -> Option<usize>;
    fn stats(&self) -> NetStats;
    /// Name of the driver (for `ethtool`-like output).
    fn driver(&self) -> &'static str;
}
