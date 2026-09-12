//! smoltcp device adapter for a physical NIC.
//!
//! Every frame in either direction passes through here, which is where the
//! loopback path lives: frames addressed to one of our own IPs (including
//! 127.0.0.0/8) never touch the wire — ARP for them is answered locally and
//! the IP frame is fed straight back into the receive path. The firewall
//! hooks in at the same two points.

use crate::drivers::net::{NetDevice, NetStats};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{Ipv4Address, Ipv6Address};

const ETH_HDR: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IPPROTO_ICMPV6: u8 = 58;
const ICMPV6_NS: u8 = 135; // Neighbor Solicitation
const ICMPV6_NA: u8 = 136; // Neighbor Advertisement

pub struct PhysDevice {
    nic: Option<Box<dyn NetDevice>>,
    mac: [u8; 6],
    loopback: VecDeque<Vec<u8>>,
    /// Our addresses (kept in sync with the interface by the stack).
    pub local_ips: Vec<Ipv4Address>,
    pub local_ips6: Vec<Ipv6Address>,
    rx_buf: Vec<u8>,
    pub lo_stats: NetStats,
    pub filtered_in: u64,
    pub filtered_out: u64,
}

impl PhysDevice {
    pub fn new(nic: Option<Box<dyn NetDevice>>) -> PhysDevice {
        let mac = nic.as_ref().map(|n| n.mac()).unwrap_or([0x02, 0, 0, 0, 0, 1]);
        PhysDevice {
            nic,
            mac,
            loopback: VecDeque::new(),
            local_ips: Vec::new(),
            local_ips6: Vec::new(),
            rx_buf: vec![0; 2048],
            lo_stats: NetStats::default(),
            filtered_in: 0,
            filtered_out: 0,
        }
    }
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    pub fn nic_stats(&self) -> Option<NetStats> {
        self.nic.as_ref().map(|n| n.stats())
    }
    pub fn link_up(&self) -> bool {
        self.nic.as_ref().is_some_and(|n| n.link_up())
    }
    pub fn has_nic(&self) -> bool {
        self.nic.is_some()
    }
    pub fn driver(&self) -> &'static str {
        self.nic.as_ref().map(|n| n.driver()).unwrap_or("none")
    }

    fn is_local(&self, ip: Ipv4Address) -> bool {
        ip.octets()[0] == 127 || self.local_ips.contains(&ip)
    }

    fn is_local6(&self, ip: Ipv6Address) -> bool {
        ip == Ipv6Address::LOCALHOST || self.local_ips6.contains(&ip)
    }

    /// Answer an IPv6 Neighbor Solicitation for one of our own addresses locally
    /// (the mirror of the ARP reply above), so smoltcp can resolve the next hop
    /// for a loopback IPv6 exchange without any real neighbour on the wire. A
    /// solicitation from the unspecified address (`::`, i.e. DAD) is ignored so
    /// our own address configuration is never seen as a duplicate.
    fn ndp_reply(&self, frame: &[u8]) -> Option<Vec<u8>> {
        // Ethernet + IPv6(40) + ICMPv6 NS: type(1) code(1) csum(2) resv(4) target(16).
        if frame.len() < ETH_HDR + 40 + 24 {
            return None;
        }
        let ip = &frame[ETH_HDR..];
        if ip[6] != IPPROTO_ICMPV6 {
            return None;
        }
        let icmp = &frame[ETH_HDR + 40..];
        if icmp[0] != ICMPV6_NS {
            return None;
        }
        let src = ipv6(&ip[8..24]);
        let target = ipv6(&icmp[8..24]);
        if src.is_unspecified() || !self.is_local6(target) {
            return None;
        }
        // Build the Neighbor Advertisement: reply unicast to the solicitor.
        let mut out = vec![0u8; ETH_HDR + 40 + 32];
        // Ethernet.
        out[0..6].copy_from_slice(&frame[6..12]); // to solicitor's MAC
        out[6..12].copy_from_slice(&self.mac);
        out[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        // IPv6 header.
        let payload_len: u16 = 32;
        out[ETH_HDR] = 0x60; // version 6
        out[ETH_HDR + 4..ETH_HDR + 6].copy_from_slice(&payload_len.to_be_bytes());
        out[ETH_HDR + 6] = IPPROTO_ICMPV6;
        out[ETH_HDR + 7] = 255; // hop limit
        out[ETH_HDR + 8..ETH_HDR + 24].copy_from_slice(&target.octets()); // src = target
        out[ETH_HDR + 24..ETH_HDR + 40].copy_from_slice(&src.octets()); // dst = solicitor
        // ICMPv6 Neighbor Advertisement.
        let na = ETH_HDR + 40;
        out[na] = ICMPV6_NA;
        out[na + 4] = 0x60; // flags: solicited + override
        out[na + 8..na + 24].copy_from_slice(&target.octets());
        // Target link-layer address option (type 2, len 1).
        out[na + 24] = 2;
        out[na + 25] = 1;
        out[na + 26..na + 32].copy_from_slice(&self.mac);
        // ICMPv6 checksum over the pseudo-header + message.
        let csum = icmpv6_checksum(&target.octets(), &src.octets(), &out[na..na + 32]);
        out[na + 2..na + 4].copy_from_slice(&csum.to_be_bytes());
        Some(out)
    }

    /// Decide where an outgoing frame goes: back to us, or out of the NIC.
    fn dispatch(&mut self, frame: Vec<u8>) {
        if frame.len() < ETH_HDR {
            return;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype == ETHERTYPE_ARP && frame.len() >= ETH_HDR + 28 {
            let a = &frame[ETH_HDR..];
            let op = u16::from_be_bytes([a[6], a[7]]);
            let target = ip4(&a[24..28]);
            if op == 1 && self.is_local(target) {
                // Answer ARP for our own addresses ourselves.
                let mut reply = frame.clone();
                reply[0..6].copy_from_slice(&self.mac);
                reply[6..12].copy_from_slice(&self.mac);
                let r = &mut reply[ETH_HDR..];
                r[6..8].copy_from_slice(&2u16.to_be_bytes());
                r[8..14].copy_from_slice(&self.mac);
                r[14..18].copy_from_slice(&target.octets());
                let (sha, spa) = (a[8..14].to_vec(), a[14..18].to_vec());
                r[18..24].copy_from_slice(&sha);
                r[24..28].copy_from_slice(&spa);
                self.loopback.push_back(reply);
                return;
            }
        }
        if ethertype == ETHERTYPE_IPV4 && frame.len() >= ETH_HDR + 20 {
            let dst = ip4(&frame[ETH_HDR + 16..ETH_HDR + 20]);
            if self.is_local(dst) {
                self.lo_stats.tx_packets += 1;
                self.lo_stats.tx_bytes += frame.len() as u64;
                self.lo_stats.rx_packets += 1;
                self.lo_stats.rx_bytes += frame.len() as u64;
                self.loopback.push_back(frame);
                return;
            }
        }
        if ethertype == ETHERTYPE_IPV6 && frame.len() >= ETH_HDR + 40 {
            // Answer NDP for our own addresses ourselves (loopback resolution).
            if let Some(na) = self.ndp_reply(&frame) {
                self.loopback.push_back(na);
                return;
            }
            let dst = ipv6(&frame[ETH_HDR + 24..ETH_HDR + 40]);
            if self.is_local6(dst) {
                self.lo_stats.tx_packets += 1;
                self.lo_stats.tx_bytes += frame.len() as u64;
                self.lo_stats.rx_packets += 1;
                self.lo_stats.rx_bytes += frame.len() as u64;
                self.loopback.push_back(frame);
                return;
            }
        }
        if !crate::net::filter::allow_out(&frame) {
            self.filtered_out += 1;
            return;
        }
        if let Some(nic) = self.nic.as_mut() {
            let _ = nic.transmit(&frame);
        }
    }
}

pub struct Rx(Vec<u8>);
pub struct Tx<'a>(&'a mut PhysDevice);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.dispatch(buf);
        r
    }
}

impl phy::Device for PhysDevice {
    type RxToken<'a> = Rx where Self: 'a;
    type TxToken<'a> = Tx<'a> where Self: 'a;

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(f) = self.loopback.pop_front() {
            return Some((Rx(f), Tx(self)));
        }
        loop {
            let nic = self.nic.as_mut()?;
            let n = nic.receive(&mut self.rx_buf)?;
            let frame = self.rx_buf[..n].to_vec();
            if crate::net::filter::allow_in(&frame) {
                crate::crypto::rng::add_interrupt_entropy();
                return Some((Rx(frame), Tx(self)));
            }
            self.filtered_in += 1;
        }
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(Tx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = 1514;
        c
    }
}

fn ip4(b: &[u8]) -> Ipv4Address {
    Ipv4Address::new(b[0], b[1], b[2], b[3])
}

fn ipv6(b: &[u8]) -> Ipv6Address {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    Ipv6Address::from(a)
}

/// The ICMPv6 checksum: a 16-bit ones-complement sum over the IPv6 pseudo-header
/// (src, dst, upper-layer length, next-header = 58) followed by the message.
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |b: &[u8]| {
        let mut i = 0;
        while i + 1 < b.len() {
            sum += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
            i += 2;
        }
        if i < b.len() {
            sum += (b[i] as u32) << 8;
        }
    };
    add(src);
    add(dst);
    add(&(msg.len() as u32).to_be_bytes());
    add(&[0, 0, 0, IPPROTO_ICMPV6]);
    add(msg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
