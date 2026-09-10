//! Ethernet II frame encode / decode.
//!
//! Linux equivalent: net/ethernet/eth.c  include/linux/if_ether.h

pub const ETH_ALEN:  usize = 6;
pub const ETH_HLEN:  usize = 14;
pub const ETH_P_IP:  u16   = 0x0800;
pub const ETH_P_ARP: u16   = 0x0806;

pub const MAC_BCAST: [u8; ETH_ALEN] = [0xFF; ETH_ALEN];
pub const MAC_ZERO:  [u8; ETH_ALEN] = [0x00; ETH_ALEN];

/// Parsed Ethernet header.
pub struct EthHdr {
    pub dst:       [u8; ETH_ALEN],
    pub src:       [u8; ETH_ALEN],
    pub ethertype: u16,
}

/// Parse an Ethernet II frame.
/// Returns (header, payload) or None if too short.
pub fn parse(frame: &[u8]) -> Option<(EthHdr, &[u8])> {
    if frame.len() < ETH_HLEN { return None; }
    let mut hdr = EthHdr { dst: [0;6], src: [0;6], ethertype: 0 };
    hdr.dst.copy_from_slice(&frame[0..6]);
    hdr.src.copy_from_slice(&frame[6..12]);
    hdr.ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    Some((hdr, &frame[ETH_HLEN..]))
}

/// Write a 14-byte Ethernet header into `buf[0..14]`.
pub fn build(buf: &mut [u8], dst: &[u8; ETH_ALEN], src: &[u8; ETH_ALEN], ethertype: u16) {
    buf[0..6].copy_from_slice(dst);
    buf[6..12].copy_from_slice(src);
    buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
}

/// Format a MAC address into a 17-byte ASCII buffer (XX:XX:XX:XX:XX:XX).
pub fn fmt_mac(mac: &[u8; ETH_ALEN], out: &mut [u8; 17]) {
    const HEX: &[u8] = b"0123456789abcdef";
    for i in 0..6 {
        out[i * 3]     = HEX[(mac[i] >> 4) as usize];
        out[i * 3 + 1] = HEX[(mac[i] & 0xF) as usize];
        if i < 5 { out[i * 3 + 2] = b':'; }
    }
}
