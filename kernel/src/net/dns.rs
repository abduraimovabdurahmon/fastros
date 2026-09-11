//! Stub DNS resolver: `/etc/hosts`, then the nameservers from DHCP or
//! `/etc/resolv.conf` over UDP, with a TTL-bounded cache.

use super::socket::UdpSocket;
use crate::errno::{Errno, KResult};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};

static CACHE: SpinLock<BTreeMap<String, (Vec<Ipv4Address>, u64)>> = SpinLock::new(BTreeMap::new());

pub fn parse_ipv4(s: &str) -> Option<Ipv4Address> {
    let mut o = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        o[n] = part.parse().ok()?;
        n += 1;
    }
    (n == 4).then(|| Ipv4Address::new(o[0], o[1], o[2], o[3]))
}

fn hosts_lookup(name: &str) -> Option<Ipv4Address> {
    let ctx = crate::fs::ops::Ctx::current();
    let data = crate::fs::ops::read_file(&ctx, "/etc/hosts").ok()?;
    let text = String::from_utf8_lossy(&data);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut f = line.split_whitespace();
        let Some(ip) = f.next().and_then(parse_ipv4) else { continue };
        if f.any(|h| h.eq_ignore_ascii_case(name)) {
            return Some(ip);
        }
    }
    None
}

fn nameservers() -> Vec<Ipv4Address> {
    let mut v = super::config().dns;
    let ctx = crate::fs::ops::Ctx::current();
    if let Ok(data) = crate::fs::ops::read_file(&ctx, "/etc/resolv.conf") {
        for line in String::from_utf8_lossy(&data).lines() {
            let mut f = line.split_whitespace();
            if f.next() == Some("nameserver") {
                if let Some(ip) = f.next().and_then(parse_ipv4) {
                    if !v.contains(&ip) {
                        v.push(ip);
                    }
                }
            }
        }
    }
    v
}

fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // QTYPE A, QCLASS IN
    q
}

fn skip_name(p: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *p.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

/// (addresses, min TTL) from a response to query `id`.
fn parse_response(p: &[u8], id: u16) -> KResult<(Vec<Ipv4Address>, u32)> {
    if p.len() < 12 || u16::from_be_bytes([p[0], p[1]]) != id || p[2] & 0x80 == 0 {
        return Err(Errno::EBADMSG);
    }
    match p[3] & 0x0F {
        0 => {}
        3 => return Err(Errno::ENOENT), // NXDOMAIN
        _ => return Err(Errno::EHOSTUNREACH),
    }
    let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
    let an = u16::from_be_bytes([p[6], p[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(p, i).ok_or(Errno::EBADMSG)? + 4;
    }
    let mut out = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        i = skip_name(p, i).ok_or(Errno::EBADMSG)?;
        let h = p.get(i..i + 10).ok_or(Errno::EBADMSG)?;
        let typ = u16::from_be_bytes([h[0], h[1]]);
        let t = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let len = u16::from_be_bytes([h[8], h[9]]) as usize;
        let data = p.get(i + 10..i + 10 + len).ok_or(Errno::EBADMSG)?;
        if typ == 1 && len == 4 {
            out.push(Ipv4Address::new(data[0], data[1], data[2], data[3]));
            ttl = ttl.min(t);
        }
        i += 10 + len;
    }
    if out.is_empty() {
        return Err(Errno::ENOENT);
    }
    Ok((out, ttl))
}

/// Resolve a host name (or dotted quad) to IPv4 addresses.
pub fn resolve(name: &str) -> KResult<Vec<Ipv4Address>> {
    if let Some(ip) = parse_ipv4(name) {
        return Ok(alloc::vec![ip]);
    }
    if name.is_empty() || name.len() > 253 {
        return Err(Errno::EINVAL);
    }
    let key = name.to_ascii_lowercase();
    if key == "localhost" {
        return Ok(alloc::vec![Ipv4Address::new(127, 0, 0, 1)]);
    }
    if let Some(ip) = hosts_lookup(&key) {
        return Ok(alloc::vec![ip]);
    }
    let now = crate::time::now_ns();
    if let Some((ips, exp)) = CACHE.lock().get(&key) {
        if *exp > now {
            return Ok(ips.clone());
        }
    }
    let servers = nameservers();
    if servers.is_empty() {
        return Err(Errno::ENETUNREACH);
    }
    let sock = UdpSocket::bind(None)?;
    let mut last = Errno::ETIMEDOUT;
    for _ in 0..3 {
        for &ns in &servers {
            let id = crate::crypto::rng::u32() as u16;
            sock.send_to(&build_query(id, &key), IpEndpoint::new(IpAddress::Ipv4(ns), 53))?;
            let mut buf = [0u8; 1500];
            let deadline = crate::time::now_ns() + 2_000_000_000;
            loop {
                let left = deadline.saturating_sub(crate::time::now_ns()) / 1_000_000;
                if left == 0 {
                    break;
                }
                match sock.recv_from(&mut buf, Some(left)) {
                    Ok((n, from)) if from.addr == IpAddress::Ipv4(ns) => match parse_response(&buf[..n], id) {
                        Ok((ips, ttl)) => {
                            let exp = crate::time::now_ns() + (ttl.clamp(5, 3600) as u64) * 1_000_000_000;
                            CACHE.lock().insert(key.clone(), (ips.clone(), exp));
                            return Ok(ips);
                        }
                        Err(Errno::EBADMSG) => continue, // stray/forged answer: keep waiting
                        Err(e) => return Err(e),
                    },
                    Ok(_) => continue,
                    Err(Errno::EINTR) => return Err(Errno::EINTR),
                    Err(_) => break,
                }
            }
            last = Errno::ETIMEDOUT;
        }
    }
    Err(last)
}

pub fn first(name: &str) -> KResult<Ipv4Address> {
    resolve(name)?.into_iter().next().ok_or(Errno::ENOENT)
}

pub fn fmt(ip: Ipv4Address) -> String {
    ip.to_string()
}
