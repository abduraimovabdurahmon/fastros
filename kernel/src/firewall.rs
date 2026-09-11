//! The system firewall: `fastros_netfilter` wired to the network stack,
//! the SSH server (brute-force bans) and the `fw` command.

use crate::sync::SpinLock;
use fastros_netfilter as nf;
use nf::{Firewall, Ip};

pub use nf::{Action, Cidr, Dir, PortRange, Proto, Rule};

static FW: SpinLock<Option<Firewall>> = SpinLock::new(None);
static AUTH_FAILS: SpinLock<alloc::collections::BTreeMap<Ip, (u64, u32)>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// Failed logins from one address within this window that trigger a ban.
const AUTH_FAIL_LIMIT: u32 = 5;
const AUTH_FAIL_WINDOW_MS: u64 = 600_000;
const AUTH_BAN_MS: u64 = 600_000;

fn now_ms() -> u64 {
    crate::time::now_ns() / 1_000_000
}

pub fn init() {
    *FW.lock() = Some(Firewall::with_defaults());
    crate::sched::spawn("kfirewalld", || loop {
        crate::sched::sleep_ms(1000);
        let drops: alloc::vec::Vec<_> = {
            let mut g = FW.lock();
            let Some(fw) = g.as_mut() else { continue };
            fw.expire(now_ms());
            core::mem::take(&mut fw.log)
        };
        for (dir, p, r) in drops.iter().take(8) {
            crate::knotice!(
                "firewall",
                "drop {} {} {}:{} -> {}:{} ({})",
                dir.name(),
                p.proto.name(),
                nf::fmt_ip(p.src),
                p.sport,
                nf::fmt_ip(p.dst),
                p.dport,
                r.name()
            );
        }
        if drops.len() > 8 {
            crate::knotice!("firewall", "... and {} more drops", drops.len() - 8);
        }
    });
}

/// Filter hook called by the NIC path for every frame.
pub fn check(dir: Dir, frame: &[u8]) -> bool {
    let mut g = FW.lock();
    match g.as_mut() {
        Some(fw) => fw.check_frame(dir, frame, now_ms()) == nf::Verdict::Accept,
        None => true,
    }
}

/// Keep the anti-spoofing list in sync with the interface addresses.
pub fn set_local_ips(ips: &[Ip]) {
    if let Some(fw) = FW.lock().as_mut() {
        fw.local_ips = ips.to_vec();
    }
}

pub fn with<R>(f: impl FnOnce(&mut Firewall) -> R) -> Option<R> {
    FW.lock().as_mut().map(f)
}

pub fn ban(ip: Ip, ms: u64, reason: &str) -> u64 {
    let d = with(|fw| fw.ban(ip, now_ms(), ms, reason)).unwrap_or(0);
    if d > 0 {
        crate::kwarn!("firewall", "banned {} for {}s: {}", nf::fmt_ip(ip), d / 1000, reason);
    }
    d
}

pub fn is_banned(ip: Ip) -> bool {
    with(|fw| fw.is_banned(ip, now_ms())).unwrap_or(false)
}

/// Record a failed authentication (SSH, su); ban on repeated failures.
pub fn auth_failure(ip: Ip) {
    let now = now_ms();
    let hit = {
        let mut m = AUTH_FAILS.lock();
        let e = m.entry(ip).or_insert((now, 0));
        if now - e.0 > AUTH_FAIL_WINDOW_MS {
            *e = (now, 0);
        }
        e.1 += 1;
        let hit = e.1 >= AUTH_FAIL_LIMIT;
        if hit {
            m.remove(&ip);
        }
        hit
    };
    if hit {
        ban(ip, AUTH_BAN_MS, "repeated authentication failures");
    }
}

pub fn auth_success(ip: Ip) {
    AUTH_FAILS.lock().remove(&ip);
}

/// Open an inbound port (used by container port mappings).
pub fn open_port(proto: Proto, port: u16, comment: &str) {
    with(|fw| {
        let exists = fw.rules.iter().any(|r| r.system && r.proto == Some(proto) && r.dport == Some(PortRange { lo: port, hi: port }));
        if !exists {
            let mut r = Rule::new(Dir::In, Action::Accept);
            r.proto = Some(proto);
            r.dport = Some(PortRange { lo: port, hi: port });
            r.comment = alloc::string::String::from(comment);
            r.system = true;
            fw.add_rule(r);
        }
    });
}

pub fn close_port(proto: Proto, port: u16) {
    with(|fw| fw.rules.retain(|r| !(r.system && r.proto == Some(proto) && r.dport == Some(PortRange { lo: port, hi: port }) && r.comment.starts_with("container"))));
}
