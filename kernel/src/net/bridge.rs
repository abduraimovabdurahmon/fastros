//! Software bridges for container networks.
//!
//! Each user-defined network (`fastman run --network <name>` with a name other
//! than `bridge`/`host`/`none`) is an isolated L2 bridge. Every container on it
//! gets a private-namespace stack whose device is a *port* on the bridge: a
//! frame to a peer on the same bridge is delivered by destination MAC into that
//! peer's receive queue, and ARP for a peer is answered from the bridge's table
//! (proxy ARP). Containers on the same network reach each other by IP; different
//! networks are fully isolated (separate port tables), and none can reach the
//! host stack (that is a later NAT phase).
//!
//! A single `bridge-netd` task polls every private namespace so a frame handed
//! to a peer's queue is processed even though bridge ports have no interrupt.

use crate::sync::{SpinLock, WaitQueue};
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use smoltcp::wire::Ipv4Address;

/// A port on a bridge: the peer's address, MAC, and the queue frames destined
/// for it are delivered into (shared with its `PhysDevice`).
struct Port {
    ip: Ipv4Address,
    mac: [u8; 6],
    rx: Arc<SpinLock<VecDeque<Vec<u8>>>>,
}

static BRIDGES: SpinLock<BTreeMap<String, Vec<Port>>> = SpinLock::new(BTreeMap::new());
/// Next host IP to hand out on `10.88.0.0/16` (shared pool; isolation is by the
/// per-bridge port table, not by subnet).
static NEXT_IP: AtomicU32 = AtomicU32::new(0x0A58_0002); // 10.88.0.2
static NEXT_MAC: AtomicU32 = AtomicU32::new(2);

static BRIDGE_WQ: WaitQueue = WaitQueue::new();
static PENDING: AtomicBool = AtomicBool::new(false);

/// The subnet every bridge IP lives on (a /16), so peers are on-link.
pub const BRIDGE_PREFIX: u8 = 16;

/// Attach a new port to bridge `name`, returning its assigned IP, MAC and the
/// receive queue the bridge will deliver into (installed on the port's device).
pub fn attach(name: &str) -> (Ipv4Address, [u8; 6], Arc<SpinLock<VecDeque<Vec<u8>>>>) {
    let ip_raw = NEXT_IP.fetch_add(1, Ordering::Relaxed);
    let ip = Ipv4Address::new((ip_raw >> 24) as u8, (ip_raw >> 16) as u8, (ip_raw >> 8) as u8, ip_raw as u8);
    let n = NEXT_MAC.fetch_add(1, Ordering::Relaxed);
    let mac = [0x02, 0x88, (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    let rx = Arc::new(SpinLock::new(VecDeque::new()));
    BRIDGES.lock().entry(name.to_string()).or_default().push(Port { ip, mac, rx: rx.clone() });
    (ip, mac, rx)
}

/// Remove a port (by MAC) from bridge `name`; drop the bridge when empty.
pub fn detach(name: &str, mac: [u8; 6]) {
    let mut b = BRIDGES.lock();
    if let Some(ports) = b.get_mut(name) {
        ports.retain(|p| p.mac != mac);
        if ports.is_empty() {
            b.remove(name);
        }
    }
}

/// The MAC of the peer holding `ip` on bridge `name` (proxy-ARP lookup).
pub fn arp_mac(name: &str, ip: Ipv4Address) -> Option<[u8; 6]> {
    let b = BRIDGES.lock();
    b.get(name)?.iter().find(|p| p.ip == ip).map(|p| p.mac)
}

/// Deliver a frame to the peer with `dst_mac` on bridge `name` (or flood to all
/// peers for the broadcast address), then wake `bridge-netd` to process it.
pub fn deliver(name: &str, dst_mac: [u8; 6], frame: Vec<u8>) {
    let broadcast = dst_mac == [0xff; 6];
    {
        let b = BRIDGES.lock();
        let Some(ports) = b.get(name) else { return };
        let src_mac: [u8; 6] = frame[6..12].try_into().unwrap_or([0; 6]);
        for p in ports {
            if broadcast {
                if p.mac != src_mac {
                    p.rx.lock().push_back(frame.clone());
                }
            } else if p.mac == dst_mac {
                p.rx.lock().push_back(frame);
                break;
            }
        }
    }
    PENDING.store(true, Ordering::Release);
    BRIDGE_WQ.wake_all();
}

/// Start the bridge service task: it polls every private namespace whenever a
/// frame is delivered (bridge ports have no NIC interrupt), so cross-container
/// exchanges make progress.
pub fn start() {
    crate::sched::spawn("bridge-netd", || loop {
        // Poll repeatedly until no namespace changes (a handshake bounces
        // between two ports through this task).
        loop {
            let changed = super::netns::poll_all_private();
            if changed {
                super::SOCK_WQ.wake_all();
            } else {
                break;
            }
        }
        let deadline = crate::time::now_ns() + 200_000_000;
        let _ = BRIDGE_WQ.wait_until_interruptible(|| PENDING.swap(false, Ordering::AcqRel).then_some(()), Some(deadline));
    });
}
