//! Network namespaces.
//!
//! A [`NetNs`] is a process's view of the network. The **host** namespace is the
//! shared stack every host process and every default (`bridge`) container uses —
//! it owns the NIC and is serviced by `netd`, so its behaviour is exactly as
//! before. A **private** namespace owns an isolated loopback stack with no NIC:
//! its `127.0.0.1`/`::1` and port space are entirely its own, so two private
//! containers can each bind the same port without colliding and neither can see
//! the other's sockets — the core isolation guarantee of `--network none`.
//!
//! Every socket carries the `Arc<NetNs>` it was created in, so all of its
//! operations (and its `Drop`) always target the right stack regardless of which
//! task runs them. A process inherits its namespace across fork and exec.

use super::Stack;
use crate::sync::{Mutex, Once, SpinLock};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

enum Kind {
    /// The shared host stack (the existing global `net::stack()`).
    Host,
    /// An isolated loopback stack owned by this namespace.
    Private(Mutex<Stack>),
}

pub struct NetNs {
    pub id: String,
    kind: Kind,
    /// For a bridged namespace: the network name, assigned IP and MAC (used to
    /// detach from the bridge on teardown and to report the container's address).
    bridge: Option<String>,
    pub ip: Option<smoltcp::wire::Ipv4Address>,
    mac: Option<[u8; 6]>,
}

impl NetNs {
    /// The stack this namespace operates on. For the host namespace this is the
    /// process-shared global stack; for a private one, its own loopback stack.
    pub fn stack(&self) -> &Mutex<Stack> {
        match &self.kind {
            Kind::Host => super::stack(),
            Kind::Private(s) => s,
        }
    }

    /// Poll this namespace's stack to completion after queueing data. A private
    /// namespace has no NIC and no `netd`, so loopback exchanges are driven here.
    pub fn poll_now(&self) {
        match &self.kind {
            Kind::Host => super::poll_now(),
            Kind::Private(s) => super::poll_now_on(s),
        }
    }

    pub fn is_host(&self) -> bool {
        matches!(self.kind, Kind::Host)
    }
}

static HOST: Once<Arc<NetNs>> = Once::new();
static NAMESPACES: SpinLock<BTreeMap<String, Arc<NetNs>>> = SpinLock::new(BTreeMap::new());

/// The host (shared) network namespace.
pub fn host() -> Arc<NetNs> {
    HOST.call_once(|| Arc::new(NetNs { id: String::from("host"), kind: Kind::Host, bridge: None, ip: None, mac: None })).clone()
}

/// Poll every private namespace's stack once; returns whether any changed. This
/// is how `bridge-netd` drives receive on bridge ports (which have no NIC IRQ).
pub fn poll_all_private() -> bool {
    let all: Vec<Arc<NetNs>> = NAMESPACES.lock().values().cloned().collect();
    let mut changed = false;
    for ns in all {
        if let Kind::Private(s) = &ns.kind {
            changed |= s.lock().poll();
        }
    }
    changed
}

/// The current process's namespace (its own if set, else the host).
pub fn current() -> Arc<NetNs> {
    crate::proc::current().netns.lock().clone().unwrap_or_else(host)
}

/// Create (or fetch) a private namespace keyed by `id` (a container id) with an
/// isolated loopback stack (`--network none`).
pub fn create(id: &str) -> Arc<NetNs> {
    let mut map = NAMESPACES.lock();
    if let Some(ns) = map.get(id) {
        return ns.clone();
    }
    let ns = Arc::new(NetNs { id: id.to_string(), kind: Kind::Private(Mutex::new(super::new_loopback_stack())), bridge: None, ip: None, mac: None });
    map.insert(id.to_string(), ns.clone());
    ns
}

/// Create (or fetch) a private namespace attached to user bridge network
/// `network`: an isolated stack that can also reach peers on the same bridge by
/// IP. Returns the same namespace on repeated calls for one container id.
pub fn create_bridged(id: &str, network: &str) -> Arc<NetNs> {
    let mut map = NAMESPACES.lock();
    if let Some(ns) = map.get(id) {
        return ns.clone();
    }
    let (ip, mac, rx) = super::bridge::attach(network);
    let stack = super::new_bridge_stack(network, ip, mac, rx);
    let ns = Arc::new(NetNs {
        id: id.to_string(),
        kind: Kind::Private(Mutex::new(stack)),
        bridge: Some(network.to_string()),
        ip: Some(ip),
        mac: Some(mac),
    });
    map.insert(id.to_string(), ns.clone());
    ns
}

pub fn get(id: &str) -> Option<Arc<NetNs>> {
    NAMESPACES.lock().get(id).cloned()
}

/// The bridge IP assigned to container `id`, if it is on a bridge network.
pub fn container_ip(id: &str) -> Option<smoltcp::wire::Ipv4Address> {
    NAMESPACES.lock().get(id).and_then(|ns| ns.ip)
}

/// Drop a private namespace (on container removal), detaching it from its bridge.
/// Any sockets still holding an `Arc<NetNs>` keep the stack alive until dropped.
pub fn remove(id: &str) {
    let ns = NAMESPACES.lock().remove(id);
    if let Some(ns) = ns {
        if let (Some(b), Some(mac)) = (&ns.bridge, ns.mac) {
            super::bridge::detach(b, mac);
        }
    }
}
