//! Networking: smoltcp-based TCP/IP stack, the `knetd` service task,
//! a kernel socket API, DNS resolution and packet filtering.
//!
//! Concurrency: the stack lives behind one sleeping lock. `knetd` polls it
//! whenever the NIC interrupts or a protocol timer is due; socket operations
//! poll it inline right after queueing data (lowest latency). Tasks blocked on
//! a socket sleep on [`SOCK_WQ`], which is woken after every poll that may
//! have changed a socket's state.

pub mod device;
pub mod http;
pub mod tls;
pub mod dns;
pub mod filter;
pub mod socket;

use crate::drivers::net::e1000;
use crate::sync::{Mutex, Once, WaitQueue};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use device::PhysDevice;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};

pub use smoltcp::wire::{IpAddress, IpEndpoint};

/// Woken after every poll that may have changed socket state.
pub static SOCK_WQ: WaitQueue = WaitQueue::new();
static NETD_WQ: WaitQueue = WaitQueue::new();
static IRQ_PENDING: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, Default)]
pub struct IfConfig {
    pub addr: Option<Ipv4Cidr>,
    pub gateway: Option<Ipv4Address>,
    pub dns: Vec<Ipv4Address>,
    pub dhcp: bool,
    pub lease_secs: u32,
}

pub struct Stack {
    pub iface: Interface,
    pub dev: PhysDevice,
    pub sockets: SocketSet<'static>,
    dhcp: Option<SocketHandle>,
    pub cfg: IfConfig,
    /// Sockets whose owner is gone; removed once fully closed.
    orphans: Vec<SocketHandle>,
}

static STACK: Once<Mutex<Stack>> = Once::new();
static NEXT_EPHEMERAL: AtomicU16 = AtomicU16::new(49152);

pub fn now() -> Instant {
    Instant::from_micros((crate::time::now_ns() / 1000) as i64)
}

/// The host network stack.
pub fn stack() -> &'static Mutex<Stack> {
    STACK.expect_init()
}

pub fn is_up() -> bool {
    STACK.get().is_some()
}

/// A free local port for outgoing connections.
pub fn ephemeral_port() -> u16 {
    loop {
        let p = NEXT_EPHEMERAL.fetch_add(1, Ordering::Relaxed);
        if p >= 49152 {
            return p;
        }
        NEXT_EPHEMERAL.store(49152 + (crate::crypto::rng::below(16000) as u16), Ordering::Relaxed);
    }
}

impl Stack {
    fn sync_local_ips(&mut self) {
        self.dev.local_ips = self
            .iface
            .ip_addrs()
            .iter()
            .filter_map(|c| match c.address() {
                IpAddress::Ipv4(a) => Some(a),
            })
            .collect();
        let ips: Vec<[u8; 4]> = self.dev.local_ips.iter().map(|a| a.octets()).collect();
        crate::firewall::set_local_ips(&ips);
    }

    /// Poll the interface once; returns true if socket state may have changed.
    pub fn poll(&mut self) -> bool {
        let r = self.iface.poll(now(), &mut self.dev, &mut self.sockets);
        let mut changed = r == PollResult::SocketStateChanged;
        if let Some(h) = self.dhcp {
            let ev = self.sockets.get_mut::<dhcpv4::Socket>(h).poll().map(|e| match e {
                dhcpv4::Event::Configured(c) => Some((c.address, c.router, c.dns_servers.iter().copied().collect::<Vec<_>>())),
                dhcpv4::Event::Deconfigured => None,
            });
            if let Some(ev) = ev {
                self.apply_dhcp(ev);
                changed = true;
            }
        }
        // Reap closed orphan sockets.
        let mut i = 0;
        while i < self.orphans.len() {
            let h = self.orphans[i];
            let done = match self.sockets.get::<smoltcp::socket::tcp::Socket>(h).state() {
                smoltcp::socket::tcp::State::Closed | smoltcp::socket::tcp::State::TimeWait => true,
                _ => false,
            };
            if done {
                self.sockets.remove(h);
                self.orphans.swap_remove(i);
            } else {
                i += 1;
            }
        }
        changed
    }

    fn apply_dhcp(&mut self, ev: Option<(Ipv4Cidr, Option<Ipv4Address>, Vec<Ipv4Address>)>) {
        match ev {
            Some((addr, router, dns)) => {
                crate::kinfo!("net", "DHCP: {} gateway {:?} dns {:?}", addr, router, dns);
                self.set_address(addr, router);
                self.cfg.dns = dns;
                self.cfg.dhcp = true;
            }
            None if self.cfg.dhcp => {
                crate::kwarn!("net", "DHCP lease lost");
                self.cfg.dhcp = false;
                self.iface.update_ip_addrs(|a| a.retain(|c| matches!(c.address(), IpAddress::Ipv4(v) if v.octets()[0] == 127)));
                self.iface.routes_mut().remove_default_ipv4_route();
                self.cfg.addr = None;
                self.cfg.gateway = None;
                self.sync_local_ips();
            }
            // Deconfigured before any lease (startup): nothing to undo.
            None => {}
        }
    }

    /// Replace the interface address (keeps 127.0.0.1/8) and default route.
    pub fn set_address(&mut self, addr: Ipv4Cidr, gw: Option<Ipv4Address>) {
        self.iface.update_ip_addrs(|a| {
            a.retain(|c| matches!(c.address(), IpAddress::Ipv4(v) if v.octets()[0] == 127));
            let _ = a.push(IpCidr::Ipv4(addr));
        });
        self.iface.routes_mut().remove_default_ipv4_route();
        if let Some(g) = gw {
            let _ = self.iface.routes_mut().add_default_ipv4_route(g);
        }
        self.cfg.addr = Some(addr);
        self.cfg.gateway = gw;
        self.sync_local_ips();
    }

    pub fn orphan(&mut self, h: SocketHandle) {
        self.orphans.push(h);
    }

    pub fn mac(&self) -> [u8; 6] {
        self.dev.mac()
    }
}

/// Sockets dropped while the stack lock was busy (drained by `knetd`).
static DEFERRED_ORPHANS: crate::sync::SpinLock<Vec<SocketHandle>> = crate::sync::SpinLock::new(Vec::new());

pub fn defer_orphan(h: SocketHandle) {
    DEFERRED_ORPHANS.lock().push(h);
}

/// Ask `knetd` to run a poll soon.
pub fn kick() {
    NETD_WQ.wake_all();
}

/// Poll the host stack now (after queueing data) and wake socket waiters.
///
/// Loops while a poll keeps changing state so a loopback exchange (a frame
/// this host both sends and receives) completes in one call instead of
/// waiting for the next `knetd` tick: send → deliver → reply → deliver.
pub fn poll_now() {
    if let Some(s) = STACK.get() {
        let mut changed = false;
        // A loopback echo takes several device passes (send → deliver request
        // → generate reply → deliver reply). The middle passes move a frame
        // without changing socket state, so poll a few times unconditionally
        // before trusting the "no change" signal to stop.
        for i in 0..8 {
            let c = s.lock().poll();
            changed |= c;
            if !c && i >= 3 {
                break;
            }
        }
        if changed {
            SOCK_WQ.wake_all();
        }
        NETD_WQ.wake_all();
    }
}

fn nic_irq() {
    e1000::ack_irq();
    crate::crypto::rng::add_interrupt_entropy();
    IRQ_PENDING.store(true, Ordering::Release);
    NETD_WQ.wake_all();
}

/// Probe the NIC, build the stack and start `knetd`.
pub fn init() {
    let nic = e1000::E1000::probe();
    let irq = nic.as_ref().map(|n| n.irq);
    let nic: Option<Box<dyn crate::drivers::net::NetDevice>> = nic.map(|n| Box::new(n) as _);
    if nic.is_none() {
        crate::kwarn!("net", "no network interface found: loopback only");
    }
    let mut dev = PhysDevice::new(nic);
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(dev.mac())));
    config.random_seed = crate::crypto::rng::u64();
    let mut iface = Interface::new(config, &mut dev, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
    });
    let mut sockets = SocketSet::new(vec![]);
    let dhcp = dev.has_nic().then(|| sockets.add(dhcpv4::Socket::new()));
    let mut st = Stack { iface, dev, sockets, dhcp, cfg: IfConfig::default(), orphans: Vec::new() };
    st.sync_local_ips();
    STACK.call_once(|| Mutex::new(st));
    if let Some(irq) = irq {
        if irq > 0 && irq < 16 {
            crate::trap::register_irq(irq, nic_irq);
        }
    }
    crate::sched::spawn("knetd", netd);
}

/// Configure a static address when DHCP gave nothing within `wait_ms`.
pub fn static_fallback(wait_ms: u64, addr: Ipv4Cidr, gw: Ipv4Address, dns: Ipv4Address) {
    let deadline = crate::time::now_ns() + wait_ms * 1_000_000;
    while crate::time::now_ns() < deadline {
        if stack().lock().cfg.addr.is_some() {
            return;
        }
        crate::sched::sleep_ms(100);
    }
    let mut s = stack().lock();
    if s.cfg.addr.is_none() && s.dev.has_nic() {
        crate::knotice!("net", "no DHCP answer: using static {} via {}", addr, gw);
        s.set_address(addr, Some(gw));
        s.cfg.dns = vec![dns];
    }
}

fn netd() {
    loop {
        let (changed, delay) = {
            let mut s = stack().lock();
            let deferred = core::mem::take(&mut *DEFERRED_ORPHANS.lock());
            for h in deferred {
                s.sockets.get_mut::<smoltcp::socket::tcp::Socket>(h).close();
                s.orphan(h);
            }
            let c = s.poll();
            let Stack { iface, sockets, .. } = &mut *s;
            let d = iface.poll_delay(now(), sockets);
            (c, d)
        };
        if changed {
            SOCK_WQ.wake_all();
        }
        let wait_ns = delay.map(|d| d.total_micros() * 1000).unwrap_or(1_000_000_000).clamp(0, 1_000_000_000);
        if wait_ns == 0 {
            crate::sched::yield_now();
            continue;
        }
        let deadline = crate::time::now_ns() + wait_ns;
        let _ = NETD_WQ.wait_until_interruptible(|| IRQ_PENDING.swap(false, Ordering::AcqRel).then_some(()), Some(deadline));
    }
}

pub fn config() -> IfConfig {
    STACK.get().map(|s| s.lock().cfg.clone()).unwrap_or_default()
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    e1000::fmt_mac(m)
}

/// `/proc/net/*`.
pub fn procfs(name: &str) -> String {
    let mut s = String::new();
    let Some(st) = STACK.get() else { return s };
    let st = st.lock();
    match name {
        "dev" => {
            s.push_str("Inter-|   Receive                                                |  Transmit\n");
            s.push_str(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
            let lo = st.dev.lo_stats;
            let _ = writeln!(s, "{:>6}: {} {} 0 0 0 0 0 0 {} {} 0 0 0 0 0 0", "lo", lo.rx_bytes, lo.rx_packets, lo.tx_bytes, lo.tx_packets);
            if let Some(n) = st.dev.nic_stats() {
                let _ = writeln!(
                    s,
                    "{:>6}: {} {} {} {} 0 0 0 0 {} {} {} {} 0 0 0 0",
                    "eth0", n.rx_bytes, n.rx_packets, n.rx_errors, n.rx_dropped + st.dev.filtered_in, n.tx_bytes, n.tx_packets, n.tx_errors, n.tx_dropped + st.dev.filtered_out
                );
            }
        }
        "route" => {
            s.push_str("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");
            let hex = |a: Ipv4Address| {
                let o = a.octets();
                u32::from_le_bytes(o)
            };
            if let Some(gw) = st.cfg.gateway {
                let _ = writeln!(s, "eth0\t00000000\t{:08X}\t0003\t0\t0\t100\t00000000\t0\t0\t0", hex(gw));
            }
            if let Some(a) = st.cfg.addr {
                let _ = writeln!(s, "eth0\t{:08X}\t00000000\t0001\t0\t0\t0\t{:08X}\t0\t0\t0", hex(a.network().address()), hex(a.netmask()));
            }
        }
        "tcp" => {
            s.push_str("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
            for (i, sock) in socket::tcp_table(&st).iter().enumerate() {
                let _ = writeln!(
                    s,
                    "{:>4}: {} {} {:02X} {:08X}:{:08X} 00:00000000 00000000     0        0 0 1 0000000000000000 20 4 30 10 -1",
                    i, sock.local, sock.remote, sock.state_code, sock.tx_queue, sock.rx_queue
                );
            }
        }
        "udp" => {
            s.push_str("   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n");
        }
        "arp" => s.push_str("IP address       HW type     Flags       HW address            Mask     Device\n"),
        "sockstat" => {
            let tcp = socket::tcp_table(&st).len();
            let _ = writeln!(s, "sockets: used {}\nTCP: inuse {} orphan {} tw 0 alloc {} mem 0\nUDP: inuse 0 mem 0", st.sockets.iter().count(), tcp, st.orphans.len(), tcp);
        }
        _ => {
            s.push_str("Ip: Forwarding DefaultTTL\nIp: 1 64\n");
        }
    }
    s
}
