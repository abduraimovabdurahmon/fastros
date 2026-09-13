//! Port publishing for containers in a private network namespace.
//!
//! A container on `--network none`/`private`/`<bridge>` binds its ports inside
//! its own network namespace, invisible to the host. `-p HOST:CONT` bridges that
//! gap with a userspace forwarding proxy (the model Docker's `docker-proxy`
//! uses): a listener on the host stack accepts connections on `HOST` and splices
//! each to a fresh connection into the container's namespace on `CONT`. This is
//! far simpler and safer than L3 packet NAT — no connection tracking or checksum
//! rewriting — and it makes an isolated container reachable from outside.

use super::container::Port;
use crate::net::netns::NetNs;
use crate::net::socket::{TcpListener, TcpStream};
use crate::net::{IpAddress, IpEndpoint};
use crate::proc::Pid;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Publish every port of a container whose server lives in `cont_ns`. `target`
/// is the address to reach inside the namespace (its bridge IP, or loopback).
/// Each proxy runs until the container's init process (`pid`) exits.
pub fn publish(cont_ns: Arc<NetNs>, pid: Pid, ports: Vec<Port>, target: IpAddress) {
    for p in ports {
        let ns = cont_ns.clone();
        crate::sched::spawn("fm-proxy", move || run_one(ns, pid, p.host, p.container, target));
    }
}

fn alive(pid: Pid) -> bool {
    crate::proc::find(pid).is_some_and(|p| !p.is_zombie())
}

fn run_one(cont_ns: Arc<NetNs>, pid: Pid, host_port: u16, cont_port: u16, target: IpAddress) {
    // Listen on the host stack. A pre-armed backlog lets several clients queue.
    let listener = match TcpListener::bind_in(crate::net::netns::host(), host_port, 16) {
        Ok(l) => l,
        Err(_) => return, // port already taken on the host
    };
    while alive(pid) {
        match listener.try_accept() {
            Some((host_conn, _)) => {
                // Open a matching connection into the container's namespace.
                match TcpStream::connect_in(cont_ns.clone(), IpEndpoint::new(target, cont_port), 5_000) {
                    Ok(cont_conn) => splice(host_conn, cont_conn),
                    Err(_) => { /* server not up yet: drop, the client retries */ }
                }
            }
            None => {
                if !crate::sched::sleep_ms(50) {
                    crate::proc::absorb_signals();
                }
            }
        }
    }
}

/// Copy bytes in both directions between two connections until either closes.
fn splice(a: TcpStream, b: TcpStream) {
    let a = Arc::new(a);
    let b = Arc::new(b);
    let (a2, b2) = (a.clone(), b.clone());
    crate::sched::spawn("fm-splice", move || pump(&a2, &b2));
    crate::sched::spawn("fm-splice", move || pump(&b, &a));
}

/// Read from `src`, write to `dst`, until end of stream; then half-close `dst`.
fn pump(src: &TcpStream, dst: &TcpStream) {
    let mut buf = alloc::vec![0u8; 16 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(crate::errno::Errno::EINTR) => {
                crate::proc::absorb_signals();
            }
            Err(_) => break,
        }
    }
    dst.shutdown();
}
