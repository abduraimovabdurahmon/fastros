//! The first kernel task: brings up everything that may block, in order.

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

pub fn main() {
    crate::crypto::rng::init();
    crate::drivers::pci::init();
    crate::drivers::block::ata::init();

    let ns = crate::fs::boot::mount_root();
    crate::proc::init(ns.clone());
    crate::fs::boot::populate(&ns);
    crate::fs::bcache::start_flusher();
    crate::utmp::boot();
    crate::power::init();

    crate::firewall::init();
    crate::net::init();
    crate::sched::spawn("dhcp-fallback", || {
        crate::net::static_fallback(
            4000,
            Ipv4Cidr::new(Ipv4Address::new(10, 0, 2, 15), 24),
            Ipv4Address::new(10, 0, 2, 2),
            Ipv4Address::new(10, 0, 2, 3),
        )
    });

    crate::console::init();
    crate::ssh::start();
    crate::console::start_getty();
    let m = crate::mm::stats();
    kinfo!("init", "system ready: {} MiB free, {} tasks", m.free_bytes >> 20, crate::sched::stats().tasks);
    // Supervisors look for this line.
    crate::drivers::serial::write(b"  Boot complete.\n");
}
