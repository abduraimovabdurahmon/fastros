//! Software loopback driver (lo, 127.0.0.1).
//!
//! Packets sent to 127.x.x.x are looped back directly into
//! the receive path without touching any hardware.
//!
//! Linux equivalent: drivers/net/loopback.c

use crate::kernel::net;

static mut DEV_IDX: usize = 0;
static mut READY: bool = false;

pub fn init() {
    if let Some(idx) = net::register_device(net::DevConfig {
        name:     b"lo",
        mac:      [0; 6],         // loopback has no real MAC
        ip:       [127, 0, 0, 1],
        netmask:  [255, 0, 0, 0],
        gateway:  [0, 0, 0, 0],   // no gateway for loopback
        mtu:      65535,
        loopback: true,
        send_fn:  loopback_send,
    }) {
        unsafe { DEV_IDX = idx; READY = true; }
    }
}

/// Loopback TX: immediately re-inject the frame as RX on the same device.
fn loopback_send(frame: &[u8]) -> bool {
    let dev_idx = unsafe { DEV_IDX };
    net::receive_frame(frame, dev_idx);
    true
}
