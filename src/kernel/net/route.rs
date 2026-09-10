//! IPv4 Routing Table — Forwarding Information Base (FIB).
//!
//! Longest-prefix match (like Linux's fib_trie / route cache).
//! Supports up to MAX_ROUTES static routes.
//!
//! Linux equivalent: net/ipv4/fib_trie.c  net/ipv4/route.c

const MAX_ROUTES: usize = 8;

// ── Route entry ───────────────────────────────────────────────────────────────

pub struct Route {
    pub dest:    [u8; 4],   // network address
    pub mask:    [u8; 4],   // subnet mask (e.g. 255.255.255.0)
    pub gateway: [u8; 4],   // 0.0.0.0 = directly connected
    pub dev_idx: usize,     // which network device to use
    pub metric:  u32,       // lower = preferred
    valid:       bool,
}

impl Route {
    const fn empty() -> Self {
        Self {
            dest: [0;4], mask: [0;4], gateway: [0;4],
            dev_idx: 0, metric: 0, valid: false,
        }
    }

    /// True if `dst` matches this route (masked comparison).
    fn matches(&self, dst: &[u8; 4]) -> bool {
        dst[0] & self.mask[0] == self.dest[0] & self.mask[0] &&
        dst[1] & self.mask[1] == self.dest[1] & self.mask[1] &&
        dst[2] & self.mask[2] == self.dest[2] & self.mask[2] &&
        dst[3] & self.mask[3] == self.dest[3] & self.mask[3]
    }

    /// Prefix length (number of set bits in mask) for longest-prefix match.
    fn prefix_len(&self) -> u32 {
        self.mask.iter().map(|b| b.count_ones()).sum()
    }
}

static mut TABLE: [Route; MAX_ROUTES] = [const { Route::empty() }; MAX_ROUTES];

// ── Management ────────────────────────────────────────────────────────────────

/// Add a route to the table.
pub fn add(dest: [u8;4], mask: [u8;4], gateway: [u8;4], dev_idx: usize, metric: u32) {
    unsafe {
        for r in TABLE.iter_mut() {
            if !r.valid {
                r.dest    = dest;
                r.mask    = mask;
                r.gateway = gateway;
                r.dev_idx = dev_idx;
                r.metric  = metric;
                r.valid   = true;
                return;
            }
        }
    }
}

/// Remove all routes for a device.
pub fn flush_dev(dev_idx: usize) {
    unsafe {
        for r in TABLE.iter_mut() {
            if r.valid && r.dev_idx == dev_idx { r.valid = false; }
        }
    }
}

// ── Lookup ────────────────────────────────────────────────────────────────────

pub struct NextHop {
    /// 0.0.0.0 means directly connected — use `dst` itself for ARP
    pub gateway: [u8; 4],
    pub dev_idx: usize,
}

/// Find the best route for `dst` using longest-prefix match.
/// Returns None if no route (host unreachable).
///
/// Linux analogue: fib_lookup() → rt_fill_info()
pub fn lookup(dst: &[u8; 4]) -> Option<NextHop> {
    unsafe {
        let mut best: Option<&Route> = None;
        let mut best_prefix = 0u32;
        let mut best_metric = u32::MAX;

        for r in TABLE.iter() {
            if !r.valid || !r.matches(dst) { continue; }
            let pl = r.prefix_len();
            // Prefer longer prefix; tie-break by lower metric
            if pl > best_prefix || (pl == best_prefix && r.metric < best_metric) {
                best_prefix = pl;
                best_metric = r.metric;
                best = Some(r);
            }
        }

        best.map(|r| NextHop { gateway: r.gateway, dev_idx: r.dev_idx })
    }
}

/// Iterate all valid routes (for `netstat -r` output).
pub fn iter<F: FnMut(&Route)>(mut f: F) {
    unsafe {
        for r in TABLE.iter() {
            if r.valid { f(r); }
        }
    }
}

pub use Route as RouteEntry;
