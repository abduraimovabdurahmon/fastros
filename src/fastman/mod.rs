//! fastman — built-in container image manager.
//!
//! Similar to Podman / docker CLI but fully OS-integrated: no daemon,
//! no OCI runtime, no userspace escape.  Runs directly in kernel space.
//!
//! Supported commands (see shell/command/fastman.rs for the CLI layer):
//!   fastman pull  <image>          — pull image from registry
//!   fastman images                 — list local images
//!   fastman rmi   <image>          — remove a local image
//!
//! Registry support (plain HTTP):
//!   docker.io  (registry-1.docker.io:80)  — official images (auth via HTTPS TODO)
//!   quay.io:80                            — Quay images
//!   <ip>:<port>                           — local / insecure registries ✓
//!
//! LAYER ARCHITECTURE CONSTRAINT:
//!   fastman/ is Layer 6 (container).  It may import: kernel/, fs/, drivers/, hal/, libs/
//!   It MUST NOT import shell/ directly — use the Output trait below.

pub mod container;
pub mod dns;
pub mod http;
pub mod registry;
pub mod runtime;
pub mod store;
pub mod tar;
pub mod tls;
pub mod types;

use self::types::ImageRef;

// ── Output trait (avoids importing shell/) ────────────────────────────────────

/// Minimal write interface passed down from the shell command layer.
pub trait Output {
    fn print(&mut self, s: &[u8]);
    fn println(&mut self, s: &[u8]) { self.print(s); self.print(b"\n"); }
    fn newline(&mut self) { self.print(b"\n"); }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Pull an image from a registry.
///
/// `image_str` is the user-supplied string, e.g.:
///   "nginx"              "nginx:alpine"
///   "quay.io/nginx:latest"
///   "10.0.2.2:5000/myimage:v1"
pub fn pull(image_str: &[u8], out: &mut dyn Output) -> bool {
    // Parse image reference
    let image_ref = match ImageRef::parse(image_str) {
        Some(r) => r,
        None    => { out.println(b"fastman: invalid image reference"); return false; }
    };

    out.print(b"Pulling ");
    out.print(image_str);
    out.print(b"\n");
    out.print(b"Registry: ");
    out.print(image_ref.registry_host());
    out.print(b":");
    print_u64(out, image_ref.registry_port as u64);
    out.print(b"\n");

    // Connect to registry
    let reg = match registry::connect(image_ref.registry_host(), image_ref.registry_port, out) {
        Some(r) => r,
        None    => {
            out.println(b"fastman: cannot connect to registry");
            return false;
        }
    };

    // Fetch manifest
    out.print(b"Fetching manifest for ");
    out.print(image_ref.name());
    out.print(b":");
    out.print(image_ref.tag());
    out.print(b"\n");

    let manifest = match registry::get_manifest(&reg, image_ref.name(), image_ref.tag(), out) {
        Some(m) => m,
        None    => {
            out.println(b"fastman: failed to fetch manifest");
            return false;
        }
    };

    // Display layer info
    let mut total_size = 0u64;
    for i in 0..manifest.layer_count {
        let layer = &manifest.layers[i];
        out.print(b"  Layer ");
        print_u64(out, i as u64 + 1);
        out.print(b": ");
        // Print short digest (first 19 chars: "sha256:" + 12 chars)
        let digest = layer.digest_str();
        let dlen   = digest.len().min(19);
        out.print(&digest[..dlen]);
        out.print(b"...  ");
        let mut size_buf = [0u8; 16];
        out.print(store::fmt_size(layer.size, &mut size_buf));
        out.newline();
        total_size = total_size.saturating_add(layer.size);
    }

    out.print(b"Total: ");
    let mut total_buf = [0u8; 16];
    out.print(store::fmt_size(total_size, &mut total_buf));
    out.print(b" (");
    print_u64(out, manifest.layer_count as u64);
    out.println(b" layers)");

    // Save metadata to store
    let id = store::save(image_ref.name(), image_ref.tag(), &manifest);
    out.print(b"Pulled: ");
    out.print(image_ref.name());
    out.print(b":");
    out.print(image_ref.tag());
    out.print(b"  id=");
    out.print(&id[..]);
    out.newline();

    true
}

/// Start a container (delegates to runtime::run).
pub fn run(cfg: &container::ContainerConfig, out: &mut dyn Output) -> Option<[u8; 12]> {
    runtime::run(cfg, out)
}

/// Initialise the fastman subsystem.
pub fn init() {
    // Nothing to do yet — image store and container table are static.
    // Future: restore persisted container state from diskfs.
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn print_u64(out: &mut dyn Output, n: u64) {
    if n == 0 { out.print(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut pos = 20usize;
    let mut v = n;
    while v > 0 { pos -= 1; buf[pos] = b'0' + (v % 10) as u8; v /= 10; }
    out.print(&buf[pos..]);
}
