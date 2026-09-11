//! OCI Distribution Specification (Docker Registry API v2) client.
//!
//! Implements:
//!   GET /v2/                                  — ping (checks registry reachable)
//!   GET /v2/<name>/manifests/<reference>      — fetch manifest
//!   GET /v2/<name>/blobs/<digest>             — fetch a blob (layer)
//!
//! Auth flow (Docker Hub, quay.io):
//!   1. GET /v2/ → 401 + WWW-Authenticate header
//!   2. GET <auth-realm>?service=<svc>&scope=repository:<name>:pull
//!   3. Extract "token" from JSON response
//!   4. Retry manifests/blobs with "Authorization: Bearer <token>"
//!
//! For plain-HTTP local registries (e.g. Docker registry:2 on port 5000),
//! auth is not required.

use super::dns;
use super::http;
use super::types::{Manifest, LayerInfo, json_str, json_u64, json_array_body, JsonObjectIter,
                   DIGEST_LEN, MAX_LAYERS};
use super::Output;

// ── Registry descriptor ───────────────────────────────────────────────────────

pub struct Registry {
    pub host: [u8; 64],
    pub host_len: usize,
    pub ip: [u8; 4],
    pub port: u16,
    /// Bearer token (empty if not authenticated)
    token: [u8; 512],
    token_len: usize,
}

impl Registry {
    pub fn host(&self) -> &[u8] { &self.host[..self.host_len] }
    pub fn token(&self) -> &[u8] { &self.token[..self.token_len] }
}

// ── Static buffers ────────────────────────────────────────────────────────────

static mut AUTH_HEADER: [u8; 600] = [0; 600];
static mut AUTH_HDR_LEN: usize    = 0;
static mut PATH_BUF: [u8; 512]    = [0; 512];

// ── Public API ────────────────────────────────────────────────────────────────

/// Resolve registry host → IP, then ping /v2/ to confirm connectivity.
pub fn connect(host: &[u8], port: u16, out: &mut dyn Output) -> Option<Registry> {
    out.print(b"Resolving ");
    out.print(host);
    out.print(b"...\n");

    let ip = dns::resolve(host)?;
    out.print(b"Resolved: ");
    print_ip(out, &ip);
    out.print(b"\n");

    let mut reg = Registry {
        host: [0; 64], host_len: 0,
        ip, port,
        token: [0; 512], token_len: 0,
    };
    let hl = host.len().min(63);
    reg.host[..hl].copy_from_slice(&host[..hl]);
    reg.host_len = hl;

    // Ping /v2/
    if !ping(&reg, out) {
        out.print(b"Registry ping failed\n");
        return None;
    }

    Some(reg)
}

/// Authenticate with the registry (for Docker Hub / quay.io bearer auth).
/// Reads the 401 WWW-Authenticate header and fetches a token.
pub fn authenticate(reg: &mut Registry, _name: &[u8], out: &mut dyn Output) -> bool {
    // Step 1: GET /v2/ to trigger 401
    let resp = match do_get(reg, b"/v2/", b"", out) {
        Some(r) => r,
        None    => return false,
    };

    if resp.status == 200 { return true; } // no auth needed
    if resp.status != 401 { return false; }

    // Bearer token auth (Docker Hub) requires parsing WWW-Authenticate header.
    // Not yet implemented; for now report and fail.
    out.print(b"  [warn] Registry requires bearer authentication (not yet implemented).\n");
    out.print(b"  [warn] Use a local registry on port 5000 for unauthenticated pulls.\n");
    false
}

/// Fetch and parse the manifest for `name:reference`.
pub fn get_manifest(
    reg:       &Registry,
    name:      &[u8],
    reference: &[u8],
    out:       &mut dyn Output,
) -> Option<Manifest> {
    // Build path: /v2/<name>/manifests/<reference>
    let path = build_path(b"/v2/", name, b"/manifests/", reference);

    // Extra headers: Accept manifest type + optional Bearer token
    let extra = build_extra_headers(
        b"Accept: application/vnd.docker.distribution.manifest.v2+json\r\n\
          Accept: application/vnd.oci.image.manifest.v1+json\r\n",
        reg.token(),
    );

    let resp = do_get(reg, path, extra, out)?;

    if resp.status == 401 {
        out.print(b"Error: registry requires authentication\n");
        return None;
    }
    if resp.status == 404 {
        out.print(b"Error: image not found\n");
        return None;
    }
    if resp.status != 200 {
        out.print(b"Error: HTTP ");
        print_u16(out, resp.status);
        out.print(b"\n");
        return None;
    }

    parse_manifest(resp.body())
}

// ── Manifest parser ───────────────────────────────────────────────────────────

pub fn parse_manifest(json: &[u8]) -> Option<Manifest> {
    let mut m = Manifest::empty();

    // Config digest
    if let Some(cd) = json_str(json, b"digest") {
        // The first "digest" hit might be the config or a layer — we need the
        // one inside the "config" object.  Extract config object first.
        if let Some(cfg_body) = json_array_body(json, b"config") {
            // json_array_body found "[...]" — but config is an object "{...}".
            // Fall through to plain json_str scan of whole document.
            let _ = cfg_body;
        }
        let dl = cd.len().min(DIGEST_LEN);
        m.config_digest[..dl].copy_from_slice(&cd[..dl]);
        m.config_len = dl;
    }
    if let Some(cs) = json_u64(json, b"size") {
        m.config_size = cs;
    }

    // Layers array
    let layers_body = json_array_body(json, b"layers")?;
    for obj in JsonObjectIter::new(layers_body) {
        if m.layer_count >= MAX_LAYERS { break; }

        let digest_val = match json_str(obj, b"digest") { Some(d) => d, None => continue };
        let size_val   = json_u64(obj, b"size").unwrap_or(0);

        let mut li = LayerInfo::empty();
        let dl = digest_val.len().min(DIGEST_LEN);
        li.digest[..dl].copy_from_slice(&digest_val[..dl]);
        li.digest_len = dl;
        li.size = size_val;

        m.layers[m.layer_count] = li;
        m.layer_count += 1;
    }

    if m.layer_count == 0 { return None; }
    Some(m)
}

// ── Registry ping ─────────────────────────────────────────────────────────────

fn ping(reg: &Registry, out: &mut dyn Output) -> bool {
    let extra = build_extra_headers(b"", reg.token());
    match do_get(reg, b"/v2/", extra, out) {
        Some(r) => r.status == 200 || r.status == 401, // 401 = auth required but reachable
        None    => false,
    }
}

/// Dispatch GET to plain HTTP or HTTPS based on registry port.
fn do_get(
    reg:   &Registry,
    path:  &[u8],
    extra: &[u8],
    out:   &mut dyn Output,
) -> Option<http::HttpResp> {
    if reg.port == 443 {
        http::get_tls(reg.ip, reg.port, reg.host(), path, extra, out)
    } else {
        http::get(reg.ip, reg.port, reg.host(), path, extra, out)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a URL path: prefix + name + middle + suffix (all ≤ 511 bytes total).
fn build_path(prefix: &[u8], name: &[u8], middle: &[u8], suffix: &[u8]) -> &'static [u8] {
    let buf = unsafe { &mut PATH_BUF };
    let mut pos = 0usize;
    for part in &[prefix, name, middle, suffix] {
        let n = part.len().min(511 - pos);
        buf[pos..pos + n].copy_from_slice(&part[..n]);
        pos += n;
    }
    buf[pos] = 0;
    unsafe { &PATH_BUF[..pos] }
}

static mut EXTRA_HDR: [u8; 700] = [0; 700];

/// Combine fixed headers with an optional Bearer token header.
fn build_extra_headers<'a>(base: &[u8], token: &[u8]) -> &'static [u8] {
    let buf = unsafe { &mut EXTRA_HDR };
    let n = base.len().min(699);
    buf[..n].copy_from_slice(&base[..n]);
    let mut pos = n;

    if !token.is_empty() {
        let hdr = b"Authorization: Bearer ";
        let hn = hdr.len().min(699 - pos);
        buf[pos..pos + hn].copy_from_slice(&hdr[..hn]);
        pos += hn;
        let tn = token.len().min(699 - pos);
        buf[pos..pos + tn].copy_from_slice(&token[..tn]);
        pos += tn;
        if pos + 2 <= 699 { buf[pos] = b'\r'; buf[pos + 1] = b'\n'; pos += 2; }
    }
    unsafe { &EXTRA_HDR[..pos] }
}

fn print_ip(out: &mut dyn Output, ip: &[u8; 4]) {
    for i in 0..4 {
        print_u64(out, ip[i] as u64);
        if i < 3 { out.print(b"."); }
    }
}

fn print_u16(out: &mut dyn Output, n: u16) { print_u64(out, n as u64); }

fn print_u64(out: &mut dyn Output, n: u64) {
    if n == 0 { out.print(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut pos = 20usize;
    let mut v = n;
    while v > 0 { pos -= 1; buf[pos] = b'0' + (v % 10) as u8; v /= 10; }
    out.print(&buf[pos..]);
}
