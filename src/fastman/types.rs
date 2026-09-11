//! fastman — core type definitions.
//!
//! ImageRef:  parsed image reference string (name[:tag], registry/name[:tag], etc.)
//! Manifest:  parsed OCI/Docker manifest v2 layer list
//! LayerInfo: per-layer digest + size from the manifest

// ── ImageRef ──────────────────────────────────────────────────────────────────

/// Parsed image reference.
///
/// Supported input formats:
///   `nginx`                              → registry-1.docker.io / library/nginx:latest
///   `nginx:1.25`                         → registry-1.docker.io / library/nginx:1.25
///   `quay.io/openshift/origin-cli:v4`   → quay.io:80 / openshift/origin-cli:v4
///   `10.0.2.2:5000/myapp:v2`            → 10.0.2.2:5000 / myapp:v2
pub struct ImageRef {
    pub registry_host:     [u8; 64],
    pub registry_host_len: usize,
    pub registry_port:     u16,
    pub name:              [u8; 128],
    pub name_len:          usize,
    pub tag:               [u8; 64],
    pub tag_len:           usize,
}

impl ImageRef {
    pub fn parse(s: &[u8]) -> Option<Self> {
        // Step 1: split off the tag (":tag" after the last '/')
        let (rest, tag_part) = split_tag(s);

        // Step 2: decide if the first path component is a registry host
        let (registry_part, name_part) = split_registry(rest);

        // Step 3: fill in registry host + port
        let mut host     = [0u8; 64];
        let mut host_len = 0usize;
        let mut port: u16;

        if let Some(rp) = registry_part {
            let (h, explicit_port) = split_host_port(rp);
            host_len = h.len().min(63);
            host[..host_len].copy_from_slice(&h[..host_len]);
            port = explicit_port.unwrap_or_else(|| {
                if is_https_host(&host[..host_len]) { 443 } else { 80 }
            });
        } else {
            // Default registry: Docker Hub (requires TLS)
            let dh = b"registry-1.docker.io";
            host_len = dh.len();
            host[..host_len].copy_from_slice(dh);
            port = 443;
        }

        // Step 4: canonical image name (official Docker images → "library/" prefix)
        let mut name     = [0u8; 128];
        let mut name_len = 0usize;

        if registry_part.is_none() && !name_part.contains(&b'/') {
            // Official image: "nginx" → "library/nginx"
            let prefix = b"library/";
            let total  = (prefix.len() + name_part.len()).min(127);
            let pl     = prefix.len().min(total);
            name[..pl].copy_from_slice(&prefix[..pl]);
            let rem = total - pl;
            name[pl..pl + rem].copy_from_slice(&name_part[..rem]);
            name_len = total;
        } else {
            name_len = name_part.len().min(127);
            name[..name_len].copy_from_slice(&name_part[..name_len]);
        }

        // Step 5: tag (default: "latest")
        let mut tag     = [0u8; 64];
        let mut tag_len = 0usize;
        let tp = tag_part.unwrap_or(b"latest");
        tag_len = tp.len().min(63);
        tag[..tag_len].copy_from_slice(&tp[..tag_len]);

        if name_len == 0 { return None; }

        Some(Self {
            registry_host: host,
            registry_host_len: host_len,
            registry_port: port,
            name,
            name_len,
            tag,
            tag_len,
        })
    }

    pub fn registry_host(&self) -> &[u8] { &self.registry_host[..self.registry_host_len] }
    pub fn name(&self)          -> &[u8] { &self.name[..self.name_len] }
    pub fn tag(&self)           -> &[u8] { &self.tag[..self.tag_len] }
}

// ── Splitting helpers ─────────────────────────────────────────────────────────

/// Split "name:tag" → ("name", Some("tag")).
/// Only looks for ':' after the last '/' to avoid splitting on host:port.
fn split_tag(s: &[u8]) -> (&[u8], Option<&[u8]>) {
    let search_from = s.iter().rposition(|&b| b == b'/').map(|p| p + 1).unwrap_or(0);
    if let Some(rel) = s[search_from..].iter().position(|&b| b == b':') {
        let abs = search_from + rel;
        (&s[..abs], Some(&s[abs + 1..]))
    } else {
        (s, None)
    }
}

/// Decide if the first path component is a registry host.
/// A component is a registry host if it contains '.' or ':', or equals "localhost".
fn split_registry(s: &[u8]) -> (Option<&[u8]>, &[u8]) {
    let slash = match s.iter().position(|&b| b == b'/') {
        None    => return (None, s),
        Some(p) => p,
    };
    let first = &s[..slash];
    let is_registry = first.contains(&b'.') || first.contains(&b':') || first == b"localhost";
    if is_registry { (Some(first), &s[slash + 1..]) }
    else           { (None, s) }
}

/// Split "host:port" → ("host", Some(port)) or ("host", None) if no port given.
fn split_host_port(s: &[u8]) -> (&[u8], Option<u16>) {
    if let Some(p) = s.iter().position(|&b| b == b':') {
        let port = parse_u16(&s[p + 1..]);
        (&s[..p], Some(if port == 0 { 80 } else { port }))
    } else {
        (s, None)
    }
}

/// Registries that only speak HTTPS (no explicit port given → 443).
fn is_https_host(h: &[u8]) -> bool {
    h == b"registry-1.docker.io" || h == b"docker.io"  ||
    h == b"quay.io"              || h == b"ghcr.io"    ||
    h == b"index.docker.io"
}

fn parse_u16(s: &[u8]) -> u16 {
    let mut v = 0u16;
    for &b in s {
        if b >= b'0' && b <= b'9' {
            v = v.saturating_mul(10).saturating_add((b - b'0') as u16);
        }
    }
    v
}

// ── Manifest ──────────────────────────────────────────────────────────────────

pub const MAX_LAYERS: usize = 32;
pub const DIGEST_LEN: usize = 71; // "sha256:" + 64 hex chars

/// One layer from an OCI/Docker manifest v2.
#[derive(Copy, Clone)]
pub struct LayerInfo {
    pub digest:     [u8; DIGEST_LEN],
    pub digest_len: usize,
    pub size:       u64,
}

impl LayerInfo {
    pub const fn empty() -> Self {
        Self { digest: [0; DIGEST_LEN], digest_len: 0, size: 0 }
    }
    pub fn digest_str(&self) -> &[u8] { &self.digest[..self.digest_len] }
}

/// Parsed OCI/Docker manifest v2.
pub struct Manifest {
    pub config_digest: [u8; DIGEST_LEN],
    pub config_len:    usize,
    pub config_size:   u64,
    pub layers:        [LayerInfo; MAX_LAYERS],
    pub layer_count:   usize,
}

impl Manifest {
    pub const fn empty() -> Self {
        Self {
            config_digest: [0; DIGEST_LEN],
            config_len: 0,
            config_size: 0,
            layers: [LayerInfo::empty(); MAX_LAYERS],
            layer_count: 0,
        }
    }
}

// ── JSON micro-parser ─────────────────────────────────────────────────────────
// Needed to extract manifest fields without heap or external crates.

/// Find the first occurrence of `needle` in `haystack`.
pub fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract the value of a JSON string field: `"key": "VALUE"` → VALUE bytes.
pub fn json_str<'a>(json: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    // Build `"key":` pattern
    let mut pat = [0u8; 80];
    pat[0] = b'"';
    let kl = key.len().min(76);
    pat[1..1 + kl].copy_from_slice(&key[..kl]);
    pat[1 + kl] = b'"';
    let pat_len = 2 + kl;

    let start = find_sub(json, &pat[..pat_len])?;
    let after = start + pat_len;

    // Skip whitespace and ':'
    let mut i = after;
    while i < json.len() && (json[i] == b' ' || json[i] == b'\t' || json[i] == b':') { i += 1; }
    if i >= json.len() || json[i] != b'"' { return None; }
    i += 1; // skip opening '"'

    let val_start = i;
    while i < json.len() && json[i] != b'"' { i += 1; }
    Some(&json[val_start..i])
}

/// Extract the value of a JSON number field: `"key": NUMBER` → u64.
pub fn json_u64(json: &[u8], key: &[u8]) -> Option<u64> {
    let mut pat = [0u8; 80];
    pat[0] = b'"';
    let kl = key.len().min(76);
    pat[1..1 + kl].copy_from_slice(&key[..kl]);
    pat[1 + kl] = b'"';
    let pat_len = 2 + kl;

    let start = find_sub(json, &pat[..pat_len])?;
    let after = start + pat_len;

    let mut i = after;
    while i < json.len() && (json[i] == b' ' || json[i] == b'\t' || json[i] == b':') { i += 1; }

    let mut val = 0u64;
    let mut found = false;
    while i < json.len() && json[i] >= b'0' && json[i] <= b'9' {
        val = val.saturating_mul(10).saturating_add((json[i] - b'0') as u64);
        found = true;
        i += 1;
    }
    if found { Some(val) } else { None }
}

/// Find the body of a JSON array field: `"key": [BODY]` → BODY bytes.
pub fn json_array_body<'a>(json: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut pat = [0u8; 80];
    pat[0] = b'"';
    let kl = key.len().min(76);
    pat[1..1 + kl].copy_from_slice(&key[..kl]);
    pat[1 + kl] = b'"';
    let pat_len = 2 + kl;

    let start = find_sub(json, &pat[..pat_len])?;
    let after = start + pat_len;

    let mut i = after;
    while i < json.len() && (json[i] == b' ' || json[i] == b'\t' || json[i] == b':') { i += 1; }
    if i >= json.len() || json[i] != b'[' { return None; }
    i += 1; // skip '['

    let body_start = i;
    let mut depth = 1i32;
    while i < json.len() && depth > 0 {
        match json[i] {
            b'[' => depth += 1,
            b']' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    if depth != 0 { return None; }
    Some(&json[body_start..i - 1])
}

/// Iterate over top-level `{...}` objects in a JSON array body.
/// Yields slices of each object (without the braces).
pub struct JsonObjectIter<'a> {
    remaining: &'a [u8],
}

impl<'a> JsonObjectIter<'a> {
    pub fn new(array_body: &'a [u8]) -> Self { Self { remaining: array_body } }
}

impl<'a> Iterator for JsonObjectIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        // Find next '{'
        let start = self.remaining.iter().position(|&b| b == b'{')?;
        let s = &self.remaining[start + 1..];
        let mut depth = 1i32;
        let mut i = 0;
        while i < s.len() && depth > 0 {
            match s[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        if depth != 0 { return None; }
        let obj_body = &s[..i - 1];
        self.remaining = &s[i..];
        Some(obj_body)
    }
}
