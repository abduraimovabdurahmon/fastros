//! Docker Registry HTTP API v2 client: resolve a reference to a manifest,
//! authenticate (Bearer token), and download the config and layer blobs.
//!
//! Works against Docker Hub, quay.io and GHCR over TLS. Blob integrity is
//! verified against the sha256 digest in the manifest, so image content is
//! trustworthy even though the TLS layer does not yet verify certificates.

use super::image::{ImageConfig, ImageRef};
use super::json::{self, Value};
use crate::net::http::{self, Request, Response, Url};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const UA: &str = "fastman/0.2";
const TIMEOUT: u64 = 30_000;
const ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json";

/// Progress callbacks so the CLI can show a live pull.
pub trait Progress {
    fn line(&mut self, msg: &str);
}

pub struct PullResult {
    pub config: ImageConfig,
    /// Layer blobs in application order (already gunzip-able tarballs).
    pub layers: Vec<Vec<u8>>,
    pub digest: String,
}

#[derive(Debug)]
pub enum Error {
    Http(String),
    Auth,
    NotFound,
    Manifest(String),
    Digest,
    NoAmd64,
}

impl Error {
    pub fn message(&self) -> String {
        match self {
            Error::Http(s) => format!("network error: {s}"),
            Error::Auth => "authentication failed".to_string(),
            Error::NotFound => "image or tag not found".to_string(),
            Error::Manifest(s) => format!("bad manifest: {s}"),
            Error::Digest => "blob digest mismatch (corrupt download)".to_string(),
            Error::NoAmd64 => "no linux/amd64 image in this manifest".to_string(),
        }
    }
}

fn registry_host(r: &ImageRef) -> String {
    match &r.registry {
        Some(h) if h == "docker.io" || h == "registry-1.docker.io" => "registry-1.docker.io".to_string(),
        Some(h) => h.clone(),
        None => "registry-1.docker.io".to_string(),
    }
}

fn get(url_str: &str, headers: &[(String, String)]) -> Result<Response, Error> {
    let url = Url::parse(url_str).map_err(|e| Error::Http(e.message()))?;
    let req = Request { method: "GET", url: &url, headers, body: None, head_only: false, timeout_ms: TIMEOUT, user_agent: UA };
    let (resp, _) = http::fetch_follow(&req, 5).map_err(|e| Error::Http(e.message()))?;
    Ok(resp)
}

/// Parse a Bearer challenge and fetch a token.
fn authenticate(www_auth: &str, extra_headers: &mut Vec<(String, String)>) -> Result<(), Error> {
    // Bearer realm="...",service="...",scope="..."
    let params = www_auth.trim().strip_prefix("Bearer").unwrap_or(www_auth);
    let mut realm = String::new();
    let mut service = String::new();
    let mut scope = String::new();
    for part in params.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            let v = v.trim().trim_matches('"');
            match k.trim() {
                "realm" => realm = v.to_string(),
                "service" => service = v.to_string(),
                "scope" => scope = v.to_string(),
                _ => {}
            }
        }
    }
    if realm.is_empty() {
        return Err(Error::Auth);
    }
    let sep = if realm.contains('?') { '&' } else { '?' };
    let mut url = format!("{realm}{sep}");
    if !service.is_empty() {
        url.push_str(&format!("service={service}"));
    }
    if !scope.is_empty() {
        url.push_str(&format!("&scope={scope}"));
    }
    let resp = get(&url, &[])?;
    if resp.status != 200 {
        return Err(Error::Auth);
    }
    let v = json::parse(&resp.body).ok_or(Error::Auth)?;
    let token = v.get("token").or_else(|| v.get("access_token")).and_then(|t| t.as_str()).ok_or(Error::Auth)?;
    extra_headers.retain(|(k, _)| k != "Authorization");
    extra_headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    Ok(())
}

/// GET a registry URL, doing Bearer auth on a 401 and retrying once.
fn get_auth(url: &str, auth: &mut Vec<(String, String)>, accept: Option<&str>) -> Result<Response, Error> {
    let mut headers = auth.clone();
    if let Some(a) = accept {
        headers.push(("Accept".to_string(), a.to_string()));
    }
    let resp = get(url, &headers)?;
    if resp.status == 401 {
        let challenge = resp.header("www-authenticate").ok_or(Error::Auth)?.to_string();
        authenticate(&challenge, auth)?;
        let mut headers = auth.clone();
        if let Some(a) = accept {
            headers.push(("Accept".to_string(), a.to_string()));
        }
        return get(url, &headers);
    }
    Ok(resp)
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Pull an image: resolve the manifest, download config and layers.
pub fn pull(r: &ImageRef, prog: &mut dyn Progress) -> Result<PullResult, Error> {
    let host = registry_host(r);
    let base = format!("https://{host}/v2/{}", r.name);
    let mut auth: Vec<(String, String)> = Vec::new();

    prog.line(&format!("{}: Pulling from {}", r.tag, r.name));
    let man_url = format!("{base}/manifests/{}", r.tag);
    let resp = get_auth(&man_url, &mut auth, Some(ACCEPT))?;
    if resp.status == 404 {
        return Err(Error::NotFound);
    }
    if resp.status != 200 {
        return Err(Error::Manifest(format!("HTTP {}", resp.status)));
    }
    let man = json::parse(&resp.body).ok_or_else(|| Error::Manifest("not JSON".to_string()))?;

    // Multi-arch index? Select linux/amd64 and fetch that manifest.
    let man = if man.get("manifests").is_some() {
        let list = man.get("manifests").and_then(|m| m.as_array()).ok_or_else(|| Error::Manifest("bad index".to_string()))?;
        let pick = list
            .iter()
            .find(|m| {
                let p = m.get("platform");
                p.and_then(|p| p.get("architecture")).and_then(|a| a.as_str()) == Some("amd64")
                    && p.and_then(|p| p.get("os")).and_then(|a| a.as_str()) == Some("linux")
            })
            .ok_or(Error::NoAmd64)?;
        let digest = pick.get("digest").and_then(|d| d.as_str()).ok_or_else(|| Error::Manifest("no digest".to_string()))?;
        prog.line(&format!("{}: Resolving linux/amd64", &digest[..digest.len().min(19)]));
        let resp = get_auth(&format!("{base}/manifests/{digest}"), &mut auth, Some(ACCEPT))?;
        json::parse(&resp.body).ok_or_else(|| Error::Manifest("not JSON".to_string()))?
    } else {
        man
    };

    // Config blob → ImageConfig.
    let config = match man.get("config").and_then(|c| c.get("digest")).and_then(|d| d.as_str()) {
        Some(digest) => {
            let resp = fetch_blob(&base, digest, &mut auth, prog, "config")?;
            parse_config(&resp)
        }
        None => ImageConfig::defaults(),
    };

    // Layers, in order.
    let layer_list = man.get("layers").and_then(|l| l.as_array()).ok_or_else(|| Error::Manifest("no layers".to_string()))?;
    let mut layers = Vec::new();
    for l in layer_list {
        let digest = l.get("digest").and_then(|d| d.as_str()).ok_or_else(|| Error::Manifest("layer without digest".to_string()))?;
        let blob = fetch_blob(&base, digest, &mut auth, prog, "layer")?;
        layers.push(blob);
    }
    let digest = man.get("config").and_then(|c| c.get("digest")).and_then(|d| d.as_str()).unwrap_or("").to_string();
    prog.line("Download complete");
    Ok(PullResult { config, layers, digest })
}

fn fetch_blob(base: &str, digest: &str, auth: &mut Vec<(String, String)>, prog: &mut dyn Progress, kind: &str) -> Result<Vec<u8>, Error> {
    let short = &digest[digest.find(':').map(|i| i + 1).unwrap_or(0)..];
    let short = &short[..short.len().min(12)];
    prog.line(&format!("{short}: Downloading {kind}"));
    let resp = get_auth(&format!("{base}/blobs/{digest}"), auth, None)?;
    if resp.status != 200 {
        return Err(Error::Http(format!("blob HTTP {}", resp.status)));
    }
    // Verify the content against its digest.
    if let Some(want) = digest.strip_prefix("sha256:") {
        let got = hex(&crate::crypto::sha256(&resp.body));
        if got != want {
            return Err(Error::Digest);
        }
    }
    prog.line(&format!("{short}: Pull complete"));
    Ok(resp.body)
}

fn parse_config(blob: &[u8]) -> ImageConfig {
    let mut cfg = ImageConfig::defaults();
    let Some(v) = json::parse(blob) else { return cfg };
    if let Some(c) = v.get("config") {
        if let Some(env) = c.get("Env") {
            let e = env.str_array();
            if !e.is_empty() {
                cfg.env = e;
            }
        }
        cfg.entrypoint = c.get("Entrypoint").map(Value::str_array).unwrap_or_default();
        let cmd = c.get("Cmd").map(Value::str_array).unwrap_or_default();
        if !cmd.is_empty() {
            cfg.cmd = cmd;
        } else if !cfg.entrypoint.is_empty() {
            cfg.cmd = Vec::new();
        }
        if let Some(wd) = c.get("WorkingDir").and_then(|w| w.as_str()) {
            if !wd.is_empty() {
                cfg.workdir = wd.to_string();
            }
        }
    }
    cfg
}
