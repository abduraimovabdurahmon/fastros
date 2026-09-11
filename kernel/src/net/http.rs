//! A minimal HTTP/1.1 client over [`TcpStream`], shared by `curl`, `wget`
//! and (later) fastman's registry puller.
//!
//! Plain HTTP only; `https://` returns [`HttpError::Tls`] until a TLS client
//! lands. Handles chunked transfer-encoding, `Content-Length` bodies,
//! read-to-close bodies, and redirects (the caller follows them).

use super::dns;
use super::socket::TcpStream;
use crate::errno::Errno;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, IpEndpoint};

/// A parsed request target.
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, HttpError> {
        let (scheme, rest) = match s.split_once("://") {
            Some((sc, r)) => (sc.to_ascii_lowercase(), r),
            None => ("http".to_string(), s),
        };
        if scheme != "http" && scheme != "https" {
            return Err(HttpError::BadUrl);
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        // Strip userinfo@ if present.
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => (h.to_string(), p.parse().map_err(|_| HttpError::BadUrl)?),
            _ => (authority.to_string(), if scheme == "https" { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err(HttpError::BadUrl);
        }
        Ok(Url { scheme, host, port, path: if path.is_empty() { "/".to_string() } else { path.to_string() } })
    }

    pub fn is_tls(&self) -> bool {
        self.scheme == "https"
    }

    /// `host` or `host:port` for the Host header (default ports omitted).
    pub fn host_header(&self) -> String {
        let default = if self.is_tls() { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            alloc::format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug)]
pub enum HttpError {
    BadUrl,
    Tls,
    Dns,
    Connect(Errno),
    Io(Errno),
    BadResponse,
    TooManyRedirects,
}

impl HttpError {
    pub fn message(&self) -> String {
        match self {
            HttpError::BadUrl => "URL using bad/illegal format or missing URL".to_string(),
            HttpError::Tls => "HTTPS/TLS is not supported yet".to_string(),
            HttpError::Dns => "Could not resolve host".to_string(),
            HttpError::Connect(e) => alloc::format!("Failed to connect: {e}"),
            HttpError::Io(e) => alloc::format!("Transfer closed: {e}"),
            HttpError::BadResponse => "Received malformed HTTP response".to_string(),
            HttpError::TooManyRedirects => "Number of redirects hit maximum".to_string(),
        }
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
    /// Send the request but read only headers (a HEAD-like read for bodies).
    pub head_only: bool,
    pub timeout_ms: u64,
    pub user_agent: &'a str,
}

pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The raw status line + headers, for `curl -i` / `-I`.
    pub header_block: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308) && self.location().is_some()
    }
}

/// The byte transport under HTTP: plain TCP or TLS.
pub enum Conn {
    Plain(TcpStream),
    Tls(crate::net::tls::TlsStream),
}

impl Conn {
    fn read(&mut self, buf: &mut [u8], timeout_ms: u64) -> Result<usize, HttpError> {
        match self {
            Conn::Plain(s) => s.read_timeout(buf, Some(timeout_ms)).map_err(HttpError::Io),
            Conn::Tls(s) => s.read(buf).map_err(HttpError::Io),
        }
    }
    fn write_all(&mut self, data: &[u8]) -> Result<(), HttpError> {
        match self {
            Conn::Plain(s) => s.write_all(data).map_err(HttpError::Io),
            Conn::Tls(s) => s.write_all(data).map_err(HttpError::Io),
        }
    }
}

fn read_line(conn: &mut Conn, buf: &mut Vec<u8>, timeout_ms: u64) -> Result<Vec<u8>, HttpError> {
    // Read a CRLF-terminated line, buffering any overshoot in `buf`.
    loop {
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..pos].to_vec();
            buf.drain(..pos + 2);
            return Ok(line);
        }
        let mut tmp = [0u8; 2048];
        let n = conn.read(&mut tmp, timeout_ms)?;
        if n == 0 {
            // EOF without CRLF: return whatever is left.
            if buf.is_empty() {
                return Err(HttpError::BadResponse);
            }
            let line = buf.clone();
            buf.clear();
            return Ok(line);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn read_exact(conn: &mut Conn, buf: &mut Vec<u8>, want: usize, timeout_ms: u64) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::with_capacity(want);
    let take = want.min(buf.len());
    out.extend_from_slice(&buf[..take]);
    buf.drain(..take);
    let mut tmp = [0u8; 8192];
    while out.len() < want {
        let n = conn.read(&mut tmp, timeout_ms)?;
        if n == 0 {
            break;
        }
        let need = want - out.len();
        out.extend_from_slice(&tmp[..n.min(need)]);
        if n > need {
            buf.extend_from_slice(&tmp[need..n]);
        }
    }
    Ok(out)
}

/// Perform one request (no redirect following).
pub fn fetch(req: &Request) -> Result<Response, HttpError> {
    let ip = match dns::parse_ipv4(&req.url.host) {
        Some(a) => a,
        None => *dns::resolve(&req.url.host).map_err(|_| HttpError::Dns)?.first().ok_or(HttpError::Dns)?,
    };
    let ep = IpEndpoint::new(IpAddress::Ipv4(ip), req.url.port);
    let stream = TcpStream::connect(ep, req.timeout_ms).map_err(HttpError::Connect)?;
    let mut conn = if req.url.is_tls() {
        Conn::Tls(crate::net::tls::connect(stream, &req.url.host, req.timeout_ms).map_err(|_| HttpError::Tls)?)
    } else {
        Conn::Plain(stream)
    };

    // Build and send the request.
    let mut head = alloc::format!("{} {} HTTP/1.1\r\n", req.method, req.url.path);
    head.push_str(&alloc::format!("Host: {}\r\n", req.url.host_header()));
    head.push_str(&alloc::format!("User-Agent: {}\r\n", req.user_agent));
    head.push_str("Accept: */*\r\n");
    head.push_str("Connection: close\r\n");
    let mut have_ct = false;
    let mut have_clen = false;
    for (k, v) in req.headers {
        if k.eq_ignore_ascii_case("content-type") {
            have_ct = true;
        }
        if k.eq_ignore_ascii_case("content-length") {
            have_clen = true;
        }
        head.push_str(&alloc::format!("{k}: {v}\r\n"));
    }
    if let Some(body) = req.body {
        if !have_clen {
            head.push_str(&alloc::format!("Content-Length: {}\r\n", body.len()));
        }
        if !have_ct {
            head.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
    }
    head.push_str("\r\n");
    conn.write_all(head.as_bytes())?;
    if let Some(body) = req.body {
        conn.write_all(body)?;
    }
    // Do not half-close here: sending our FIN before the reply can race the
    // reply on the loopback path. The `Connection: close` header tells the
    // server to close once it has answered.

    // Status line.
    let mut buf = Vec::new();
    let status_line = read_line(&mut conn, &mut buf, req.timeout_ms)?;
    let status_str = String::from_utf8_lossy(&status_line).into_owned();
    let mut parts = status_str.splitn(3, ' ');
    let _http = parts.next().ok_or(HttpError::BadResponse)?;
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or(HttpError::BadResponse)?;
    let reason = parts.next().unwrap_or("").to_string();

    let mut header_block = Vec::new();
    header_block.extend_from_slice(&status_line);
    header_block.extend_from_slice(b"\r\n");
    let mut headers = Vec::new();
    loop {
        let line = read_line(&mut conn, &mut buf, req.timeout_ms)?;
        if line.is_empty() {
            header_block.extend_from_slice(b"\r\n");
            break;
        }
        header_block.extend_from_slice(&line);
        header_block.extend_from_slice(b"\r\n");
        let s = String::from_utf8_lossy(&line);
        if let Some((k, v)) = s.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let hdr = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
    let chunked = hdr("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let content_length: Option<usize> = hdr("content-length").and_then(|v| v.trim().parse().ok());

    let mut body = Vec::new();
    let no_body = req.head_only || req.method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status);
    if !no_body {
        if chunked {
            loop {
                let size_line = read_line(&mut conn, &mut buf, req.timeout_ms)?;
                let size_str = String::from_utf8_lossy(&size_line);
                let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).map_err(|_| HttpError::BadResponse)?;
                if size == 0 {
                    let _ = read_line(&mut conn, &mut buf, req.timeout_ms); // trailing CRLF / trailers
                    break;
                }
                let chunk = read_exact(&mut conn, &mut buf, size, req.timeout_ms)?;
                body.extend_from_slice(&chunk);
                let _ = read_line(&mut conn, &mut buf, req.timeout_ms); // CRLF after chunk
                if crate::proc::interrupted() {
                    break;
                }
            }
        } else if let Some(len) = content_length {
            body = read_exact(&mut conn, &mut buf, len, req.timeout_ms)?;
        } else {
            // Read until the server closes.
            body.append(&mut buf);
            let mut tmp = [0u8; 8192];
            loop {
                let n = conn.read(&mut tmp, req.timeout_ms)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
                if crate::proc::interrupted() {
                    break;
                }
            }
        }
    }

    Ok(Response { status, reason, headers, body, header_block })
}

/// Fetch, following up to `max_redirects` 3xx responses.
pub fn fetch_follow(req: &Request, max_redirects: u32) -> Result<(Response, Url), HttpError> {
    let mut url = Url::parse(&alloc::format!("{}://{}{}", req.url.scheme, req.url.host_header(), req.url.path))?;
    let mut redirects = 0;
    loop {
        let this = Request { url: &url, ..*req };
        let resp = fetch(&this)?;
        if resp.is_redirect() {
            if redirects >= max_redirects {
                return Err(HttpError::TooManyRedirects);
            }
            let loc = resp.location().unwrap().to_string();
            url = resolve_redirect(&url, &loc)?;
            redirects += 1;
            continue;
        }
        return Ok((resp, url));
    }
}

/// Resolve a possibly-relative Location against the current URL.
pub fn resolve_redirect(base: &Url, loc: &str) -> Result<Url, HttpError> {
    if loc.contains("://") {
        Url::parse(loc)
    } else if let Some(rest) = loc.strip_prefix("//") {
        Url::parse(&alloc::format!("{}://{}", base.scheme, rest))
    } else if loc.starts_with('/') {
        Url::parse(&alloc::format!("{}://{}{}", base.scheme, base.host_header(), loc))
    } else {
        // Relative to the directory of the current path.
        let dir = match base.path.rfind('/') {
            Some(i) => &base.path[..=i],
            None => "/",
        };
        Url::parse(&alloc::format!("{}://{}{}{}", base.scheme, base.host_header(), dir, loc))
    }
}
