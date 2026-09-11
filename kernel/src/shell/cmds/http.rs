//! `curl` and `wget` — HTTP clients over [`crate::net::http`].

use crate::fs::file::flags;
use crate::fs::ops;
use crate::net::http::{self, HttpError, Request, Url};
use crate::shell::ctx::Ctx;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const CURL_UA: &str = "curl/8.5.0-fastros";
const WGET_UA: &str = "Wget/1.21-fastros";
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Seconds (possibly fractional) as milliseconds, for -m/--max-time.
struct Secs(u64);
impl core::str::FromStr for Secs {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        let (i, f) = s.split_once('.').unwrap_or((s, ""));
        let whole: u64 = if i.is_empty() { 0 } else { i.parse().map_err(|_| ())? };
        let mut ms = whole * 1000;
        let mut scale = 100;
        for c in f.chars().take(3) {
            ms += c.to_digit(10).ok_or(())? as u64 * scale;
            scale /= 10;
        }
        Ok(Secs(ms))
    }
}

fn write_out_file(ctx: &mut Ctx, path: &str, data: &[u8]) -> Result<(), i32> {
    let fs = ops::Ctx::of(&ctx.proc);
    match ops::open(&fs, path, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, 0o644) {
        Ok(f) => f.write_all(data).map_err(|e| ctx.fail_errno(path, e)),
        Err(e) => Err(ctx.fail_errno(path, e)),
    }
}

/// The trailing path component of a URL, or "index.html".
fn basename_of(url: &Url) -> String {
    let name = url.path.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or("");
    if name.is_empty() {
        "index.html".to_string()
    } else {
        name.to_string()
    }
}

pub fn curl(ctx: &mut Ctx) -> i32 {
    let args = ctx.args[1..].to_vec();
    let mut method: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut data: Option<Vec<u8>> = None;
    let mut output: Option<String> = None;
    let mut remote_name = false;
    let (mut silent, mut show_error, mut follow, mut head, mut include, mut fail) = (false, false, false, false, false, false);
    let mut write_out: Option<String> = None;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut urls: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut val = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match a.as_str() {
            "-X" | "--request" => method = val(&mut i),
            "-H" | "--header" => {
                if let Some(h) = val(&mut i) {
                    if let Some((k, v)) = h.split_once(':') {
                        headers.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" => {
                if let Some(d) = val(&mut i) {
                    data = Some(d.into_bytes());
                }
            }
            "-o" | "--output" => output = val(&mut i),
            "-O" | "--remote-name" => remote_name = true,
            "-s" | "--silent" => silent = true,
            "-S" | "--show-error" => show_error = true,
            "-L" | "--location" => follow = true,
            "-I" | "--head" => head = true,
            "-i" | "--include" => include = true,
            "-f" | "--fail" => fail = true,
            "-A" | "--user-agent" => {
                if let Some(ua) = val(&mut i) {
                    headers.push(("User-Agent".to_string(), ua));
                }
            }
            "-w" | "--write-out" => write_out = val(&mut i),
            "-m" | "--max-time" | "--connect-timeout" => {
                if let Some(t) = val(&mut i).and_then(|s| s.parse::<Secs>().ok()) {
                    timeout_ms = t.0.max(1);
                }
            }
            "--url" => {
                if let Some(u) = val(&mut i) {
                    urls.push(u);
                }
            }
            "-sS" => {
                silent = true;
                show_error = true;
            }
            s if s.starts_with('-') && s.len() > 1 && !s.starts_with("--") => {
                // Bundled short flags (e.g. -sSL).
                for c in s[1..].chars() {
                    match c {
                        's' => silent = true,
                        'S' => show_error = true,
                        'L' => follow = true,
                        'I' => head = true,
                        'i' => include = true,
                        'f' => fail = true,
                        'O' => remote_name = true,
                        _ => {
                            ctx.eprint(&alloc::format!("curl: option -{c}: is unknown\n"));
                            return 2;
                        }
                    }
                }
            }
            s if s.starts_with("--") => {
                ctx.eprint(&alloc::format!("curl: option {s}: is unknown\n"));
                return 2;
            }
            s => urls.push(s.to_string()),
        }
        i += 1;
    }

    if urls.is_empty() {
        ctx.eprint("curl: try 'curl --help' for more information\n");
        return 2;
    }

    let method = method.unwrap_or_else(|| if head { "HEAD".to_string() } else if data.is_some() { "POST".to_string() } else { "GET".to_string() });
    let ua = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("user-agent")).map(|(_, v)| v.clone()).unwrap_or_else(|| CURL_UA.to_string());
    let send_headers: Vec<(String, String)> = headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("user-agent")).cloned().collect();

    let mut status = 0;
    for raw in &urls {
        let url = match Url::parse(raw) {
            Ok(u) => u,
            Err(e) => {
                if !silent || show_error {
                    ctx.eprint(&alloc::format!("curl: (3) {}\n", e.message()));
                }
                status = 3;
                continue;
            }
        };
        let req = Request {
            method: &method,
            url: &url,
            headers: &send_headers,
            body: data.as_deref(),
            head_only: head,
            timeout_ms,
            user_agent: &ua,
        };
        let result = if follow { http::fetch_follow(&req, 50).map(|(r, _)| r) } else { http::fetch(&req) };
        let resp = match result {
            Ok(r) => r,
            Err(e) => {
                if !silent || show_error {
                    let code = match e {
                        HttpError::BadUrl => 3,
                        HttpError::Dns => 6,
                        HttpError::Connect(_) => 7,
                        HttpError::Tls => 60,
                        HttpError::TooManyRedirects => 47,
                        _ => 56,
                    };
                    ctx.eprint(&alloc::format!("curl: ({code}) {}\n", e.message()));
                    status = code;
                } else {
                    status = 56;
                }
                continue;
            }
        };

        if fail && resp.status >= 400 {
            if !silent || show_error {
                ctx.eprint(&alloc::format!("curl: (22) The requested URL returned error: {} {}\n", resp.status, resp.reason));
            }
            status = 22;
            continue;
        }

        // Assemble the output payload.
        let mut payload = Vec::new();
        if head || include {
            payload.extend_from_slice(&resp.header_block);
        }
        payload.extend_from_slice(&resp.body);

        let out_path = if remote_name { Some(basename_of(&url)) } else { output.clone() };
        match out_path {
            Some(path) if path != "-" => {
                if let Err(c) = write_out_file(ctx, &path, &payload) {
                    status = c;
                    continue;
                }
            }
            _ => ctx.write(&payload),
        }
        if let Some(fmt) = &write_out {
            ctx.print(&expand_write_out(fmt, &resp, &url));
        }
    }
    ctx.flush();
    status
}

/// curl `-w` format: `%{http_code}`, `%{size_download}`, `\n`, `\t`.
fn expand_write_out(fmt: &str, resp: &http::Response, url: &Url) -> String {
    let mut out = String::new();
    let c: Vec<char> = fmt.chars().collect();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '\\' && i + 1 < c.len() {
            i += 1;
            out.push(match c[i] {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            });
            i += 1;
            continue;
        }
        if c[i] == '%' && i + 1 < c.len() && c[i + 1] == '{' {
            if let Some(end) = c[i..].iter().position(|&x| x == '}') {
                let var: String = c[i + 2..i + end].iter().collect();
                out.push_str(&match var.as_str() {
                    "http_code" | "response_code" => resp.status.to_string(),
                    "size_download" => resp.body.len().to_string(),
                    "content_type" => resp.header("content-type").unwrap_or("").to_string(),
                    "url_effective" => alloc::format!("{}://{}{}", url.scheme, url.host_header(), url.path),
                    "num_redirects" => "0".to_string(),
                    _ => String::new(),
                });
                i += end + 1;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

pub fn wget(ctx: &mut Ctx) -> i32 {
    let args = ctx.args[1..].to_vec();
    let mut output: Option<String> = None;
    let mut to_stdout = false;
    let (mut quiet, mut headers) = (false, Vec::<(String, String)>::new());
    let mut max_redirect = 20u32;
    let mut urls: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut val = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match a.as_str() {
            "-O" | "--output-document" => {
                match val(&mut i) {
                    Some(o) if o == "-" => to_stdout = true,
                    o => output = o,
                }
            }
            "-q" | "--quiet" => quiet = true,
            "-nv" | "--no-verbose" => {}
            "--header" => {
                if let Some(h) = val(&mut i) {
                    if let Some((k, v)) = h.split_once(':') {
                        headers.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
            }
            "--max-redirect" => {
                max_redirect = val(&mut i).and_then(|v| v.parse().ok()).unwrap_or(20);
            }
            s if s.starts_with("-O") && s.len() > 2 => output = Some(s[2..].to_string()),
            s if s.starts_with('-') && s.len() > 1 && !s.starts_with("--") => {
                for c in s[1..].chars() {
                    match c {
                        'q' => quiet = true,
                        _ => {}
                    }
                }
            }
            s if s.starts_with("--") => {}
            s => urls.push(s.to_string()),
        }
        i += 1;
    }

    if urls.is_empty() {
        ctx.eprint("wget: missing URL\nUsage: wget [OPTION]... [URL]...\n");
        return 1;
    }

    let mut status = 0;
    let emit = |ctx: &mut Ctx, quiet: bool, s: &str| {
        if !quiet {
            ctx.eprint(s);
        }
    };
    for raw in &urls {
        let url = match Url::parse(raw) {
            Ok(u) => u,
            Err(e) => {
                emit(ctx, quiet, &alloc::format!("wget: {}\n", e.message()));
                status = 1;
                continue;
            }
        };
        let now = crate::time::civil::from_unix(crate::time::unix_now() as i64);
        emit(ctx, quiet, &alloc::format!("--{:04}-{:02}-{:02} {:02}:{:02}:{:02}--  {}\n", now.year, now.month, now.day, now.hour, now.min, now.sec, raw));
        let req = Request {
            method: "GET",
            url: &url,
            headers: &headers,
            body: None,
            head_only: false,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            user_agent: WGET_UA,
        };
        let (resp, final_url) = match http::fetch_follow(&req, max_redirect) {
            Ok(v) => v,
            Err(e) => {
                emit(ctx, quiet, &alloc::format!("wget: {}\n", e.message()));
                status = 4;
                continue;
            }
        };
        if resp.status >= 400 {
            emit(ctx, quiet, &alloc::format!("wget: server returned error: HTTP/1.1 {} {}\n", resp.status, resp.reason));
            status = 8;
            continue;
        }
        let ct = resp.header("content-type").unwrap_or("application/octet-stream").to_string();
        emit(ctx, quiet, &alloc::format!("HTTP request sent, awaiting response... {} {}\n", resp.status, resp.reason));
        emit(ctx, quiet, &alloc::format!("Length: {} [{}]\n", resp.body.len(), ct.split(';').next().unwrap_or(&ct)));

        if to_stdout {
            ctx.write(&resp.body);
            ctx.flush();
            continue;
        }
        let path = output.clone().unwrap_or_else(|| basename_of(&final_url));
        emit(ctx, quiet, &alloc::format!("Saving to: '{path}'\n"));
        if let Err(c) = write_out_file(ctx, &path, &resp.body) {
            status = c;
            continue;
        }
        emit(ctx, quiet, &alloc::format!("'{}' saved [{}/{}]\n", path, resp.body.len(), resp.body.len()));
    }
    status
}
