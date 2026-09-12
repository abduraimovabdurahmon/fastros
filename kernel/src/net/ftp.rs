//! A minimal FTP client (RFC 959) over [`crate::net::socket::TcpStream`], used
//! by the `ftp` shell command. Passive mode only (the client always opens the
//! data connection), which is what works from behind NAT and matches how real
//! clients default today. Binary transfers (`TYPE I`).

use super::dns;
use super::socket::TcpStream;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, IpEndpoint};

pub enum FtpError {
    Dns,
    Connect,
    Io,
    /// An unexpected reply: (code, text).
    Reply(u16, String),
    BadUrl,
}

impl FtpError {
    pub fn message(&self) -> String {
        match self {
            FtpError::Dns => "could not resolve host".to_string(),
            FtpError::Connect => "could not connect".to_string(),
            FtpError::Io => "connection error".to_string(),
            FtpError::Reply(c, t) => alloc::format!("server replied {c}: {}", t.trim()),
            FtpError::BadUrl => "malformed ftp:// URL".to_string(),
        }
    }
}

type R<T> = Result<T, FtpError>;

/// A parsed `ftp://[user[:pass]@]host[:port]/path` URL.
pub struct Url {
    pub user: String,
    pub pass: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> R<Url> {
        let rest = s.strip_prefix("ftp://").ok_or(FtpError::BadUrl)?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (creds, hostport) = match authority.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, authority),
        };
        let (user, pass) = match creds {
            Some(c) => match c.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (c.to_string(), String::new()),
            },
            None => ("anonymous".to_string(), "anonymous@fastros".to_string()),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => (h.to_string(), p.parse().map_err(|_| FtpError::BadUrl)?),
            _ => (hostport.to_string(), 21),
        };
        if host.is_empty() {
            return Err(FtpError::BadUrl);
        }
        Ok(Url { user, pass, host, port, path: path.to_string() })
    }
}

fn resolve(host: &str) -> R<IpAddress> {
    let ip = match dns::parse_ipv4(host) {
        Some(ip) => ip,
        None => *dns::resolve(host).map_err(|_| FtpError::Dns)?.first().ok_or(FtpError::Dns)?,
    };
    Ok(IpAddress::Ipv4(ip))
}

pub struct Ftp {
    ctrl: TcpStream,
    buf: Vec<u8>,
    host_ip: IpAddress,
    timeout: u64,
}

impl Ftp {
    pub fn connect(host: &str, port: u16, timeout_ms: u64) -> R<Ftp> {
        let ip = resolve(host)?;
        let ctrl = TcpStream::connect(IpEndpoint::new(ip, port), timeout_ms).map_err(|_| FtpError::Connect)?;
        let mut f = Ftp { ctrl, buf: Vec::new(), host_ip: ip, timeout: timeout_ms };
        let (code, text) = f.response()?; // greeting
        if code / 100 != 2 {
            return Err(FtpError::Reply(code, text));
        }
        Ok(f)
    }

    /// One CRLF-terminated line from the control connection.
    fn read_line(&mut self) -> R<String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop(); // \n
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(String::from_utf8_lossy(&line).into_owned());
            }
            let mut tmp = [0u8; 512];
            let n = self.ctrl.read_timeout(&mut tmp, Some(self.timeout)).map_err(|_| FtpError::Io)?;
            if n == 0 {
                return Err(FtpError::Io);
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    /// A full reply, joining continuation lines ("nnn-..." until "nnn ...").
    fn response(&mut self) -> R<(u16, String)> {
        let first = self.read_line()?;
        let code: u16 = first.get(..3).and_then(|c| c.parse().ok()).ok_or(FtpError::Io)?;
        let mut text = first.get(4..).unwrap_or("").to_string();
        // Multi-line: first line has a '-' at index 3; final line is "nnn ".
        if first.as_bytes().get(3) == Some(&b'-') {
            loop {
                let line = self.read_line()?;
                let done = line.len() >= 4
                    && line.as_bytes()[..3].iter().all(|b| b.is_ascii_digit())
                    && line.as_bytes()[3] == b' ';
                text.push('\n');
                text.push_str(&line);
                if done {
                    break;
                }
            }
        }
        Ok((code, text))
    }

    pub fn cmd(&mut self, line: &str) -> R<(u16, String)> {
        let mut wire = String::with_capacity(line.len() + 2);
        wire.push_str(line);
        wire.push_str("\r\n");
        self.ctrl.write_all(wire.as_bytes()).map_err(|_| FtpError::Io)?;
        self.response()
    }

    fn expect(&mut self, line: &str, class: u16) -> R<(u16, String)> {
        let (code, text) = self.cmd(line)?;
        if code / 100 != class {
            return Err(FtpError::Reply(code, text));
        }
        Ok((code, text))
    }

    pub fn login(&mut self, user: &str, pass: &str) -> R<()> {
        let (code, text) = self.cmd(&alloc::format!("USER {user}"))?;
        match code {
            230 => {} // no password needed
            331 => {
                let (c2, t2) = self.cmd(&alloc::format!("PASS {pass}"))?;
                if c2 / 100 != 2 {
                    return Err(FtpError::Reply(c2, t2));
                }
            }
            _ => return Err(FtpError::Reply(code, text)),
        }
        self.expect("TYPE I", 2)?; // binary
        Ok(())
    }

    /// Enter passive mode and open the data connection.
    fn data_conn(&mut self) -> R<TcpStream> {
        let (_c, text) = self.expect("PASV", 2)?;
        // "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)."
        let open = text.find('(').ok_or(FtpError::Io)?;
        let close = text[open..].find(')').ok_or(FtpError::Io)? + open;
        let nums: Vec<u16> = text[open + 1..close].split(',').filter_map(|s| s.trim().parse().ok()).collect();
        if nums.len() != 6 {
            return Err(FtpError::Io);
        }
        let port = (nums[4] << 8) | nums[5];
        // Some servers report 0.0.0.0 in PASV; fall back to the control host IP.
        let ip = if nums[0] == 0 {
            self.host_ip
        } else {
            IpAddress::v4(nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8)
        };
        TcpStream::connect(IpEndpoint::new(ip, port), self.timeout).map_err(|_| FtpError::Connect)
    }

    /// Read a whole data transfer (LIST/NLST/RETR) to EOF.
    fn recv_all(&mut self, data: TcpStream) -> R<Vec<u8>> {
        let mut out = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = data.read_timeout(&mut tmp, Some(self.timeout)).map_err(|_| FtpError::Io)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        data.shutdown();
        let (code, text) = self.response()?; // 226 transfer complete
        if code / 100 != 2 {
            return Err(FtpError::Reply(code, text));
        }
        Ok(out)
    }

    pub fn list(&mut self, path: &str) -> R<Vec<u8>> {
        let data = self.data_conn()?;
        let cmd = if path.is_empty() { "LIST".to_string() } else { alloc::format!("LIST {path}") };
        let (code, text) = self.cmd(&cmd)?;
        if code / 100 != 1 {
            return Err(FtpError::Reply(code, text));
        }
        self.recv_all(data)
    }

    pub fn retr(&mut self, path: &str) -> R<Vec<u8>> {
        let data = self.data_conn()?;
        let (code, text) = self.cmd(&alloc::format!("RETR {path}"))?;
        if code / 100 != 1 {
            return Err(FtpError::Reply(code, text));
        }
        self.recv_all(data)
    }

    pub fn stor(&mut self, path: &str, bytes: &[u8]) -> R<()> {
        let data = self.data_conn()?;
        let (code, text) = self.cmd(&alloc::format!("STOR {path}"))?;
        if code / 100 != 1 {
            return Err(FtpError::Reply(code, text));
        }
        data.write_all(bytes).map_err(|_| FtpError::Io)?;
        data.shutdown();
        let (c2, t2) = self.response()?; // 226
        if c2 / 100 != 2 {
            return Err(FtpError::Reply(c2, t2));
        }
        Ok(())
    }

    pub fn cwd(&mut self, path: &str) -> R<()> {
        self.expect(&alloc::format!("CWD {path}"), 2).map(|_| ())
    }

    pub fn pwd(&mut self) -> R<String> {
        let (_c, text) = self.expect("PWD", 2)?;
        Ok(text.trim().to_string())
    }

    pub fn quit(&mut self) {
        let _ = self.cmd("QUIT");
        self.ctrl.shutdown();
    }
}
