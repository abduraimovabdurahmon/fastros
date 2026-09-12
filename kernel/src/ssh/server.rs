//! SSH connections: authentication (RFC 4252) and channels (RFC 4254).

use super::transport::{self, disconnect_msg, reasons, KexContext, Negotiated, RecvHalf, SResult, Sender, SshError};
use super::wire::{msg, Reader, Writer};
use super::{Config, RootPolicy};
use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File, Poll};
use crate::fs::pipe::{self, PipeEnd};
use crate::fs::{FileType, Metadata, Timespec};
use crate::net::socket::{TcpListener, TcpStream};
use crate::net::{IpAddress, IpEndpoint};
use crate::proc::fdtable::FdTable;
use crate::proc::{self, Process, Spawn};
use crate::sync::{SpinLock, WaitQueue};
use crate::tty::{Tty, TtyDriver, TtyFile, WinSize};
use crate::users::User;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const LOCAL_WINDOW: u32 = 2 * 1024 * 1024;
const LOCAL_MAX_PACKET: u32 = 32 * 1024;

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static PREAUTH: AtomicUsize = AtomicUsize::new(0);

fn peer_ip(ep: &IpEndpoint) -> [u8; 4] {
    match ep.addr {
        IpAddress::Ipv4(a) => a.octets(),
    }
}

pub fn listen() {
    let cfg = super::load_config();
    let _ = super::host_key();
    let listener = loop {
        match TcpListener::bind(cfg.port, 8) {
            Ok(l) => break l,
            Err(e) => {
                crate::kerr!("sshd", "cannot listen on port {}: {}", cfg.port, e);
                crate::sched::sleep_ms(5000);
            }
        }
    };
    crate::kinfo!("sshd", "listening on port {} ({})", cfg.port, super::fingerprint(&super::host_key().public_blob()));
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(_) => continue,
        };
        if ACTIVE.load(Ordering::Relaxed) >= cfg.max_sessions || PREAUTH.load(Ordering::Relaxed) >= cfg.max_startups {
            crate::kwarn!("sshd", "refusing connection from {}: too many connections", peer);
            stream.abort();
            continue;
        }
        let cfg = cfg.clone();
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        crate::sched::spawn("sshd-conn", move || {
            let stream = Arc::new(stream);
            let mut conn = Conn::new(stream.clone(), peer, cfg);
            let r = conn.run();
            match r {
                Ok(()) | Err(SshError::Closed) => {}
                Err(SshError::Disconnected(m)) => crate::kdebug!("sshd", "{}: {}", peer, m),
                Err(e) => crate::knotice!("sshd", "connection from {} ended: {:?}", peer, e),
            }
            conn.teardown();
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// One channel of a connection.
pub struct Channel {
    pub local_id: u32,
    remote_id: u32,
    sender: Arc<Sender>,
    /// Bytes the peer is still willing to accept.
    remote_window: SpinLock<u64>,
    window_wq: WaitQueue,
    max_packet: u32,
    closed: AtomicBool,
    eof_sent: AtomicBool,
    /// Received but not yet consumed (drives our WINDOW_ADJUST).
    consumed: AtomicU32,
    /// Echo output that did not fit the window (sent when it opens).
    backlog: SpinLock<Vec<u8>>,
    kind: SpinLock<ChanKind>,
}

enum ChanKind {
    Session(Session),
    Tcp { stream: Arc<TcpStream> },
}

#[derive(Default)]
struct Session {
    term: Option<String>,
    winsize: WinSize,
    env: Vec<(String, String)>,
    tty: Option<Arc<Tty>>,
    pts: Option<u32>,
    /// Input queue for pipe-backed sessions (drained by the stdin pump).
    inbox: Option<Arc<Inbox>>,
    process: Option<Arc<Process>>,
    started: bool,
}

struct Inbox {
    data: SpinLock<VecDeque<u8>>,
    eof: AtomicBool,
    wq: WaitQueue,
}

impl Channel {
    fn send_msg(&self, payload: &[u8]) -> KResult<()> {
        self.sender.send(payload).map_err(|_| Errno::EPIPE)
    }

    /// Send channel data, respecting the peer's window and packet size.
    /// Non-blocking callers (echo) queue what does not fit.
    pub fn send_data(&self, mut data: &[u8], ext: Option<u32>, may_block: bool) -> KResult<()> {
        if self.closed.load(Ordering::Acquire) || self.eof_sent.load(Ordering::Acquire) {
            return Err(Errno::EPIPE);
        }
        if !may_block {
            let mut bl = self.backlog.lock();
            if !bl.is_empty() {
                bl.extend_from_slice(data);
                return Ok(());
            }
        }
        while !data.is_empty() {
            let allowed = {
                let mut w = self.remote_window.lock();
                let n = (*w as usize).min(data.len()).min(self.max_packet as usize - 64);
                *w -= n as u64;
                n
            };
            if allowed == 0 {
                if !may_block {
                    self.backlog.lock().extend_from_slice(data);
                    return Ok(());
                }
                self.window_wq
                    .wait_until_interruptible(
                        || (*self.remote_window.lock() > 0 || self.closed.load(Ordering::Acquire)).then_some(()),
                        None,
                    )
                    .map_err(|_| Errno::EINTR)?;
                if self.closed.load(Ordering::Acquire) {
                    return Err(Errno::EPIPE);
                }
                continue;
            }
            let mut w = match ext {
                Some(t) => {
                    let mut w = Writer::msg(msg::CHANNEL_EXTENDED_DATA);
                    w.u32(self.remote_id).u32(t);
                    w
                }
                None => {
                    let mut w = Writer::msg(msg::CHANNEL_DATA);
                    w.u32(self.remote_id);
                    w
                }
            };
            w.string(&data[..allowed]);
            self.send_msg(&w.done())?;
            data = &data[allowed..];
        }
        Ok(())
    }

    fn add_window(&self, n: u32) {
        {
            let mut w = self.remote_window.lock();
            *w = (*w + n as u64).min(u32::MAX as u64);
        }
        self.window_wq.wake_all();
        let pending = core::mem::take(&mut *self.backlog.lock());
        if !pending.is_empty() {
            let _ = self.send_data(&pending, None, false);
        }
    }

    fn send_eof(&self) {
        if !self.eof_sent.swap(true, Ordering::AcqRel) && !self.closed.load(Ordering::Acquire) {
            let mut w = Writer::msg(msg::CHANNEL_EOF);
            w.u32(self.remote_id);
            let _ = self.send_msg(&w.done());
        }
    }

    fn send_close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let mut w = Writer::msg(msg::CHANNEL_CLOSE);
            w.u32(self.remote_id);
            let _ = self.sender.send(&w.done());
        }
        self.window_wq.wake_all();
    }

    fn send_exit_status(&self, code: i32) {
        let mut w = Writer::msg(msg::CHANNEL_REQUEST);
        w.u32(self.remote_id).str("exit-status").bool(false).u32(code as u32);
        let _ = self.send_msg(&w.done());
    }
}

/// Terminal driver writing to a channel.
struct PtyDriver {
    chan: Weak<Channel>,
}

impl TtyDriver for PtyDriver {
    fn write(&self, data: &[u8], echo: bool) -> KResult<()> {
        match self.chan.upgrade() {
            Some(c) => c.send_data(data, None, !echo),
            None => Err(Errno::EIO),
        }
    }
    fn pending(&self) -> usize {
        self.chan.upgrade().map(|c| c.backlog.lock().len()).unwrap_or(0)
    }
}

/// stdout/stderr of a pipe-backed session.
struct ChanWriter {
    chan: Arc<Channel>,
    ext: Option<u32>,
}

impl File for ChanWriter {
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        self.chan.send_data(buf, self.ext, true)?;
        Ok(buf.len())
    }
    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata {
            dev: 0,
            ino: self.chan.local_id as u64,
            kind: FileType::Fifo,
            perm: 0o600,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: 0,
            blksize: 4096,
            rdev: 0,
            atime: now,
            mtime: now,
            ctime: now,
        })
    }
    fn poll(&self) -> Poll {
        Poll::OUT
    }
    fn flags(&self) -> u32 {
        flags::O_WRONLY
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Conn {
    stream: Arc<TcpStream>,
    peer: IpEndpoint,
    cfg: Config,
    recv: RecvHalf,
    sender: Arc<Sender>,
    client_version: String,
    server_kexinit: Vec<u8>,
    session_id: Option<[u8; 32]>,
    neg: Option<Negotiated>,
    user: Option<User>,
    auth_failures: u32,
    channels: BTreeMap<u32, Arc<Channel>>,
    next_id: u32,
    preauth: bool,
}

fn truncated(_: super::wire::Truncated) -> SshError {
    SshError::Protocol("truncated message".into())
}

impl Conn {
    fn new(stream: Arc<TcpStream>, peer: IpEndpoint, cfg: Config) -> Conn {
        PREAUTH.fetch_add(1, Ordering::Relaxed);
        Conn {
            recv: RecvHalf::new(stream.clone()),
            sender: Sender::new(stream.clone()),
            stream,
            peer,
            cfg,
            client_version: String::new(),
            server_kexinit: Vec::new(),
            session_id: None,
            neg: None,
            user: None,
            auth_failures: 0,
            channels: BTreeMap::new(),
            next_id: 0,
            preauth: true,
        }
    }

    fn disconnect(&self, reason: u32, text: &str) -> SshError {
        let _ = self.sender.send_kex(&disconnect_msg(reason, text));
        SshError::Disconnected(text.to_string())
    }

    fn run(&mut self) -> SResult<()> {
        self.stream.write_all(alloc::format!("{}\r\n", transport::SERVER_VERSION).as_bytes()).map_err(|_| SshError::Io)?;
        self.client_version = self.recv.read_version()?;
        // Initial key exchange.
        self.start_kex()?;
        let first = self.recv.read_packet(Some(30_000))?;
        if first[0] != msg::KEXINIT {
            return Err(self.disconnect(reasons::PROTOCOL_ERROR, "expected KEXINIT"));
        }
        self.do_kex(first)?;
        let grace = crate::time::now_ns() + self.cfg.login_grace_secs * 1_000_000_000;
        loop {
            let timeout = if self.user.is_none() {
                let left = grace.saturating_sub(crate::time::now_ns()) / 1_000_000;
                if left == 0 {
                    return Err(self.disconnect(reasons::BY_APPLICATION, "login grace time exceeded"));
                }
                Some(left)
            } else {
                None
            };
            let p = match self.recv.read_packet(timeout) {
                Ok(p) => p,
                Err(SshError::Mac) => return Err(self.disconnect(reasons::MAC_ERROR, "message authentication failed")),
                Err(e) => return Err(e),
            };
            if !self.dispatch(p)? {
                return Ok(());
            }
        }
    }

    fn start_kex(&mut self) -> SResult<()> {
        self.server_kexinit = transport::server_kexinit();
        self.sender.lock().in_kex = true;
        self.sender.send_kex(&self.server_kexinit.clone())
    }

    /// Complete a key exchange whose client KEXINIT is `client_kexinit`
    /// (our KEXINIT has already been sent).
    fn do_kex(&mut self, client_kexinit: Vec<u8>) -> SResult<()> {
        let neg = match transport::negotiate(&client_kexinit) {
            Ok(n) => n,
            Err(SshError::Protocol(m)) => return Err(self.disconnect(reasons::KEY_EXCHANGE_FAILED, &m)),
            Err(e) => return Err(e),
        };
        let init = loop {
            let p = self.recv.read_packet(Some(30_000))?;
            match p[0] {
                msg::KEX_ECDH_INIT => break p,
                msg::IGNORE | msg::DEBUG if !(neg.strict && self.session_id.is_none()) => continue,
                msg::DISCONNECT => return Err(SshError::Disconnected("client disconnected".into())),
                _ => return Err(self.disconnect(reasons::PROTOCOL_ERROR, "unexpected message during key exchange")),
            }
        };
        let host = super::host_key();
        let ctx = KexContext { client_version: &self.client_version, client_kexinit: &client_kexinit, server_kexinit: &self.server_kexinit };
        let first = self.session_id.is_none();
        let h = transport::server_kex(&ctx, &neg, &host, self.session_id, &mut self.recv, &self.sender, &init)?;
        if first {
            self.session_id = Some(h);
        }
        self.sender.lock().in_kex = false;
        self.sender.kex_done.wake_all();
        if first && neg.ext_info {
            let mut w = Writer::msg(msg::EXT_INFO);
            w.u32(1).str("server-sig-algs").str("ssh-ed25519");
            self.sender.send(&w.done())?;
        }
        self.neg = Some(neg);
        Ok(())
    }

    /// Handle one message; false when the connection should end.
    fn dispatch(&mut self, p: Vec<u8>) -> SResult<bool> {
        let mut r = Reader::new(&p);
        let t = r.u8().map_err(truncated)?;
        match t {
            msg::DISCONNECT => return Ok(false),
            msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED | msg::EXT_INFO => {}
            msg::KEXINIT => {
                // Client-initiated re-key.
                self.start_kex()?;
                self.do_kex(p.clone())?;
            }
            msg::SERVICE_REQUEST => {
                let svc = r.utf8().map_err(truncated)?;
                if svc != "ssh-userauth" {
                    return Err(self.disconnect(reasons::SERVICE_NOT_AVAILABLE, "service not available"));
                }
                let mut w = Writer::msg(msg::SERVICE_ACCEPT);
                w.str(&svc);
                self.sender.send(&w.done())?;
            }
            msg::USERAUTH_REQUEST => self.userauth(&mut r)?,
            _ if self.user.is_none() => {
                return Err(self.disconnect(reasons::PROTOCOL_ERROR, &alloc::format!("message {t} before authentication")));
            }
            msg::GLOBAL_REQUEST => {
                let _name = r.utf8().map_err(truncated)?;
                if r.bool().map_err(truncated)? {
                    self.sender.send(&[msg::REQUEST_FAILURE])?;
                }
            }
            msg::CHANNEL_OPEN => self.channel_open(&mut r)?,
            msg::CHANNEL_REQUEST => self.channel_request(&mut r)?,
            msg::CHANNEL_DATA | msg::CHANNEL_EXTENDED_DATA => {
                let id = r.u32().map_err(truncated)?;
                if t == msg::CHANNEL_EXTENDED_DATA {
                    r.u32().map_err(truncated)?;
                }
                let data = r.string().map_err(truncated)?.to_vec();
                if let Some(c) = self.channels.get(&id).cloned() {
                    self.channel_input(&c, &data)?;
                }
            }
            msg::CHANNEL_WINDOW_ADJUST => {
                let id = r.u32().map_err(truncated)?;
                let n = r.u32().map_err(truncated)?;
                if let Some(c) = self.channels.get(&id) {
                    c.add_window(n);
                }
            }
            msg::CHANNEL_EOF => {
                let id = r.u32().map_err(truncated)?;
                if let Some(c) = self.channels.get(&id).cloned() {
                    self.channel_eof(&c);
                }
            }
            msg::CHANNEL_CLOSE => {
                let id = r.u32().map_err(truncated)?;
                if let Some(c) = self.channels.remove(&id) {
                    self.close_channel(&c);
                }
            }
            msg::CHANNEL_SUCCESS | msg::CHANNEL_FAILURE | msg::REQUEST_SUCCESS | msg::REQUEST_FAILURE => {}
            _ => {
                let seq = 0u32;
                let mut w = Writer::msg(msg::UNIMPLEMENTED);
                w.u32(seq);
                self.sender.send(&w.done())?;
            }
        }
        Ok(true)
    }

    // ── authentication ──────────────────────────────────────────────────

    fn auth_failure(&mut self, partial_methods: &str) -> SResult<()> {
        let mut w = Writer::msg(msg::USERAUTH_FAILURE);
        w.str(partial_methods).bool(false);
        self.sender.send(&w.done())
    }

    fn methods(&self) -> &'static str {
        if self.cfg.password_auth {
            "publickey,password"
        } else {
            "publickey"
        }
    }

    fn userauth(&mut self, r: &mut Reader) -> SResult<()> {
        if self.user.is_some() {
            return Ok(()); // already authenticated: ignore (RFC 4252 §5.1)
        }
        let username = r.utf8().map_err(truncated)?;
        let service = r.utf8().map_err(truncated)?;
        let method = r.utf8().map_err(truncated)?;
        if service != "ssh-connection" {
            return Err(self.disconnect(reasons::SERVICE_NOT_AVAILABLE, "service not available"));
        }
        let ip = peer_ip(&self.peer);
        let methods = self.methods();
        match method.as_str() {
            "none" => self.auth_failure(methods),
            "password" if self.cfg.password_auth => {
                let _change = r.bool().map_err(truncated)?;
                let password = r.utf8().map_err(truncated)?;
                let root_denied = username == "root" && self.cfg.permit_root != RootPolicy::Yes;
                match crate::users::authenticate(&username, &password) {
                    Ok(u) if !root_denied => self.auth_success(u, "password"),
                    _ => {
                        crate::knotice!("sshd", "Failed password for {} from {} port {}", username, self.peer.addr, self.peer.port);
                        crate::firewall::auth_failure(ip);
                        self.count_failure()?;
                        self.auth_failure(methods)
                    }
                }
            }
            "publickey" => {
                let has_sig = r.bool().map_err(truncated)?;
                let alg = r.utf8().map_err(truncated)?;
                let blob = r.string().map_err(truncated)?.to_vec();
                let user = crate::users::by_name(&username);
                let root_denied = username == "root" && self.cfg.permit_root == RootPolicy::No;
                let authorized = alg == "ssh-ed25519" && !root_denied && user.as_ref().is_some_and(|u| key_authorized(u, &blob));
                if !authorized {
                    if has_sig {
                        crate::firewall::auth_failure(ip);
                        self.count_failure()?;
                    }
                    return self.auth_failure(methods);
                }
                if !has_sig {
                    let mut w = Writer::msg(msg::USERAUTH_PK_OK);
                    w.str(&alg).string(&blob);
                    return self.sender.send(&w.done());
                }
                let sig = r.string().map_err(truncated)?.to_vec();
                let sid = self.session_id.expect("kex done");
                let mut signed = Writer::new();
                signed.string(&sid).u8(msg::USERAUTH_REQUEST).str(&username).str(&service).str("publickey").bool(true).str(&alg).string(&blob);
                if verify_ed25519(&blob, &signed.b, &sig) {
                    self.auth_success(user.expect("authorized implies user"), "publickey")
                } else {
                    crate::firewall::auth_failure(ip);
                    self.count_failure()?;
                    self.auth_failure(methods)
                }
            }
            _ => self.auth_failure(methods),
        }
    }

    fn count_failure(&mut self) -> SResult<()> {
        self.auth_failures += 1;
        if self.auth_failures >= self.cfg.max_auth_tries {
            return Err(self.disconnect(reasons::NO_MORE_AUTH_METHODS, "too many authentication failures"));
        }
        Ok(())
    }

    fn auth_success(&mut self, u: User, how: &str) -> SResult<()> {
        crate::kinfo!("sshd", "Accepted {} for {} from {} port {}", how, u.name, self.peer.addr, self.peer.port);
        crate::firewall::auth_success(peer_ip(&self.peer));
        self.user = Some(u);
        if self.preauth {
            self.preauth = false;
            PREAUTH.fetch_sub(1, Ordering::Relaxed);
        }
        self.sender.send(&[msg::USERAUTH_SUCCESS])
    }

    // ── channels ────────────────────────────────────────────────────────

    fn open_failure(&self, remote: u32, reason: u32, text: &str) -> SResult<()> {
        let mut w = Writer::msg(msg::CHANNEL_OPEN_FAILURE);
        w.u32(remote).u32(reason).str(text).str("");
        self.sender.send(&w.done())
    }

    fn channel_open(&mut self, r: &mut Reader) -> SResult<()> {
        let kind = r.utf8().map_err(truncated)?;
        let remote = r.u32().map_err(truncated)?;
        let window = r.u32().map_err(truncated)?;
        let max_packet = r.u32().map_err(truncated)?.clamp(256, 256 * 1024);
        let chan_kind = match kind.as_str() {
            "session" => ChanKind::Session(Session::default()),
            "direct-tcpip" if self.cfg.allow_tcp_forwarding => {
                let host = r.utf8().map_err(truncated)?;
                let port = r.u32().map_err(truncated)? as u16;
                let target = crate::net::dns::first(&host);
                let stream = match target.and_then(|ip| TcpStream::connect(IpEndpoint::new(IpAddress::Ipv4(ip), port), 10_000)) {
                    Ok(s) => Arc::new(s),
                    Err(e) => return self.open_failure(remote, 2, &alloc::format!("{host}:{port}: {e}")),
                };
                ChanKind::Tcp { stream }
            }
            _ => return self.open_failure(remote, 3, "unknown channel type"),
        };
        if self.channels.len() >= 16 {
            return self.open_failure(remote, 4, "too many channels");
        }
        let id = self.next_id;
        self.next_id += 1;
        let chan = Arc::new(Channel {
            local_id: id,
            remote_id: remote,
            sender: self.sender.clone(),
            remote_window: SpinLock::new(window as u64),
            window_wq: WaitQueue::new(),
            max_packet,
            closed: AtomicBool::new(false),
            eof_sent: AtomicBool::new(false),
            consumed: AtomicU32::new(0),
            backlog: SpinLock::new(Vec::new()),
            kind: SpinLock::new(chan_kind),
        });
        let mut w = Writer::msg(msg::CHANNEL_OPEN_CONFIRMATION);
        w.u32(remote).u32(id).u32(LOCAL_WINDOW).u32(LOCAL_MAX_PACKET);
        self.sender.send(&w.done())?;
        let tcp = match &*chan.kind.lock() {
            ChanKind::Tcp { stream } => Some(stream.clone()),
            _ => None,
        };
        if let Some(stream) = tcp {
            let c = chan.clone();
            crate::sched::spawn("sshd-fwd", move || {
                let mut buf = alloc::vec![0u8; 16384];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if c.send_data(&buf[..n], None, true).is_err() {
                                break;
                            }
                        }
                    }
                }
                c.send_eof();
                c.send_close();
            });
        }
        self.channels.insert(id, chan);
        Ok(())
    }

    fn channel_input(&mut self, c: &Arc<Channel>, data: &[u8]) -> SResult<()> {
        match Self::parts(c) {
            (Some(tty), _, _, _) => tty.receive(data),
            (None, Some(inbox), _, _) => {
                inbox.data.lock().extend(data.iter().copied());
                inbox.wq.wake_all();
            }
            (None, None, _, Some(stream)) => {
                let _ = stream.write_all(data);
            }
            _ => {}
        }
        let used = c.consumed.fetch_add(data.len() as u32, Ordering::AcqRel) + data.len() as u32;
        if used >= LOCAL_WINDOW / 2 {
            c.consumed.store(0, Ordering::Release);
            let mut w = Writer::msg(msg::CHANNEL_WINDOW_ADJUST);
            w.u32(c.remote_id).u32(used);
            self.sender.send(&w.done())?;
        }
        Ok(())
    }

    /// (tty, inbox, process, tcp stream) of a channel, copied out of its
    /// lock so that nothing that may sleep runs while it is held.
    fn parts(c: &Channel) -> (Option<Arc<Tty>>, Option<Arc<Inbox>>, Option<Arc<Process>>, Option<Arc<TcpStream>>) {
        match &*c.kind.lock() {
            ChanKind::Session(s) => (s.tty.clone(), s.inbox.clone(), s.process.clone(), None),
            ChanKind::Tcp { stream } => (None, None, None, Some(stream.clone())),
        }
    }

    fn channel_eof(&mut self, c: &Arc<Channel>) {
        let (tty, inbox, _, tcp) = Self::parts(c);
        if let Some(inbox) = inbox {
            inbox.eof.store(true, Ordering::Release);
            inbox.wq.wake_all();
        }
        if let Some(t) = tty {
            // ^D on the terminal = EOF for whoever reads it.
            let eof = t.termios().cc[crate::tty::consts::VEOF];
            t.receive(&[eof]);
        }
        if let Some(s) = tcp {
            s.shutdown();
        }
    }

    fn close_channel(&mut self, c: &Arc<Channel>) {
        c.send_close();
        let (tty, inbox, process, tcp) = Self::parts(c);
        if let Some(t) = tty {
            t.hangup();
        }
        if let Some(inbox) = inbox {
            inbox.eof.store(true, Ordering::Release);
            inbox.wq.wake_all();
        }
        if let Some(p) = process {
            if !p.is_zombie() {
                p.signal(proc::signal::SIGHUP);
            }
        }
        if let Some(s) = tcp {
            s.abort();
        }
    }

    fn channel_request(&mut self, r: &mut Reader) -> SResult<()> {
        let id = r.u32().map_err(truncated)?;
        let req = r.utf8().map_err(truncated)?;
        let want_reply = r.bool().map_err(truncated)?;
        let Some(c) = self.channels.get(&id).cloned() else { return Ok(()) };
        let ok = match req.as_str() {
            "pty-req" => {
                let term = r.utf8().map_err(truncated)?;
                let cols = r.u32().map_err(truncated)?;
                let rows = r.u32().map_err(truncated)?;
                let xp = r.u32().map_err(truncated)?;
                let yp = r.u32().map_err(truncated)?;
                if let ChanKind::Session(s) = &mut *c.kind.lock() {
                    s.term = Some(term);
                    s.winsize = WinSize { rows: rows.min(1000) as u16, cols: cols.min(1000) as u16, xpixel: xp as u16, ypixel: yp as u16 };
                    true
                } else {
                    false
                }
            }
            "env" => {
                let k = r.utf8().map_err(truncated)?;
                let v = r.utf8().map_err(truncated)?;
                // Only harmless variables (like OpenSSH's AcceptEnv LANG LC_*).
                let ok = k == "LANG" || k.starts_with("LC_") || k == "TZ" || k == "COLORTERM";
                if ok {
                    if let ChanKind::Session(s) = &mut *c.kind.lock() {
                        s.env.push((k, v));
                    }
                }
                ok
            }
            "window-change" => {
                let cols = r.u32().map_err(truncated)?;
                let rows = r.u32().map_err(truncated)?;
                if let ChanKind::Session(s) = &mut *c.kind.lock() {
                    s.winsize.cols = cols.min(1000) as u16;
                    s.winsize.rows = rows.min(1000) as u16;
                    if let Some(t) = &s.tty {
                        t.set_winsize(s.winsize);
                    }
                }
                true
            }
            "signal" => {
                let name = r.utf8().map_err(truncated)?;
                if let ChanKind::Session(s) = &*c.kind.lock() {
                    if let (Some(p), Some(sig)) = (&s.process, proc::signal::parse(&name)) {
                        let _ = proc::kill(&proc::kernel(), -(p.pgid.load(Ordering::Relaxed) as i64), sig);
                    }
                }
                true
            }
            "shell" => self.start_session(&c, None),
            "exec" => {
                let cmd = r.utf8().map_err(truncated)?;
                self.start_session(&c, Some(cmd))
            }
            "subsystem" => false,
            _ => false,
        };
        if want_reply {
            let mut w = Writer::msg(if ok { msg::CHANNEL_SUCCESS } else { msg::CHANNEL_FAILURE });
            w.u32(c.remote_id);
            self.sender.send(&w.done())?;
        }
        Ok(())
    }

    fn start_session(&mut self, c: &Arc<Channel>, command: Option<String>) -> bool {
        let Some(user) = self.user.clone() else { return false };
        // Reading /etc/group may sleep: do it before taking the channel lock.
        let cred = crate::users::cred_for(&user);
        let (term, winsize, extra_env) = {
            let mut k = c.kind.lock();
            let ChanKind::Session(s) = &mut *k else { return false };
            if s.started {
                return false;
            }
            s.started = true;
            (s.term.clone(), s.winsize, s.env.clone())
        };
        let kernel = proc::kernel();
        let mut fds = FdTable::new();
        let mut env: Vec<(String, String)> = alloc::vec![
            (String::from("PATH"), String::from("/bin:/usr/local/bin")),
            (String::from("HOME"), user.home.clone()),
            (String::from("USER"), user.name.clone()),
            (String::from("LOGNAME"), user.name.clone()),
            (String::from("SHELL"), String::from("/bin/sh")),
        ];
        let local = self.stream.local();
        let conn = alloc::format!(
            "{} {} {} {}",
            self.peer.addr,
            self.peer.port,
            local.map(|l| l.addr.to_string()).unwrap_or_default(),
            local.map(|l| l.port).unwrap_or(22)
        );
        env.push((String::from("SSH_CONNECTION"), conn));
        env.push((String::from("SSH_CLIENT"), alloc::format!("{} {} 22", self.peer.addr, self.peer.port)));
        env.extend(extra_env);
        let mut tty_for_proc = None;
        let mut pts = None;
        let mut inbox_for_chan = None;
        if let Some(term) = term {
            let driver = Arc::new(PtyDriver { chan: Arc::downgrade(c) });
            let ws = if winsize.cols == 0 { WinSize { rows: 24, cols: 80, xpixel: 0, ypixel: 0 } } else { winsize };
            let (n, tty) = crate::tty::alloc_pty(driver, ws);
            crate::fs::devfs::add_pts(n, user.uid);
            let f: Arc<dyn File> = TtyFile::new(tty.clone(), flags::O_RDWR);
            fds.set(0, f.clone(), false);
            fds.set(1, f.clone(), false);
            fds.set(2, f, false);
            env.push((String::from("TERM"), term));
            env.push((String::from("SSH_TTY"), alloc::format!("/dev/pts/{n}")));
            pts = Some(n);
            tty_for_proc = Some(tty);
        } else {
            let (rd, wr) = pipe::pipe();
            let inbox = Arc::new(Inbox { data: SpinLock::new(VecDeque::new()), eof: AtomicBool::new(false), wq: WaitQueue::new() });
            inbox_for_chan = Some(inbox.clone());
            spawn_stdin_pump(inbox, wr);
            fds.set(0, rd, false);
            fds.set(1, Arc::new(ChanWriter { chan: c.clone(), ext: None }), false);
            fds.set(2, Arc::new(ChanWriter { chan: c.clone(), ext: Some(1) }), false);
        }
        let root = kernel.fs.lock().clone();
        let spawn = Spawn {
            name: String::from(if command.is_some() { "sh" } else { "-sh" }),
            args: match &command {
                Some(cmd) => alloc::vec![String::from("sh"), String::from("-c"), cmd.clone()],
                None => alloc::vec![String::from("-sh")],
            },
            env,
            cred,
            fs: root,
            fds,
            parent: kernel.clone(),
            pgid: None,
            new_session: true,
            ctty: tty_for_proc.clone(),
            uts: kernel.uts.clone(),
            container: None,
            aspace: None,
            ignored: 0,
            vfork: false,
        };
        let interactive = command.is_none() && tty_for_proc.is_some();
        let u2 = user.clone();
        let result = proc::spawn(spawn, move || match command {
            Some(cmd) => crate::shell::command_main(cmd, u2),
            None if interactive => crate::shell::login_shell_main(u2),
            None => {
                // `ssh -T host`: commands on stdin, no prompt.
                let me = proc::current();
                let mut data = Vec::new();
                if let Ok(f) = me.fds.lock().get(0) {
                    let _ = f.read_to_end(&mut data);
                }
                crate::shell::command_main(String::from_utf8_lossy(&data).into_owned(), u2)
            }
        });
        let p = match result {
            Ok(p) => p,
            Err(_) => return false,
        };
        if let Some(t) = &tty_for_proc {
            t.set_session(p.pid);
            t.set_fg_pgrp(p.pid);
        }
        if let ChanKind::Session(s) = &mut *c.kind.lock() {
            s.tty = tty_for_proc.clone();
            s.pts = pts;
            s.inbox = inbox_for_chan;
            s.process = Some(p.clone());
        }
        if let (Some(n), true) = (pts, interactive) {
            crate::utmp::login(crate::utmp::Session {
                user: user.name.clone(),
                tty: alloc::format!("pts/{n}"),
                from: self.peer.addr.to_string(),
                login_unix: crate::time::unix_now(),
                pid: p.pid,
            });
        }
        // Report the exit status and close the channel when the process ends.
        let chan = c.clone();
        let task = p.tasks().into_iter().next();
        crate::sched::spawn("sshd-wait", move || {
            let code = task.map(|t| t.join()).unwrap_or(0);
            crate::utmp::logout(p.pid);
            chan.send_exit_status(code);
            chan.send_eof();
            chan.send_close();
            if let Some(n) = pts {
                crate::fs::devfs::remove_pts(n);
            }
        });
        true
    }

    fn teardown(&mut self) {
        let chans: Vec<Arc<Channel>> = self.channels.values().cloned().collect();
        for c in chans {
            self.close_channel(&c);
        }
        self.channels.clear();
        self.sender.close();
        self.stream.shutdown();
        if self.preauth {
            self.preauth = false;
            PREAUTH.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Feed queued channel input into a session's stdin pipe (may block on a
/// full pipe without stalling the connection).
fn spawn_stdin_pump(inbox: Arc<Inbox>, wr: Arc<PipeEnd>) {
    crate::sched::spawn("sshd-stdin", move || loop {
        let chunk: Option<Vec<u8>> = inbox.wq.wait_until(|| {
            let mut d = inbox.data.lock();
            if !d.is_empty() {
                let n = d.len().min(16384);
                return Some(Some(d.drain(..n).collect()));
            }
            inbox.eof.load(Ordering::Acquire).then_some(None)
        });
        match chunk {
            Some(c) => {
                if (wr.as_ref() as &dyn File).write_all(&c).is_err() {
                    return;
                }
            }
            None => return, // EOF: dropping `wr` closes the pipe
        }
    });
}

fn verify_ed25519(blob: &[u8], data: &[u8], sig_blob: &[u8]) -> bool {
    let mut r = Reader::new(blob);
    let (Ok(alg), Ok(pk)) = (r.utf8(), r.string()) else { return false };
    let mut s = Reader::new(sig_blob);
    let (Ok(salg), Ok(sig)) = (s.utf8(), s.string()) else { return false };
    if alg != "ssh-ed25519" || salg != "ssh-ed25519" || pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    let (Ok(pk32), Ok(sig64)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sig)) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk32) else { return false };
    vk.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&sig64)).is_ok()
}

/// Is `blob` listed in the user's `~/.ssh/authorized_keys`?
fn key_authorized(u: &User, blob: &[u8]) -> bool {
    let ctx = crate::fs::ops::Ctx::of(&proc::kernel());
    let path = alloc::format!("{}/.ssh/authorized_keys", u.home);
    let Ok(data) = crate::fs::ops::read_file(&ctx, &path) else { return false };
    // Refuse keys files others can write (like OpenSSH StrictModes).
    if let Ok(m) = crate::fs::ops::stat(&ctx, &path, true) {
        if m.perm & 0o022 != 0 || (m.uid != u.uid && m.uid != 0) {
            crate::kwarn!("sshd", "ignoring {}: bad ownership or modes", path);
            return false;
        }
    }
    for line in String::from_utf8_lossy(&data).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_whitespace();
        let Some(mut first) = f.next() else { continue };
        if !first.starts_with("ssh-") {
            // Options prefix (e.g. `no-pty ssh-ed25519 AAAA...`).
            match f.next() {
                Some(k) => first = k,
                None => continue,
            }
        }
        if first != "ssh-ed25519" {
            continue;
        }
        if let Some(b64) = f.next() {
            if fastros_codec::base64::decode(b64).is_some_and(|k| k == blob) {
                return true;
            }
        }
    }
    false
}
