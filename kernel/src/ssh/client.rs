//! SSH client: connect to a remote sshd, authenticate (password), open a
//! session channel and exec a command. Used by the `ssh` command and by
//! outbound `scp` (which runs the remote `scp -t/-f` over the channel).
//!
//! A single background task reads packets and drives flow control; `read`/
//! `write`/`wait_exit` are simple waiters on top of it, so the same Session
//! serves both a lock-step scp transfer and an interactive two-task shell.

use super::transport::{self, RecvHalf, Sender, SshError, SResult};
use super::wire::{msg, Reader, Writer};
use crate::net::socket::TcpStream;
use crate::net::{dns, IpAddress, IpEndpoint};
use crate::sync::{SpinLock, WaitQueue};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

const LOCAL_WINDOW: u32 = 2 * 1024 * 1024;
const MAX_PKT: u32 = 32 * 1024;

pub struct Session {
    send: Arc<Sender>,
    peer_chan: SpinLock<u32>,
    send_window: SpinLock<i64>,
    send_wq: WaitQueue,
    inbuf: SpinLock<VecDeque<u8>>,
    errbuf: SpinLock<Vec<u8>>,
    data_wq: WaitQueue,
    in_eof: AtomicBool,
    closed: AtomicBool,
    exit: SpinLock<Option<i32>>,
    /// Bytes consumed since we last replenished our receive window.
    consumed: SpinLock<u32>,
    /// The server's ed25519 host key blob (for the caller to fingerprint).
    pub host_key: SpinLock<Vec<u8>>,
    session_id: SpinLock<[u8; 32]>,
}

/// How the client authenticates: an ed25519 identity (tried first) and/or a
/// password (fallback). At least one should be present.
#[derive(Default)]
pub struct Auth {
    pub key: Option<(ed25519_dalek::SigningKey, Vec<u8>)>,
    pub password: Option<String>,
}

fn proto<T>(m: &str) -> SResult<T> {
    Err(SshError::Protocol(alloc::string::String::from(m)))
}

impl Session {
    /// Connect, key-exchange, verify the host key against `expected` (if the
    /// host is already known), authenticate, and open a session.
    pub fn open(host: &str, port: u16, user: &str, auth: &Auth, expected_hostkey: Option<&[u8]>, timeout_ms: u64) -> SResult<Arc<Session>> {
        let ip = match dns::parse_ipv4(host) {
            Some(ip) => ip,
            None => *dns::resolve(host).map_err(|_| SshError::Io)?.first().ok_or(SshError::Io)?,
        };
        let stream = TcpStream::connect(IpEndpoint::new(IpAddress::Ipv4(ip), port), timeout_ms).map_err(|_| SshError::Io)?;
        let stream = Arc::new(stream);
        // Version exchange: send ours, read theirs.
        stream.write_all(alloc::format!("{}\r\n", transport::CLIENT_VERSION).as_bytes()).map_err(|_| SshError::Io)?;
        let mut recv = RecvHalf::new(stream.clone());
        let server_version = recv.read_version()?;
        let send = Sender::new(stream.clone());
        // KEXINIT exchange.
        let client_kexinit = transport::client_kexinit();
        send.send(&client_kexinit)?;
        let server_kexinit = loop {
            let p = recv.read_packet(Some(timeout_ms))?;
            match p[0] {
                msg::KEXINIT => break p,
                msg::IGNORE | msg::DEBUG => continue,
                _ => return proto("expected KEXINIT"),
            }
        };
        let (h, host_key) = transport::client_kex(transport::CLIENT_VERSION, &server_version, &client_kexinit, &server_kexinit, &mut recv, &send)?;

        // Host-key check: if we already know this host, the key must match.
        if let Some(exp) = expected_hostkey {
            if exp != host_key.as_slice() {
                let _ = send.send(&transport::disconnect_msg(transport::reasons::BY_APPLICATION, "host key mismatch"));
                return Err(SshError::Disconnected("REMOTE HOST KEY CHANGED — possible man-in-the-middle; refusing to connect".into()));
            }
        }

        let sess = Arc::new(Session {
            send,
            peer_chan: SpinLock::new(0),
            send_window: SpinLock::new(0),
            send_wq: WaitQueue::new(),
            inbuf: SpinLock::new(VecDeque::new()),
            errbuf: SpinLock::new(Vec::new()),
            data_wq: WaitQueue::new(),
            in_eof: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            exit: SpinLock::new(None),
            consumed: SpinLock::new(0),
            host_key: SpinLock::new(host_key),
            session_id: SpinLock::new(h),
        });

        // Authenticate, then open a session channel — done inline so we can
        // report failures before spawning the reader.
        sess.authenticate(&mut recv, user, auth)?;
        sess.open_channel(&mut recv)?;

        // Hand the receiver to a background pump.
        let s2 = sess.clone();
        crate::sched::spawn("ssh-client-rx", move || s2.pump(recv));
        Ok(sess)
    }

    fn authenticate(&self, recv: &mut RecvHalf, user: &str, auth: &Auth) -> SResult<()> {
        let mut sr = Writer::msg(msg::SERVICE_REQUEST);
        sr.str("ssh-userauth");
        self.send.send(&sr.done())?;
        loop {
            let p = recv.read_packet(Some(30_000))?;
            match p[0] {
                msg::SERVICE_ACCEPT => break,
                msg::IGNORE | msg::DEBUG | msg::EXT_INFO => continue,
                _ => return proto("service request rejected"),
            }
        }
        // Public key first (if we have an identity), then password.
        if let Some((sk, blob)) = &auth.key {
            if self.auth_pubkey(recv, user, sk, blob)? {
                return Ok(());
            }
        }
        if let Some(pass) = &auth.password {
            if self.auth_password(recv, user, pass)? {
                return Ok(());
            }
        }
        Err(SshError::Disconnected("authentication failed (no accepted method — check password / authorized_keys)".into()))
    }

    fn auth_password(&self, recv: &mut RecvHalf, user: &str, pass: &str) -> SResult<bool> {
        let mut a = Writer::msg(msg::USERAUTH_REQUEST);
        a.str(user).str("ssh-connection").str("password").bool(false).str(pass);
        self.send.send(&a.done())?;
        self.auth_result(recv)
    }

    fn auth_pubkey(&self, recv: &mut RecvHalf, user: &str, sk: &ed25519_dalek::SigningKey, blob: &[u8]) -> SResult<bool> {
        // The signature covers session id + the request up to the public key.
        let sid = *self.session_id.lock();
        let mut signed = Writer::new();
        signed.string(&sid).u8(msg::USERAUTH_REQUEST).str(user).str("ssh-connection").str("publickey").bool(true).str("ssh-ed25519").string(blob);
        let sig = ed25519_dalek::Signer::sign(sk, &signed.done());
        let mut sig_blob = Writer::new();
        sig_blob.str("ssh-ed25519").string(&sig.to_bytes());
        let mut a = Writer::msg(msg::USERAUTH_REQUEST);
        a.str(user).str("ssh-connection").str("publickey").bool(true).str("ssh-ed25519").string(blob).string(&sig_blob.done());
        self.send.send(&a.done())?;
        self.auth_result(recv)
    }

    /// Read the reply to an auth attempt: Ok(true)=success, Ok(false)=failure.
    fn auth_result(&self, recv: &mut RecvHalf) -> SResult<bool> {
        loop {
            let p = recv.read_packet(Some(30_000))?;
            match p[0] {
                msg::USERAUTH_SUCCESS => return Ok(true),
                msg::USERAUTH_FAILURE => return Ok(false),
                msg::USERAUTH_BANNER | msg::IGNORE | msg::DEBUG => continue,
                _ => return proto("unexpected auth reply"),
            }
        }
    }

    fn open_channel(&self, recv: &mut RecvHalf) -> SResult<()> {
        let mut o = Writer::msg(msg::CHANNEL_OPEN);
        o.str("session").u32(0).u32(LOCAL_WINDOW).u32(MAX_PKT);
        self.send.send(&o.done())?;
        loop {
            let p = recv.read_packet(Some(30_000))?;
            let mut r = Reader::new(&p);
            let t = r.u8().unwrap_or(0);
            match t {
                msg::CHANNEL_OPEN_CONFIRMATION => {
                    let _local = r.u32().map_err(|_| SshError::Io)?;
                    let peer = r.u32().map_err(|_| SshError::Io)?;
                    let win = r.u32().map_err(|_| SshError::Io)?;
                    *self.peer_chan.lock() = peer;
                    *self.send_window.lock() = win as i64;
                    return Ok(());
                }
                msg::CHANNEL_OPEN_FAILURE => return Err(SshError::Disconnected("channel open failed".into())),
                msg::IGNORE | msg::DEBUG | msg::GLOBAL_REQUEST => continue,
                _ => continue,
            }
        }
    }

    /// Request execution of `cmd` on the channel.
    pub fn exec(&self, cmd: &str) -> SResult<()> {
        let mut w = Writer::msg(msg::CHANNEL_REQUEST);
        w.u32(*self.peer_chan.lock()).str("exec").bool(false).str(cmd);
        self.send.send(&w.done())
    }

    /// Request an interactive login shell.
    pub fn shell(&self) -> SResult<()> {
        let mut w = Writer::msg(msg::CHANNEL_REQUEST);
        w.u32(*self.peer_chan.lock()).str("shell").bool(false);
        self.send.send(&w.done())
    }

    /// The background reader: process packets until the channel closes.
    fn pump(self: Arc<Session>, mut recv: RecvHalf) {
        loop {
            let p = match recv.read_packet(None) {
                Ok(p) => p,
                Err(_) => break,
            };
            let mut r = Reader::new(&p);
            let t = match r.u8() {
                Ok(t) => t,
                Err(_) => continue,
            };
            match t {
                msg::CHANNEL_DATA => {
                    let _c = r.u32();
                    if let Ok(d) = r.string() {
                        self.inbuf.lock().extend(d.iter().copied());
                        self.data_wq.wake_all();
                        self.replenish(d.len() as u32);
                    }
                }
                msg::CHANNEL_EXTENDED_DATA => {
                    let _c = r.u32();
                    let _code = r.u32();
                    if let Ok(d) = r.string() {
                        self.errbuf.lock().extend_from_slice(d);
                        self.replenish(d.len() as u32);
                    }
                }
                msg::CHANNEL_WINDOW_ADJUST => {
                    let _c = r.u32();
                    if let Ok(n) = r.u32() {
                        *self.send_window.lock() += n as i64;
                        self.send_wq.wake_all();
                    }
                }
                msg::CHANNEL_EOF => {
                    self.in_eof.store(true, Ordering::Release);
                    self.data_wq.wake_all();
                }
                msg::CHANNEL_REQUEST => {
                    let _c = r.u32();
                    if let Ok(kind) = r.string() {
                        if kind == b"exit-status" {
                            let _want = r.bool();
                            if let Ok(code) = r.u32() {
                                *self.exit.lock() = Some(code as i32);
                            }
                        }
                    }
                }
                msg::CHANNEL_CLOSE => {
                    self.closed.store(true, Ordering::Release);
                    self.in_eof.store(true, Ordering::Release);
                    self.data_wq.wake_all();
                    self.send_wq.wake_all();
                    break;
                }
                msg::DISCONNECT => break,
                _ => {}
            }
        }
        self.closed.store(true, Ordering::Release);
        self.in_eof.store(true, Ordering::Release);
        self.data_wq.wake_all();
        self.send_wq.wake_all();
    }

    /// Top up our receive window as we consume data.
    fn replenish(&self, n: u32) {
        let mut c = self.consumed.lock();
        *c += n;
        if *c >= LOCAL_WINDOW / 2 {
            let add = *c;
            *c = 0;
            drop(c);
            let mut w = Writer::msg(msg::CHANNEL_WINDOW_ADJUST);
            w.u32(*self.peer_chan.lock()).u32(add);
            let _ = self.send.send(&w.done());
        }
    }

    /// Read channel data into `buf`; `Ok(0)` at end of stream.
    pub fn read(&self, buf: &mut [u8]) -> usize {
        loop {
            {
                let mut ib = self.inbuf.lock();
                if !ib.is_empty() {
                    let n = buf.len().min(ib.len());
                    for b in buf.iter_mut().take(n) {
                        *b = ib.pop_front().unwrap();
                    }
                    return n;
                }
            }
            if self.in_eof.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
                return 0;
            }
            let _ = self.data_wq.wait_until_interruptible(
                || {
                    (!self.inbuf.lock().is_empty() || self.in_eof.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire)).then_some(())
                },
                None,
            );
        }
    }

    /// Send channel data, respecting the remote window and max packet size.
    pub fn write(&self, data: &[u8]) -> SResult<()> {
        let mut off = 0;
        while off < data.len() {
            if self.closed.load(Ordering::Acquire) {
                return Err(SshError::Closed);
            }
            // Wait for send window.
            let avail = loop {
                let w = *self.send_window.lock();
                if w > 0 || self.closed.load(Ordering::Acquire) {
                    break w;
                }
                let _ = self.send_wq.wait_until_interruptible(
                    || (*self.send_window.lock() > 0 || self.closed.load(Ordering::Acquire)).then_some(()),
                    None,
                );
            };
            if self.closed.load(Ordering::Acquire) {
                return Err(SshError::Closed);
            }
            let chunk = (data.len() - off).min(MAX_PKT as usize).min(avail.max(0) as usize);
            if chunk == 0 {
                continue;
            }
            let mut w = Writer::msg(msg::CHANNEL_DATA);
            w.u32(*self.peer_chan.lock()).string(&data[off..off + chunk]);
            self.send.send(&w.done())?;
            *self.send_window.lock() -= chunk as i64;
            off += chunk;
        }
        Ok(())
    }

    pub fn eof(&self) {
        let mut w = Writer::msg(msg::CHANNEL_EOF);
        w.u32(*self.peer_chan.lock());
        let _ = self.send.send(&w.done());
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn stderr(&self) -> Vec<u8> {
        core::mem::take(&mut *self.errbuf.lock())
    }

    /// Wait for the command to finish; returns its exit status (default 0).
    pub fn wait_exit(&self) -> i32 {
        loop {
            if let Some(c) = *self.exit.lock() {
                return c;
            }
            if self.closed.load(Ordering::Acquire) {
                return self.exit.lock().unwrap_or(0);
            }
            let _ = self.data_wq.wait_until_interruptible(
                || (self.exit.lock().is_some() || self.closed.load(Ordering::Acquire)).then_some(()),
                None,
            );
        }
    }

    /// Close the channel and disconnect.
    pub fn close(&self) {
        let mut w = Writer::msg(msg::CHANNEL_CLOSE);
        w.u32(*self.peer_chan.lock());
        let _ = self.send.send(&w.done());
        let _ = self.send.send(&transport::disconnect_msg(transport::reasons::BY_APPLICATION, "bye"));
        self.send.close();
    }
}

/// ed25519 host-key fingerprint (SHA256, base64, no padding) — `SHA256:...`.
pub fn fingerprint(host_key: &[u8]) -> String {
    super::fingerprint(host_key)
}
