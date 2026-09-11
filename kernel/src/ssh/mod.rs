//! SSH server (`sshd`).

pub mod server;
pub mod transport;
pub mod wire;

use crate::fs::ops::{self, Ctx};
use crate::sync::{Once, SpinLock};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use fastros_codec::{base64, hex};
use transport::HostKey;

pub const HOST_KEY_PATH: &str = "/etc/ssh/ssh_host_ed25519_key";
pub const CONFIG_PATH: &str = "/etc/ssh/sshd_config";

static HOST_KEY: Once<Arc<HostKey>> = Once::new();

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub permit_root: RootPolicy,
    pub password_auth: bool,
    pub max_auth_tries: u32,
    pub login_grace_secs: u64,
    pub max_sessions: usize,
    pub max_startups: usize,
    pub allow_tcp_forwarding: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootPolicy {
    Yes,
    No,
    ProhibitPassword,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: 22,
            permit_root: RootPolicy::Yes,
            password_auth: true,
            max_auth_tries: 6,
            login_grace_secs: 60,
            max_sessions: 32,
            max_startups: 10,
            allow_tcp_forwarding: true,
        }
    }
}

const DEFAULT_CONFIG: &str = "# FastROS sshd configuration\n\
Port 22\n\
# yes | no | prohibit-password (keys only)\n\
PermitRootLogin yes\n\
PasswordAuthentication yes\n\
MaxAuthTries 6\n\
LoginGraceTime 60\n\
MaxSessions 32\n\
MaxStartups 10\n\
AllowTcpForwarding yes\n";

pub fn load_config() -> Config {
    let ctx = Ctx::of(&crate::proc::kernel());
    if !ops::exists(&ctx, CONFIG_PATH) {
        let _ = ops::write_file(&ctx, CONFIG_PATH, DEFAULT_CONFIG.as_bytes(), 0o644);
    }
    let mut c = Config::default();
    let Ok(data) = ops::read_file(&ctx, CONFIG_PATH) else { return c };
    for line in String::from_utf8_lossy(&data).lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut f = line.split_whitespace();
        let (Some(k), Some(v)) = (f.next(), f.next()) else { continue };
        let yes = v.eq_ignore_ascii_case("yes");
        match k.to_ascii_lowercase().as_str() {
            "port" => c.port = v.parse().unwrap_or(22),
            "permitrootlogin" => {
                c.permit_root = match v {
                    "no" => RootPolicy::No,
                    "prohibit-password" | "without-password" => RootPolicy::ProhibitPassword,
                    _ => RootPolicy::Yes,
                }
            }
            "passwordauthentication" => c.password_auth = yes,
            "maxauthtries" => c.max_auth_tries = v.parse().unwrap_or(6).clamp(1, 20),
            "logingracetime" => c.login_grace_secs = v.parse().unwrap_or(60).clamp(5, 600),
            "maxsessions" => c.max_sessions = v.parse().unwrap_or(32).clamp(1, 256),
            "maxstartups" => c.max_startups = v.parse().unwrap_or(10).clamp(1, 100),
            "allowtcpforwarding" => c.allow_tcp_forwarding = yes,
            _ => {}
        }
    }
    c
}

/// Load the host key, generating (and persisting) one on first boot.
pub fn host_key() -> Arc<HostKey> {
    HOST_KEY
        .call_once(|| {
            let ctx = Ctx::of(&crate::proc::kernel());
            let existing = ops::read_file(&ctx, HOST_KEY_PATH).ok().and_then(|d| {
                let s = String::from_utf8_lossy(&d).to_string();
                let h = s.lines().find_map(|l| l.strip_prefix("fastros-ed25519-seed "))?.trim().to_string();
                let b = hex::decode(&h)?;
                <[u8; 32]>::try_from(b.as_slice()).ok()
            });
            let seed = match existing {
                Some(s) => s,
                None => {
                    let seed: [u8; 32] = crate::crypto::rng::array();
                    let text = alloc::format!("# FastROS SSH host key (keep secret)\nfastros-ed25519-seed {}\n", hex::encode(&seed));
                    let _ = ops::write_file(&ctx, HOST_KEY_PATH, text.as_bytes(), 0o600);
                    let _ = ops::chmod(&ctx, HOST_KEY_PATH, 0o600, true);
                    let key = HostKey { signing: ed25519_dalek::SigningKey::from_bytes(&seed) };
                    let pubtxt = alloc::format!("ssh-ed25519 {} root@fastros\n", base64::encode(&key.public_blob()));
                    let _ = ops::write_file(&ctx, &alloc::format!("{HOST_KEY_PATH}.pub"), pubtxt.as_bytes(), 0o644);
                    crate::knotice!("sshd", "generated a new ed25519 host key");
                    seed
                }
            };
            Arc::new(HostKey { signing: ed25519_dalek::SigningKey::from_bytes(&seed) })
        })
        .clone()
}

/// SHA256 fingerprint as OpenSSH prints it.
pub fn fingerprint(blob: &[u8]) -> String {
    let d = crate::crypto::sha256(blob);
    alloc::format!("SHA256:{}", base64::encode_nopad(&d))
}

/// A logged-in session (for `who`, `w`, `users`).
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub user: String,
    pub tty: String,
    pub from: String,
    pub login_unix: u64,
    pub pid: u32,
}

static SESSIONS: SpinLock<Vec<SessionInfo>> = SpinLock::new(Vec::new());

pub fn register_session(s: SessionInfo) {
    SESSIONS.lock().push(s);
}

pub fn unregister_session(pid: u32) {
    SESSIONS.lock().retain(|s| s.pid != pid);
}

pub fn sessions() -> Vec<SessionInfo> {
    let mut v = SESSIONS.lock().clone();
    v.retain(|s| crate::proc::find(s.pid).is_some_and(|p| !p.is_zombie()));
    v
}

/// Start the listener task.
pub fn start() {
    crate::sched::spawn("sshd", server::listen);
}
