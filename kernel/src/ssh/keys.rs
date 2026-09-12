//! ed25519 key handling for the SSH client: the public-key blob, parsing an
//! unencrypted OpenSSH private key (`id_ed25519`), and generating a new pair
//! (`ssh-keygen`). Encrypted private keys are not supported.

use super::wire::{Reader, Writer};
use crate::crypto::rng;
use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::SigningKey;
use fastros_codec::base64;

const MAGIC: &[u8] = b"openssh-key-v1\0";

/// The `ssh-ed25519` public-key blob: string(alg) + string(32-byte key).
pub fn public_blob(sk: &SigningKey) -> Vec<u8> {
    let mut w = Writer::new();
    w.str("ssh-ed25519").string(sk.verifying_key().as_bytes());
    w.done()
}

/// One-line authorized_keys / .pub form: `ssh-ed25519 <base64> [comment]`.
pub fn public_line(sk: &SigningKey, comment: &str) -> String {
    alloc::format!("ssh-ed25519 {} {}\n", base64::encode(&public_blob(sk)), comment)
}

/// Parse an unencrypted OpenSSH ed25519 private key (PEM-armored).
pub fn parse_openssh_ed25519(pem: &str) -> Option<(SigningKey, Vec<u8>)> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----") && !l.is_empty()).collect();
    let raw = base64::decode(&b64)?;
    if !raw.starts_with(MAGIC) {
        return None;
    }
    let mut r = Reader::new(&raw[MAGIC.len()..]);
    let cipher = r.utf8().ok()?;
    let kdf = r.utf8().ok()?;
    let _kdfopts = r.string().ok()?;
    let nkeys = r.u32().ok()?;
    if cipher != "none" || kdf != "none" || nkeys != 1 {
        return None; // encrypted or multi-key: unsupported
    }
    let _pub = r.string().ok()?;
    let priv_section = r.string().ok()?;
    let mut pr = Reader::new(priv_section);
    let c1 = pr.u32().ok()?;
    let c2 = pr.u32().ok()?;
    if c1 != c2 {
        return None;
    }
    let ktype = pr.utf8().ok()?;
    if ktype != "ssh-ed25519" {
        return None;
    }
    let pubk = pr.string().ok()?;
    let privk = pr.string().ok()?;
    if privk.len() != 64 || pubk.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&privk[..32]);
    let sk = SigningKey::from_bytes(&seed);
    let mut w = Writer::new();
    w.str("ssh-ed25519").string(pubk);
    Some((sk, w.done()))
}

/// Serialize a signing key as an unencrypted OpenSSH private key (PEM).
pub fn to_openssh_pem(sk: &SigningKey, comment: &str) -> String {
    let pk = sk.verifying_key().to_bytes();
    let pubblob = public_blob(sk);
    // 64-byte private = seed(32) || public(32).
    let mut privkey = Vec::with_capacity(64);
    privkey.extend_from_slice(&sk.to_bytes());
    privkey.extend_from_slice(&pk);

    let check: u32 = rng::u32();
    let mut inner = Writer::new();
    inner.u32(check).u32(check);
    inner.str("ssh-ed25519").string(&pk).string(&privkey).str(comment);
    // Pad to an 8-byte boundary with 1,2,3,...
    let mut body = inner.done();
    let mut pad = 1u8;
    while body.len() % 8 != 0 {
        body.push(pad);
        pad += 1;
    }

    let mut w = Writer::new();
    w.raw(MAGIC);
    w.str("none").str("none").string(&[]);
    w.u32(1);
    w.string(&pubblob);
    w.string(&body);
    let blob = w.done();

    let b64 = base64::encode(&blob);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(core::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out
}

/// Generate a fresh ed25519 signing key.
pub fn generate() -> SigningKey {
    SigningKey::from_bytes(&rng::array::<32>())
}
