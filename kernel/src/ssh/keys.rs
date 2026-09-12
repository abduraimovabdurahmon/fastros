//! ed25519 key handling for the SSH client: the public-key blob, parsing an
//! unencrypted OpenSSH private key (`id_ed25519`), and generating a new pair
//! (`ssh-keygen`). Encrypted private keys are not supported.

use super::wire::{Reader, Writer};
use crate::crypto::rng;
use aes::{Aes128, Aes192, Aes256};
use alloc::string::String;
use alloc::vec::Vec;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use ed25519_dalek::SigningKey;
use fastros_codec::base64;

const MAGIC: &[u8] = b"openssh-key-v1\0";

/// Why parsing a private key failed — lets the caller prompt for a passphrase.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Not an OpenSSH ed25519 private key we can read.
    Unsupported,
    /// The key is encrypted; a passphrase is required.
    NeedPassphrase,
    /// A passphrase was given but is wrong (checkints mismatch).
    BadPassphrase,
}

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

/// aes*-ctr → (key length, iv length). Other ciphers are unsupported.
fn ctr_cipher(name: &str) -> Option<usize> {
    match name {
        "aes128-ctr" => Some(16),
        "aes192-ctr" => Some(24),
        "aes256-ctr" => Some(32),
        _ => None,
    }
}

/// Decrypt an aes-ctr encrypted private section in place.
fn ctr_decrypt(name: &str, key: &[u8], iv: &[u8], data: &mut [u8]) {
    match name {
        "aes128-ctr" => Ctr128BE::<Aes128>::new(key[..16].into(), iv[..16].into()).apply_keystream(data),
        "aes192-ctr" => Ctr128BE::<Aes192>::new(key[..24].into(), iv[..16].into()).apply_keystream(data),
        "aes256-ctr" => Ctr128BE::<Aes256>::new(key[..32].into(), iv[..16].into()).apply_keystream(data),
        _ => {}
    }
}

/// Parse an OpenSSH ed25519 private key (PEM). Handles unencrypted keys and
/// `bcrypt` + aes*-ctr encrypted keys when `passphrase` is supplied.
pub fn parse_openssh_ed25519(pem: &str, passphrase: Option<&str>) -> Result<(SigningKey, Vec<u8>), KeyError> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----") && !l.is_empty()).collect();
    let raw = base64::decode(&b64).ok_or(KeyError::Unsupported)?;
    if !raw.starts_with(MAGIC) {
        return Err(KeyError::Unsupported);
    }
    let mut r = Reader::new(&raw[MAGIC.len()..]);
    let cipher = r.utf8().map_err(|_| KeyError::Unsupported)?;
    let kdf = r.utf8().map_err(|_| KeyError::Unsupported)?;
    let kdfopts = r.string().map_err(|_| KeyError::Unsupported)?.to_vec();
    let nkeys = r.u32().map_err(|_| KeyError::Unsupported)?;
    if nkeys != 1 {
        return Err(KeyError::Unsupported);
    }
    let _pub = r.string().map_err(|_| KeyError::Unsupported)?;
    let mut priv_section = r.string().map_err(|_| KeyError::Unsupported)?.to_vec();

    if cipher == "none" && kdf == "none" {
        // unencrypted — fall through
    } else if kdf == "bcrypt" {
        let keylen = ctr_cipher(&cipher).ok_or(KeyError::Unsupported)?;
        let pass = passphrase.ok_or(KeyError::NeedPassphrase)?;
        // kdfoptions = string(salt) + u32(rounds)
        let mut ko = Reader::new(&kdfopts);
        let salt = ko.string().map_err(|_| KeyError::Unsupported)?;
        let rounds = ko.u32().map_err(|_| KeyError::Unsupported)?;
        // Derive key||iv (iv is 16 for all aes-ctr) via bcrypt_pbkdf.
        let mut material = alloc::vec![0u8; keylen + 16];
        bcrypt_pbkdf::bcrypt_pbkdf(pass.as_bytes(), salt, rounds, &mut material).map_err(|_| KeyError::Unsupported)?;
        ctr_decrypt(&cipher, &material[..keylen], &material[keylen..keylen + 16], &mut priv_section);
    } else {
        return Err(KeyError::Unsupported);
    }

    let mut pr = Reader::new(&priv_section);
    let c1 = pr.u32().map_err(|_| KeyError::Unsupported)?;
    let c2 = pr.u32().map_err(|_| KeyError::Unsupported)?;
    if c1 != c2 {
        // Mismatched check integers ⇒ the passphrase was wrong.
        return Err(KeyError::BadPassphrase);
    }
    let ktype = pr.utf8().map_err(|_| KeyError::Unsupported)?;
    if ktype != "ssh-ed25519" {
        return Err(KeyError::Unsupported);
    }
    let pubk = pr.string().map_err(|_| KeyError::Unsupported)?;
    let privk = pr.string().map_err(|_| KeyError::Unsupported)?;
    if privk.len() != 64 || pubk.len() != 32 {
        return Err(KeyError::Unsupported);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&privk[..32]);
    let sk = SigningKey::from_bytes(&seed);
    let mut w = Writer::new();
    w.str("ssh-ed25519").string(pubk);
    Ok((sk, w.done()))
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
