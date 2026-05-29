//! Envelope encryption for PII fields.
//!
//! Each entry with PII gets a fresh random 256-bit data-encryption key (DEK).
//! The PII JSON is sealed with the DEK using XChaCha20-Poly1305. The DEK itself
//! is then "wrapped" (encrypted) by a key-encryption key (KEK) obtained from a
//! [`KeyProvider`]. Only the wrapped DEK, the nonce, and the ciphertext are
//! persisted — never the plaintext, never the bare DEK.
//!
//! Why envelope encryption?
//! - **Crypto-shred**: discard a KEK (or a per-subject KEK) and every entry
//!   sealed under it becomes permanently unreadable, satisfying erasure
//!   requirements *without* mutating the immutable chain.
//! - **Key rotation**: rewrap DEKs under a new KEK without touching ciphertext.
//! - **Least privilege**: a writer that can append doesn't need read access;
//!   only a holder of the KEK can decrypt.

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

use crate::entry::EncryptedPii;
use crate::error::{Error, Result};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub(crate) const MASTER_KEY_LEN: usize = KEY_LEN;

pub(crate) fn random_bytes(out: &mut [u8]) -> Result<()> {
    getrandom::getrandom(out).map_err(|e| Error::Crypto(format!("rng failure: {e}")))
}

/// Wrap (encrypt) `dek` under a raw 256-bit key, returning `nonce ‖ ciphertext`.
pub(crate) fn wrap_with_key(key: &[u8; KEY_LEN], dek: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), dek)
        .map_err(|e| Error::Crypto(format!("wrap dek: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap (decrypt) a `nonce ‖ ciphertext` blob under a raw 256-bit key.
pub(crate) fn unwrap_with_key(key: &[u8; KEY_LEN], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < NONCE_LEN {
        return Err(Error::Crypto("wrapped dek too short".into()));
    }
    let (nonce, ct) = wrapped.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|e| Error::Crypto(format!("unwrap dek (wrong key or tampered?): {e}")))
}

/// Abstraction over "something that can wrap and unwrap data keys".
///
/// Implement this to back the KEK with a cloud KMS, an HSM, a TPM, etc. The
/// bundled [`LocalKeyProvider`] keeps the master key in process memory.
pub trait KeyProvider: Send + Sync {
    /// Encrypt (wrap) a data key under the named KEK.
    fn wrap_dek(&self, key_id: &str, dek: &[u8]) -> Result<Vec<u8>>;
    /// Decrypt (unwrap) a data key that was wrapped under the named KEK.
    fn unwrap_dek(&self, key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>>;
}

/// A simple in-process key provider holding a single 256-bit master key.
///
/// The same master key wraps every DEK regardless of `key_id`. This is the
/// zero-dependency default; swap in a KMS-backed provider for production.
#[derive(Clone)]
pub struct LocalKeyProvider {
    master: [u8; KEY_LEN],
}

impl LocalKeyProvider {
    /// Construct from raw 32 bytes.
    pub fn new(master: [u8; KEY_LEN]) -> Self {
        LocalKeyProvider { master }
    }

    /// Generate a fresh random master key.
    pub fn generate() -> Result<Self> {
        let mut master = [0u8; KEY_LEN];
        random_bytes(&mut master)?;
        Ok(LocalKeyProvider { master })
    }

    /// Load a base64-encoded 32-byte key (e.g. the contents of a key file).
    pub fn from_base64(s: &str) -> Result<Self> {
        let raw = B64.decode(s.trim())?;
        if raw.len() != KEY_LEN {
            return Err(Error::Key(format!(
                "master key must be {KEY_LEN} bytes, got {}",
                raw.len()
            )));
        }
        let mut master = [0u8; KEY_LEN];
        master.copy_from_slice(&raw);
        Ok(LocalKeyProvider { master })
    }

    /// Export the master key as base64 (for writing a key file).
    pub fn to_base64(&self) -> String {
        B64.encode(self.master)
    }
}

impl KeyProvider for LocalKeyProvider {
    fn wrap_dek(&self, _key_id: &str, dek: &[u8]) -> Result<Vec<u8>> {
        wrap_with_key(&self.master, dek)
    }

    fn unwrap_dek(&self, _key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>> {
        unwrap_with_key(&self.master, wrapped)
    }
}

/// Seal a PII JSON value into an [`EncryptedPii`] bundle.
pub fn seal(
    provider: &dyn KeyProvider,
    key_id: &str,
    pii: &serde_json::Value,
) -> Result<EncryptedPii> {
    // Fresh per-entry data key.
    let mut dek = [0u8; KEY_LEN];
    random_bytes(&mut dek)?;

    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;

    let plaintext = serde_json::to_vec(pii)?;
    let cipher = XChaCha20Poly1305::new((&dek).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| Error::Crypto(format!("seal pii: {e}")))?;

    let wrapped = provider.wrap_dek(key_id, &dek)?;

    Ok(EncryptedPii {
        key_id: key_id.to_string(),
        wrapped_dek: B64.encode(wrapped),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Open a sealed [`EncryptedPii`] bundle back into the original JSON value.
///
/// Fails if the KEK is unavailable (e.g. crypto-shredded) or the data was
/// tampered with (AEAD authentication failure).
pub fn open(provider: &dyn KeyProvider, sealed: &EncryptedPii) -> Result<serde_json::Value> {
    let wrapped = B64.decode(&sealed.wrapped_dek)?;
    let nonce = B64.decode(&sealed.nonce)?;
    let ciphertext = B64.decode(&sealed.ciphertext)?;

    let dek = provider.unwrap_dek(&sealed.key_id, &wrapped)?;
    if dek.len() != KEY_LEN {
        return Err(Error::Crypto("unwrapped dek has wrong length".into()));
    }
    let cipher = XChaCha20Poly1305::new(dek.as_slice().into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|e| Error::Crypto(format!("open pii (wrong key or tampered?): {e}")))?;
    Ok(serde_json::from_slice(&plaintext)?)
}
