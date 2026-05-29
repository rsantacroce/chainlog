//! A multi-key, per-subject [`KeyProvider`] with crypto-shredding.
//!
//! Where [`crate::LocalKeyProvider`] wraps every DEK under one master key, the
//! keyring keeps a *separate* key-encryption key per `key_id` — typically one
//! per data subject. Two consequences:
//!
//! - **Crypto-shred**: [`KeyringProvider::shred`] destroys a subject's KEK.
//!   Every entry whose PII was sealed under that `key_id` becomes permanently
//!   undecryptable — a GDPR-style erasure — while the hash chain (which covers
//!   ciphertext) stays fully intact and verifiable.
//! - **Blast radius**: losing/rotating one subject's key never affects another.
//!
//! Keys live as base64 files (`key-<id>.b64`) in a directory. This is the local
//! reference backend; the same [`KeyProvider`] trait is the seam where a real
//! KMS/HSM (AWS KMS, GCP KMS, Vault, a TPM) would plug in — there, `wrap_dek` /
//! `unwrap_dek` become Encrypt/Decrypt calls against a customer master key and
//! "shred" becomes "schedule key deletion".

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use base64::Engine;

use crate::crypto::{random_bytes, unwrap_with_key, wrap_with_key, KeyProvider, MASTER_KEY_LEN};
use crate::error::{Error, Result};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const KEY_FILE_PREFIX: &str = "key-";
const KEY_FILE_SUFFIX: &str = ".b64";

/// `key_id`s must be filesystem-safe to map onto key files.
fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Per-subject key provider backed by a directory of key files.
pub struct KeyringProvider {
    dir: PathBuf,
    cache: RwLock<HashMap<String, [u8; MASTER_KEY_LEN]>>,
    /// If true, `wrap_dek` mints a new key for an unknown `key_id` on demand.
    auto_create: bool,
}

impl KeyringProvider {
    /// Open (creating if needed) a keyring directory. `auto_create` controls
    /// whether writing under an unknown `key_id` mints a key automatically.
    pub fn open(dir: impl AsRef<Path>, auto_create: bool) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let mut cache = HashMap::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name
                .strip_prefix(KEY_FILE_PREFIX)
                .and_then(|s| s.strip_suffix(KEY_FILE_SUFFIX))
            {
                if let Ok(key) = Self::read_key_file(&entry.path()) {
                    cache.insert(id.to_string(), key);
                }
            }
        }
        Ok(KeyringProvider {
            dir,
            cache: RwLock::new(cache),
            auto_create,
        })
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        self.dir
            .join(format!("{KEY_FILE_PREFIX}{key_id}{KEY_FILE_SUFFIX}"))
    }

    fn read_key_file(path: &Path) -> Result<[u8; MASTER_KEY_LEN]> {
        let raw = std::fs::read_to_string(path)?;
        let bytes = B64.decode(raw.trim())?;
        bytes
            .try_into()
            .map_err(|_| Error::Key(format!("key file {} has wrong length", path.display())))
    }

    fn lock_err() -> Error {
        Error::Key("keyring lock poisoned".into())
    }

    /// Ensure a key exists for `key_id`, creating it if absent.
    /// Returns `true` if a new key was created.
    pub fn ensure(&self, key_id: &str) -> Result<bool> {
        if !valid_key_id(key_id) {
            return Err(Error::Key(format!("invalid key_id {key_id:?}")));
        }
        {
            let cache = self.cache.read().map_err(|_| Self::lock_err())?;
            if cache.contains_key(key_id) {
                return Ok(false);
            }
        }
        let mut cache = self.cache.write().map_err(|_| Self::lock_err())?;
        if cache.contains_key(key_id) {
            return Ok(false); // raced; already created
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        random_bytes(&mut key)?;
        std::fs::write(self.key_path(key_id), B64.encode(key))?;
        cache.insert(key_id.to_string(), key);
        Ok(true)
    }

    fn get(&self, key_id: &str) -> Result<[u8; MASTER_KEY_LEN]> {
        let cache = self.cache.read().map_err(|_| Self::lock_err())?;
        cache.get(key_id).copied().ok_or_else(|| {
            Error::Key(format!(
                "no key for key_id {key_id:?} (shredded or never created)"
            ))
        })
    }

    /// Destroy the key for `key_id` (crypto-shred). Returns `true` if a key was
    /// present and removed. After this, PII sealed under `key_id` is
    /// permanently unrecoverable; the chain stays verifiable.
    pub fn shred(&self, key_id: &str) -> Result<bool> {
        if !valid_key_id(key_id) {
            return Err(Error::Key(format!("invalid key_id {key_id:?}")));
        }
        let mut cache = self.cache.write().map_err(|_| Self::lock_err())?;
        let had = cache.remove(key_id).is_some();
        let path = self.key_path(key_id);
        let file_existed = path.exists();
        if file_existed {
            std::fs::remove_file(&path)?;
        }
        Ok(had || file_existed)
    }

    /// List the `key_id`s currently held.
    pub fn list(&self) -> Result<Vec<String>> {
        let cache = self.cache.read().map_err(|_| Self::lock_err())?;
        let mut ids: Vec<String> = cache.keys().cloned().collect();
        ids.sort();
        Ok(ids)
    }
}

impl KeyProvider for KeyringProvider {
    fn wrap_dek(&self, key_id: &str, dek: &[u8]) -> Result<Vec<u8>> {
        if self.auto_create {
            self.ensure(key_id)?;
        }
        let key = self.get(key_id)?;
        wrap_with_key(&key, dek)
    }

    fn unwrap_dek(&self, key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>> {
        let key = self.get(key_id)?;
        unwrap_with_key(&key, wrapped)
    }
}
