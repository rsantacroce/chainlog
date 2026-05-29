//! Signed checkpoints.
//!
//! A checkpoint is a small, signed statement: "at time T, the chain head was
//! `(seq, head_hash)`". Publishing or co-signing checkpoints lets an outside
//! party pin the state of the log at a point in time — so even an operator who
//! controls the storage cannot later rewrite history *before* a checkpoint
//! without the forgery being detectable. It is also the anchor that lets a
//! pruned (retention-trimmed) log still verify (see [`crate::verify`]).
//!
//! Signatures are Ed25519. The signed message is a length-prefixed canonical
//! encoding of `(seq, head_hash, timestamp)`.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::push_field;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// A signed statement about the chain head at a moment in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub seq: u64,
    pub head_hash: String,
    pub timestamp: i64,
    /// Base64 Ed25519 public key (32 bytes) of the signer.
    pub public_key: String,
    /// Base64 Ed25519 signature (64 bytes) over the canonical message.
    pub signature: String,
}

fn message(seq: u64, head_hash: &str, timestamp: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, b"chainlog-checkpoint-v1");
    push_field(&mut buf, &seq.to_be_bytes());
    push_field(&mut buf, head_hash.as_bytes());
    push_field(&mut buf, &timestamp.to_be_bytes());
    buf
}

/// Holds an Ed25519 signing key and produces signed checkpoints.
pub struct CheckpointSigner {
    key: SigningKey,
}

impl CheckpointSigner {
    /// Generate a fresh random signing key.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| Error::Crypto(format!("rng failure: {e}")))?;
        Ok(CheckpointSigner {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Load a signing key from a base64-encoded 32-byte secret seed.
    pub fn from_base64(secret_b64: &str) -> Result<Self> {
        let raw = B64.decode(secret_b64.trim())?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error::Key("signing key must be 32 bytes".into()))?;
        Ok(CheckpointSigner {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Export the secret seed as base64 (store this securely).
    pub fn secret_base64(&self) -> String {
        B64.encode(self.key.to_bytes())
    }

    /// Export the public key as base64 (distribute this to verifiers).
    pub fn public_base64(&self) -> String {
        B64.encode(self.key.verifying_key().to_bytes())
    }

    /// Produce a signed checkpoint for the given head.
    pub fn sign(&self, seq: u64, head_hash: &str, timestamp: i64) -> Checkpoint {
        let msg = message(seq, head_hash, timestamp);
        let sig: Signature = self.key.sign(&msg);
        Checkpoint {
            seq,
            head_hash: head_hash.to_string(),
            timestamp,
            public_key: self.public_base64(),
            signature: B64.encode(sig.to_bytes()),
        }
    }
}

/// Verify that a checkpoint's signature is valid for its embedded public key.
///
/// NOTE: this proves the checkpoint was signed by *whoever holds* `public_key`.
/// To establish trust, the caller must additionally confirm `public_key` is one
/// they expect (pin it out of band) — see [`verify_checkpoint_with`].
pub fn verify_checkpoint(cp: &Checkpoint) -> Result<()> {
    let pk_bytes: [u8; 32] = B64
        .decode(&cp.public_key)?
        .try_into()
        .map_err(|_| Error::Crypto("public key must be 32 bytes".into()))?;
    verify_checkpoint_with(cp, &pk_bytes)
}

/// Verify a checkpoint against an expected (pinned) public key.
pub fn verify_checkpoint_with(cp: &Checkpoint, expected_public_key: &[u8; 32]) -> Result<()> {
    // The embedded key must match the pinned one.
    let embedded: [u8; 32] = B64
        .decode(&cp.public_key)?
        .try_into()
        .map_err(|_| Error::Crypto("public key must be 32 bytes".into()))?;
    if &embedded != expected_public_key {
        return Err(Error::Crypto(
            "checkpoint public key does not match the expected key".into(),
        ));
    }

    let vk = VerifyingKey::from_bytes(expected_public_key)
        .map_err(|e| Error::Crypto(format!("bad public key: {e}")))?;
    let sig_bytes: [u8; 64] = B64
        .decode(&cp.signature)?
        .try_into()
        .map_err(|_| Error::Crypto("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let msg = message(cp.seq, &cp.head_hash, cp.timestamp);
    vk.verify(&msg, &sig)
        .map_err(|e| Error::Crypto(format!("checkpoint signature invalid: {e}")))
}
