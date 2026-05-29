use serde::{Deserialize, Serialize};

use crate::hash;

/// The outcome of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Denied => "denied",
        }
    }
}

/// A PII bundle after envelope encryption.
///
/// The chain hash covers these ciphertext bytes (not the plaintext), which is
/// what allows "crypto-shredding": destroy the key and the PII becomes
/// unrecoverable while the chain stays intact and verifiable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPii {
    /// Identifier of the key-encryption-key used to wrap the data key.
    pub key_id: String,
    /// The per-entry data-encryption-key (DEK), wrapped by the KEK. base64.
    pub wrapped_dek: String,
    /// Nonce used to encrypt the PII payload with the DEK. base64.
    pub nonce: String,
    /// The PII JSON, encrypted with the DEK. base64.
    pub ciphertext: String,
}

/// The structured body of an audit entry: plaintext data plus optional
/// encrypted PII.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Payload {
    /// Non-sensitive structured data, stored in the clear.
    #[serde(default)]
    pub data: serde_json::Value,
    /// Sensitive data, encrypted at rest. `None` if the entry has no PII.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii: Option<EncryptedPii>,
}

/// What a caller submits. The engine turns this into a sealed [`AuditEntry`].
#[derive(Debug, Clone)]
pub struct Record {
    pub event_type: String,
    pub outcome: Outcome,
    /// The responsible entity (user id, service name, api key id, ...).
    pub actor: String,
    /// Correlation id linking entries that belong to one logical flow.
    pub instruction_id: Option<String>,
    /// Non-sensitive structured detail.
    pub data: serde_json::Value,
    /// Sensitive detail to be encrypted before it ever touches disk.
    pub pii: Option<serde_json::Value>,
    /// Which KEK to wrap this entry's DEK with. Use a per-subject key id here
    /// to make per-subject crypto-shredding possible.
    pub key_id: String,
}

impl Record {
    pub fn new(event_type: impl Into<String>, outcome: Outcome, actor: impl Into<String>) -> Self {
        Record {
            event_type: event_type.into(),
            outcome,
            actor: actor.into(),
            instruction_id: None,
            data: serde_json::Value::Null,
            pii: None,
            key_id: "master".to_string(),
        }
    }

    pub fn instruction_id(mut self, id: impl Into<String>) -> Self {
        self.instruction_id = Some(id.into());
        self
    }

    pub fn data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }

    pub fn pii(mut self, pii: serde_json::Value) -> Self {
        self.pii = Some(pii);
        self
    }

    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = key_id.into();
        self
    }
}

/// A sealed, hash-chained entry. This is the immutable record written to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number. The first entry is `1`. A gap proves a
    /// deletion.
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub timestamp: i64,
    pub event_type: String,
    pub outcome: Outcome,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_id: Option<String>,
    pub payload: Payload,
    /// Hex `entry_hash` of the previous entry (all zeros for the genesis entry).
    pub prev_hash: String,
    /// Hex hash of this entry, computed over every field above plus `prev_hash`.
    pub entry_hash: String,
}

impl AuditEntry {
    /// Recompute the hash this entry *should* have, given its contents.
    pub fn recompute_hash(&self) -> String {
        hash::entry_hash(self)
    }
}

/// Returned to the caller once an entry is durably written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub timestamp: i64,
    pub entry_hash: String,
    pub prev_hash: String,
}

/// The genesis previous-hash: 32 zero bytes, hex-encoded.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
