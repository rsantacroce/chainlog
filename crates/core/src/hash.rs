//! Deterministic, canonical hashing of audit entries.
//!
//! The hash is computed over a length-prefixed concatenation of every field, in
//! a fixed order, ending with `prev_hash`. Length prefixes make the encoding
//! unambiguous (no field boundary can be forged by shifting bytes between
//! adjacent fields). The payload is serialized with `serde_json`, whose default
//! `Value` map is a `BTreeMap`, so object keys are emitted in sorted order and
//! the bytes are reproducible across runs and machines.

use crate::entry::AuditEntry;

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Build the canonical byte string that the entry hash is computed over.
/// Note: this deliberately excludes `entry_hash` itself.
fn canonical_bytes(e: &AuditEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, &e.seq.to_be_bytes());
    push_field(&mut buf, &e.timestamp.to_be_bytes());
    push_field(&mut buf, e.event_type.as_bytes());
    push_field(&mut buf, e.outcome.as_str().as_bytes());
    push_field(&mut buf, e.actor.as_bytes());
    push_field(&mut buf, e.instruction_id.as_deref().unwrap_or("").as_bytes());
    // Payload is serialized canonically; covers ciphertext, not plaintext PII.
    let payload = serde_json::to_vec(&e.payload).expect("payload is always serializable");
    push_field(&mut buf, &payload);
    push_field(&mut buf, e.prev_hash.as_bytes());
    buf
}

/// Compute the hex-encoded BLAKE3 hash of an entry.
pub fn entry_hash(e: &AuditEntry) -> String {
    let bytes = canonical_bytes(e);
    blake3::hash(&bytes).to_hex().to_string()
}
