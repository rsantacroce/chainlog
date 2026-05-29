//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. Returns 0 if the clock is before the
/// epoch (which should never happen in practice).
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Append a length-prefixed field to a buffer, for unambiguous canonical
/// encodings used by hashing and signing.
pub fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}
