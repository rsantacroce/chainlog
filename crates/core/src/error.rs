use thiserror::Error;

/// Errors that can occur anywhere in the audit log.
#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("key provider error: {0}")]
    Key(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// The on-disk / in-memory chain failed integrity verification.
    #[error("chain integrity violation at seq {seq}: {reason}")]
    Integrity { seq: u64, reason: String },

    /// The background writer thread is gone (log was closed / panicked).
    #[error("audit log writer is not available: {0}")]
    WriterGone(String),

    #[error("invalid configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;
