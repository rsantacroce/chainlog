//! Pluggable, append-only storage backends.
//!
//! A [`Store`] only knows how to do two things: report the tail of the chain
//! (so the engine can resume) and append a new entry. There is intentionally no
//! `update` or `delete` — immutability is enforced by the absence of those
//! operations.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::entry::AuditEntry;
use crate::error::Result;

/// Backend for persisting the chain. Append-only by construction.
pub trait Store: Send {
    /// Return the `(seq, entry_hash)` of the last entry, or `None` if empty.
    /// Used by the engine to resume an existing chain.
    fn tail(&self) -> Result<Option<(u64, String)>>;

    /// Durably append one entry. Implementations must not return until the
    /// entry is persisted (e.g. fsynced) when durability is required.
    fn append(&mut self, entry: &AuditEntry) -> Result<()>;
}

/// Append-only file backend: one JSON entry per line (JSONL), fsynced on every
/// append for crash durability.
pub struct FileStore {
    file: File,
    tail: Option<(u64, String)>,
}

impl FileStore {
    /// Open (creating if needed) an append-only log file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let tail = Self::read_tail(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(FileStore { file, tail })
    }

    fn read_tail(path: &Path) -> Result<Option<(u64, String)>> {
        if !path.exists() {
            return Ok(None);
        }
        let last = read_all(path)?
            .into_iter()
            .last()
            .map(|e| (e.seq, e.entry_hash));
        Ok(last)
    }
}

impl Store for FileStore {
    fn tail(&self) -> Result<Option<(u64, String)>> {
        Ok(self.tail.clone())
    }

    fn append(&mut self, entry: &AuditEntry) -> Result<()> {
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.file.sync_all()?; // fsync: durable before we acknowledge
        self.tail = Some((entry.seq, entry.entry_hash.clone()));
        Ok(())
    }
}

/// In-memory backend, mainly for tests and ephemeral use.
#[derive(Default)]
pub struct MemoryStore {
    entries: Vec<AuditEntry>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore::default()
    }

    /// Snapshot of all entries (for verification / inspection in tests).
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

impl Store for MemoryStore {
    fn tail(&self) -> Result<Option<(u64, String)>> {
        Ok(self
            .entries
            .last()
            .map(|e| (e.seq, e.entry_hash.clone())))
    }

    fn append(&mut self, entry: &AuditEntry) -> Result<()> {
        self.entries.push(entry.clone());
        Ok(())
    }
}

/// Read every entry from a JSONL log file, in order.
///
/// This deliberately uses a fresh read handle independent of any writer, so an
/// auditor (or the read side of a service) can iterate the chain without
/// touching the append path. Verification needs no decryption key.
pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<AuditEntry>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}
