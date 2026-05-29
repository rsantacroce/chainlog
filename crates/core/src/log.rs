//! The audit log engine.
//!
//! Many callers (threads, or many services over a network front-end) submit
//! records concurrently. They all funnel through a single channel into one
//! writer thread. That thread is the *only* place that assigns sequence
//! numbers, computes the hash chain, and appends to the store — which is
//! exactly what guarantees a gap-free, totally-ordered, unforgeable chain.
//! Concurrency lives at the edges; serialization lives at the core.

use std::sync::Arc;
use std::thread::JoinHandle;

use crossbeam_channel::{bounded, Sender};

use crate::crypto::{self, KeyProvider};
use crate::entry::{AuditEntry, Payload, Receipt, Record, GENESIS_PREV_HASH};
use crate::error::{Error, Result};
use crate::hash;
use crate::store::Store;
use crate::util::now_ms;

enum Cmd {
    Write {
        record: Box<Record>,
        reply: Sender<Result<Receipt>>,
    },
    Head {
        reply: Sender<(u64, String)>,
    },
}

/// Mutable state owned exclusively by the writer thread.
struct WriterState {
    store: Box<dyn Store>,
    provider: Arc<dyn KeyProvider>,
    seq: u64,
    prev_hash: String,
}

impl WriterState {
    fn process(&mut self, record: Record) -> Result<Receipt> {
        // Encrypt PII before anything touches the store.
        let pii = match &record.pii {
            Some(v) => Some(crypto::seal(self.provider.as_ref(), &record.key_id, v)?),
            None => None,
        };

        let next_seq = self.seq + 1;
        let timestamp = now_ms();
        let mut entry = AuditEntry {
            seq: next_seq,
            timestamp,
            event_type: record.event_type,
            outcome: record.outcome,
            actor: record.actor,
            instruction_id: record.instruction_id,
            payload: Payload {
                data: record.data,
                pii,
            },
            prev_hash: self.prev_hash.clone(),
            entry_hash: String::new(),
        };
        entry.entry_hash = hash::entry_hash(&entry);

        // Only advance the chain state after a durable append succeeds.
        self.store.append(&entry)?;
        self.seq = next_seq;
        self.prev_hash = entry.entry_hash.clone();

        Ok(Receipt {
            seq: entry.seq,
            timestamp,
            entry_hash: entry.entry_hash,
            prev_hash: entry.prev_hash,
        })
    }
}

fn writer_loop(mut state: WriterState, rx: crossbeam_channel::Receiver<Cmd>) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Cmd::Write { record, reply } => {
                let res = state.process(*record);
                let _ = reply.send(res);
            }
            Cmd::Head { reply } => {
                let _ = reply.send((state.seq, state.prev_hash.clone()));
            }
        }
    }
}

struct Inner {
    tx: Option<Sender<Cmd>>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Closing the sender ends the writer loop; then we join it so any
        // in-flight append is fully flushed before we return.
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A handle to the audit log. Cheap to clone; all clones share one writer
/// thread and one chain.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Inner>,
}

impl AuditLog {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Append a record. Blocks until the entry is durably written, then returns
    /// its receipt (sequence number + hash).
    pub fn record(&self, record: Record) -> Result<Receipt> {
        let tx = self
            .inner
            .tx
            .as_ref()
            .ok_or_else(|| Error::WriterGone("log is closed".into()))?;
        let (reply_tx, reply_rx) = bounded(1);
        tx.send(Cmd::Write {
            record: Box::new(record),
            reply: reply_tx,
        })
        .map_err(|_| Error::WriterGone("writer thread has stopped".into()))?;
        reply_rx
            .recv()
            .map_err(|_| Error::WriterGone("writer dropped the reply".into()))?
    }

    /// Current head of the chain as `(seq, head_hash)`. For an empty log this is
    /// `(0, GENESIS_PREV_HASH)`. Useful for emitting signed checkpoints.
    pub fn head(&self) -> Result<(u64, String)> {
        let tx = self
            .inner
            .tx
            .as_ref()
            .ok_or_else(|| Error::WriterGone("log is closed".into()))?;
        let (reply_tx, reply_rx) = bounded(1);
        tx.send(Cmd::Head { reply: reply_tx })
            .map_err(|_| Error::WriterGone("writer thread has stopped".into()))?;
        reply_rx
            .recv()
            .map_err(|_| Error::WriterGone("writer dropped the reply".into()))
    }
}

/// Builder for an [`AuditLog`].
#[derive(Default)]
pub struct Builder {
    store: Option<Box<dyn Store>>,
    provider: Option<Arc<dyn KeyProvider>>,
}

impl Builder {
    /// Set the storage backend (e.g. `FileStore` or `MemoryStore`).
    pub fn store<S: Store + 'static>(mut self, store: S) -> Self {
        self.store = Some(Box::new(store));
        self
    }

    /// Set the key provider used to wrap per-entry data keys.
    pub fn key_provider<K: KeyProvider + 'static>(mut self, provider: K) -> Self {
        self.provider = Some(Arc::new(provider));
        self
    }

    /// Set the key provider from a shared `Arc` (handy when the same provider is
    /// also used elsewhere, e.g. the read side of a server).
    pub fn key_provider_arc(mut self, provider: Arc<dyn KeyProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn build(self) -> Result<AuditLog> {
        let store = self
            .store
            .ok_or_else(|| Error::Config("no store configured".into()))?;
        let provider = self
            .provider
            .ok_or_else(|| Error::Config("no key provider configured".into()))?;

        // Resume from the existing tail, if any.
        let (seq, prev_hash) = match store.tail()? {
            Some((seq, hash)) => (seq, hash),
            None => (0, GENESIS_PREV_HASH.to_string()),
        };

        let state = WriterState {
            store,
            provider,
            seq,
            prev_hash,
        };

        let (tx, rx) = crossbeam_channel::unbounded();
        let handle = std::thread::Builder::new()
            .name("chainlog-writer".to_string())
            .spawn(move || writer_loop(state, rx))
            .map_err(|e| Error::Config(format!("failed to spawn writer thread: {e}")))?;

        Ok(AuditLog {
            inner: Arc::new(Inner {
                tx: Some(tx),
                handle: Some(handle),
            }),
        })
    }
}
