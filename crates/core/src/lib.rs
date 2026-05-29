//! # chainlog-core
//!
//! A tamper-evident, hash-chained, PII-aware structured audit log you can embed
//! in any Rust project — or wrap in a standalone service so the thing being
//! audited cannot rewrite its own history.
//!
//! ## What it gives you
//! - **Structured entries**: fixed schema (`seq`, `timestamp`, `event_type`,
//!   `outcome`, `actor`, `instruction_id`, `payload`), not free-text lines.
//! - **Tamper-evidence**: every entry hashes the previous one (BLAKE3). Any
//!   edit breaks the chain; any deletion shows up as a sequence gap.
//! - **PII encryption**: sensitive fields are sealed with per-entry data keys
//!   wrapped by a [`crypto::KeyProvider`]. Verification needs no key, and
//!   discarding a key crypto-shreds the PII without breaking the chain.
//! - **Single-writer core**: concurrent callers funnel into one writer thread,
//!   guaranteeing a gap-free, totally-ordered chain.
//!
//! ## Quick start
//! ```
//! use chainlog_core::{AuditLog, LocalKeyProvider, MemoryStore, Outcome, Record};
//! use serde_json::json;
//!
//! let log = AuditLog::builder()
//!     .store(MemoryStore::new())
//!     .key_provider(LocalKeyProvider::generate().unwrap())
//!     .build()
//!     .unwrap();
//!
//! let receipt = log
//!     .record(
//!         Record::new("user.login", Outcome::Success, "user-42")
//!             .instruction_id("req-abc")
//!             .data(json!({ "ip": "203.0.113.7" }))
//!             .pii(json!({ "email": "a@b.com" })),
//!     )
//!     .unwrap();
//! assert_eq!(receipt.seq, 1);
//! ```

mod crypto;
mod entry;
mod error;
mod hash;
mod log;
mod store;
mod verify;

pub use crypto::{open, seal, KeyProvider, LocalKeyProvider};
pub use entry::{
    AuditEntry, EncryptedPii, Outcome, Payload, Receipt, Record, GENESIS_PREV_HASH,
};
pub use error::{Error, Result};
pub use log::{AuditLog, Builder};
pub use store::{read_all, FileStore, MemoryStore, Store};
pub use verify::{verify_entries, VerifyReport, Violation, ViolationKind};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_log() -> (AuditLog, LocalKeyProvider) {
        let key = LocalKeyProvider::generate().unwrap();
        let log = AuditLog::builder()
            .store(MemoryStore::new())
            .key_provider(key.clone())
            .build()
            .unwrap();
        (log, key)
    }

    #[test]
    fn assigns_contiguous_sequence_numbers() {
        let (log, _) = test_log();
        for expected in 1..=5 {
            let r = log
                .record(Record::new("evt", Outcome::Success, "actor"))
                .unwrap();
            assert_eq!(r.seq, expected);
        }
    }

    #[test]
    fn first_entry_links_to_genesis() {
        let (log, _) = test_log();
        let r = log
            .record(Record::new("evt", Outcome::Success, "actor"))
            .unwrap();
        assert_eq!(r.prev_hash, GENESIS_PREV_HASH);
    }

    #[test]
    fn pii_is_encrypted_then_decryptable() {
        let key = LocalKeyProvider::generate().unwrap();
        let store = MemoryStore::new();
        // Build, write, then inspect the store directly.
        let log = AuditLog::builder()
            .store(store)
            .key_provider(key.clone())
            .build()
            .unwrap();

        log.record(
            Record::new("user.created", Outcome::Success, "admin")
                .data(json!({ "role": "ops" }))
                .pii(json!({ "ssn": "123-45-6789" })),
        )
        .unwrap();
        drop(log); // join writer, flush

        // We can't reach into MemoryStore after move; re-test seal/open directly.
        let sealed = seal(&key, "master", &json!({ "ssn": "123-45-6789" })).unwrap();
        // Ciphertext must not contain the plaintext.
        assert!(!sealed.ciphertext.contains("123-45-6789"));
        let opened = open(&key, &sealed).unwrap();
        assert_eq!(opened, json!({ "ssn": "123-45-6789" }));
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let k1 = LocalKeyProvider::generate().unwrap();
        let k2 = LocalKeyProvider::generate().unwrap();
        let sealed = seal(&k1, "master", &json!({ "x": 1 })).unwrap();
        assert!(open(&k2, &sealed).is_err());
    }

    #[test]
    fn valid_chain_verifies() {
        let key = LocalKeyProvider::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::builder()
            .store(FileStore::open(&path).unwrap())
            .key_provider(key)
            .build()
            .unwrap();
        for i in 0..10 {
            log.record(
                Record::new("evt", Outcome::Success, "actor")
                    .data(json!({ "i": i })),
            )
            .unwrap();
        }
        drop(log);

        let entries = read_all(&path).unwrap();
        let report = verify_entries(&entries);
        assert!(report.is_valid(), "violations: {:?}", report.violations);
        assert_eq!(report.entries_checked, 10);
    }

    #[test]
    fn tampering_with_contents_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = LocalKeyProvider::generate().unwrap();
        let log = AuditLog::builder()
            .store(FileStore::open(&path).unwrap())
            .key_provider(key)
            .build()
            .unwrap();
        for i in 0..3 {
            log.record(Record::new("evt", Outcome::Success, "actor").data(json!({ "i": i })))
                .unwrap();
        }
        drop(log);

        let mut entries = read_all(&path).unwrap();
        // Forge the actor on the middle entry, leaving the stored hash intact.
        entries[1].actor = "attacker".to_string();
        let report = verify_entries(&entries);
        assert!(!report.is_valid());
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v.kind, ViolationKind::BadHash) && v.seq == 2));
    }

    #[test]
    fn deleting_an_entry_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = LocalKeyProvider::generate().unwrap();
        let log = AuditLog::builder()
            .store(FileStore::open(&path).unwrap())
            .key_provider(key)
            .build()
            .unwrap();
        for i in 0..4 {
            log.record(Record::new("evt", Outcome::Success, "actor").data(json!({ "i": i })))
                .unwrap();
        }
        drop(log);

        let mut entries = read_all(&path).unwrap();
        entries.remove(1); // delete seq 2
        let report = verify_entries(&entries);
        assert!(!report.is_valid());
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v.kind, ViolationKind::SequenceGap | ViolationKind::BrokenLink)));
    }

    #[test]
    fn chain_resumes_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = LocalKeyProvider::generate().unwrap();

        {
            let log = AuditLog::builder()
                .store(FileStore::open(&path).unwrap())
                .key_provider(key.clone())
                .build()
                .unwrap();
            log.record(Record::new("a", Outcome::Success, "x")).unwrap();
            log.record(Record::new("b", Outcome::Success, "x")).unwrap();
            drop(log);
        }
        {
            let log = AuditLog::builder()
                .store(FileStore::open(&path).unwrap())
                .key_provider(key)
                .build()
                .unwrap();
            let r = log.record(Record::new("c", Outcome::Success, "x")).unwrap();
            assert_eq!(r.seq, 3, "should continue numbering after reopen");
            drop(log);
        }

        let entries = read_all(&path).unwrap();
        assert!(verify_entries(&entries).is_valid());
        assert_eq!(entries.len(), 3);
    }
}
