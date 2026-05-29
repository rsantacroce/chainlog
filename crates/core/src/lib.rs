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

mod checkpoint;
mod crypto;
mod entry;
mod error;
mod hash;
mod keyring;
mod log;
mod segment;
mod store;
mod util;
mod verify;

pub use checkpoint::{verify_checkpoint, verify_checkpoint_with, Checkpoint, CheckpointSigner};
pub use crypto::{open, seal, KeyProvider, LocalKeyProvider};
pub use entry::{AuditEntry, EncryptedPii, Outcome, Payload, Receipt, Record, GENESIS_PREV_HASH};
pub use error::{Error, Result};
pub use keyring::KeyringProvider;
pub use log::{AuditLog, Builder};
pub use segment::{prune_before, prune_before_timestamp, read_all_segmented, SegmentedStore};
pub use store::{read_all, FileStore, MemoryStore, Store};
pub use util::now_ms;
pub use verify::{
    verify_entries, verify_entries_from, Anchor, VerifyReport, Violation, ViolationKind,
};

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
            log.record(Record::new("evt", Outcome::Success, "actor").data(json!({ "i": i })))
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
        assert!(report.violations.iter().any(|v| matches!(
            v.kind,
            ViolationKind::SequenceGap | ViolationKind::BrokenLink
        )));
    }

    #[test]
    fn checkpoint_signs_and_verifies() {
        let signer = CheckpointSigner::generate().unwrap();
        let cp = signer.sign(7, "deadbeef", 1780000000000);
        assert!(verify_checkpoint(&cp).is_ok());

        // Tampering with any field breaks the signature.
        let mut forged = cp.clone();
        forged.head_hash = "cafebabe".into();
        assert!(verify_checkpoint(&forged).is_err());
    }

    #[test]
    fn checkpoint_pinned_key_mismatch_is_rejected() {
        let signer = CheckpointSigner::generate().unwrap();
        let other = CheckpointSigner::generate().unwrap();
        let cp = signer.sign(1, "abc", 1);
        use base64::Engine as _;
        let wrong_pk: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(other.public_base64())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_checkpoint_with(&cp, &wrong_pk).is_err());
    }

    #[test]
    fn anchored_verify_accepts_a_pruned_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = LocalKeyProvider::generate().unwrap();
        let log = AuditLog::builder()
            .store(FileStore::open(&path).unwrap())
            .key_provider(key)
            .build()
            .unwrap();
        for i in 0..6 {
            log.record(Record::new("evt", Outcome::Success, "a").data(json!({ "i": i })))
                .unwrap();
        }
        drop(log);

        let entries = read_all(&path).unwrap();
        // Pretend entries 1..=3 were pruned; anchor on entry 3.
        let anchor = Anchor {
            seq: entries[2].seq,
            hash: entries[2].entry_hash.clone(),
        };
        let tail: Vec<_> = entries[3..].to_vec();

        // Without an anchor, the tail looks like it has a bad genesis / gap.
        assert!(!verify_entries(&tail).is_valid());
        // With the anchor, it verifies cleanly.
        let report = verify_entries_from(Some(&anchor), &tail);
        assert!(report.is_valid(), "violations: {:?}", report.violations);
    }

    #[test]
    fn segmented_store_rotates_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        // 3 entries per segment.
        {
            let log = AuditLog::builder()
                .store(SegmentedStore::open(dir.path(), 3).unwrap())
                .key_provider(LocalKeyProvider::generate().unwrap())
                .build()
                .unwrap();
            for i in 0..7 {
                log.record(Record::new("evt", Outcome::Success, "a").data(json!({ "i": i })))
                    .unwrap();
            }
            drop(log);
        }
        // 7 entries / 3 per segment => 3 segment files.
        let seg_count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("seg-")
            })
            .count();
        assert_eq!(seg_count, 3);

        let entries = read_all_segmented(dir.path()).unwrap();
        assert_eq!(entries.len(), 7);
        assert!(verify_entries(&entries).is_valid());

        // Reopen and continue numbering.
        let log = AuditLog::builder()
            .store(SegmentedStore::open(dir.path(), 3).unwrap())
            .key_provider(LocalKeyProvider::generate().unwrap())
            .build()
            .unwrap();
        let r = log
            .record(Record::new("evt", Outcome::Success, "a"))
            .unwrap();
        assert_eq!(r.seq, 8);
        drop(log);
    }

    #[test]
    fn prune_then_verify_from_anchor() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = AuditLog::builder()
                .store(SegmentedStore::open(dir.path(), 2).unwrap())
                .key_provider(LocalKeyProvider::generate().unwrap())
                .build()
                .unwrap();
            for i in 0..8 {
                log.record(Record::new("evt", Outcome::Success, "a").data(json!({ "i": i })))
                    .unwrap();
            }
            drop(log);
        }
        // Prune everything before seq 5.
        let anchor = prune_before(dir.path(), 5).unwrap();
        assert!(anchor.is_some(), "expected an anchor after pruning");

        let remaining = read_all_segmented(dir.path()).unwrap();
        // Old segments gone; remaining starts at or before the boundary segment.
        assert!(remaining.first().unwrap().seq <= 5);
        assert!(remaining.last().unwrap().seq == 8);

        // Anchored verification of the pruned log succeeds.
        let report = verify_entries_from(anchor.as_ref(), &remaining);
        assert!(report.is_valid(), "violations: {:?}", report.violations);
    }

    #[test]
    fn keyring_crypto_shred_makes_pii_unrecoverable_but_chain_intact() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Arc::new(KeyringProvider::open(dir.path(), true).unwrap());

        let logdir = tempfile::tempdir().unwrap();
        let path = logdir.path().join("audit.log");
        let log = AuditLog::builder()
            .store(FileStore::open(&path).unwrap())
            .key_provider_arc(keyring.clone())
            .build()
            .unwrap();

        // Two subjects, each with their own key.
        log.record(
            Record::new("user.created", Outcome::Success, "admin")
                .key_id("subject-alice")
                .pii(json!({ "email": "alice@example.com" })),
        )
        .unwrap();
        log.record(
            Record::new("user.created", Outcome::Success, "admin")
                .key_id("subject-bob")
                .pii(json!({ "email": "bob@example.com" })),
        )
        .unwrap();
        drop(log);

        let entries = read_all(&path).unwrap();
        assert!(verify_entries(&entries).is_valid());

        // Both decrypt before shredding.
        let alice_pii = entries[0].payload.pii.as_ref().unwrap();
        let bob_pii = entries[1].payload.pii.as_ref().unwrap();
        assert_eq!(
            open(keyring.as_ref(), alice_pii).unwrap(),
            json!({ "email": "alice@example.com" })
        );

        // Crypto-shred Alice.
        assert!(keyring.shred("subject-alice").unwrap());

        // Alice's PII is now unrecoverable...
        assert!(open(keyring.as_ref(), alice_pii).is_err());
        // ...but Bob is unaffected...
        assert_eq!(
            open(keyring.as_ref(), bob_pii).unwrap(),
            json!({ "email": "bob@example.com" })
        );
        // ...and the chain still verifies (hash covers ciphertext).
        let entries = read_all(&path).unwrap();
        assert!(verify_entries(&entries).is_valid());
    }

    use std::sync::Arc;

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
