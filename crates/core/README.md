# chainlog-core

The embeddable engine for [chainlog](https://github.com/rsantacroce/chainlog) — a
tamper-evident, hash-chained, PII-aware structured audit log.

- Single-writer hash chain (BLAKE3), gap-free and totally ordered.
- Envelope-encrypted PII (XChaCha20-Poly1305) via a pluggable `KeyProvider`;
  verification needs no key, and discarding a key crypto-shreds the PII.
- File / in-memory / segmented (rotating) stores.
- Ed25519 signed checkpoints, Merkle batch anchoring, retention pruning with
  anchor-aware verification.

```rust
use chainlog_core::{AuditLog, LocalKeyProvider, MemoryStore, Outcome, Record};
use serde_json::json;

let log = AuditLog::builder()
    .store(MemoryStore::new())
    .key_provider(LocalKeyProvider::generate().unwrap())
    .build().unwrap();

let receipt = log.record(
    Record::new("user.login", Outcome::Success, "user-42")
        .pii(json!({ "email": "a@b.com" })),
).unwrap();
assert_eq!(receipt.seq, 1);
```

See the [repository](https://github.com/rsantacroce/chainlog) for the full docs.

License: MIT
