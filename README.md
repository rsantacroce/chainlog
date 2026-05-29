# chainlog

[![CI](https://github.com/rsantacroce/chainlog/actions/workflows/ci.yml/badge.svg)](https://github.com/rsantacroce/chainlog/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

A tamper-evident, hash-chained, PII-aware **structured audit log** for Rust.

Use it like a logger — `log.record(...)` — but every entry is sealed into an
append-only chain where each record carries the hash of the one before it. Any
edit breaks the chain; any deletion shows up as a sequence gap. Sensitive fields
are encrypted at write time, and the integrity of the whole log can be verified
**without** the decryption key.

> Think of it as the "immutable, auditable log" half of a ledger system, pulled
> out into a standalone library you can drop into any project.

## Why

Most projects have either a fast log *or* a verifiable one. chainlog is built so
the two are the same append-only stream:

- **Structured, not free-text.** Fixed schema: `seq`, `timestamp`,
  `event_type`, `outcome`, `actor`, `instruction_id`, `payload`.
- **Tamper-evident.** `entry_hash = BLAKE3(fields ‖ prev_hash)`. Recompute and
  compare to detect any change; contiguous `seq` proves nothing was removed.
- **PII-aware.** Sensitive fields are sealed with a per-entry data key (DEK),
  itself wrapped by a key-encryption key (KEK) from a pluggable `KeyProvider`.
- **Crypto-shred friendly.** The chain hashes *ciphertext*, so destroying a key
  makes PII unrecoverable (GDPR-style erasure) while the chain stays intact and
  verifiable.
- **Single-writer core.** Concurrent callers funnel through one writer thread,
  which is what guarantees a gap-free, totally-ordered chain (LMAX-style).

## Workspace layout

```
chainlog/
├── crates/
│   ├── core/     chainlog-core  — the embeddable library (engine, crypto, store, verify)
│   ├── server/   chainlog-server — standalone HTTP service (append-only, isolated)
│   ├── cli/      chainlog        — offline verifier / inspector / keygen
│   └── client/   chainlog-client — typed async HTTP client (reqwest)
└── docs/
    └── PROTOCOL.md — HTTP wire protocol
```

## Two ways to deploy

### 1. Embedded library

Fast, in-process, no extra moving parts. The audit code shares your process.

```rust
use chainlog_core::{AuditLog, FileStore, LocalKeyProvider, Outcome, Record};
use serde_json::json;

let log = AuditLog::builder()
    .store(FileStore::open("audit.log")?)
    .key_provider(LocalKeyProvider::from_base64(&std::env::var("CHAINLOG_KEY")?)?)
    .build()?;

let receipt = log.record(
    Record::new("payout.created", Outcome::Success, "svc-payments")
        .instruction_id("payout-9f3")
        .data(json!({ "amount": "100.00", "currency": "USDC" }))
        .pii(json!({ "beneficiary_name": "Jane Doe" })),
)?;

println!("sealed seq={} hash={}", receipt.seq, receipt.entry_hash);
```

`AuditLog` is `Clone` and `Send + Sync` — share it across threads; every clone
talks to the same writer thread and the same chain.

### 2. Standalone service (recommended for compliance)

Run `chainlog-server` as its own process. It owns the log file and the key; your
app talks to it over HTTP and can only **append** — never rewrite history. This
is the separation-of-duties property auditors want: *the thing being audited
cannot modify its own audit log.*

```bash
# generate a key
cargo run -p chainlog-cli -- keygen > master.key

CHAINLOG_KEY_FILE=master.key \
CHAINLOG_DATA=./chainlog.log \
CHAINLOG_WRITE_TOKEN=write-secret \
CHAINLOG_READ_TOKEN=read-secret \
cargo run -p chainlog-server

# append
curl -s localhost:8888/v1/records \
  -H 'Authorization: Bearer write-secret' \
  -H 'content-type: application/json' \
  -d '{"event_type":"user.login","outcome":"success","actor":"user-42",
       "data":{"ip":"203.0.113.7"},"pii":{"email":"a@b.com"}}'

# verify (no key needed)
curl -s localhost:8888/v1/verify -H 'Authorization: Bearer read-secret'
```

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full HTTP API.

## Offline verification

An auditor with only the log file (and no key) can still prove integrity:

```bash
chainlog verify ./chainlog.log     # exits non-zero on any violation
chainlog head   ./chainlog.log     # last seq + hash
chainlog inspect ./chainlog.log --key "$CHAINLOG_KEY"   # decrypt PII to read
```

`verify` accepts either a single log file or a segment directory.

## Signed checkpoints

A checkpoint is a small Ed25519-signed statement — "at time T the head was
`(seq, head_hash)`". Co-signing or publishing checkpoints pins history so even an
operator with storage access cannot rewrite entries before a checkpoint
undetectably.

```bash
chainlog gen-sign-key > sign.json                       # {secret, public}
CHAINLOG_SIGN_KEY=<secret> chainlog-server              # enables GET /v1/checkpoint
chainlog checkpoint ./chainlog.log --sign-key <secret>  # offline checkpoint
chainlog verify ./chainlog.log --checkpoint cp.json     # head must match checkpoint
```

## Retention without breaking the chain

Rotate into segment files and prune old ones. Pruning returns an **anchor**; pair
it with a signed checkpoint taken at that boundary and the trimmed log still
verifies — from the anchor instead of from genesis.

```bash
# server in segmented mode
CHAINLOG_DATA=./segs CHAINLOG_SEGMENT_MAX_ENTRIES=100000 chainlog-server

# retention sweep (offline): drop everything older than 365 days
chainlog prune ./segs --before-days 365     # prints the anchor to keep

# the pruned log verifies against the boundary checkpoint
chainlog verify ./segs --anchor boundary_checkpoint.json
```

## PII erasure (crypto-shred)

With a per-subject **keyring**, each subject's PII is sealed under its own key.
Destroying that key makes the subject's PII permanently unrecoverable (GDPR-style
erasure) while every hash and signature stays valid.

```bash
# server in keyring mode
CHAINLOG_KEYRING_DIR=./keys CHAINLOG_ADMIN_TOKEN=admin chainlog-server

# write with a per-subject key_id, then erase that subject:
curl -X DELETE localhost:8888/v1/keys/subject-123 -H 'Authorization: Bearer admin'
# or offline:
chainlog shred ./keys subject-123

chainlog verify ./chainlog.log    # still intact after the erasure
```

## Merkle batch anchoring

Commit to *many* entries with one signed root, then prove any single entry is
included with an `O(log n)` proof — without revealing the others.

```bash
chainlog merkle-anchor ./chainlog.log --sign-key <secret> > anchor.json
chainlog merkle-proof  ./chainlog.log --seq 3            > proof.json
chainlog merkle-verify proof.json --anchor anchor.json   # checks proof + signed root
```

The tree is RFC 6962-style (domain-separated leaves/nodes, BLAKE3). Proof
verification needs no key.

## Architecture

```
app A ─┐
app B ─┤ →  [ inbound channel ] → [ single writer thread ] → seal PII → hash-chain → fsync → store
app C ─┘                                (assigns seq, the source of truth)
```

Concurrency lives at the edges; serialization lives at the core. Because the
hash chain is inherently sequential (`entry_hash` depends on the previous
`entry_hash`), a single writer is not a bottleneck to tolerate — it is what
makes the chain unambiguous.

### Key management

`KeyProvider` is a trait:

```rust
pub trait KeyProvider: Send + Sync {
    fn wrap_dek(&self, key_id: &str, dek: &[u8]) -> Result<Vec<u8>>;
    fn unwrap_dek(&self, key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>>;
}
```

The bundled `LocalKeyProvider` holds a 256-bit master key in process memory.
Implement the trait to back the KEK with AWS KMS, GCP KMS, an HSM, a TPM, etc.
The `key_id` on each record lets you use a **per-subject KEK** so you can
crypto-shred a single subject's PII on request.

## Status

`v0.1`. Implemented and tested:

- core engine (single-writer chain), BLAKE3 hashing, envelope-encrypted PII
- file, in-memory, and **segmented/rotating** stores
- key-free verifier with **anchor** support for pruned logs
- **Ed25519 signed checkpoints**
- **retention pruning** that keeps the log verifiable via an anchor
- **per-subject keyring** with **crypto-shred** (KMS/HSM pluggable via `KeyProvider`)
- standalone HTTP server and offline CLI

Roadmap: Merkle batch anchoring, first-party KMS adapters (AWS/GCP/Vault), and a
typed async client crate.

## License

MIT

