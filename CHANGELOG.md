# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-29

Initial release.

### Core (`chainlog-core`)
- Single-writer hash-chained audit log (BLAKE3) with a fixed structured schema
  (`seq`, `timestamp`, `event_type`, `outcome`, `actor`, `instruction_id`,
  `payload`).
- Envelope-encrypted PII (XChaCha20-Poly1305) via a pluggable `KeyProvider`;
  chain hashes cover ciphertext, so verification needs no key.
- Stores: `FileStore`, `MemoryStore`, and rotating `SegmentedStore`.
- Key-free verifier with `Anchor` support for retention-pruned logs.
- Ed25519 signed checkpoints (`CheckpointSigner`, `verify_checkpoint`).
- Retention: `prune_before` / `prune_before_timestamp` returning an anchor.
- Per-subject `KeyringProvider` with crypto-shred.
- Merkle batch anchoring (RFC 6962-style) with signed roots and inclusion proofs.

### Server (`chainlog-server`)
- Append-only HTTP API (no update/delete) with role-split bearer tokens.
- Endpoints: records (append/read), head, verify, checkpoint, merkle-anchor,
  merkle-proof, and admin-gated key management.
- Optional segmented mode, checkpoint signing, and keyring/crypto-shred mode.

### CLI (`chainlog`)
- `keygen`, `gen-sign-key`, `verify` (with `--checkpoint` / `--anchor`),
  `head`, `inspect`, `checkpoint`, `prune`, `shred`, and
  `merkle-anchor` / `merkle-proof` / `merkle-verify`.

### Client (`chainlog-client`)
- Typed async client (reqwest/rustls) covering the full HTTP API.

[0.1.0]: https://github.com/rsantacroce/chainlog/releases/tag/v0.1.0
