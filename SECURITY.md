# Security Policy

chainlog is security-sensitive software (tamper-evident logging and PII
encryption). We take vulnerability reports seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting ("Report a vulnerability"
under the repository's Security tab), or email the maintainers. Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected versions/commits.

We aim to acknowledge reports within a few days and to coordinate a fix and
disclosure timeline with you.

## Scope / threat model

chainlog is designed to make the following detectable or impossible:

- **Tampering**: editing any persisted entry breaks its `entry_hash`; deleting
  an entry breaks sequence contiguity and the chain link. `verify` detects both
  **without** any decryption key.
- **History rewrite by the audited app**: in the standalone-server deployment,
  the application can only *append*; it cannot modify or delete past entries.
- **PII exposure at rest**: PII is encrypted (XChaCha20-Poly1305) under per-entry
  data keys wrapped by a `KeyProvider` KEK.

Things explicitly **outside** the current threat model (contributions welcome):

- An attacker who holds the KEK and full write access to storage simultaneously.
- Side-channel / timing attacks on the local crypto.
- Availability (DoS) of the standalone server.

## Cryptography

- Hash chain: BLAKE3 over a length-prefixed canonical encoding.
- PII: XChaCha20-Poly1305 (AEAD) with envelope-wrapped per-entry data keys.
- Checkpoints: Ed25519 signatures.

These are provided as a reference implementation. If you are deploying in a
regulated environment, have the integration independently reviewed.
