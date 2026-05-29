# chainlog HTTP wire protocol (v1)

`chainlog-server` exposes a deliberately small, append-only HTTP API. There is
**no** update or delete endpoint — by construction a client can only add to the
chain, never rewrite it.

All request/response bodies are JSON (`Content-Type: application/json`).

## Authentication

Bearer tokens, split by role (separation of duties):

| Role  | Header                              | Grants                                |
|-------|-------------------------------------|---------------------------------------|
| Write | `Authorization: Bearer <WRITE>`     | append entries                        |
| Read  | `Authorization: Bearer <READ>`      | read, head, verify, checkpoint, decrypt |
| Admin | `Authorization: Bearer <ADMIN>`     | key management (`/v1/keys`)           |

A missing/incorrect token returns `401`. If a token env var is empty, every
request for that role is rejected.

---

## `GET /health`

No auth. Liveness probe.

```json
200 OK
{ "status": "ok" }
```

---

## `POST /v1/records`  *(write token)*

Append one entry. Blocks until the entry is fsynced, then returns its receipt.

**Request**

```json
{
  "event_type": "user.login",      // required
  "outcome": "success",            // required: "success" | "failure" | "denied"
  "actor": "user-42",              // required: the responsible entity
  "instruction_id": "req-abc",     // optional: correlation id for a flow
  "data": { "ip": "203.0.113.7" }, // optional: non-sensitive structured detail
  "pii": { "email": "a@b.com" },   // optional: encrypted before touching disk
  "key_id": "master"               // optional: which KEK wraps this entry's DEK
}
```

**Response**

```json
201 Created
{
  "seq": 1,
  "timestamp": 1780000000000,
  "entry_hash": "88199f51…",
  "prev_hash": "00000000…"   // genesis (all zeros) for the first entry
}
```

`key_id` lets you scope PII to a per-subject key so a single subject can later be
crypto-shredded.

---

## `GET /v1/records`  *(read token)*

Read entries. Query parameters:

| Param     | Type | Default | Meaning                                  |
|-----------|------|---------|------------------------------------------|
| `from`    | u64  | `0`     | only entries with `seq >= from`          |
| `to`      | u64  | `∞`     | only entries with `seq <= to`            |
| `decrypt` | bool | `false` | attach decrypted PII as `pii_plaintext`  |

**Response**

```json
200 OK
{
  "count": 1,
  "entries": [
    {
      "seq": 1,
      "timestamp": 1780000000000,
      "event_type": "user.login",
      "outcome": "success",
      "actor": "user-42",
      "instruction_id": "req-abc",
      "payload": {
        "data": { "ip": "203.0.113.7" },
        "pii": { "key_id": "master", "wrapped_dek": "…", "nonce": "…", "ciphertext": "…" },
        "pii_plaintext": { "email": "a@b.com" }   // only when ?decrypt=true
      },
      "prev_hash": "00000000…",
      "entry_hash": "88199f51…"
    }
  ]
}
```

If a PII bundle cannot be decrypted (e.g. crypto-shredded key), the entry gets
`"pii_error": "<reason>"` instead of `pii_plaintext` — the rest of the read still
succeeds.

---

## `GET /v1/head`  *(read token)*

Current tip of the chain. Use as a lightweight checkpoint to anchor externally
(e.g. sign or publish the `head_hash`).

```json
200 OK
{ "seq": 2, "head_hash": "0365e711…" }
```

For an empty log: `{ "seq": 0, "head_hash": "0000…0000" }`.

---

## `GET /v1/verify`  *(read token)*

Walk and validate the whole chain. Needs no decryption key.

- `200 OK` — chain intact (`violations` is empty)
- `409 Conflict` — one or more violations detected

```json
{
  "entries_checked": 2,
  "violations": [],
  "head": [2, "0365e711…"]
}
```

A violation looks like:

```json
{ "seq": 2, "kind": "bad_hash", "detail": "stored entry_hash … != recomputed …" }
```

`kind` is one of: `bad_hash`, `broken_link`, `sequence_gap`, `bad_genesis`.

---

## `GET /v1/checkpoint`  *(read token)*

Return a fresh Ed25519-signed checkpoint of the current head. Requires the server
to be started with `CHAINLOG_SIGN_KEY`; otherwise returns `501 Not Implemented`.

```json
200 OK
{
  "seq": 4,
  "head_hash": "6487b734…",
  "timestamp": 1780000000000,
  "public_key": "jiEqRs/r…",   // base64 Ed25519 public key
  "signature": "mw3poBaf…"     // base64 Ed25519 signature
}
```

Keep checkpoints to pin history and to anchor retention-pruned logs (verify the
remaining tail against the checkpoint at the prune boundary).

---

## `GET /v1/merkle-anchor`  *(read token)*

Return a single Ed25519-signed Merkle root over all entries — commit to many
entries with one signature. Requires `CHAINLOG_SIGN_KEY`, else `501`.

```json
200 OK
{
  "from_seq": 1,
  "to_seq": 5,
  "count": 5,
  "root": "d0679278…",
  "timestamp": 1780000000000,
  "public_key": "…",
  "signature": "…"
}
```

## `GET /v1/merkle-proof?seq=N`  *(read token)*

Return a compact inclusion proof that entry `N` is committed under the current
Merkle root. `404` if no such entry.

```json
200 OK
{
  "seq": 3,
  "leaf": "03c7efe0…",                 // the entry_hash
  "root": "d0679278…",
  "proof": {
    "leaf_index": 2,
    "leaf_count": 5,
    "path": [ { "hash": "f9ded6b5…", "right": true }, ... ]
  }
}
```

Verify offline with `chainlog merkle-verify` (optionally against the signed
anchor). Proof verification needs no key.

---

## Key management *(admin token)*

Only available when the server runs in keyring mode (`CHAINLOG_KEYRING_DIR`).
Otherwise these return `501 Not Implemented`.

### `POST /v1/keys/{key_id}`

Create a per-subject key (idempotent).

```json
201 Created
{ "key_id": "subject-123", "created": true }
```

Writing a record with a new `key_id` also mints its key automatically; this
endpoint is for pre-provisioning.

### `DELETE /v1/keys/{key_id}`

**Crypto-shred** a subject's key. All PII sealed under it becomes permanently
undecryptable; the chain stays intact and continues to verify.

```json
200 OK
{ "key_id": "subject-123", "shredded": true }
```

### `GET /v1/keys`

List the `key_id`s currently held.

```json
200 OK
{ "key_ids": ["subject-123", "subject-456"] }
```

---

## Error shape

All errors return a JSON body:

```json
{ "error": "human-readable reason" }
```

with an appropriate status (`400`, `401`, `409`, `500`).
