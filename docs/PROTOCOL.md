# chainlog HTTP wire protocol (v1)

`chainlog-server` exposes a deliberately small, append-only HTTP API. There is
**no** update or delete endpoint — by construction a client can only add to the
chain, never rewrite it.

All request/response bodies are JSON (`Content-Type: application/json`).

## Authentication

Bearer tokens, split by role (separation of duties):

| Role  | Header                              | Grants                          |
|-------|-------------------------------------|---------------------------------|
| Write | `Authorization: Bearer <WRITE>`     | append entries                  |
| Read  | `Authorization: Bearer <READ>`      | read, head, verify, decrypt PII |

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

## Error shape

All errors return a JSON body:

```json
{ "error": "human-readable reason" }
```

with an appropriate status (`400`, `401`, `409`, `500`).
