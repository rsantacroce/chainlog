//! Chain verification. Requires **no** decryption key — the hash covers
//! ciphertext, so an auditor can prove integrity without the power to read PII.

use serde::{Deserialize, Serialize};

use crate::entry::{AuditEntry, GENESIS_PREV_HASH};

/// A trusted starting point for verifying a chain that no longer begins at
/// genesis (e.g. after retention pruning). Typically taken from a signed
/// checkpoint at the prune boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// The seq of the last entry *before* the first entry being verified.
    pub seq: u64,
    /// That entry's `entry_hash` — the first verified entry must point at it.
    pub hash: String,
}

/// A single detected problem with the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub seq: u64,
    pub kind: ViolationKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// `entry_hash` does not match the recomputed hash → contents were altered.
    BadHash,
    /// `prev_hash` does not match the previous entry's `entry_hash` → a break
    /// or reordering in the chain.
    BrokenLink,
    /// Sequence numbers are not contiguous → an entry was deleted or inserted.
    SequenceGap,
    /// The first entry's `prev_hash` is not the genesis value.
    BadGenesis,
}

/// The result of walking and checking a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    pub entries_checked: u64,
    pub violations: Vec<Violation>,
    /// `(seq, entry_hash)` of the last entry, useful as a signed checkpoint.
    pub head: Option<(u64, String)>,
}

impl VerifyReport {
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Verify a chain given its entries in order, starting from genesis.
pub fn verify_entries<'a, I>(entries: I) -> VerifyReport
where
    I: IntoIterator<Item = &'a AuditEntry>,
{
    verify_entries_from(None, entries)
}

/// Verify a chain that may start after a trusted [`Anchor`] instead of genesis.
///
/// Pass `None` to require the chain to begin at genesis (`seq == 1`,
/// `prev_hash == GENESIS`). Pass `Some(anchor)` — e.g. from a signed checkpoint
/// at a prune boundary — to require the first entry to follow that anchor.
pub fn verify_entries_from<'a, I>(anchor: Option<&Anchor>, entries: I) -> VerifyReport
where
    I: IntoIterator<Item = &'a AuditEntry>,
{
    let mut violations = Vec::new();
    let mut count: u64 = 0;
    let mut prev: Option<&AuditEntry> = None;
    let mut head = None;

    for entry in entries {
        count += 1;

        // 1. Content integrity: does the stored hash match the contents?
        let recomputed = entry.recompute_hash();
        if recomputed != entry.entry_hash {
            violations.push(Violation {
                seq: entry.seq,
                kind: ViolationKind::BadHash,
                detail: format!(
                    "stored entry_hash {} != recomputed {}",
                    entry.entry_hash, recomputed
                ),
            });
        }

        match prev {
            None => match anchor {
                // 2a-anchored: first entry must follow the trusted anchor.
                Some(a) => {
                    if entry.prev_hash != a.hash {
                        violations.push(Violation {
                            seq: entry.seq,
                            kind: ViolationKind::BrokenLink,
                            detail: format!(
                                "first entry prev_hash {} != anchor hash {}",
                                entry.prev_hash, a.hash
                            ),
                        });
                    }
                    if entry.seq != a.seq + 1 {
                        violations.push(Violation {
                            seq: entry.seq,
                            kind: ViolationKind::SequenceGap,
                            detail: format!(
                                "first entry seq {} does not follow anchor seq {}",
                                entry.seq, a.seq
                            ),
                        });
                    }
                }
                // 2a-genesis: classic genesis checks.
                None => {
                    if entry.prev_hash != GENESIS_PREV_HASH {
                        violations.push(Violation {
                            seq: entry.seq,
                            kind: ViolationKind::BadGenesis,
                            detail: format!(
                                "first entry prev_hash {} != genesis {}",
                                entry.prev_hash, GENESIS_PREV_HASH
                            ),
                        });
                    }
                    if entry.seq != 1 {
                        violations.push(Violation {
                            seq: entry.seq,
                            kind: ViolationKind::SequenceGap,
                            detail: format!("first entry seq is {}, expected 1", entry.seq),
                        });
                    }
                }
            },
            Some(p) => {
                // 2b. Linkage: this entry must point at the previous hash.
                if entry.prev_hash != p.entry_hash {
                    violations.push(Violation {
                        seq: entry.seq,
                        kind: ViolationKind::BrokenLink,
                        detail: format!(
                            "prev_hash {} != previous entry_hash {}",
                            entry.prev_hash, p.entry_hash
                        ),
                    });
                }
                // 3. Contiguity.
                if entry.seq != p.seq + 1 {
                    violations.push(Violation {
                        seq: entry.seq,
                        kind: ViolationKind::SequenceGap,
                        detail: format!("seq {} does not follow previous seq {}", entry.seq, p.seq),
                    });
                }
            }
        }

        head = Some((entry.seq, entry.entry_hash.clone()));
        prev = Some(entry);
    }

    VerifyReport {
        entries_checked: count,
        violations,
        head,
    }
}
