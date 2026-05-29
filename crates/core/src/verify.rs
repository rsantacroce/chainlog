//! Chain verification. Requires **no** decryption key — the hash covers
//! ciphertext, so an auditor can prove integrity without the power to read PII.

use serde::{Deserialize, Serialize};

use crate::entry::{AuditEntry, GENESIS_PREV_HASH};

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

/// Verify a chain given its entries in order.
pub fn verify_entries<'a, I>(entries: I) -> VerifyReport
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
            None => {
                // 2a. Genesis checks.
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
                        detail: format!(
                            "seq {} does not follow previous seq {}",
                            entry.seq, p.seq
                        ),
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
