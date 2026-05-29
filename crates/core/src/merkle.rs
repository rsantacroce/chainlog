//! Merkle batch anchoring.
//!
//! A signed [`Checkpoint`] pins a single head. A Merkle anchor instead commits
//! to *many* entries at once with one signed root, and lets you prove that any
//! individual entry is included with a compact `O(log n)` inclusion proof —
//! without revealing the other entries. Useful for publishing one signed root
//! per day/batch and handing a third party a proof for just their record.
//!
//! The tree follows RFC 6962 (Certificate Transparency): leaves are domain-
//! separated with a `0x00` prefix and internal nodes with `0x01`, which blocks
//! second-preimage attacks and the duplicate-leaf ambiguity of naive Merkle
//! trees. The hash is BLAKE3, consistent with the rest of chainlog.

use serde::{Deserialize, Serialize};

use crate::checkpoint::{verify_signature, CheckpointSigner};
use crate::entry::AuditEntry;
use crate::error::{Error, Result};
use crate::util::push_field;

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(data);
    *h.finalize().as_bytes()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Largest power of two strictly less than `n` (requires `n >= 2`).
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle Tree Hash over a list of leaf byte-slices.
fn mth(leaves: &[&[u8]]) -> [u8; 32] {
    match leaves.len() {
        0 => *blake3::hash(b"").as_bytes(),
        1 => leaf_hash(leaves[0]),
        n => {
            let k = split_point(n);
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

fn path(leaves: &[&[u8]], m: usize, out: &mut Vec<([u8; 32], bool)>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if m < k {
        path(&leaves[..k], m, out);
        out.push((mth(&leaves[k..]), true)); // sibling is on the right
    } else {
        path(&leaves[k..], m - k, out);
        out.push((mth(&leaves[..k]), false)); // sibling is on the left
    }
}

fn to_hex(b: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*b).to_hex().to_string()
}

fn from_hex(s: &str) -> Result<[u8; 32]> {
    let h = blake3::Hash::from_hex(s).map_err(|e| Error::Crypto(format!("bad hex hash: {e}")))?;
    Ok(*h.as_bytes())
}

/// Compute the hex Merkle root over a list of leaves.
pub fn merkle_root<S: AsRef<[u8]>>(leaves: &[S]) -> String {
    let refs: Vec<&[u8]> = leaves.iter().map(|s| s.as_ref()).collect();
    to_hex(&mth(&refs))
}

/// One step of an inclusion proof: a sibling hash and which side it is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    /// Hex sibling hash.
    pub hash: String,
    /// True if the sibling sits to the *right* of the running node.
    pub right: bool,
}

/// A compact proof that one leaf is included in a Merkle root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub path: Vec<ProofStep>,
}

/// Build an inclusion proof for the leaf at `index`. Returns `None` if out of
/// range.
pub fn merkle_proof<S: AsRef<[u8]>>(leaves: &[S], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() {
        return None;
    }
    let refs: Vec<&[u8]> = leaves.iter().map(|s| s.as_ref()).collect();
    let mut raw = Vec::new();
    path(&refs, index, &mut raw);
    Some(MerkleProof {
        leaf_index: index,
        leaf_count: leaves.len(),
        path: raw
            .into_iter()
            .map(|(h, right)| ProofStep {
                hash: to_hex(&h),
                right,
            })
            .collect(),
    })
}

/// Verify that `leaf` is included under `root_hex` given `proof`.
pub fn verify_merkle_proof(leaf: &[u8], proof: &MerkleProof, root_hex: &str) -> Result<bool> {
    let mut node = leaf_hash(leaf);
    for step in &proof.path {
        let sib = from_hex(&step.hash)?;
        node = if step.right {
            node_hash(&node, &sib)
        } else {
            node_hash(&sib, &node)
        };
    }
    Ok(to_hex(&node) == root_hex)
}

/// A signed commitment to a contiguous range of entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleAnchor {
    pub from_seq: u64,
    pub to_seq: u64,
    pub count: usize,
    pub root: String,
    pub timestamp: i64,
    pub public_key: String,
    pub signature: String,
}

fn anchor_message(from_seq: u64, to_seq: u64, count: usize, root: &str, timestamp: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, b"chainlog-merkle-v1");
    push_field(&mut buf, &from_seq.to_be_bytes());
    push_field(&mut buf, &to_seq.to_be_bytes());
    push_field(&mut buf, &(count as u64).to_be_bytes());
    push_field(&mut buf, root.as_bytes());
    push_field(&mut buf, &timestamp.to_be_bytes());
    buf
}

/// Build a signed Merkle anchor over `entries` (leaves are their `entry_hash`).
pub fn build_merkle_anchor(
    signer: &CheckpointSigner,
    entries: &[AuditEntry],
    timestamp: i64,
) -> MerkleAnchor {
    let leaves: Vec<&[u8]> = entries.iter().map(|e| e.entry_hash.as_bytes()).collect();
    let root = to_hex(&mth(&leaves));
    let from_seq = entries.first().map(|e| e.seq).unwrap_or(0);
    let to_seq = entries.last().map(|e| e.seq).unwrap_or(0);
    let count = entries.len();
    let msg = anchor_message(from_seq, to_seq, count, &root, timestamp);
    MerkleAnchor {
        from_seq,
        to_seq,
        count,
        root,
        timestamp,
        public_key: signer.public_base64(),
        signature: signer.sign_bytes(&msg),
    }
}

/// Verify the signature on a Merkle anchor (against its embedded public key).
pub fn verify_merkle_anchor(anchor: &MerkleAnchor) -> Result<()> {
    let msg = anchor_message(
        anchor.from_seq,
        anchor.to_seq,
        anchor.count,
        &anchor.root,
        anchor.timestamp,
    );
    verify_signature(&anchor.public_key, &msg, &anchor.signature)
}

/// Inclusion proof for the entry with sequence `seq` within `entries`.
pub fn merkle_proof_for_seq(entries: &[AuditEntry], seq: u64) -> Option<MerkleProof> {
    let index = entries.iter().position(|e| e.seq == seq)?;
    let leaves: Vec<&[u8]> = entries.iter().map(|e| e.entry_hash.as_bytes()).collect();
    merkle_proof(&leaves, index)
}
