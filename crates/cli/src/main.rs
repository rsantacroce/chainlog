//! `chainlog` — offline tooling for audit logs.
//!
//! The headline feature is `verify`: an auditor can prove a log has not been
//! tampered with **without any decryption key**, because the hash chain covers
//! ciphertext, not plaintext.

use std::path::PathBuf;
use std::process::ExitCode;

use chainlog_core::{
    build_merkle_anchor, merkle_proof_for_seq, merkle_root, now_ms, open, prune_before,
    prune_before_timestamp, read_all, read_all_segmented, verify_checkpoint, verify_entries_from,
    verify_merkle_anchor, verify_merkle_proof, Anchor, AuditEntry, Checkpoint, CheckpointSigner,
    KeyProvider, KeyringProvider, LocalKeyProvider, MerkleAnchor, MerkleProof,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// A self-contained Merkle inclusion proof bundle (printed by `merkle-proof`,
/// consumed by `merkle-verify`).
#[derive(Serialize, Deserialize)]
struct ProofBundle {
    seq: u64,
    leaf: String,
    root: String,
    proof: MerkleProof,
}

#[derive(Parser)]
#[command(name = "chainlog", version, about = "Tamper-evident audit log tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh 256-bit master key (base64).
    Keygen {
        /// Write the key to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Generate an Ed25519 checkpoint signing key (prints secret + public).
    GenSignKey,
    /// Verify the integrity of a log file. Exits non-zero on any violation.
    Verify {
        /// Path to the JSONL log file.
        path: PathBuf,
        /// Verify the chain head matches this signed checkpoint file.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Treat this signed checkpoint as a trusted anchor; verify the log as
        /// the tail that follows it (for retention-pruned logs).
        #[arg(long)]
        anchor: Option<PathBuf>,
    },
    /// Produce a signed checkpoint of a log file's current head.
    Checkpoint {
        path: PathBuf,
        /// Base64 Ed25519 signing key (secret seed).
        #[arg(long, env = "CHAINLOG_SIGN_KEY")]
        sign_key: String,
    },
    /// Print the head (last seq + hash) of a log file.
    Head { path: PathBuf },
    /// Prune old segments from a segment directory (retention).
    ///
    /// Deletes whole segments entirely older than the boundary, keeping the
    /// segment that straddles it. Prints the resulting anchor — sign it as a
    /// checkpoint and keep it so the pruned log still verifies.
    Prune {
        /// Segment directory.
        dir: PathBuf,
        /// Remove segments entirely before this sequence number.
        #[arg(long, conflicts_with = "before_days")]
        before_seq: Option<u64>,
        /// Remove segments whose entries are all older than this many days.
        #[arg(long)]
        before_days: Option<i64>,
    },
    /// Print entries, optionally decrypting PII with a key.
    Inspect {
        path: PathBuf,
        /// Only show entries with seq >= from.
        #[arg(long)]
        from: Option<u64>,
        /// Only show entries with seq <= to.
        #[arg(long)]
        to: Option<u64>,
        /// Base64 master key, used to decrypt PII fields.
        #[arg(long, env = "CHAINLOG_KEY", conflicts_with = "keyring")]
        key: Option<String>,
        /// Keyring directory (per-subject keys) to decrypt PII fields.
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Crypto-shred a subject key in a keyring directory (irreversible).
    Shred {
        /// Keyring directory.
        keyring: PathBuf,
        /// The key_id (e.g. subject id) to destroy.
        key_id: String,
    },
    /// Produce a signed Merkle anchor (one signed root over many entries).
    MerkleAnchor {
        path: PathBuf,
        #[arg(long, env = "CHAINLOG_SIGN_KEY")]
        sign_key: String,
    },
    /// Produce an inclusion proof bundle for one entry.
    MerkleProof {
        path: PathBuf,
        #[arg(long)]
        seq: u64,
    },
    /// Verify an inclusion proof bundle; optionally check it against an anchor.
    MerkleVerify {
        /// Proof bundle file (output of `merkle-proof`).
        proof: PathBuf,
        /// Optional signed anchor file; verifies its signature and that roots match.
        #[arg(long)]
        anchor: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load_checkpoint(path: &PathBuf) -> Result<Checkpoint, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

/// Read entries from either a single log file or a segment directory.
fn load_entries(path: &PathBuf) -> Result<Vec<AuditEntry>, Box<dyn std::error::Error>> {
    if path.is_dir() {
        Ok(read_all_segmented(path)?)
    } else {
        Ok(read_all(path)?)
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Keygen { out } => {
            let key = LocalKeyProvider::generate()?;
            let b64 = key.to_base64();
            match out {
                Some(path) => {
                    std::fs::write(&path, &b64)?;
                    eprintln!("wrote master key to {}", path.display());
                }
                None => println!("{b64}"),
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::GenSignKey => {
            let signer = CheckpointSigner::generate()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "secret": signer.secret_base64(),
                    "public": signer.public_base64(),
                }))?
            );
            Ok(ExitCode::SUCCESS)
        }

        Command::Verify {
            path,
            checkpoint,
            anchor,
        } => {
            let entries = load_entries(&path)?;

            // Optional trusted anchor (pruned-log tail verification).
            let anchor_val = match &anchor {
                Some(p) => {
                    let cp = load_checkpoint(p)?;
                    verify_checkpoint(&cp)?; // signature must be valid
                    Some(Anchor {
                        seq: cp.seq,
                        hash: cp.head_hash,
                    })
                }
                None => None,
            };

            let report = verify_entries_from(anchor_val.as_ref(), &entries);
            println!("{}", serde_json::to_string_pretty(&report)?);

            let mut ok = report.is_valid();
            if ok {
                eprintln!("OK: {} entries, chain intact", report.entries_checked);
            } else {
                eprintln!(
                    "FAIL: {} violation(s) across {} entries",
                    report.violations.len(),
                    report.entries_checked
                );
            }

            // Optional: confirm the head matches a signed checkpoint.
            if let Some(p) = &checkpoint {
                let cp = load_checkpoint(p)?;
                match verify_checkpoint(&cp) {
                    Ok(()) => match &report.head {
                        Some((seq, hash)) if *seq == cp.seq && *hash == cp.head_hash => {
                            eprintln!("OK: head matches signed checkpoint (seq {})", cp.seq);
                        }
                        Some((seq, hash)) => {
                            eprintln!(
                                "FAIL: head ({seq}, {hash}) != checkpoint ({}, {})",
                                cp.seq, cp.head_hash
                            );
                            ok = false;
                        }
                        None => {
                            eprintln!("FAIL: log is empty but a checkpoint was supplied");
                            ok = false;
                        }
                    },
                    Err(e) => {
                        eprintln!("FAIL: checkpoint signature invalid: {e}");
                        ok = false;
                    }
                }
            }

            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }

        Command::Checkpoint { path, sign_key } => {
            let entries = load_entries(&path)?;
            let (seq, head_hash) = match entries.last() {
                Some(e) => (e.seq, e.entry_hash.clone()),
                None => (0, chainlog_core::GENESIS_PREV_HASH.to_string()),
            };
            let signer = CheckpointSigner::from_base64(&sign_key)?;
            let cp = signer.sign(seq, &head_hash, now_ms());
            println!("{}", serde_json::to_string_pretty(&cp)?);
            Ok(ExitCode::SUCCESS)
        }

        Command::Prune {
            dir,
            before_seq,
            before_days,
        } => {
            let anchor = match (before_seq, before_days) {
                (Some(seq), _) => prune_before(&dir, seq)?,
                (None, Some(days)) => {
                    let cutoff = now_ms() - days * 86_400_000;
                    prune_before_timestamp(&dir, cutoff)?
                }
                (None, None) => {
                    eprintln!("error: specify --before-seq or --before-days");
                    return Ok(ExitCode::FAILURE);
                }
            };
            match anchor {
                Some(a) => {
                    eprintln!("pruned; sign and keep this anchor so the log still verifies:");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "anchor_seq": a.seq,
                            "anchor_hash": a.hash,
                        }))?
                    );
                }
                None => {
                    eprintln!("nothing pruned (need >1 segment and entries below the boundary)")
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Head { path } => {
            let entries = load_entries(&path)?;
            match entries.last() {
                Some(e) => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "seq": e.seq,
                        "head_hash": e.entry_hash,
                        "timestamp": e.timestamp,
                    }))?
                ),
                None => println!("{{\"seq\":0,\"head_hash\":null}}"),
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Inspect {
            path,
            from,
            to,
            key,
            keyring,
        } => {
            let entries = load_entries(&path)?;
            let provider: Option<Box<dyn KeyProvider>> = match (key, keyring) {
                (Some(b64), _) => Some(Box::new(LocalKeyProvider::from_base64(&b64)?)),
                (None, Some(dir)) => Some(Box::new(KeyringProvider::open(&dir, false)?)),
                (None, None) => None,
            };
            let from = from.unwrap_or(0);
            let to = to.unwrap_or(u64::MAX);

            for e in entries.iter().filter(|e| e.seq >= from && e.seq <= to) {
                let mut v = serde_json::to_value(e)?;
                if let (Some(p), Some(pii)) = (&provider, &e.payload.pii) {
                    match open(p.as_ref(), pii) {
                        Ok(plain) => v["payload"]["pii_plaintext"] = plain,
                        Err(err) => v["payload"]["pii_error"] = serde_json::json!(err.to_string()),
                    }
                }
                println!("{}", serde_json::to_string(&v)?);
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::MerkleAnchor { path, sign_key } => {
            let entries = load_entries(&path)?;
            let signer = CheckpointSigner::from_base64(&sign_key)?;
            let anchor = build_merkle_anchor(&signer, &entries, now_ms());
            println!("{}", serde_json::to_string_pretty(&anchor)?);
            Ok(ExitCode::SUCCESS)
        }

        Command::MerkleProof { path, seq } => {
            let entries = load_entries(&path)?;
            let proof = match merkle_proof_for_seq(&entries, seq) {
                Some(p) => p,
                None => {
                    eprintln!("no entry with seq {seq}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let leaf = entries
                .iter()
                .find(|e| e.seq == seq)
                .map(|e| e.entry_hash.clone())
                .unwrap_or_default();
            let leaves: Vec<&str> = entries.iter().map(|e| e.entry_hash.as_str()).collect();
            let bundle = ProofBundle {
                seq,
                leaf,
                root: merkle_root(&leaves),
                proof,
            };
            println!("{}", serde_json::to_string_pretty(&bundle)?);
            Ok(ExitCode::SUCCESS)
        }

        Command::MerkleVerify { proof, anchor } => {
            let bundle: ProofBundle = serde_json::from_str(&std::fs::read_to_string(&proof)?)?;
            let mut ok = verify_merkle_proof(bundle.leaf.as_bytes(), &bundle.proof, &bundle.root)?;
            if ok {
                eprintln!("OK: leaf is included in root {}", bundle.root);
            } else {
                eprintln!("FAIL: inclusion proof does not validate");
            }
            if let Some(apath) = anchor {
                let a: MerkleAnchor = serde_json::from_str(&std::fs::read_to_string(&apath)?)?;
                match verify_merkle_anchor(&a) {
                    Ok(()) if a.root == bundle.root => {
                        eprintln!("OK: anchor signature valid and root matches");
                    }
                    Ok(()) => {
                        eprintln!("FAIL: anchor root {} != proof root {}", a.root, bundle.root);
                        ok = false;
                    }
                    Err(e) => {
                        eprintln!("FAIL: anchor signature invalid: {e}");
                        ok = false;
                    }
                }
            }
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }

        Command::Shred { keyring, key_id } => {
            let provider = KeyringProvider::open(&keyring, false)?;
            let shredded = provider.shred(&key_id)?;
            if shredded {
                eprintln!("crypto-shredded key_id {key_id:?}; its PII is now unrecoverable");
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!("no key found for key_id {key_id:?}");
                Ok(ExitCode::FAILURE)
            }
        }
    }
}
