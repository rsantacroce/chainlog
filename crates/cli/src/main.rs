//! `chainlog` — offline tooling for audit logs.
//!
//! The headline feature is `verify`: an auditor can prove a log has not been
//! tampered with **without any decryption key**, because the hash chain covers
//! ciphertext, not plaintext.

use std::path::PathBuf;
use std::process::ExitCode;

use chainlog_core::{open, read_all, verify_entries, LocalKeyProvider};
use clap::{Parser, Subcommand};

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
    /// Verify the integrity of a log file. Exits non-zero on any violation.
    Verify {
        /// Path to the JSONL log file.
        path: PathBuf,
    },
    /// Print the head (last seq + hash) of a log file.
    Head {
        path: PathBuf,
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
        #[arg(long, env = "CHAINLOG_KEY")]
        key: Option<String>,
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

        Command::Verify { path } => {
            let entries = read_all(&path)?;
            let report = verify_entries(&entries);
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.is_valid() {
                eprintln!("OK: {} entries, chain intact", report.entries_checked);
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!(
                    "FAIL: {} violation(s) across {} entries",
                    report.violations.len(),
                    report.entries_checked
                );
                Ok(ExitCode::FAILURE)
            }
        }

        Command::Head { path } => {
            let entries = read_all(&path)?;
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
        } => {
            let entries = read_all(&path)?;
            let provider = match key {
                Some(b64) => Some(LocalKeyProvider::from_base64(&b64)?),
                None => None,
            };
            let from = from.unwrap_or(0);
            let to = to.unwrap_or(u64::MAX);

            for e in entries.iter().filter(|e| e.seq >= from && e.seq <= to) {
                let mut v = serde_json::to_value(e)?;
                if let (Some(p), Some(pii)) = (&provider, &e.payload.pii) {
                    match open(p, pii) {
                        Ok(plain) => v["payload"]["pii_plaintext"] = plain,
                        Err(err) => v["payload"]["pii_error"] = serde_json::json!(err.to_string()),
                    }
                }
                println!("{}", serde_json::to_string(&v)?);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
