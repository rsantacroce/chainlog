//! Segmented, rotating storage with retention pruning.
//!
//! Instead of one growing file, the chain is split across segment files in a
//! directory, each holding up to `max_entries` records. Segments are named
//! `seg-<first_seq:020>.jsonl`, so lexical order is chain order.
//!
//! Retention is the tension at the heart of an immutable log: regulations both
//! require keeping data *and* deleting it after a window. We resolve it by
//! pruning whole old segments and pairing the surviving log with a trusted
//! [`Anchor`] (typically from a signed checkpoint). The remaining chain then
//! still verifies from that anchor instead of from genesis — see
//! [`crate::verify::verify_entries_from`].

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::entry::AuditEntry;
use crate::error::{Error, Result};
use crate::store::{read_all, Store};
use crate::verify::Anchor;

const SEG_PREFIX: &str = "seg-";
const SEG_SUFFIX: &str = ".jsonl";

fn segment_name(first_seq: u64) -> String {
    format!("{SEG_PREFIX}{first_seq:020}{SEG_SUFFIX}")
}

fn parse_segment_first_seq(name: &str) -> Option<u64> {
    name.strip_prefix(SEG_PREFIX)?
        .strip_suffix(SEG_SUFFIX)?
        .parse()
        .ok()
}

/// List segment files in `dir`, sorted by their first sequence number.
fn list_segments(dir: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut segs = Vec::new();
    if !dir.exists() {
        return Ok(segs);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(first) = parse_segment_first_seq(&name) {
            segs.push((first, entry.path()));
        }
    }
    segs.sort_by_key(|(first, _)| *first);
    Ok(segs)
}

/// Append-only store that rotates into a new segment file every `max_entries`
/// records.
pub struct SegmentedStore {
    dir: PathBuf,
    max_entries: u64,
    file: File,
    cur_first: u64,
    cur_count: u64,
    tail: Option<(u64, String)>,
}

impl SegmentedStore {
    /// Open (creating if needed) a segmented store in `dir`.
    pub fn open(dir: impl AsRef<Path>, max_entries: u64) -> Result<Self> {
        if max_entries == 0 {
            return Err(Error::Config("max_entries must be >= 1".into()));
        }
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;

        let segs = list_segments(&dir)?;
        let (cur_first, cur_count, tail) = match segs.last() {
            Some((first, path)) => {
                let entries = read_all(path)?;
                let count = entries.len() as u64;
                let tail = entries.last().map(|e| (e.seq, e.entry_hash.clone()));
                // If a previous tail exists in earlier segments but the last
                // segment is empty (shouldn't happen), fall back to scanning.
                let tail = tail.or_else(|| {
                    segs.iter().rev().find_map(|(_, p)| {
                        read_all(p)
                            .ok()?
                            .last()
                            .map(|e| (e.seq, e.entry_hash.clone()))
                    })
                });
                (*first, count, tail)
            }
            None => (1, 0, None),
        };

        let path = dir.join(segment_name(cur_first));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(SegmentedStore {
            dir,
            max_entries,
            file,
            cur_first,
            cur_count,
            tail,
        })
    }

    fn rotate_to(&mut self, first_seq: u64) -> Result<()> {
        let path = self.dir.join(segment_name(first_seq));
        self.file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.cur_first = first_seq;
        self.cur_count = 0;
        Ok(())
    }
}

impl Store for SegmentedStore {
    fn tail(&self) -> Result<Option<(u64, String)>> {
        Ok(self.tail.clone())
    }

    fn append(&mut self, entry: &AuditEntry) -> Result<()> {
        if self.cur_count >= self.max_entries {
            self.rotate_to(entry.seq)?;
        }
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.file.sync_all()?;
        self.cur_count += 1;
        self.tail = Some((entry.seq, entry.entry_hash.clone()));
        Ok(())
    }
}

/// Read every entry across all segments in `dir`, in chain order.
pub fn read_all_segmented(dir: impl AsRef<Path>) -> Result<Vec<AuditEntry>> {
    let mut out = Vec::new();
    for (_, path) in list_segments(dir.as_ref())? {
        out.extend(read_all(path)?);
    }
    Ok(out)
}

/// Prune whole segments whose entries are entirely older than `boundary_seq`,
/// keeping the segment that straddles the boundary and everything after it.
///
/// Returns the [`Anchor`] that the surviving log should be verified against
/// (the entry immediately before the new earliest entry). Returns `None` if
/// nothing was pruned or the log still begins at genesis. The current
/// (most-recent) segment is never deleted.
pub fn prune_before(dir: impl AsRef<Path>, boundary_seq: u64) -> Result<Option<Anchor>> {
    let dir = dir.as_ref();
    let segs = list_segments(dir)?;
    if segs.len() <= 1 {
        return Ok(None); // nothing safely prunable
    }

    // Delete segment i only if the *next* segment starts at or before the
    // boundary — i.e. segment i is entirely below it. Never touch the last.
    let mut deleted_any = false;
    for i in 0..segs.len() - 1 {
        let next_first = segs[i + 1].0;
        if next_first <= boundary_seq {
            std::fs::remove_file(&segs[i].1)?;
            deleted_any = true;
        } else {
            break; // segments are ordered; the rest straddle/exceed the boundary
        }
    }

    if !deleted_any {
        return Ok(None);
    }

    // Anchor = the entry just before the new earliest retained entry.
    let remaining = list_segments(dir)?;
    let first_entry = remaining
        .first()
        .and_then(|(_, p)| read_all(p).ok())
        .and_then(|v| v.into_iter().next());

    match first_entry {
        Some(e) if e.seq > 1 => Ok(Some(Anchor {
            seq: e.seq - 1,
            hash: e.prev_hash,
        })),
        _ => Ok(None),
    }
}

/// Convenience: prune everything strictly older than `cutoff_ms` (Unix millis),
/// based on entry timestamps. Returns the resulting [`Anchor`], if any.
pub fn prune_before_timestamp(dir: impl AsRef<Path>, cutoff_ms: i64) -> Result<Option<Anchor>> {
    let dir = dir.as_ref();
    // Find the first entry at or after the cutoff; prune before its seq.
    let boundary = read_all_segmented(dir)?
        .into_iter()
        .find(|e| e.timestamp >= cutoff_ms)
        .map(|e| e.seq);
    match boundary {
        Some(seq) => prune_before(dir, seq),
        None => Ok(None), // every entry is older; keep current segment anyway
    }
}
