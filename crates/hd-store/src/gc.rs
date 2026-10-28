//! Releasing what nothing needs any more. This is one of the two places in
//! shipped code allowed to delete files (the client's trash is the other),
//! and everything here deletes only what a rule proves is unneeded.
//!
//! Metadata pruning keeps the newest snapshots and every journal that any
//! of them might need. A journal is deleted only when the next journal
//! starts at or before the record after the oldest kept snapshot, which
//! means every record in it is already inside that snapshot. The newest
//! journal is never deleted.

use std::fs;
use std::path::Path;

use hd_common::Result;
use hd_common::fsio;

use crate::journal;
use crate::meta::{self, snapshot_name};

/// Deletes snapshots older than the newest `keep`, and journals that only
/// hold records the oldest kept snapshot already contains.
pub(crate) fn prune_meta(dir: &Path, keep: usize) -> Result<()> {
    let (snapshots, journals) = meta::listing(dir)?;
    let keep = keep.max(1);
    if snapshots.len() < keep {
        return Ok(());
    }
    let oldest_kept = snapshots[snapshots.len() - keep];
    let mut removed = false;
    for &seq in &snapshots[..snapshots.len() - keep] {
        fs::remove_file(dir.join(snapshot_name(seq)))?;
        removed = true;
    }
    for pair in journals.windows(2) {
        let (first, next_first) = (pair[0], pair[1]);
        if next_first <= oldest_kept + 1 {
            fs::remove_file(dir.join(journal::file_name(first)))?;
            removed = true;
        }
    }
    if removed {
        fsio::sync_directory(dir)?;
    }
    Ok(())
}
