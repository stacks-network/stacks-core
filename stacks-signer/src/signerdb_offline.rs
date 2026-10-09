// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Offline maintenance of the signer db, run with the signer stopped (`stacks-signer prune-db`):
//! prune it at full speed with the same rules as the online pruner, then compact its file so the
//! freed space goes back to the OS.

use std::fmt::{self, Display};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use blockstack_lib::util_lib::db::Error as DBError;
use rusqlite::{Error as SqliteError, ErrorCode};
use stacks_common::{info, MB};

use crate::signerdb::{PruneHorizon, PruneParams, PruneStats, SignerDb, SpaceUsage, VacuumTemp};
use crate::signerdb_pruner::PRUNE_PARAMS;

/// Default number of blocks removed per pruning transaction
pub const DEFAULT_BATCH_SIZE: u64 = 1_000;
/// Live data up to which `VACUUM` builds its temporary copy in memory, unless a temporary
/// directory is given
const VACUUM_IN_MEMORY_MAX_BYTES: u64 = MB!(1024);
/// Pruning passes between two WAL checkpoints, so the WAL stays small however large the backlog
const PASSES_PER_CHECKPOINT: u64 = 10;

/// What [`prune_offline`] does
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePruneOptions {
    /// Blocks removed per pruning transaction
    pub batch_size: u64,
    /// Whether to compact the file with `VACUUM` after pruning
    pub vacuum: bool,
    /// Where `VACUUM` builds its temporary copy. If `None`, in memory when the live data is small
    /// enough, else in SQLite's default temporary directory.
    pub temp_dir: Option<PathBuf>,
    /// Report only: remove and compact nothing, and do not migrate the database
    pub dry_run: bool,
}

impl Default for OfflinePruneOptions {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            vacuum: true,
            temp_dir: None,
            dry_run: false,
        }
    }
}

/// What [`prune_offline`] did
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePruneReport {
    /// The database file
    pub db_path: PathBuf,
    /// Whether nothing was changed (`--dry-run`)
    pub dry_run: bool,
    /// The file before pruning
    pub before: SpaceUsage,
    /// Blocks stored before pruning
    pub blocks_before: u64,
    /// Where the fork horizon was placed before pruning; `None` if it could not be placed, in
    /// which case nothing is pruned
    pub horizon: Option<PruneHorizon>,
    /// What all the pruning passes removed
    pub removed: PruneStats,
    /// Pruning passes that removed something
    pub passes: u64,
    /// Time spent pruning
    pub prune_time: Duration,
    /// Where `VACUUM` built its temporary copy, and how long it took; `None` if it did not run
    pub vacuum: Option<(VacuumTemp, Duration)>,
    /// The file after pruning and compacting
    pub after: SpaceUsage,
    /// Blocks stored after pruning
    pub blocks_after: u64,
}

/// Whether `error` means another connection holds the database, e.g. from
/// [`SignerDb::open_exclusive`] while a signer is running
pub fn is_database_in_use(error: &DBError) -> bool {
    matches!(
        error,
        DBError::SqliteError(SqliteError::SqliteFailure(e, _))
            if matches!(e.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

/// Whether `error` means the disk ran out of space, e.g. during `VACUUM`
pub fn is_disk_full(error: &DBError) -> bool {
    matches!(
        error,
        DBError::SqliteError(SqliteError::SqliteFailure(e, _)) if e.code == ErrorCode::DiskFull
    )
}

/// Prune the signer db at `db_path` with the online pruner's rules until nothing is left to
/// remove, then compact its file in place, unless `options` says otherwise.
///
/// The database must not be in use: it is opened with [`SignerDb::open_exclusive`], which fails
/// at once if a signer has it open (see [`is_database_in_use`]).
///
/// Each pruning pass is its own transaction and `VACUUM` is transactional, so an interrupted or
/// failed run leaves a consistent database, pruned as far as it got; running again continues.
pub fn prune_offline(
    db_path: &Path,
    options: &OfflinePruneOptions,
) -> Result<OfflinePruneReport, DBError> {
    if let Some(dir) = &options.temp_dir {
        if !dir.is_dir() {
            return Err(DBError::Other(format!(
                "temporary directory {} does not exist",
                dir.display()
            )));
        }
    }
    let mut db = SignerDb::open_exclusive(db_path, !options.dry_run)?;
    if !options.dry_run {
        // Start from a database file that holds everything, so the report adds up
        db.checkpoint()?;
    }
    let params = PruneParams {
        batch_size: options.batch_size,
        ..PRUNE_PARAMS
    };
    let before = db.space_usage()?;
    let blocks_before = db.block_count()?;
    let mut report = OfflinePruneReport {
        db_path: db_path.to_path_buf(),
        dry_run: options.dry_run,
        before,
        blocks_before,
        horizon: db.prune_horizon(&params)?,
        removed: PruneStats::skipped(),
        passes: 0,
        prune_time: Duration::ZERO,
        vacuum: None,
        after: before,
        blocks_after: blocks_before,
    };
    if options.dry_run {
        return Ok(report);
    }

    let started = Instant::now();
    loop {
        let stats = db.prune(&params)?;
        if !stats.removed_any() {
            break;
        }
        report.removed.add(&stats);
        report.passes += 1;
        if report.passes.is_multiple_of(PASSES_PER_CHECKPOINT) {
            db.checkpoint()?;
            info!("Pruning the signer db";
                "passes" => report.passes,
                "blocks_removed" => report.removed.blocks,
            );
        }
    }
    report.prune_time = started.elapsed();
    db.checkpoint()?;

    if options.vacuum {
        let temp = match &options.temp_dir {
            Some(dir) => VacuumTemp::Dir(dir.clone()),
            None if db.space_usage()?.live_bytes() <= VACUUM_IN_MEMORY_MAX_BYTES => {
                VacuumTemp::Memory
            }
            None => VacuumTemp::SystemDefault,
        };
        info!("Compacting the signer db"; "temp" => ?temp);
        let started = Instant::now();
        db.vacuum(&temp)?;
        db.checkpoint()?;
        report.vacuum = Some((temp, started.elapsed()));
    }

    report.after = db.space_usage()?;
    report.blocks_after = db.block_count()?;
    Ok(report)
}

/// A size in bytes, for people
fn human(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    let mb = bytes as f64 / MB;
    if mb >= 1024.0 {
        format!("{:.2} GB", mb / 1024.0)
    } else {
        format!("{mb:.1} MB")
    }
}

fn space_line(space: &SpaceUsage, blocks: u64) -> String {
    format!(
        "file {} | live {} | free {} | {blocks} blocks",
        human(space.file_bytes()),
        human(space.live_bytes()),
        human(space.free_bytes()),
    )
}

impl Display for OfflinePruneReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Signer db: {}", self.db_path.display())?;
        writeln!(
            f,
            "Before:  {}",
            space_line(&self.before, self.blocks_before)
        )?;
        match &self.horizon {
            Some(h) => writeln!(
                f,
                "Horizon: burn tip {} | tenure in charge elected at {} | cutoff stacks height {}",
                h.burn_tip, h.in_charge_burn_height, h.cutoff_height
            )?,
            None => writeln!(
                f,
                "Horizon: cannot be placed from the data in the database (e.g. no accepted tenure \
                 near it after a long stop): nothing is pruned"
            )?,
        }
        if self.dry_run {
            // A VACUUM needs about the live data twice: a WAL next to the database, and the
            // temporary copy. Pruning first only lowers it.
            return writeln!(
                f,
                "Dry run: nothing changed. Compacting needs at most {} free next to the database, \
                 and as much again in memory or in the temporary directory; less once pruned.",
                human(self.before.live_bytes())
            );
        }
        writeln!(
            f,
            "Pruned:  {} blocks, {} block rows, {} other rows in {} passes ({:.1} s)",
            self.removed.blocks,
            self.removed.block_rows,
            self.removed.other_rows,
            self.passes,
            self.prune_time.as_secs_f64()
        )?;
        match &self.vacuum {
            Some((temp, time)) => {
                let temp = match temp {
                    VacuumTemp::Memory => "in memory".to_string(),
                    VacuumTemp::Dir(dir) => format!("in {}", dir.display()),
                    VacuumTemp::SystemDefault => "in the system temporary directory".to_string(),
                };
                writeln!(
                    f,
                    "Vacuum:  in place, temporary copy {temp}, {:.1} s",
                    time.as_secs_f64()
                )?
            }
            None => writeln!(
                f,
                "Vacuum:  skipped; the freed space stays in the file and is reused"
            )?,
        }
        writeln!(f, "After:   {}", space_line(&self.after, self.blocks_after))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::signerdb::tests::{
        create_block_override, prune_test_seed_data, prune_test_table_count, tmp_db_path,
    };
    use crate::signerdb::BlockState;

    fn file_size(path: &Path) -> u64 {
        fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    /// A database with the shared seed data (burn tip 300, horizon 200, tenure in charge elected
    /// at 190 with cutoff 5; 8 blocks, 4 of them removable) plus `extra` more removable blocks:
    /// competing proposals at height 1 in the oldest tenure, so the backlog spans many batches
    fn seeded_db(extra: u64) -> PathBuf {
        let path = tmp_db_path();
        let mut db = SignerDb::new(&path).unwrap();
        let seeded = prune_test_seed_data(&mut db);
        let oldest = db.block_lookup(&seeded[0]).unwrap().unwrap();
        for i in 0..extra {
            let mut block = oldest.clone();
            // a different header, so a different block
            block.block.header.timestamp = i + 1;
            db.insert_block(&block).unwrap();
        }
        drop(db);
        path
    }

    #[test]
    fn test_prune_offline_drains_the_backlog_and_compacts() {
        let path = seeded_db(250);
        let options = OfflinePruneOptions {
            batch_size: 10,
            ..OfflinePruneOptions::default()
        };
        let report = prune_offline(&path, &options).unwrap();

        // the seed's two removable tenures: 4 blocks, plus the 250 extra ones
        assert_eq!(report.removed.blocks, 254);
        assert!(report.passes > 25, "{report:?}");
        assert_eq!(report.blocks_before - report.blocks_after, 254);
        assert!(report.horizon.is_some());
        assert_eq!(
            report.vacuum.as_ref().map(|v| &v.0),
            Some(&VacuumTemp::Memory)
        );
        assert_eq!(report.after.freelist_count, 0);
        assert!(report.after.file_bytes() < report.before.file_bytes());
        assert_eq!(file_size(&path), report.after.file_bytes());

        // Same end state as the online pruner: nothing left for it to do
        let mut db = SignerDb::new(&path).unwrap();
        assert!(!db.prune(&PRUNE_PARAMS).unwrap().removed_any());
        assert_eq!(prune_test_table_count(&db, "blocks"), 4);
    }

    #[test]
    fn test_prune_offline_without_vacuum_keeps_the_file_size() {
        let path = seeded_db(250);
        let options = OfflinePruneOptions {
            vacuum: false,
            ..OfflinePruneOptions::default()
        };
        let report = prune_offline(&path, &options).unwrap();

        assert_eq!(report.removed.blocks, 254);
        assert!(report.vacuum.is_none());
        assert_eq!(report.after.file_bytes(), report.before.file_bytes());
        assert!(report.after.freelist_count > report.before.freelist_count);
    }

    #[test]
    fn test_prune_offline_with_a_temp_dir() {
        let path = seeded_db(50);
        let options = OfflinePruneOptions {
            temp_dir: Some(std::env::temp_dir()),
            ..OfflinePruneOptions::default()
        };
        let report = prune_offline(&path, &options).unwrap();
        assert_eq!(
            report.vacuum.map(|v| v.0),
            Some(VacuumTemp::Dir(std::env::temp_dir()))
        );
        assert_eq!(report.after.freelist_count, 0);
    }

    #[test]
    fn test_prune_offline_refuses_a_missing_temp_dir_before_changing_anything() {
        let path = seeded_db(50);
        let size = file_size(&path);
        let options = OfflinePruneOptions {
            temp_dir: Some(std::env::temp_dir().join(format!("missing-{}", rand::random::<u64>()))),
            ..OfflinePruneOptions::default()
        };
        prune_offline(&path, &options).unwrap_err();

        assert_eq!(file_size(&path), size);
        let db = SignerDb::new(&path).unwrap();
        assert_eq!(prune_test_table_count(&db, "blocks"), 8 + 50);
    }

    #[test]
    fn test_prune_offline_dry_run_changes_nothing() {
        let path = seeded_db(50);
        let size = file_size(&path);
        let options = OfflinePruneOptions {
            dry_run: true,
            ..OfflinePruneOptions::default()
        };
        let report = prune_offline(&path, &options).unwrap();

        assert_eq!(report.removed, PruneStats::skipped());
        assert_eq!(report.passes, 0);
        assert!(report.vacuum.is_none());
        assert_eq!(report.after, report.before);
        let horizon = report.horizon.unwrap();
        assert_eq!(horizon.burn_tip, 300);
        assert_eq!(horizon.in_charge_burn_height, 190);
        assert_eq!(horizon.cutoff_height, 5);
        assert!(report.to_string().contains("Dry run: nothing changed"));

        assert_eq!(file_size(&path), size);
        let db = SignerDb::new(&path).unwrap();
        assert_eq!(prune_test_table_count(&db, "blocks"), 8 + 50);
    }

    #[test]
    fn test_prune_offline_without_a_horizon_still_compacts() {
        // Blocks but no burn blocks: the fork horizon cannot be placed
        let path = tmp_db_path();
        let mut db = SignerDb::new(&path).unwrap();
        for i in 0..20 {
            let (mut block, _) = create_block_override(|b| b.block.header.chain_length = i);
            block.state = BlockState::GloballyAccepted;
            db.insert_block(&block).unwrap();
        }
        drop(db);

        let report = prune_offline(&path, &OfflinePruneOptions::default()).unwrap();
        assert!(report.horizon.is_none());
        assert_eq!(report.removed, PruneStats::skipped());
        assert_eq!(report.blocks_after, 20);
        assert!(report.vacuum.is_some());
        assert_eq!(report.after.freelist_count, 0);
        assert!(report.to_string().contains("cannot be placed"));
    }

    #[test]
    fn test_prune_offline_refuses_a_database_in_use() {
        let path = seeded_db(10);
        let _signer = SignerDb::new(&path).unwrap();
        let err = prune_offline(&path, &OfflinePruneOptions::default()).unwrap_err();
        assert!(is_database_in_use(&err), "{err:?}");
    }

    #[test]
    fn test_report_formatting() {
        let path = seeded_db(30);
        let report = prune_offline(&path, &OfflinePruneOptions::default()).unwrap();
        let text = report.to_string();
        for line in [
            "Signer db: ",
            "Before:  file ",
            "Horizon: burn tip 300 | tenure in charge elected at 190 | cutoff stacks height 5",
            "Pruned:  34 blocks",
            "Vacuum:  in place, temporary copy in memory",
            "After:   file ",
        ] {
            assert!(text.contains(line), "missing {line:?} in:\n{text}");
        }
    }
}
