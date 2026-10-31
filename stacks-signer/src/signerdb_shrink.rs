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

//! Shrinking of the signer db file at startup (`db_shrink`). Pruning frees pages that SQLite
//! reuses but never gives back to the OS, so the file keeps its peak size. When enough of it is
//! free, a `VACUUM` before the signer opens the database rebuilds the file with only its live
//! data. Its temporary copy goes next to the database, on the disk sized for it, never in memory:
//! running out of disk fails cleanly, whereas running out of memory can get the signer killed.
//!
//! It works on the file alone, through the SQLite maintenance helpers of
//! [`stacks_common::util::db`], and never migrates the database: the signer's own connections do
//! that right after, as on any start.

use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::Error as SqliteError;
use stacks_common::util::db::{
    is_busy, is_disk_full, sql_checkpoint_truncate, sql_space_usage, sql_vacuum_with_temp,
    sqlite_open_exclusive, SpaceUsage, VacuumTemp,
};
use stacks_common::{info, warn, MB};

/// Free space below which the file is not shrunk
const SHRINK_MIN_FREE_BYTES: u64 = MB!(256);
/// Live data above which the file is not shrunk
const SHRINK_MAX_LIVE_BYTES: u64 = MB!(1024);

/// The limits used at startup. A pruned database holds ~300 MiB of live data, so more than the
/// live data limit points to a problem rather than to something to compact.
const SHRINK_LIMITS: ShrinkLimits = ShrinkLimits {
    min_free_bytes: SHRINK_MIN_FREE_BYTES,
    max_live_bytes: SHRINK_MAX_LIVE_BYTES,
};

/// When shrinking is worth it, and when it is reasonable at startup (see [`skip_reason`])
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShrinkLimits {
    /// Free space below which shrinking gains too little to rewrite the file
    min_free_bytes: u64,
    /// Live data above which the file is not shrunk. Shrinking needs about twice the live data in
    /// free disk space next to the database (the temporary copy and the WAL), so this bounds
    /// that space, and the time the startup takes.
    max_live_bytes: u64,
}

/// Why the file is not shrunk
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    /// Too little free space to be worth it, e.g. a pruned database in its steady state, or
    /// one that has not been pruned yet
    LittleFree,
    /// Enough free space, but too much live data to shrink at startup
    LiveTooLarge,
}

/// What shrinking did
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShrinkOutcome {
    /// There is no database yet, e.g. on the first start
    NoDatabase,
    /// The file was left as it is
    Skipped {
        reason: SkipReason,
        space: SpaceUsage,
    },
    /// The file was rebuilt with only its live data
    Shrunk {
        before: SpaceUsage,
        after: SpaceUsage,
        elapsed: Duration,
    },
}

/// Why the file should not be shrunk, or `None` if it should
fn skip_reason(space: &SpaceUsage, limits: &ShrinkLimits) -> Option<SkipReason> {
    if space.free_bytes() < limits.min_free_bytes {
        Some(SkipReason::LittleFree)
    } else if space.live_bytes() > limits.max_live_bytes {
        Some(SkipReason::LiveTooLarge)
    } else {
        None
    }
}

/// Shrink the database at `db_path` if `limits` allow it. It works on the file alone, whatever
/// its schema. Run it before anything else in this process opens the database.
fn inner_shrink(db_path: &Path, limits: &ShrinkLimits) -> Result<ShrinkOutcome, SqliteError> {
    if !db_path.is_file() {
        return Ok(ShrinkOutcome::NoDatabase);
    }
    // Fails at once if another connection has the database open
    let conn = sqlite_open_exclusive(db_path)?;
    // Write the WAL back first, so that the file on disk matches the page counts and the
    // `VACUUM` starts from an empty WAL
    sql_checkpoint_truncate(&conn)?;
    let before = sql_space_usage(&conn)?;
    if let Some(reason) = skip_reason(&before, limits) {
        return Ok(ShrinkOutcome::Skipped {
            reason,
            space: before,
        });
    }
    info!("Shrinking the signer db";
        "file_mib" => mib(before.file_bytes()),
        "live_mib" => mib(before.live_bytes()),
        "free_mib" => mib(before.free_bytes()),
    );
    let started = Instant::now();
    sql_vacuum_with_temp(&conn, &VacuumTemp::Dir(db_dir(db_path).to_path_buf()))?;
    // Truncate the WAL the `VACUUM` wrote
    sql_checkpoint_truncate(&conn)?;
    Ok(ShrinkOutcome::Shrunk {
        before,
        after: sql_space_usage(&conn)?,
        elapsed: started.elapsed(),
    })
}

/// Shrink the database at `db_path`, if the conditions defined by [`SHRINK_LIMITS`] are met.
/// Run it before anything else in this process opens the database.
/// It never fails: every outcome is logged, and the signer starts as usual.
pub fn maybe_shrink(db_path: &Path) {
    match inner_shrink(db_path, &SHRINK_LIMITS) {
        Ok(ShrinkOutcome::NoDatabase) => info!("Signer db not shrunk: there is no database yet"),
        Ok(ShrinkOutcome::Skipped {
            reason: SkipReason::LittleFree,
            space,
        }) => info!("Signer db not shrunk: too little free space to be worth it";
            "file_mib" => mib(space.file_bytes()),
            "live_mib" => mib(space.live_bytes()),
            "free_mib" => mib(space.free_bytes()),
            "min_free_mib" => mib(SHRINK_LIMITS.min_free_bytes),
        ),
        Ok(ShrinkOutcome::Skipped {
            reason: SkipReason::LiveTooLarge,
            space,
        }) => {
            warn!("Signer db not shrunk: its live data is larger than expected";
                "file_mib" => mib(space.file_bytes()),
                "live_mib" => mib(space.live_bytes()),
                "free_mib" => mib(space.free_bytes()),
                "max_live_mib" => mib(SHRINK_LIMITS.max_live_bytes),
            )
        }
        Ok(ShrinkOutcome::Shrunk {
            before,
            after,
            elapsed,
        }) => info!("Signer db shrunk";
            "file_before_mib" => mib(before.file_bytes()),
            "file_after_mib" => mib(after.file_bytes()),
            "elapsed_ms" => elapsed.as_millis(),
        ),
        Err(e) if is_busy(&e) => warn!(
            "Signer db not shrunk: another process has it open";
            "db_path" => %db_path.display(),
        ),
        Err(e) if is_disk_full(&e) => warn!(
            "Signer db not shrunk: not enough disk space. Shrinking needs about twice the size of its live data free next to it; the database is unchanged";
            "db_path" => %db_path.display(),
        ),
        Err(e) => warn!(
            "Signer db not shrunk; the database is unchanged";
            "db_path" => %db_path.display(),
            "err" => ?e,
        ),
    }
}

/// The directory of the database at `db_path`, where its temporary copy goes while shrinking
fn db_dir(db_path: &Path) -> &Path {
    match db_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        // A bare file name: the current directory
        _ => Path::new("."),
    }
}

/// A size in whole MiB, for the logs
fn mib(bytes: u64) -> u64 {
    bytes / MB!(1)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use rusqlite::Connection;
    use stacks_common::types::chainstate::ConsensusHash;

    use super::*;
    use crate::signerdb::tests::{create_block_override, prune_test_table_count, tmp_db_path};
    use crate::signerdb::SignerDb;

    /// Size of a file, or 0 if it does not exist
    fn file_size(path: &Path) -> u64 {
        fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    /// The WAL file of the database at `db_path`
    fn wal_path(db_path: &Path) -> PathBuf {
        let mut wal = db_path.as_os_str().to_owned();
        wal.push("-wal");
        PathBuf::from(wal)
    }

    /// A signer db file with `blocks` blocks stored, then all but `kept` deleted, and its WAL
    /// checkpointed: most of the file is on the freelist. The blocks are stored the way a signer
    /// stores them; the rest goes through a plain connection, since shrinking only sees the file.
    fn bloated_db(blocks: u64, kept: u64) -> PathBuf {
        let path = tmp_db_path();
        let mut db = SignerDb::new(&path).unwrap();
        for height in 0..blocks {
            let (block, _) = create_block_override(|b| {
                b.block.header.consensus_hash = ConsensusHash([0x01; 20]);
                b.block.header.chain_length = height;
            });
            db.insert_block(&block).unwrap();
        }
        drop(db);
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM blocks WHERE stacks_height >= ?1", [kept])
            .unwrap();
        sql_checkpoint_truncate(&conn).unwrap();
        path
    }

    /// A space usage of `live` and `free` MiB, in 4 KiB pages
    fn space(live_mib: u64, free_mib: u64) -> SpaceUsage {
        let pages_per_mib = MB!(1) / 4096;
        SpaceUsage {
            page_size: 4096,
            page_count: (live_mib + free_mib) * pages_per_mib,
            freelist_count: free_mib * pages_per_mib,
        }
    }

    /// Limits small enough for the test databases: shrink with at least one free page, and at
    /// most 1 MiB of live data
    fn small_limits() -> ShrinkLimits {
        ShrinkLimits {
            min_free_bytes: 1,
            max_live_bytes: MB!(1),
        }
    }

    #[test]
    fn test_skip_reason() {
        let cases = [
            // A bloated mock signer: 296 MiB live, 8.2 GiB free
            (space(296, 8_400), None),
            // After a long stop: 240 MiB live, 132 MiB free, slack that later writes reuse
            (space(240, 132), Some(SkipReason::LittleFree)),
            // Steady state: a few MiB free
            (space(300, 5), Some(SkipReason::LittleFree)),
            // Not pruned yet: 40 GiB live, little free
            (space(40_960, 10), Some(SkipReason::LittleFree)),
            // Drained by pruning: 0.3 GiB live, 39.7 GiB free
            (space(300, 40_650), None),
            // Grown live data, e.g. an unpruned table: 1.4 GiB live, 4.6 GiB free
            (space(1_434, 4_710), Some(SkipReason::LiveTooLarge)),
            // At the limits
            (space(1_024, 256), None),
            (space(1_024, 255), Some(SkipReason::LittleFree)),
            (space(1_025, 256), Some(SkipReason::LiveTooLarge)),
        ];
        for (space, expected) in cases {
            assert_eq!(skip_reason(&space, &SHRINK_LIMITS), expected, "{space:?}");
        }
    }

    #[test]
    fn test_shrinks_a_bloated_database() {
        let path = bloated_db(300, 10);
        let ShrinkOutcome::Shrunk { before, after, .. } =
            inner_shrink(&path, &small_limits()).unwrap()
        else {
            panic!("not shrunk");
        };
        assert!(before.free_bytes() > before.live_bytes(), "{before:?}");
        assert_eq!(after.freelist_count, 0);
        assert!(
            after.file_bytes() <= before.live_bytes(),
            "{after:?} {before:?}"
        );
        assert_eq!(file_size(&path), after.file_bytes());
        assert_eq!(file_size(&wal_path(&path)), 0);
        // The signer then opens it as usual, with its data intact
        assert_eq!(
            prune_test_table_count(&SignerDb::new(&path).unwrap(), "blocks"),
            10
        );
    }

    #[test]
    fn test_db_dir() {
        assert_eq!(
            db_dir(Path::new("/var/lib/signer/signerdb.sqlite")),
            Path::new("/var/lib/signer")
        );
        assert_eq!(db_dir(Path::new("data/signerdb.sqlite")), Path::new("data"));
        assert_eq!(db_dir(Path::new("signerdb.sqlite")), Path::new("."));
    }

    #[test]
    fn test_leaves_the_file_when_not_worth_it() {
        let path = bloated_db(300, 10);
        let size = file_size(&path);
        let limits = ShrinkLimits {
            min_free_bytes: size,
            ..small_limits()
        };
        let outcome = inner_shrink(&path, &limits).unwrap();
        assert!(
            matches!(
                outcome,
                ShrinkOutcome::Skipped {
                    reason: SkipReason::LittleFree,
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(file_size(&path), size);
    }

    #[test]
    fn test_leaves_the_file_when_the_live_data_is_too_large() {
        let path = bloated_db(300, 10);
        let size = file_size(&path);
        let limits = ShrinkLimits {
            max_live_bytes: 1,
            ..small_limits()
        };
        let outcome = inner_shrink(&path, &limits).unwrap();
        assert!(
            matches!(
                outcome,
                ShrinkOutcome::Skipped {
                    reason: SkipReason::LiveTooLarge,
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(file_size(&path), size);
    }

    #[test]
    fn test_creates_no_database() {
        let path = tmp_db_path();
        assert_eq!(
            inner_shrink(&path, &small_limits()).unwrap(),
            ShrinkOutcome::NoDatabase
        );
        assert!(!path.exists());
        maybe_shrink(&path);
        assert!(!path.exists());
    }

    #[test]
    fn test_leaves_a_database_in_use() {
        let path = bloated_db(300, 10);
        let size = file_size(&path);
        // A connection opened the way a signer opens it
        let signer = SignerDb::new(&path).unwrap();

        let start = Instant::now();
        let err = inner_shrink(&path, &small_limits()).unwrap_err();
        assert!(is_busy(&err), "{err:?}");
        assert!(start.elapsed() < Duration::from_secs(1));
        maybe_shrink(&path);

        drop(signer);
        assert_eq!(file_size(&path), size);
    }
}
