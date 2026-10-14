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

//! [`crate::signerdb::SignerDb::prune`] decides what one pass deletes. This module decides when
//! a pass runs and how much it does, and reports on it.

use std::path::Path;
use std::time::{Duration, Instant};

use blockstack_lib::util_lib::db::Error as DBError;
use stacks_common::{debug, info, warn};

use crate::signerdb::{PruneParams, PruneStats, SignerDb, MAX_FORK_DEPTH};

/// How often a pruning pass runs. The runloop checks it on every pass, whatever the event, so it
/// does not depend on the event stream going quiet.
pub const PRUNE_INTERVAL: Duration = Duration::from_secs(10);
/// The parameters of every pruning pass (see [`PruneParams`]).
const PRUNE_PARAMS: PruneParams = PruneParams {
    // Blocks are counted in Stacks blocks because they carry almost all of the cost of a pass.
    // Together with `PRUNE_INTERVAL` this bounds the time spent pruning, and drains an existing
    // backlog over repeated passes.
    batch_size: 100,
    // The signer's own fork depth
    fork_depth: MAX_FORK_DEPTH,
    // Twice the fork horizon at the 10 minute mean Bitcoin block interval (~33 h), on top of the
    // horizon's own depth: far longer than any sortition stays current
    orphaned_update_max_age: Duration::from_secs(2 * MAX_FORK_DEPTH * 600),
};
/// A pruning pass slower than this is logged as a warning.
const PRUNE_SLOW_PASS: Duration = Duration::from_millis(500);

/// Runs bounded pruning passes over the signer db on a fixed schedule, through its own
/// connection. All signers of a process share one database file, and what a pass deletes is
/// derived from that file alone, so one pruner serves the whole process whether or not a signer
/// is registered.
pub struct SignerDbPruner {
    /// Connection used only for pruning
    db: SignerDb,
    /// When the last pass ran, or when the pruner was created
    last_pass: Instant,
    /// Whether the last pass was skipped. Used only to log when
    /// pruning starts and stops being skipped, not on every pass.
    skipped: bool,
}

impl SignerDbPruner {
    /// Open a pruning connection to the signer db at `db_path`. The first pass runs
    /// [`PRUNE_INTERVAL`] after `now`.
    pub fn new(db_path: impl AsRef<Path>, now: Instant) -> Result<Self, DBError> {
        Ok(Self {
            db: SignerDb::new(db_path)?,
            last_pass: now,
            skipped: false,
        })
    }

    /// Run one pruning pass if [`PRUNE_INTERVAL`] has passed since the last one. Failures are
    /// logged and never fatal: the next pass simply tries again.
    pub fn maybe_prune(&mut self, now: Instant) {
        if !self.is_due(now) {
            return;
        }
        let started = Instant::now();
        let result = self.db.prune(&PRUNE_PARAMS);
        self.record(&result, started.elapsed());
    }

    /// Whether a pass is due at `now`. If so, the next interval starts at `now`.
    fn is_due(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.last_pass) < PRUNE_INTERVAL {
            return false;
        }
        self.last_pass = now;
        true
    }

    /// Log the outcome of one pass
    fn record(&mut self, result: &Result<PruneStats, DBError>, elapsed: Duration) {
        let elapsed_ms = elapsed.as_millis();
        let stats = match result {
            Ok(stats) => stats,
            Err(e) => {
                warn!("Failed to prune the signer db"; "err" => ?e, "elapsed_ms" => elapsed_ms);
                return;
            }
        };
        if elapsed > PRUNE_SLOW_PASS {
            warn!("Signer db pruning pass was slow"; "elapsed_ms" => elapsed_ms);
        }
        let skipped = stats.is_skipped();
        if skipped != self.skipped {
            if skipped {
                info!(
                    "Signer db pruning skipped: the fork horizon cannot be placed from local data"
                );
            } else {
                info!("Signer db pruning resumed"; "cutoff_height" => ?stats.cutoff_height);
            }
            self.skipped = skipped;
        }
        if stats.removed_any() {
            debug!("Signer db pruned";
                "cutoff_height" => ?stats.cutoff_height,
                "blocks" => stats.blocks,
                "block_rows" => stats.block_rows,
                "other_rows" => stats.other_rows,
                "elapsed_ms" => elapsed_ms,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signerdb::tests::{prune_test_seed_data, prune_test_table_count, tmp_db_path};

    #[test]
    fn test_runs_a_pass_only_once_the_interval_has_passed() {
        let path = tmp_db_path();
        let start = Instant::now();
        let mut pruner = SignerDbPruner::new(&path, start).unwrap();
        // the signers write through their own connection to the same file
        let mut signer_db = SignerDb::new(&path).unwrap();
        prune_test_seed_data(&mut signer_db);
        assert_eq!(prune_test_table_count(&signer_db, "blocks"), 8);

        // not due yet
        pruner.maybe_prune(start + PRUNE_INTERVAL / 2);
        assert_eq!(prune_test_table_count(&signer_db, "blocks"), 8);

        // due: the two tenures elected before the tenure in charge go
        let first = start + PRUNE_INTERVAL;
        pruner.maybe_prune(first);
        assert_eq!(prune_test_table_count(&signer_db, "blocks"), 4);
        assert!(!pruner.skipped);

        // the next interval starts at the pass that ran, not at creation
        assert!(!pruner.is_due(first + PRUNE_INTERVAL / 2));
        assert!(pruner.is_due(first + PRUNE_INTERVAL));
    }

    #[test]
    fn test_tracks_whether_passes_are_skipped() {
        let path = tmp_db_path();
        let start = Instant::now();
        let mut pruner = SignerDbPruner::new(&path, start).unwrap();

        // a new database has no fork horizon yet
        pruner.maybe_prune(start + PRUNE_INTERVAL);
        assert!(pruner.skipped);

        // once the chain data is there, pruning resumes
        let mut signer_db = SignerDb::new(&path).unwrap();
        prune_test_seed_data(&mut signer_db);
        pruner.maybe_prune(start + PRUNE_INTERVAL * 2);
        assert!(!pruner.skipped);
        assert_eq!(prune_test_table_count(&signer_db, "blocks"), 4);
    }
}
