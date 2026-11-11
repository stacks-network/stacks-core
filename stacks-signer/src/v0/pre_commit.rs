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

//! Pre-commit evaluation and retry scheduling.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use clarity::util::hash::Sha512Trunc256Sum;
use stacks_common::types::chainstate::StacksAddress;

/// Minimum spacing between full evaluations of repeated pre-commits for one block.
const RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound on tracked blocks.
const MAX_TRACKED: usize = 512;

/// Limit retry work in one signer pass when many blocks become due together.
const MAX_DUE_PER_PASS: usize = 8;

/// How long a block without a pending retry stays tracked after its last evaluation.
const IDLE_EXPIRY: Duration = Duration::from_secs(60);

/// Last full pre-commit evaluation of a block, and one sender to retry after the interval.
#[derive(Debug)]
struct Recheck {
    last_evaluated: Instant,
    pending_sender: Option<StacksAddress>,
}

/// Limits full evaluations of duplicate pre-commits to one per [`RECHECK_INTERVAL`] per block.
/// Duplicates within the interval are coalesced into one retry, keeping the latest sender.
#[derive(Debug, Default)]
pub struct PreCommitThrottle {
    rechecks: HashMap<Sha512Trunc256Sum, Recheck>,
}

impl PreCommitThrottle {
    /// Throttle a pre-commit for `block_hash` from `sender`. Otherwise record that the block is
    /// evaluated at `now`.
    ///
    /// Returns `true` if the pre-commit was throttled.
    pub fn throttle(
        &mut self,
        block_hash: &Sha512Trunc256Sum,
        sender: &StacksAddress,
        is_new: bool,
        now: Instant,
    ) -> bool {
        // A new sender is always evaluated. A duplicate arriving soon after the last evaluation is
        // coalesced into one retry instead: remember its sender so `take_due` returns it once the
        // interval has passed.
        if !is_new {
            let recent_recheck = self
                .rechecks
                .get_mut(block_hash)
                .filter(|recheck| now.duration_since(recheck.last_evaluated) < RECHECK_INTERVAL);

            if let Some(recheck) = recent_recheck {
                recheck.pending_sender = Some(sender.clone());
                return true;
            }
        }

        // Tracking a new block at capacity: evict the least recently evaluated block to keep the
        // map bounded.
        let is_tracked = self.rechecks.contains_key(block_hash);
        let is_at_capacity = self.rechecks.len() >= MAX_TRACKED;
        if !is_tracked && is_at_capacity {
            let oldest = self
                .rechecks
                .iter()
                .min_by_key(|(_, recheck)| recheck.last_evaluated)
                .map(|(hash, _)| hash.clone());

            if let Some(oldest) = oldest {
                self.rechecks.remove(&oldest);
            }
        }

        // Record this evaluation. It covers any deferred sender, so clear that too.
        let recheck = Recheck {
            last_evaluated: now,
            pending_sender: None,
        };
        self.rechecks.insert(block_hash.clone(), recheck);

        false
    }

    /// Take up to [`MAX_DUE_PER_PASS`] retries whose interval has passed at `now`, and stop
    /// tracking blocks idle for [`IDLE_EXPIRY`].
    ///
    /// Taking a retry does not record an evaluation: the caller re-runs it, and the resulting
    /// [`Self::throttle`] call records it.
    pub fn take_due(&mut self, now: Instant) -> Vec<(Sha512Trunc256Sum, StacksAddress)> {
        let mut due = Vec::new();

        self.rechecks.retain(|hash, recheck| {
            let age = now.duration_since(recheck.last_evaluated);

            if recheck.pending_sender.is_none() && age >= IDLE_EXPIRY {
                return false;
            }

            if due.len() < MAX_DUE_PER_PASS && age >= RECHECK_INTERVAL {
                if let Some(sender) = recheck.pending_sender.take() {
                    due.push((hash.clone(), sender));
                }
            }

            true
        });

        due
    }
}
