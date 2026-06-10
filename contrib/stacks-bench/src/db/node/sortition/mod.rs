// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use diesel::prelude::*;
use diesel::sql_query;
use diesel_async::RunQueryDsl;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

use crate::db::{DbOpen, SqliteDbHandle};

pub mod models;
pub mod schema;

#[derive(Clone)]
pub struct SortitionDb<Mode> {
    handle: SqliteDbHandle<Mode>,
    /// Whether the chainstate's sortition db has the post-Nakamoto
    /// `stacks_chain_tips_by_burn_view` table. Determined once at open
    /// time via sqlite_master introspection so the canonical-tip query
    /// can transparently union both tables when present.
    has_burn_view_table: bool,
}

impl<Mode> Deref for SortitionDb<Mode> {
    type Target = SqliteDbHandle<Mode>;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl<Mode> DerefMut for SortitionDb<Mode> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

#[derive(QueryableByName)]
struct TableExistsRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

impl<Mode> DbOpen<Mode> for SortitionDb<Mode>
where
    SqliteDbHandle<Mode>: DbOpen<Mode>,
    Mode: Send + Sync,
{
    async fn open<P: AsRef<Path> + Debug + Send>(path: P) -> Result<Self> {
        let handle = SqliteDbHandle::open(path).await?;
        // One-shot sqlite_master introspection: does the post-Nakamoto
        // canonical-tip table exist? Result drives query strategy in
        // `get_canonical_stacks_tip` without per-call branching.
        let has_burn_view_table = {
            let mut conn = handle.get_conn().await?;
            let row: TableExistsRow = sql_query(
                "SELECT COUNT(*) AS n FROM sqlite_master \
                 WHERE type = 'table' AND name = ?",
            )
            .bind::<diesel::sql_types::Text, _>("stacks_chain_tips_by_burn_view")
            .get_result(&mut conn)
            .await
            .context("Failed to introspect sortition db schema")?;
            row.n > 0
        };
        Ok(Self {
            handle,
            has_burn_view_table,
        })
    }
}

impl<Mode> SortitionDb<Mode> {
    pub async fn get_epochs(&mut self) -> Result<Vec<models::Epoch>> {
        use schema::epochs::dsl::*;

        epochs
            .load::<models::Epoch>(&mut self.handle.get_conn().await?)
            .await
            .context("Failed to load epochs from sortition db")
    }

    /// Resolve the canonical Stacks tip from the sortition db, transparently
    /// across the Epoch 3.0 (Nakamoto) storage migration.
    ///
    /// The canonical Stacks tip can live in three places, depending on the
    /// chainstate's age:
    ///
    /// 1. `stacks_chain_tips_by_burn_view` (post-Nakamoto authoritative; added
    ///    by stacks-core commit 5aa6af4e96)
    /// 2. `stacks_chain_tips` (pre-Nakamoto; populated by the schema-8 one-shot
    ///    backfill from snapshot rows)
    /// 3. `snapshots.canonical_stacks_tip_*` (very old chainstates that predate
    ///    the `stacks_chain_tips` table)
    ///
    /// Strategy: starting from the canonical burn-chain tip snapshot, walk back
    /// up the parent_sortition_id chain. At each step, check both tip tables
    /// (only if the by-burn-view table was detected at open time) and pick the
    /// row with the highest block_height. If we exhaust the parent walk without
    /// finding any row, fall back to the canonical_stacks_tip_* fields on the
    /// burn tip snapshot itself.
    pub async fn get_canonical_stacks_tip(&mut self) -> Result<(StacksBlockId, u64)> {
        use schema::snapshots::dsl as sn;
        use schema::stacks_chain_tips::dsl as sct_old;
        use schema::stacks_chain_tips_by_burn_view::dsl as sct_new;

        let mut conn = self.handle.get_conn().await?;

        // Canonical burn-chain tip: highest pox_valid=1 snapshot, ties broken
        // by burn_header_hash ASC.
        let tip_snapshot: models::Snapshot = sn::snapshots
            .filter(sn::pox_valid.eq(1))
            .order((sn::block_height.desc(), sn::burn_header_hash.asc()))
            .first(&mut conn)
            .await
            .context("Failed to get canonical burn chain tip")?;

        let mut current_snapshot = tip_snapshot.clone();
        loop {
            // Query `stacks_chain_tips_by_burn_view` if it exists (Nakamoto).
            let new_tip: Option<models::StacksChainTip> = if self.has_burn_view_table {
                sct_new::stacks_chain_tips_by_burn_view
                    .filter(sct_new::sortition_id.eq(&current_snapshot.sortition_id))
                    .order(sct_new::block_height.desc())
                    .first::<models::StacksChainTipByBurnView>(&mut conn)
                    .await
                    .optional()?
                    .map(Into::into)
            } else {
                None
            };

            // Always query `stacks_chain_tips` (pre-Nakamoto / schema-8 backfill).
            let old_tip: Option<models::StacksChainTip> = sct_old::stacks_chain_tips
                .filter(sct_old::sortition_id.eq(&current_snapshot.sortition_id))
                .order(sct_old::block_height.desc())
                .first(&mut conn)
                .await
                .optional()?;

            // Pick the higher of the two if both present; whichever exists otherwise.
            let chosen = match (new_tip, old_tip) {
                (Some(n), Some(o)) if n.block_height >= o.block_height => Some(n),
                (Some(_), Some(o)) => Some(o),
                (Some(n), None) => Some(n),
                (None, Some(o)) => Some(o),
                (None, None) => None,
            };

            if let Some(tip) = chosen {
                return Ok((
                    StacksBlockId::new(
                        &ConsensusHash::from_hex(&tip.consensus_hash)?,
                        &BlockHeaderHash::from_hex(&tip.block_hash)?,
                    ),
                    tip.block_height as u64,
                ));
            }

            // Walk to parent sortition.
            let parent_opt: Option<models::Snapshot> = sn::snapshots
                .filter(sn::sortition_id.eq(&current_snapshot.parent_sortition_id))
                .first(&mut conn)
                .await
                .optional()?;

            match parent_opt {
                Some(p) => current_snapshot = p,
                None => {
                    // Exhausted the parent walk without finding a row in either
                    // tip table. Fall back to the canonical_stacks_tip_* fields
                    // on the burn tip snapshot — the very-old-chainstate path.
                    if !tip_snapshot.canonical_stacks_tip_hash.is_empty()
                        && tip_snapshot.canonical_stacks_tip_height > 0
                    {
                        return Ok((
                            StacksBlockId::new(
                                &ConsensusHash::from_hex(
                                    &tip_snapshot.canonical_stacks_tip_consensus_hash,
                                )?,
                                &BlockHeaderHash::from_hex(
                                    &tip_snapshot.canonical_stacks_tip_hash,
                                )?,
                            ),
                            tip_snapshot.canonical_stacks_tip_height as u64,
                        ));
                    }
                    return Err(anyhow!(
                        "Failed to resolve canonical Stacks tip from sortition db: \
                         no rows in stacks_chain_tips{} matched any sortition in the \
                         parent walk, and the burn tip snapshot has no canonical \
                         tip recorded. Pass --tip <id> to override.",
                        if self.has_burn_view_table {
                            " or stacks_chain_tips_by_burn_view"
                        } else {
                            ""
                        }
                    ));
                }
            }
        }
    }
}
