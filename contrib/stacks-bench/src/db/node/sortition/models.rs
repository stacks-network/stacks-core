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

use anyhow::{Result, anyhow};
use diesel::backend::Backend;
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::prelude::*;
use diesel::sql_types::Text;
use diesel::sqlite::Sqlite;
use serde::Deserialize;
use stacks_common::types::StacksEpochId;

use super::schema;
use crate::ResolveEpochFromHeight;

#[derive(Debug, Deserialize, Clone, FromSqlRow)]
pub struct ExecutionCost {
    pub write_length: u64,
    pub write_count: u64,
    pub read_length: u64,
    pub read_count: u64,
    pub runtime: u64,
}

impl FromSql<Text, Sqlite> for ExecutionCost {
    fn from_sql(bytes: <Sqlite as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let s = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let cost = serde_json::from_str(&s)?;
        Ok(cost)
    }
}

#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = schema::epochs)]
pub struct Epoch {
    start_block_height: i64,
    end_block_height: i64,
    epoch_id: i32,
    #[diesel(column_name = block_limit)]
    pub block_limits: ExecutionCost,
    network_epoch: i32,
}

impl Epoch {
    pub fn epoch_id(&self) -> u32 {
        self.epoch_id as u32
    }

    pub fn to_stacks_epoch_id(&self) -> Result<StacksEpochId> {
        self.epoch_id()
            .try_into()
            .map_err(|e| anyhow!("Invalid StacksEpochId '{}': {e}", self.epoch_id))
    }

    pub fn network_epoch_id(&self) -> u32 {
        self.network_epoch as u32
    }

    pub fn start_block_height(&self) -> u64 {
        self.start_block_height as u64
    }

    pub fn end_block_height(&self) -> u64 {
        self.end_block_height as u64
    }
}

impl TryFrom<&Epoch> for crate::StacksEpoch {
    type Error = anyhow::Error;
    fn try_from(epoch: &Epoch) -> Result<Self> {
        Ok(Self {
            epoch_id: epoch.to_stacks_epoch_id()?,
            network_epoch_id: epoch.network_epoch_id(),
            start_block_height: epoch.start_block_height(),
            end_block_height: epoch.end_block_height(),
            write_count_budget: epoch.block_limits.write_count,
            write_length_budget: epoch.block_limits.write_length,
            read_count_budget: epoch.block_limits.read_count,
            read_length_budget: epoch.block_limits.read_length,
            runtime_budget: epoch.block_limits.runtime,
        })
    }
}

impl ResolveEpochFromHeight for [Epoch] {
    fn resolve_stacks_epoch(&self, height: u64) -> Option<StacksEpochId> {
        let height_i64: i64 = height.try_into().ok()?;
        for epoch in self {
            // Use half-open interval [start, end) to handle overlapping boundaries
            // where the end of one epoch is the start (activation) of the next.
            if height_i64 >= epoch.start_block_height && height_i64 < epoch.end_block_height {
                let epoch_id_u32: u32 = epoch.epoch_id.try_into().ok()?;
                let stacks_epoch_id: StacksEpochId = epoch_id_u32.try_into().ok()?;
                return Some(stacks_epoch_id);
            }
        }
        None
    }
}

#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = schema::snapshots)]
pub struct Snapshot {
    pub sortition_id: String,
    pub block_height: i64,
    pub burn_header_hash: String,
    pub parent_sortition_id: String,
    pub canonical_stacks_tip_hash: String,
    pub canonical_stacks_tip_consensus_hash: String,
    pub canonical_stacks_tip_height: i64,
    pub pox_valid: i32,
}

#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = schema::stacks_chain_tips)]
pub struct StacksChainTip {
    pub sortition_id: String,
    pub consensus_hash: String,
    pub block_hash: String,
    pub block_height: i64,
}

/// Post-Nakamoto canonical Stacks tip row. Same shape as [`StacksChainTip`]
/// for the columns we care about, plus a `burn_view_consensus_hash` we ignore.
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = schema::stacks_chain_tips_by_burn_view)]
pub struct StacksChainTipByBurnView {
    pub sortition_id: String,
    pub consensus_hash: String,
    pub burn_view_consensus_hash: String,
    pub block_hash: String,
    pub block_height: i64,
}

impl From<StacksChainTipByBurnView> for StacksChainTip {
    fn from(t: StacksChainTipByBurnView) -> Self {
        Self {
            sortition_id: t.sortition_id,
            consensus_hash: t.consensus_hash,
            block_hash: t.block_hash,
            block_height: t.block_height,
        }
    }
}
