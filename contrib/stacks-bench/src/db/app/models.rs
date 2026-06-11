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
use chrono::NaiveDateTime;
use diesel::prelude::*;
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};

use super::schema::{
    _staged_profiler_record_clarity_costs, _staged_profiler_record_kv, _staged_stacks_block,
    _staged_stacks_tx, benchmark_run, block_processing_baseline, burn_block, chainstate, epoch,
    network, profiler_location, profiler_record, profiler_record_clarity_costs, profiler_span,
    stacks_block, stacks_block_stats, stacks_tx, stacks_tx_stats,
};
use crate::ResolveEpochFromHeight;
use crate::db::app::schema::{
    chain_tip_cache, contract, contract_fn, principal, profiler_tag, stacks_tx_type,
    synthetic_block,
};

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = network)]
pub struct Network {
    pub id: i32,
    pub name: String,
}

impl Network {
    pub const MAINNET: i32 = 1;
    pub const TESTNET: i32 = 2;
    pub const REGTEST: i32 = 3;
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(Network))]
#[diesel(table_name = chainstate)]
pub struct Chainstate {
    pub id: i32,
    pub network_id: i32,
    pub chain_id: i64,
    pub tip_index_hash: Vec<u8>,
    pub tip_height: i64,
    pub epochs_hash: Vec<u8>,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(Chainstate))]
#[diesel(table_name = epoch)]
pub struct Epoch {
    pub id: i32,
    pub chainstate_id: i32,
    pub stacks_epoch_id: i32,
    pub network_epoch_id: i32,
    pub start_height: i64,
    pub end_height: i64,
    pub write_length_budget: i64,
    pub write_count_budget: i64,
    pub read_length_budget: i64,
    pub read_count_budget: i64,
    pub runtime_budget: i64,
}

impl Epoch {
    pub fn try_get_stacks_epoch_id(&self) -> Result<StacksEpochId> {
        (self.stacks_epoch_id as u32)
            .try_into()
            .map_err(|e| anyhow!("Invalid StacksEpochId '{}': {e}", self.stacks_epoch_id))
    }
}

impl ResolveEpochFromHeight for [Epoch] {
    fn resolve_stacks_epoch(&self, height: u64) -> Option<StacksEpochId> {
        let height_i64: i64 = height.try_into().ok()?;
        for epoch in self {
            // Use half-open interval [start, end) to handle overlapping boundaries
            // where the end of one epoch is the start (activation) of the next.
            if height_i64 >= epoch.start_height && height_i64 < epoch.end_height {
                let epoch_id_u32: u32 = epoch.stacks_epoch_id.try_into().ok()?;
                let stacks_epoch_id: StacksEpochId = epoch_id_u32.try_into().ok()?;
                return Some(stacks_epoch_id);
            }
        }
        None
    }
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone, PartialEq, Eq, Hash)]
#[diesel(table_name = stacks_tx_type)]
#[diesel(treat_none_as_null = true)]
pub struct StacksTxType {
    pub id: i32,
    pub name: String,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = principal)]
#[diesel(treat_none_as_null = true)]
pub struct Principal {
    pub id: i32,
    pub address: String,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(Principal, foreign_key = issuer_principal_id))]
#[diesel(table_name = contract)]
#[diesel(treat_none_as_null = true)]
pub struct Contract {
    pub id: i32,
    pub issuer_principal_id: i32,
    pub name: String,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(Contract, foreign_key = contract_id))]
#[diesel(table_name = contract_fn)]
#[diesel(treat_none_as_null = true)]
pub struct ContractFn {
    pub id: i32,
    pub contract_id: i32,
    pub name: String,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = burn_block)]
pub struct BurnBlock {
    pub id: i64,
    pub block_hash: Vec<u8>,
    pub block_hash_hex: String,
    pub height: i64,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(BurnBlock))]
#[diesel(table_name = stacks_block)]
#[diesel(treat_none_as_null = true)]
pub struct StacksBlock {
    pub id: i64,
    pub index_hash: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub block_hash_hex: String,
    pub height: i64,
    pub parent_stacks_block_id: Option<i64>,
    pub burn_block_id: i64,
    pub txs_indexed: bool,
}

impl TryFrom<(StacksBlock, BurnBlock, Option<Vec<u8>>)> for crate::StacksBlockHeader {
    type Error = anyhow::Error;

    fn try_from(
        (s_block, b_block, parent_hash_bytes): (StacksBlock, BurnBlock, Option<Vec<u8>>),
    ) -> Result<Self, Self::Error> {
        let id = StacksBlockId::from_vec(&s_block.index_hash)
            .ok_or_else(|| anyhow!("Invalid index hash in DB"))?;

        let block_hash = BlockHeaderHash::from_vec(&s_block.block_hash)
            .ok_or_else(|| anyhow!("Invalid block hash in DB"))?;

        let parent_id = if s_block.height == 0 {
            StacksBlockId::from_vec(&[255u8; 32]) // Genesis parent is all-0xff
                .ok_or_else(|| anyhow!("Invalid genesis parent index hash"))?
        } else {
            let parent_hash_bytes =
                parent_hash_bytes.ok_or_else(|| anyhow!("Missing parent index hash in DB"))?;
            StacksBlockId::from_vec(&parent_hash_bytes)
                .ok_or_else(|| anyhow!("Invalid parent index hash in DB"))?
        };

        let burn_hash = BurnchainHeaderHash::from_vec(&b_block.block_hash)
            .ok_or_else(|| anyhow!("Invalid burn hash in DB"))?;

        Ok(crate::StacksBlockHeader {
            id,
            hash: block_hash,
            height: s_block.height.try_into()?,
            parent_id,
            burn_block_height: b_block.height.try_into()?,
            burn_block_hash: burn_hash,
        })
    }
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = _staged_stacks_block)]
#[diesel(treat_none_as_null = true)]
pub struct StagedStacksBlock {
    pub index_hash: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub parent_index_hash: Vec<u8>,
    pub height: i64,
    pub burn_block_hash: Vec<u8>,
    pub burn_block_height: i64,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = synthetic_block)]
pub struct SyntheticBlock {
    pub id: i64,
    pub stacks_block_id: i64,
    pub index_hash: Vec<u8>,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(StacksBlock))]
#[diesel(table_name = stacks_tx)]
#[diesel(treat_none_as_null = true)]
pub struct StacksTx {
    pub id: i64,
    pub stacks_block_id: i64,
    pub tx_hash: Vec<u8>,
    pub tx_hash_hex: String,
    pub stacks_tx_type_id: i32,
    pub caller_principal_id: i32,
    pub contract_id: Option<i32>,
    pub contract_fn_id: Option<i32>,
    pub contract_call_args_json: Option<String>,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = _staged_stacks_tx)]
#[diesel(treat_none_as_null = true)]
pub struct StagedStacksTx {
    pub block_index_hash: Vec<u8>,
    pub tx_hash: Vec<u8>,
    pub stacks_tx_type_id: i32,
    pub caller_address: String,
    pub contract_issuer_address: Option<String>,
    pub contract_name: Option<String>,
    pub contract_fn_name: Option<String>,
    pub contract_call_args_json: Option<String>,
}

// Keep Queryable as Value (Diesel can deserialize Text -> Value automatically if feature is on,
// or we can use String and deserialize manually)
#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(Chainstate))]
#[diesel(table_name = benchmark_run)]
#[diesel(treat_none_as_null = true)]
pub struct BenchmarkRun {
    pub id: i32,
    pub run_name: Option<String>,
    pub chainstate_id: i32,
    pub git_commit_hash: Vec<u8>,
    pub start_time: NaiveDateTime,
    pub end_time: Option<NaiveDateTime>,
    pub args_json: String,
    pub build_profile: String,
    pub build_opt_level: String,
    pub build_debug_assertions: bool,
    pub build_overflow_checks: bool,
    pub build_target_triple: String,
    pub build_rustc_version: String,
    pub git_branch: Option<String>,
    pub git_dirty: Option<bool>,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(primary_key(benchmark_run_id))]
#[diesel(belongs_to(BenchmarkRun))]
#[diesel(table_name = block_processing_baseline)]
pub struct BlockProcessingBaselineRow {
    pub benchmark_run_id: i32,
    pub start_parent_index_hash: Vec<u8>,
    pub warmup_blocks: i32,
    pub measured_blocks: i32,
    pub avg_setup_us: i32,
    pub avg_finalize_us: i32,
    pub avg_clarity_commit_us: i32,
    pub avg_advance_tip_us: i32,
    pub avg_index_commit_us: i32,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(primary_key(benchmark_run_id, synthetic_block_id))]
#[diesel(belongs_to(BenchmarkRun))]
#[diesel(belongs_to(SyntheticBlock))]
#[diesel(table_name = stacks_block_stats)]
pub struct StacksBlockStats {
    pub benchmark_run_id: i32,
    pub synthetic_block_id: i64,
    pub total_duration_us: i32,
    pub setup_duration_us: i32,
    pub execution_duration_us: i32,
    pub commit_duration_us: i32,
    pub commit_overhead_baseline_us: i32,
    pub clarity_write_length: i32,
    pub clarity_write_count: i32,
    pub clarity_read_length: i32,
    pub clarity_read_count: i32,
    pub clarity_runtime: i32,
    pub total_storage_delta: i64,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(primary_key(benchmark_run_id, synthetic_block_id, stacks_tx_id))]
#[diesel(belongs_to(BenchmarkRun))]
#[diesel(belongs_to(StacksTx))]
#[diesel(table_name = stacks_tx_stats)]
pub struct StacksTxStats {
    pub benchmark_run_id: i32,
    pub stacks_tx_id: i64,
    pub synthetic_block_id: i64,
    pub duration_us: i32,
    pub clarity_write_length: i32,
    pub clarity_write_count: i32,
    pub clarity_read_length: i32,
    pub clarity_read_count: i32,
    pub clarity_runtime: i32,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = profiler_location)]
pub struct ProfilerLocation {
    pub id: i32,
    pub file: String,
    pub line: i32,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = profiler_span)]
#[diesel(treat_none_as_null = true)]
pub struct ProfilerSpan {
    pub id: i32,
    pub context: Option<String>,
    pub name: String,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = profiler_tag)]
pub struct ProfilerTag {
    pub id: i32,
    pub tag: String,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(BenchmarkRun))]
#[diesel(belongs_to(ProfilerSpan))]
#[diesel(belongs_to(ProfilerLocation))]
#[diesel(belongs_to(SyntheticBlock))]
#[diesel(belongs_to(StacksTx))]
#[diesel(belongs_to(ProfilerRecord, foreign_key = parent_id))]
#[diesel(table_name = profiler_record)]
#[diesel(treat_none_as_null = true)]
pub struct ProfilerRecord {
    pub id: i64,
    pub benchmark_run_id: i32,
    pub parent_id: Option<i64>,
    pub profiler_span_id: i32,
    pub profiler_tag_id: Option<i32>,
    pub profiler_location_id: i32,
    pub child_index: i32,
    pub depth: i32,
    pub synthetic_block_id: i64,
    pub stacks_tx_id: Option<i64>,
    pub wall_time_us: i64,
    pub cpu_time_us: i64,
    pub self_wall_time_us: i64,
    pub self_cpu_time_us: i64,
    pub call_count: i32,
    pub sample_count: i32,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Associations, Debug, Clone)]
#[diesel(belongs_to(ProfilerRecord, foreign_key = profiler_record_id))]
#[diesel(table_name = profiler_record_clarity_costs)]
#[diesel(primary_key(profiler_record_id))]
pub struct ProfilerRecordClarityCosts {
    pub profiler_record_id: i64,
    pub runtime: i64,
    pub read_count: i64,
    pub read_length: i64,
    pub write_count: i64,
    pub write_length: i64,
    pub input_n: i64,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = _staged_profiler_record_clarity_costs)]
pub struct StagedProfilerRecordClarityCosts {
    pub profiler_record_id: i64,
    pub runtime: i64,
    pub read_count: i64,
    pub read_length: i64,
    pub write_count: i64,
    pub write_length: i64,
    pub input_n: i64,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = _staged_profiler_record_kv)]
pub struct StagedProfilerRecordKv {
    pub profiler_record_id: i64,
    pub key: String,
    pub value_type_id: i32,
    pub value: String,
    pub count: i32,
}

#[derive(Insertable, Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = chain_tip_cache)]
#[diesel(primary_key(tip_index_hash, height))] // Explicitly define composite key
pub struct ChainTipCache {
    pub tip_index_hash: Vec<u8>,
    pub height: i64,
    pub index_hash: Vec<u8>,
}

/// Lightweight summary statistics for a benchmark run.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub block_count: u64,
    pub total_duration_us: u64,
    pub total_execution_us: u64,
    pub total_commit_us: u64,
}

/// Full summary statistics for `bench show --summary`.
#[derive(Debug, Clone)]
pub struct RunDetailedSummary {
    pub block_count: u64,
    pub total_duration_us: u64,
    pub avg_duration_us: u64,
    pub total_setup_us: u64,
    pub total_execution_us: u64,
    pub total_commit_us: u64,
    pub total_clarity_runtime: u64,
    pub total_clarity_read_length: u64,
    pub total_clarity_read_count: u64,
    pub total_clarity_write_length: u64,
    pub total_clarity_write_count: u64,
    pub total_storage_delta: i64,
}

/// A hot profiler span for `bench show --profiler-hot`.
#[derive(Debug, Clone)]
pub struct ProfilerHotSpan {
    pub span_name: String,
    pub span_context: Option<String>,
    pub est_self_wall_us: f64,
    pub est_wall_us: f64,
    pub call_count: i64,
    pub sample_count: i64,
    pub file: Option<String>,
    pub line: Option<i32>,
}

/// Per-block stats row returned by [`AppDb::get_block_stats`].
#[derive(Debug, Clone)]
pub struct BlockStatsRow {
    pub height: i64,
    pub block_id: String,
    pub total_duration_us: i32,
    pub setup_duration_us: i32,
    pub execution_duration_us: i32,
    pub commit_duration_us: i32,
    pub commit_overhead_baseline_us: i32,
    pub clarity_runtime: i32,
    pub clarity_read_length: i32,
    pub clarity_read_count: i32,
    pub clarity_write_length: i32,
    pub clarity_write_count: i32,
    pub total_storage_delta: i64,
}

/// Per-tx stats row returned by [`AppDb::get_tx_stats`].
#[derive(Debug, Clone)]
pub struct TxStatsRow {
    pub tx_hash: String,
    pub tx_type: String,
    pub block_height: i64,
    pub duration_us: i32,
    pub clarity_runtime: i32,
    pub clarity_read_length: i32,
    pub clarity_read_count: i32,
    pub clarity_write_length: i32,
    pub clarity_write_count: i32,
}

/// Per-span comparison row returned by [`AppDb::compare_run_spans`].
#[derive(Debug, Clone)]
pub struct SpanComparisonRow {
    pub span_name: String,
    pub span_context: Option<String>,
    pub baseline_self_wall_us: Option<f64>,
    pub candidate_self_wall_us: Option<f64>,
    pub delta_us: f64,
    pub delta_pct: Option<f64>,
    pub baseline_calls: Option<i64>,
    pub candidate_calls: Option<i64>,
}
