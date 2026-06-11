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

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use stacks_bench::db::app::{ProfilerThreshold, deserialize_profiler_thresholds};
use stacks_bench::{Network, StacksBlockRef};
use tokio::sync::mpsc;

use super::bench_ui::run_bench_progress_ui;
use crate::cli::common::{CliContext, ExecCommand, run_indexer_progress_ui};
// Re-export for use by rerun.rs and other CLI consumers
pub use crate::commands::bench::run::RunResult;
use crate::commands::bench::run::{BenchRunParams, FilterKind};
use crate::commands::common::{
    ContractArg, IndexerArgs, IndexerUiSpawner, TxIdArg, normalize_contract_args,
};

#[derive(clap::Args, Debug, Serialize, Deserialize)]
#[command(group(
    clap::ArgGroup::new("target_mode")
        .args(["txid", "block"])
        .multiple(false)
        .required(false),
))]
pub struct RunArgs {
    /// Stacks node data dir (the directory containing the `chainstate` folder).
    #[arg(long = "source", short = 's')]
    source_dir: PathBuf,

    /// The Stacks block (height, index_block_hash, or canonical block_hash) to start at,
    /// inclusive. Cannot be used with the `txid` or `block` flags.
    #[arg(long, conflicts_with_all = ["txid", "block"], default_value = "1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    start_at: Option<StacksBlockRef>,

    /// The Stacks block (height, index_block_hash, or canonical block_hash) to end at,
    /// inclusive. Cannot be used with the `txid`, `block`, or `count` flags.
    #[arg(long, conflicts_with_all = ["txid", "block", "block_count"])]
    #[serde(skip_serializing_if = "Option::is_none")]
    end_at: Option<StacksBlockRef>,

    /// The tip block (height, index_block_hash, or canonical block_hash) to use as the anchor for
    /// resolving canonical history. Defaults to the node's current canonical tip. Useful for
    /// benchmarking in forks: provide the fork's tip hash here.
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    tip: Option<StacksBlockRef>,

    /// The network to use. If not specified, the network is inferred from the chainstate database.
    #[arg(long, short = 'n', value_enum)]
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,

    /// The number of blocks to process, starting from `start-at`.
    #[arg(
        long = "count",
        short = 'c',
        conflicts_with_all = ["end_at", "txid", "block"],
        requires = "start_at",
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    block_count: Option<u32>,

    /// A specific transaction id (hex) to benchmark. May be passed multiple times to benchmark
    /// several transactions in a single run; each transaction is replayed `--repetitions` times
    /// from its own parent block. Cannot be combined with `--start-at`, `--end-at`, `--count`,
    /// `--filter`, `--contract`, or `--block`.
    #[arg(
        long,
        num_args = 1..,
        action = clap::ArgAction::Append,
        conflicts_with_all = ["start_at", "end_at", "block_count", "filter", "contract"],
    )]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    txid: Vec<TxIdArg>,

    /// A specific Stacks block (height, index_block_hash, or canonical block_hash) to benchmark.
    /// May be passed multiple times to benchmark several blocks in a single run; each block is
    /// replayed `--repetitions` times from its own parent block. Resolved against `--tip` for
    /// canonical history.
    /// Cannot be combined with `--start-at`, `--end-at`, `--count`, `--filter`, `--contract`,
    /// or `--txid`.
    #[arg(
        long,
        num_args = 1..,
        action = clap::ArgAction::Append,
        value_name = "BLOCK",
        conflicts_with_all = ["start_at", "end_at", "block_count", "filter", "contract"],
    )]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    block: Vec<StacksBlockRef>,

    /// Number of measured times to replay each target's block in `--txid` or `--block` mode.
    ///
    /// Warmup runs (from `--warmup`) are additional and executed before these measured
    /// repetitions, per target. Each replay forks from the target's own parent block, producing
    /// independent measurements.
    #[arg(long, default_value_t = 10, requires = "target_mode")]
    repetitions: u32,

    /// Number of measured blocks to collect before fitting the commit cost
    /// model in block-range mode.
    #[arg(
        long,
        value_name = "CALIBRATION_BLOCKS",
        default_value_t = 20,
        conflicts_with_all = ["txid", "block"],
    )]
    calibration: usize,

    /// Number of blocks to process as warmup before starting measurements.
    /// Applies to the replay phase only; the overhead baseline is self-tuning
    /// (sampled empty blocks until the rolling mean stabilizes).
    ///
    /// In block-range mode, this is the number of warmup blocks (the earliest
    /// selected blocks).
    ///
    /// In `--txid` or `--block` mode, this is the number of warmup repetitions per target
    /// (discarded before measurement begins). These runs are additive to `--repetitions`.
    #[arg(long, default_value_t = 0)]
    warmup: usize,

    /// Filter to apply when selecting transactions to process.
    #[arg(long, short = 'f', conflicts_with_all = ["txid", "block", "contract"])]
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<FilterArg>,

    /// Restrict benchmarking to blocks that call one or more specific contracts.
    ///
    /// Each value has the form `ADDR.CONTRACT[.FUNCTION]`. When a function name
    /// is omitted, the filter matches any function call on that contract. May
    /// be passed multiple times to OR-combine targets. Blocks with no matching
    /// contract-call are skipped from measurement (range-mode behavior).
    /// Compatible with `--start-at`, `--end-at`, and `--count`. Cannot be
    /// combined with `--txid`, `--block`, or `--filter`.
    #[arg(
        long,
        num_args = 1..,
        action = clap::ArgAction::Append,
        value_name = "ADDR.CONTRACT[.FUNCTION]",
        conflicts_with_all = ["txid", "block", "filter"],
    )]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    contract: Vec<ContractArg>,

    /// Store only stacks-bench generated profiler spans (`Segment`,
    /// `Transaction`, etc.). Node/Clarity profiler spans and their key-value
    /// records are omitted from persistence, but block and transaction metrics
    /// are still recorded.
    #[arg(
        long = "bench-spans-only",
        alias = "no-profiler",
        default_value_t = false,
        conflicts_with_all = ["profiler_threshold", "span", "ignore_span"],
    )]
    #[serde(default)]
    no_profiler: bool,

    /// Track per-block storage growth in the shadow directory and persist
    /// the deltas in `stacks_block_stats.total_storage_delta`, plus emit a
    /// cumulative storage-growth summary at the end of the run. Off by
    /// default because `calculate_storage_delta()` does a filesystem walk
    /// per block and is a meaningful overhead at scale (25-50k+ blocks).
    /// When off, persisted `total_storage_delta` rows are stored as `0`.
    #[arg(long = "storage-deltas", default_value_t = false)]
    #[serde(default)]
    storage_deltas: bool,

    /// **DESTRUCTIVE.** Skip the reflink/CoW copy of the source chainstate
    /// and run the bench directly against `--source`. Writes during the
    /// bench will mutate the source data permanently. Intended for
    /// ephemeral-VM setups where the host has already CoW-copied the disk
    /// image attached to the VM, so an in-VM copy would add a redundant
    /// CoW layer. Mutually exclusive with `--storage-deltas`. Not
    /// persisted in the run record — `bench rerun` always defaults this
    /// back to `false`.
    #[arg(long = "dangerous-no-chainstate-copy", default_value_t = false)]
    #[serde(skip)]
    dangerous_no_chainstate_copy: bool,

    /// Persist non-stacks-bench profiler spans only when a timing metric
    /// reaches this threshold. Bare durations use inclusive wall time. Prefix
    /// with `wall:`, `self-wall:`, `cpu:`, `self-cpu:`, `wait:`, or
    /// `self-wait:` to select another metric. May be passed multiple times;
    /// thresholds are OR-combined.
    #[arg(
        long = "profiler-threshold",
        action = clap::ArgAction::Append,
        value_name = "METRIC:DURATION",
    )]
    #[serde(
        default,
        deserialize_with = "deserialize_profiler_thresholds",
        skip_serializing_if = "Vec::is_empty"
    )]
    profiler_threshold: Vec<ProfilerThreshold>,

    /// Persist only non-stacks-bench profiler spans matching these glob
    /// patterns. Patterns match both the span name and `module::path::name`.
    /// May be passed multiple times. Mutually exclusive with `--ignore-span`.
    #[arg(
        long = "span",
        num_args = 1..,
        action = clap::ArgAction::Append,
        value_name = "GLOB",
        conflicts_with_all = ["ignore_span", "no_profiler"],
    )]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    span: Vec<String>,

    /// Omit non-stacks-bench profiler spans matching these glob patterns.
    /// Patterns match both the span name and `module::path::name`. May be
    /// passed multiple times. Mutually exclusive with `--span`.
    #[arg(
        long = "ignore-span",
        num_args = 1..,
        action = clap::ArgAction::Append,
        value_name = "GLOB",
        conflicts_with_all = ["span", "no_profiler"],
    )]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ignore_span: Vec<String>,

    /// Disable capturing of profiler key-value records generated via `record!` and `counter!`
    /// macros. This can provide a slight performance benefit and reduce storage if you do not need
    /// them.
    #[arg(long, default_value_t = false)]
    no_profiler_kv: bool,

    /// Whether or not to include pre-Nakamoto blocks in the reflink copy of the source node data
    /// directory, which is necessary if benchmarking from blocks prior to the chainstate's Nakamoto
    /// start height + 1. Enabling this can add significant time when creating the reflink copy
    /// for large chainstates. [default: false]
    #[arg(long = "with-pre-naka", default_value_t = false)]
    include_pre_nakamoto_blocks: bool,

    /// Parent directory under which the shadow (reflink) copy of the source
    /// chainstate is created. Defaults to the source directory's parent so
    /// the shadow lives on the same filesystem and benefits from reflinks.
    /// Override this when running in a sandbox where the default parent is
    /// not writable.
    ///
    /// Constraints:
    ///   * Must be on the same filesystem as `--source` — reflinks fail
    ///     across filesystems and the strict reflink check will refuse to
    ///     proceed.
    ///   * Must not resolve inside the source tree (would recurse).
    ///
    /// The shadow tempdir is still auto-named (uniquely) and auto-cleaned at
    /// end of run.
    #[arg(long = "shadow-dir-root", value_name = "DIR")]
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_dir_root: Option<PathBuf>,

    /// Human-readable name for this benchmark run. If not provided, an
    /// auto-generated timestamp-based name is used. Useful for labeling
    /// runs in `bench list` and `bench compare` (e.g. "baseline-before-refactor").
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize, Deserialize)]
pub enum FilterArg {
    ContractCall,
}

impl IndexerArgs for RunArgs {
    fn start_at(&self) -> Option<&StacksBlockRef> {
        self.start_at.as_ref()
    }
    fn end_at(&self) -> Option<&StacksBlockRef> {
        self.end_at.as_ref()
    }
    fn block_count(&self) -> Option<u32> {
        self.block_count
    }
    fn tip(&self) -> Option<&StacksBlockRef> {
        self.tip.as_ref()
    }
    fn network(&self) -> Option<Network> {
        self.network
    }
}

impl From<&RunArgs> for BenchRunParams {
    fn from(args: &RunArgs) -> Self {
        Self {
            source_dir: args.source_dir.clone(),
            start_at: args.start_at.clone(),
            end_at: args.end_at.clone(),
            tip: args.tip.clone(),
            network: args.network,
            block_count: args.block_count,
            txid: args.txid.clone(),
            block: args.block.clone(),
            repetitions: args.repetitions,
            calibration: args.calibration,
            warmup: args.warmup,
            filter: args.filter.as_ref().map(FilterKind::from),
            contract: normalize_contract_args(args.contract.clone()),
            no_profiler: args.no_profiler,
            profiler_threshold: args.profiler_threshold.clone(),
            span: args.span.clone(),
            ignore_span: args.ignore_span.clone(),
            no_profiler_kv: args.no_profiler_kv,
            include_pre_nakamoto_blocks: args.include_pre_nakamoto_blocks,
            storage_deltas: args.storage_deltas,
            dangerous_no_chainstate_copy: args.dangerous_no_chainstate_copy,
            shadow_dir_root: args.shadow_dir_root.clone(),
            name: args.name.clone(),
        }
    }
}

impl From<&FilterArg> for FilterKind {
    fn from(arg: &FilterArg) -> Self {
        match arg {
            FilterArg::ContractCall => FilterKind::ContractCall,
        }
    }
}

impl ExecCommand for RunArgs {
    type Output = RunResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Spawn the UI consumer: interactive renderer or silent drain
        let ui_handle = if ctx.interactive() {
            tokio::spawn(run_bench_progress_ui(event_rx))
        } else {
            tokio::spawn(async move {
                let mut rx = event_rx;
                while rx.recv().await.is_some() {}
                Ok(())
            })
        };

        // Install ctrl-c handler for graceful cancellation
        let interrupted = Arc::new(AtomicBool::new(false));
        {
            let interrupted = interrupted.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                interrupted.store(true, Ordering::Relaxed);
            });
        }

        let params = BenchRunParams::from(self);

        // Build indexer UI spawner based on interactivity
        let indexer_ui: IndexerUiSpawner = if ctx.interactive() {
            Box::new(|rx, start, end, tip| {
                tokio::spawn(run_indexer_progress_ui(rx, start, end, tip))
            })
        } else {
            crate::commands::common::silent_indexer_ui()
        };

        let mut app_db = ctx.app_db();
        let result = crate::commands::bench::run::run_benchmark(
            &mut app_db,
            &params,
            event_tx,
            interrupted,
            indexer_ui,
        )
        .await;

        // Wait for UI to finish processing all events
        ui_handle.await??;

        result
    }
}
