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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use blockstack_lib::burnchains::Txid;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use stacks_bench::baseline::run_convergent_baseline;
use stacks_bench::bench_events::{self, BenchEvent, BenchEventSender};
use stacks_bench::blocks::{BackwardsBlockStream, BlockRef};
use stacks_bench::context::{BenchContext, BenchEnv};
use stacks_bench::db::DbOpenForRead;
use stacks_bench::db::app::models::BenchmarkRun;
use stacks_bench::db::app::{
    AppDb, ProfilerStoragePolicy, ProfilerThreshold, deserialize_profiler_thresholds,
};
use stacks_bench::db::node::{ChainStateDb, NakamotoDb};
use stacks_bench::filter::{ContractMatcher, TxFilter};
use stacks_bench::indexer::{ChainIndexPlan, ChainstateIndexer, ResolvedRange};
use stacks_bench::metrics::{BlockMetrics, CalibrationState, MetricsAccumulator, MetricsSummary};
use stacks_bench::paths::ChainStateDir;
use stacks_bench::provenance::BenchmarkProvenance;
use stacks_bench::replay::{ReplayMode, SegmentReplayInfo};
use stacks_bench::shadow::ShadowDir;
use stacks_bench::{Network, StacksBlockHeader, StacksBlockLoader, StacksBlockRef};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_profiler::Profiler;
use tokio::sync::mpsc;

use crate::commands::common::{
    ContractArg, IndexerArgs, IndexerUiSpawner, TxIdArg, create_shadow_dir, get_git_hash,
    run_cleanup_with_events, setup_bench_env, setup_bench_env_and_plan,
};

/// Interleaved WAL checkpoint interval for warmup runs.
///
/// Warmup suppresses per-block metrics and checkpoints. Periodic checkpoints
/// keep the WAL from building up into a large boundary flush before the first
/// measured block.
const WARMUP_CHECKPOINT_INTERVAL: usize = 100;

/// Non-clap parameter struct for benchmark runs. CLI converts from `RunArgs`
/// via `From`; MCP constructs directly from tool parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRunParams {
    pub source_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_at: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_at: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_count: Option<u32>,
    /// Transaction ids to benchmark. Empty = range/filter mode; one or more =
    /// txid mode (each tx replayed independently from its own parent block).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub txid: Vec<TxIdArg>,
    /// Block refs (height, index_block_hash, or canonical block_hash) to benchmark.
    /// Empty = range/txid mode; one or more = block mode (each block replayed
    /// independently from its own parent block). Mutually exclusive with `txid`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block: Vec<StacksBlockRef>,
    pub repetitions: u32,
    pub calibration: usize,
    pub warmup: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterKind>,
    /// Contract-call filter targets (`ADDR.NAME[.FN]`). Empty = no contract
    /// filter; non-empty acts as a stricter contract-call filter (mutually
    /// exclusive with `filter`, `txid`, `block`). The Vec is expected to be
    /// already normalized via `normalize_contract_args` at construction time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contract: Vec<ContractArg>,
    /// Persist only stacks-bench generated profiler spans (Segment,
    /// Transaction, etc.). Node/Clarity profiler spans are still collected by
    /// the underlying profiler, but are pruned before database insertion.
    #[serde(default)]
    pub no_profiler: bool,
    /// Threshold predicates for non-stacks-bench profiler spans. Empty = no
    /// timing threshold. Predicates are OR-combined after the span name policy.
    #[serde(
        default,
        deserialize_with = "deserialize_profiler_thresholds",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub profiler_threshold: Vec<ProfilerThreshold>,
    /// Opt-in profiler span glob patterns. Mutually exclusive with
    /// `ignore_span`. Stacks-bench spans are always persisted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub span: Vec<String>,
    /// Opt-out profiler span glob patterns. Mutually exclusive with `span`.
    /// Stacks-bench spans are always persisted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_span: Vec<String>,
    pub no_profiler_kv: bool,
    pub include_pre_nakamoto_blocks: bool,
    /// Track per-block storage growth in the shadow directory. Off by
    /// default; opt in for runs where per-block disk attribution matters.
    /// When off, every `stacks_block_stats.total_storage_delta` row is `0`
    /// and the post-run cumulative `StorageSummary` event is suppressed.
    #[serde(default)]
    pub storage_deltas: bool,
    /// **DESTRUCTIVE.** Skip the reflink/CoW copy of the source chainstate
    /// and run the bench directly against `source_dir`. Writes during the
    /// bench will mutate the source data permanently. Intended only for
    /// ephemeral-VM setups where the host has already CoW-copied the disk
    /// image attached to the VM, so an in-VM copy would add a redundant
    /// CoW layer. Mutually exclusive with `storage_deltas` (passthrough
    /// has no base directory to compute deltas against). Not persisted
    /// across reruns — `bench rerun` always defaults this back to `false`.
    #[serde(skip)]
    pub dangerous_no_chainstate_copy: bool,
    /// Override the parent directory under which the shadow tempdir is
    /// created. Useful for sandboxed environments where the default
    /// (`source_dir.parent()`) is not writable. The shadow tempdir is still
    /// auto-named and auto-cleaned; only its parent location changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_dir_root: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Transaction filter kind (presentation-agnostic; no clap derives).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterKind {
    ContractCall,
}

impl IndexerArgs for BenchRunParams {
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

impl BenchRunParams {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("Failed to serialize BenchRunParams to JSON")
    }
}

/// Structured result returned by benchmark runs.
#[derive(serde::Serialize)]
pub struct RunResult {
    pub run_id: i32,
    pub blocks: usize,
    pub warmup_blocks: usize,
    pub measured_blocks: usize,
    pub duration_secs: f64,
    pub interrupted: bool,
    pub summary: Option<RunSummaryJson>,
    /// Per-target summaries. `None` for range mode and for single-`--txid`
    /// runs (preserves the legacy flat output shape). `Some(...)` whenever
    /// the run targets more than one transaction or block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<TargetSummary>>,
}

/// Aggregated benchmark metrics for JSON output.
#[derive(serde::Serialize)]
pub struct RunSummaryJson {
    pub total_duration_us: u64,
    pub setup_duration_us: u64,
    pub execution_duration_us: u64,
    pub commit_duration_us: u64,
    pub transactions: u64,
    pub clarity_runtime: u64,
    pub write_length: u64,
    pub read_length: u64,
}

/// Discriminator for what kind of target a [`TargetSummary`] describes.
#[derive(serde::Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Txid,
    Block,
}

/// Per-target measurement summary. Emitted in [`RunResult::targets`] for
/// multi-target runs so downstream tooling can attribute metrics back to the
/// specific txid or block being benchmarked.
#[derive(serde::Serialize)]
pub struct TargetSummary {
    pub kind: TargetKind,
    /// Hex txid (txid mode) or hex block id (block mode).
    pub identifier: String,
    /// Height of the parent block from which each replay was forked.
    pub parent_block: u64,
    pub warmup_count: u32,
    pub measured_count: u32,
    /// Aggregated measurement summary for this target. `None` if no
    /// measurements were recorded (e.g. interrupted before completing any
    /// measured iteration).
    pub summary: Option<RunSummaryJson>,
}

/// Result of scanning the canonical chain for a specific transaction.
struct TxidScanResult {
    block_header: StacksBlockHeader,
    #[allow(dead_code)]
    tx_index: usize,
}

/// One transaction target inside a [`ResolvedTarget::Txs`] run.
struct TxTarget {
    txid: Txid,
    scan: TxidScanResult,
}

/// A `--block` ref after height/hash resolution but before indexer
/// canonicalization. Carries the expected canonical block id for hash-form
/// inputs so non-canonical (forked-off) ids can be rejected once the indexer
/// reveals the canonical block at the resolved height.
struct ResolvedBlockTarget {
    /// Original textual form of the user's `--block` argument, for error
    /// messages.
    ref_text: String,
    /// Canonical block height to index up to.
    height: u64,
    /// Candidate block ids the user explicitly asked for as an index hash or
    /// that were resolved from a canonical block hash. Empty for height-form
    /// inputs, since the canonical block at that height under `--tip` is
    /// unambiguous.
    expected_ids: Vec<StacksBlockId>,
}

/// The resolved target for a benchmark run, produced after the indexer
/// pipeline completes. Collapses the correlated `(effective_filter,
/// target_txid, txid_scan, block_ids)` tuple into a single discriminant so
/// impossible states are unrepresentable.
enum ResolvedTarget {
    /// Replay a range of indexed blocks (Follower or SegmentedFiltered).
    BlockRange {
        block_ids: Vec<StacksBlockId>,
        filter: Option<FilterKind>,
    },
    /// Replay one or more transaction targets, each `repetitions` times,
    /// from each target's own parent block. `targets.len() == 1` is the
    /// legacy single-`--txid` path.
    Txs { targets: Vec<TxTarget> },
    /// Replay one or more full-block targets (FR-2 `--block` mode). Each
    /// block is re-executed in full (`ReplayMode::Follower`) `repetitions`
    /// times from its own parent. Refs come from the indexer pipeline, so
    /// each one is canonical under the run's anchor tip.
    Blocks { refs: Vec<BlockRef> },
}

/// Per-target descriptor carried on the [`ReplayPlan`] so the execution loop
/// can build per-target measurement summaries without re-deriving identity.
#[derive(Clone)]
struct TargetDescriptor {
    kind: TargetKind,
    /// Hex string identifying the target (txid or block id).
    identifier: String,
    /// Height of the parent block from which each replay forks.
    parent_block: u64,
}

/// A single entry in the replay schedule.
struct ScheduledBlock {
    block_id: StacksBlockId,
    /// Repetition index for this block. Always 0 for range mode (each block
    /// replayed once). In txid mode, increments 0..N across warmup + measured.
    repetition: u32,
    /// How to replay this specific block (Follower, SegmentedFiltered,
    /// SingleTx). Per-entry so multi-target modes can schedule heterogeneous
    /// replay shapes (e.g. one `SingleTx` per txid).
    replay_mode: ReplayMode,
    /// Whether this entry is a warmup iteration (discarded from measurements).
    is_warmup: bool,
    /// Index of the logical target this entry belongs to. Zero for the current
    /// single-target modes (one txid or one block range); future multi-target
    /// modes will use this to group entries by target.
    #[allow(dead_code)]
    target_index: usize,
}

/// Fully resolved replay schedule.
struct ReplayPlan {
    /// Ordered replay schedule — each entry is one block replay iteration.
    schedule: Vec<ScheduledBlock>,
    /// Total warmup iterations across all targets in the schedule. For range
    /// mode this equals `params.warmup`; for multi-target txid mode it is
    /// `params.warmup * targets.len()`.
    total_warmup_entries: usize,
    /// Total measured iterations across all targets in the schedule.
    total_measured_entries: usize,
    /// Per-target descriptors, indexed by `ScheduledBlock.target_index`. Used
    /// to attribute schedule entries to identifiable targets in the final
    /// [`RunResult.targets`] output.
    targets: Vec<TargetDescriptor>,
    /// Whether cost model calibration should run. False for txid mode (starts
    /// pre-calibrated with heuristic attribution).
    needs_calibration: bool,
    /// Prefix for auto-generated run name ("txid-" or "").
    name_prefix: &'static str,
    /// Human-readable mode description for event emission.
    mode_label: String,
}

impl ReplayPlan {
    fn total_iterations(&self) -> usize {
        self.schedule.len()
    }
}

/// Walk the canonical chain backwards from `tip`, loading and deserializing
/// each block, until the transaction with `target_txid` is found.
async fn scan_for_txid(
    app_db: &mut AppDb,
    source_dir: &Path,
    tip: &BlockRef,
    target_txid: &Txid,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<TxidScanResult> {
    let chainstate_dir = ChainStateDir::from_node_root(source_dir);
    let chainstate_db = ChainStateDb::open_for_read(chainstate_dir.index_db_path()).await?;
    let mut naka_db = NakamotoDb::open_for_read(chainstate_dir.nakamoto_db_path()).await?;
    let min_naka_height = naka_db.get_min_block_height().await?.unwrap_or(u64::MAX);
    let blocks_dir = chainstate_dir.blocks_dir();

    let mut stream = BackwardsBlockStream::new(&chainstate_db, tip.id.clone()).with_cache(app_db);

    let mut scanned: u64 = 0;

    loop {
        let header = stream.next_block().await?.ok_or_else(|| {
            anyhow::anyhow!(
                "Reached genesis without finding txid {}",
                target_txid.to_hex()
            )
        })?;

        let mut loader = StacksBlockLoader::new(&blocks_dir, &mut naka_db, min_naka_height);
        let block = loader.load_block(&header).await?;

        for (i, tx) in block.transactions().iter().enumerate() {
            if tx.txid() == *target_txid {
                return Ok(TxidScanResult {
                    block_header: header,
                    tx_index: i,
                });
            }
        }

        scanned += 1;
        on_progress(scanned, header.height);
    }
}

/// Create a shadow directory, emitting lifecycle events. When `passthrough`
/// is `true`, skip the CoW copy entirely and operate directly on
/// `source_dir` — see [`ShadowDir::passthrough`] for the destructive
/// semantics. Emits [`BenchEvent::ChainstatePassthroughEnabled`] instead of
/// the normal `ShadowDir{Started,Complete}` pair in that case.
fn create_shadow_dir_with_events(
    source_dir: &Path,
    include_pre_nakamoto: bool,
    shadow_dir_root: Option<&Path>,
    passthrough: bool,
    ev: &BenchEventSender,
) -> Result<ShadowDir> {
    if passthrough {
        bench_events::emit(
            ev,
            BenchEvent::ChainstatePassthroughEnabled {
                source: source_dir.display().to_string(),
            },
        );
        return ShadowDir::passthrough(source_dir);
    }
    bench_events::emit(ev, BenchEvent::ShadowDirStarted);
    let timer = Instant::now();
    let shadow_dir = create_shadow_dir(source_dir, include_pre_nakamoto, shadow_dir_root)?;
    bench_events::emit(
        ev,
        BenchEvent::ShadowDirComplete {
            duration: timer.elapsed(),
        },
    );
    Ok(shadow_dir)
}

/// Run the chainstate indexer pipeline with a UI consumer, returning the
/// resolved range and the ordered list of block IDs in the range.
///
/// `indexer_ui` is borrowed so multi-target callers can drive one UI session
/// per indexed window.
async fn run_indexer_pipeline(
    app_db: &mut AppDb,
    env: &BenchEnv,
    plan: ChainIndexPlan,
    interrupted: &Arc<AtomicBool>,
    indexer_ui: &IndexerUiSpawner,
) -> Result<(ResolvedRange, Vec<StacksBlockId>)> {
    let tip_height = plan.anchor_tip.height;
    let idx_start = plan.start_height;
    let idx_end = plan.end_height;

    let (idx_event_tx, idx_event_rx) = mpsc::unbounded_channel();
    let mut indexer = ChainstateIndexer::new(app_db, env)
        .with_events(idx_event_tx)
        .with_interrupted(interrupted.clone());

    let idx_ui_fut = indexer_ui(idx_event_rx, idx_start, idx_end, tip_height);

    let index_result = indexer
        .index_chainstate_range(env.network, env.chain_id, &env.epochs, plan)
        .await;
    drop(indexer); // Close event channel so UI task can exit on error
    idx_ui_fut.await??;
    index_result
}

/// Targeted variant of [`run_indexer_pipeline`] for callers that already know
/// the exact canonical block id (`--block <hash>` with a single candidate, or
/// `--txid` after the chain scan). Skips the canonical-tip chain walk —
/// orders of magnitude faster than [`run_indexer_pipeline`] for blocks far
/// below the anchor tip.
async fn run_indexer_pipeline_targeted(
    app_db: &mut AppDb,
    env: &BenchEnv,
    plan: ChainIndexPlan,
    target_id: StacksBlockId,
    interrupted: &Arc<AtomicBool>,
    indexer_ui: &IndexerUiSpawner,
) -> Result<(ResolvedRange, Vec<StacksBlockId>)> {
    let tip_height = plan.anchor_tip.height;
    let idx_start = plan.start_height;
    let idx_end = plan.end_height;

    let (idx_event_tx, idx_event_rx) = mpsc::unbounded_channel();
    let mut indexer = ChainstateIndexer::new(app_db, env)
        .with_events(idx_event_tx)
        .with_interrupted(interrupted.clone());

    let idx_ui_fut = indexer_ui(idx_event_rx, idx_start, idx_end, tip_height);

    let index_result = indexer
        .index_targeted_block_window(env.network, env.chain_id, &env.epochs, plan, target_id)
        .await;
    drop(indexer);
    idx_ui_fut.await??;
    index_result
}

/// Create the benchmark run DB model with auto-generated name and git hash.
async fn create_bench_run_model(
    app_db: &mut AppDb,
    chainstate_id: i32,
    params: &BenchRunParams,
    name_prefix: &str,
) -> Result<BenchmarkRun> {
    let run_name = params
        .name
        .clone()
        .unwrap_or_else(|| format!("{}{}", name_prefix, Utc::now().format("%Y%m%d-%H%M%S")));
    let args_json = params.to_json()?;
    let git_commit_hash = get_git_hash().unwrap_or(vec![0u8; 20]);
    let prov = BenchmarkProvenance::capture();

    app_db
        .create_benchmark_run(
            chainstate_id,
            Utc::now().naive_utc(),
            git_commit_hash,
            Some(run_name),
            args_json,
            prov,
        )
        .await
}

/// Build a [`RunSummaryJson`] from aggregated metrics, if any blocks were
/// measured.
fn build_run_summary(summary: &MetricsSummary) -> Option<RunSummaryJson> {
    if summary.count > 0 {
        Some(RunSummaryJson {
            total_duration_us: summary.duration.as_micros() as u64,
            setup_duration_us: summary.setup.as_micros() as u64,
            execution_duration_us: summary.exec.as_micros() as u64,
            commit_duration_us: summary.commit.as_micros() as u64,
            transactions: summary.txs,
            clarity_runtime: summary.runtime,
            write_length: summary.write_len,
            read_length: summary.read_len,
        })
    } else {
        None
    }
}

/// Accumulated state from a replay loop, consumed by [`finalize_run`].
struct ReplayOutcome {
    run_id: i32,
    total_blocks: usize,
    warmup_blocks: usize,
    completed_measured: usize,
    replay_start: Instant,
    accumulator: MetricsAccumulator,
    /// Per-target summaries when the run had more than one logical target;
    /// `None` for range mode and single-`--txid` (preserves legacy shape).
    target_summaries: Option<Vec<TargetSummary>>,
    total_checkpoint_duration: Duration,
    total_storage_delta_duration: Duration,
    total_block_load_duration: Duration,
    total_metrics_flush_duration: Duration,
    /// Wall time of the warmup phase, from the start of the replay loop
    /// through (and including) the warmup→measured boundary checkpoint.
    /// Zero when `--warmup 0`. Bucketed separately so warmup wall time
    /// doesn't get mis-attributed to "Benchmarking Overhead".
    warmup_duration: Duration,
    storage_deltas: bool,
    was_interrupted: bool,
}

/// Post-replay finalization: emit summary events, persist final state, run
/// cleanup, and build the [`RunResult`].
async fn finalize_run(
    app_db: &mut AppDb,
    outcome: ReplayOutcome,
    shadow_dir: ShadowDir,
    ev: &BenchEventSender,
) -> Result<RunResult> {
    if !outcome.was_interrupted {
        bench_events::emit(
            ev,
            BenchEvent::ReplayComplete {
                measured_blocks: outcome.completed_measured,
                duration: outcome.replay_start.elapsed(),
            },
        );
    }

    let duration = outcome.replay_start.elapsed();

    app_db
        .finish_benchmark_run(outcome.run_id, Utc::now().naive_utc())
        .await?;

    let summary = outcome.accumulator.summary();

    let overhead = duration
        .saturating_sub(outcome.warmup_duration)
        .saturating_sub(summary.duration)
        .saturating_sub(outcome.total_checkpoint_duration);

    bench_events::emit(
        ev,
        BenchEvent::ReplaySummary {
            total_blocks: outcome.total_blocks,
            warmup_blocks: outcome.warmup_blocks,
            measured_blocks: outcome.completed_measured,
            total_duration: duration,
            warmup_duration: outcome.warmup_duration,
            replay_duration: summary.duration,
            checkpoint_duration: outcome.total_checkpoint_duration,
            overhead,
            storage_delta_duration: outcome.total_storage_delta_duration,
            block_load_duration: outcome.total_block_load_duration,
            metrics_flush_duration: outcome.total_metrics_flush_duration,
            interrupted: outcome.was_interrupted,
        },
    );

    bench_events::emit(
        ev,
        BenchEvent::BenchmarkSummary(outcome.accumulator.summary()),
    );

    if outcome.storage_deltas {
        // Give the OS a moment to sync metadata
        std::thread::sleep(Duration::from_millis(100));

        let storage_delta_report = shadow_dir.calculate_storage_delta()?;
        bench_events::emit(ev, BenchEvent::StorageSummary(storage_delta_report));
    }

    run_cleanup_with_events(app_db.clone(), shadow_dir, ev).await?;

    Ok(RunResult {
        run_id: outcome.run_id,
        blocks: outcome.total_blocks,
        warmup_blocks: outcome.warmup_blocks,
        measured_blocks: outcome.completed_measured,
        duration_secs: duration.as_secs_f64(),
        interrupted: outcome.was_interrupted,
        summary: build_run_summary(&summary),
        targets: outcome.target_summaries,
    })
}

/// Build a [`ReplayPlan`] from a [`ResolvedTarget`].
///
/// All mode-dependent decisions — schedule shape, replay mode, calibration
/// strategy, and naming — are encoded here so that [`execute_replay_plan`]
/// never inspects the original filter or mode flags.
fn build_replay_plan(params: &BenchRunParams, target: ResolvedTarget) -> Result<ReplayPlan> {
    match target {
        ResolvedTarget::Txs { targets } => {
            if targets.is_empty() {
                bail!("internal error: ResolvedTarget::Txs constructed with zero targets");
            }
            let warmup_per_target = params.warmup;
            let measured_per_target = params.repetitions as usize;
            let entries_per_target = warmup_per_target + measured_per_target;
            let target_count = targets.len();

            let mode_label = if target_count == 1 {
                format!("SingleTx({})", targets[0].txid)
            } else {
                format!("SingleTx(\u{00d7}{target_count})")
            };

            // Capacity = target_count * (warmup + measured); grouped per target
            // so each target's warmup precedes its measured reps.
            let mut schedule: Vec<ScheduledBlock> =
                Vec::with_capacity(target_count * entries_per_target);
            let mut descriptors: Vec<TargetDescriptor> = Vec::with_capacity(target_count);

            for (target_index, t) in targets.into_iter().enumerate() {
                let block_id = t.scan.block_header.id.clone();
                let block_height = t.scan.block_header.height;
                let identifier = format!("0x{}", t.txid.to_hex());
                let replay_mode = ReplayMode::SingleTx(TxFilter::Txid(t.txid));

                for i in 0..entries_per_target {
                    schedule.push(ScheduledBlock {
                        block_id: block_id.clone(),
                        repetition: i as u32,
                        replay_mode: replay_mode.clone(),
                        is_warmup: i < warmup_per_target,
                        target_index,
                    });
                }

                descriptors.push(TargetDescriptor {
                    kind: TargetKind::Txid,
                    identifier,
                    parent_block: block_height.saturating_sub(1),
                });
            }

            Ok(ReplayPlan {
                schedule,
                total_warmup_entries: warmup_per_target * target_count,
                total_measured_entries: measured_per_target * target_count,
                targets: descriptors,
                needs_calibration: false,
                name_prefix: "txid-",
                mode_label,
            })
        }
        ResolvedTarget::Blocks { refs } => {
            if refs.is_empty() {
                bail!("internal error: ResolvedTarget::Blocks constructed with zero targets");
            }
            let warmup_per_target = params.warmup;
            let measured_per_target = params.repetitions as usize;
            let entries_per_target = warmup_per_target + measured_per_target;
            let target_count = refs.len();

            let mode_label = if target_count == 1 {
                format!("Block({})", refs[0].id)
            } else {
                format!("Block(\u{00d7}{target_count})")
            };
            let replay_mode = ReplayMode::Follower;

            let mut schedule: Vec<ScheduledBlock> =
                Vec::with_capacity(target_count * entries_per_target);
            let mut descriptors: Vec<TargetDescriptor> = Vec::with_capacity(target_count);

            for (target_index, block_ref) in refs.into_iter().enumerate() {
                let block_id = block_ref.id.clone();
                let block_height = block_ref.height;
                let identifier = block_ref.id.to_string();

                for i in 0..entries_per_target {
                    schedule.push(ScheduledBlock {
                        block_id: block_id.clone(),
                        repetition: i as u32,
                        replay_mode: replay_mode.clone(),
                        is_warmup: i < warmup_per_target,
                        target_index,
                    });
                }

                descriptors.push(TargetDescriptor {
                    kind: TargetKind::Block,
                    identifier,
                    parent_block: block_height.saturating_sub(1),
                });
            }

            Ok(ReplayPlan {
                schedule,
                total_warmup_entries: warmup_per_target * target_count,
                total_measured_entries: measured_per_target * target_count,
                targets: descriptors,
                needs_calibration: false,
                name_prefix: "block-",
                mode_label,
            })
        }
        ResolvedTarget::BlockRange { block_ids, filter } => {
            let warmup = params.warmup;
            if warmup >= block_ids.len() {
                bail!(
                    "--warmup ({}) must be strictly less than the selected block count ({}); \
                     otherwise the run would contain no measured blocks",
                    warmup,
                    block_ids.len()
                );
            }
            let measured = block_ids.len() - warmup;

            // `--contract` and `--filter contract-call` are mutually exclusive
            // (enforced by clap + validate_run_params); both reduce to a
            // single `TxFilter::ContractCall(matchers)` here, with an empty
            // matchers vec for the bare `--filter contract-call` case.
            let replay_mode = if !params.contract.is_empty() {
                let matchers: Vec<ContractMatcher> = params
                    .contract
                    .iter()
                    .map(|c| {
                        ContractMatcher::new(
                            c.address.clone(),
                            c.contract_name.clone(),
                            c.function_name.clone(),
                        )
                    })
                    .collect();
                ReplayMode::SegmentedFiltered(TxFilter::ContractCall(matchers))
            } else {
                match filter {
                    Some(FilterKind::ContractCall) => {
                        ReplayMode::SegmentedFiltered(TxFilter::ContractCall(vec![]))
                    }
                    _ => ReplayMode::Follower,
                }
            };
            let mode_label = replay_mode.to_string();

            let schedule: Vec<ScheduledBlock> = block_ids
                .into_iter()
                .enumerate()
                .map(|(i, id)| ScheduledBlock {
                    block_id: id,
                    repetition: 0,
                    replay_mode: replay_mode.clone(),
                    is_warmup: i < warmup,
                    target_index: 0,
                })
                .collect();

            // Range mode has a single logical target (the range itself); we
            // do not emit per-target summaries for it (descriptors is left
            // empty and execute_replay_plan suppresses RunResult.targets).
            Ok(ReplayPlan {
                schedule,
                total_warmup_entries: warmup,
                total_measured_entries: measured,
                targets: Vec::new(),
                needs_calibration: true,
                name_prefix: "",
                mode_label,
            })
        }
    }
}

struct ReplayPlanExecution<'a, 'ctx> {
    plan: &'a ReplayPlan,
    params: &'a BenchRunParams,
    shadow_dir: ShadowDir,
    bench_context: BenchContext<'ctx>,
    chainstate_model_id: i32,
    interrupted: Arc<AtomicBool>,
    ev: &'a BenchEventSender,
}

async fn execute_replay_plan(
    app_db: &mut AppDb,
    execution: ReplayPlanExecution<'_, '_>,
) -> Result<RunResult> {
    let ReplayPlanExecution {
        plan,
        params,
        shadow_dir,
        mut bench_context,
        chainstate_model_id,
        interrupted,
        ev,
    } = execution;

    let run_model =
        create_bench_run_model(app_db, chainstate_model_id, params, plan.name_prefix).await?;

    let (mut chainstate, burnchain) = bench_context.open_stacks_chainstate()?;

    let baseline_outcome = run_convergent_baseline(
        &mut chainstate,
        &burnchain,
        &bench_context.end_block().id,
        &interrupted,
        ev,
    )?;

    if interrupted.load(Ordering::Relaxed) {
        bench_events::emit(
            ev,
            BenchEvent::ReplayInterrupted {
                completed: 0,
                total: plan.total_measured_entries,
            },
        );
        run_cleanup_with_events(app_db.clone(), shadow_dir, ev).await?;
        return Ok(RunResult {
            run_id: run_model.id,
            blocks: plan.total_iterations(),
            warmup_blocks: plan.total_warmup_entries,
            measured_blocks: 0,
            duration_secs: 0.0,
            interrupted: true,
            summary: None,
            targets: None,
        });
    }

    bench_events::emit(
        ev,
        BenchEvent::BaselineComplete {
            baseline: baseline_outcome.baseline.clone(),
            converged: baseline_outcome.converged,
            segments_used: baseline_outcome.segments_used,
            measurement_window: baseline_outcome.measurement_window,
            total_blocks: baseline_outcome.total_blocks,
            duration: baseline_outcome.duration,
        },
    );

    app_db
        .save_block_processing_baseline(
            run_model.id,
            &bench_context.end_block().id,
            baseline_outcome.discarded_blocks(),
            baseline_outcome.measured_blocks(),
            &baseline_outcome.baseline,
        )
        .await?;

    if params.storage_deltas {
        shadow_dir.calculate_storage_delta()?; // Reset storage delta baseline
    }

    // Open the sortition DB once and reuse it across every replay iteration.
    // Previously `replay_nakamoto_by_segments` opened a fresh handle per
    // block; at 25-50k blocks that's a meaningful per-block sqlite/MARF
    // setup cost. The handle is read-only from replay's perspective (it
    // only queries snapshots / burn views).
    let sortdb = burnchain
        .open_sortition_db(true)
        .with_context(|| "open sortition db for replay loop")?;

    let mut calibration = CalibrationState::new(plan.needs_calibration, params.calibration);
    let mut completed_measured: usize = 0;
    let mut warmup_done: usize = 0;
    let mut total_clarity_db_checkpoint_duration = Duration::ZERO;
    let mut total_storage_delta_duration = Duration::ZERO;
    let mut total_block_load_duration = Duration::ZERO;
    let mut total_metrics_flush_duration = Duration::ZERO;
    let mut last_storage_delta: i64 = 0;

    let mut accumulator = MetricsAccumulator::default();
    let profiler_policy = ProfilerStoragePolicy::new(
        params.no_profiler,
        &params.profiler_threshold,
        &params.span,
        &params.ignore_span,
    )?;
    // Per-target accumulators and measured counters, indexed by
    // `entry.target_index`. Empty for range mode (plan.targets is empty); the
    // run-level `accumulator` covers that case alone.
    let mut target_accumulators: Vec<MetricsAccumulator> = (0..plan.targets.len())
        .map(|_| MetricsAccumulator::default())
        .collect();
    let mut target_measured_counts: Vec<u32> = vec![0; plan.targets.len()];

    bench_events::emit(
        ev,
        BenchEvent::ReplayStarted {
            total_blocks: plan.total_iterations(),
            warmup_blocks: plan.total_warmup_entries,
            mode: plan.mode_label.clone(),
        },
    );

    // --- Replay loop ---
    let mut warmup_complete_emitted = false;
    let mut warmup_duration = Duration::ZERO;
    let start = Instant::now();
    for entry in plan.schedule.iter() {
        if interrupted.load(Ordering::Relaxed) {
            bench_events::emit(
                ev,
                BenchEvent::ReplayInterrupted {
                    completed: completed_measured,
                    total: plan.total_measured_entries,
                },
            );
            break;
        }

        let is_warmup = entry.is_warmup;

        // Warmup ran without per-block checkpoints or storage-delta sampling.
        // Flush once before measuring so dirty pages and delta baselines do not
        // land on the first measured block.
        if !is_warmup && plan.total_warmup_entries > 0 && !warmup_complete_emitted {
            chainstate.checkpoint_sqlite_dbs()?;
            if params.storage_deltas {
                let storage_report = shadow_dir.calculate_storage_delta()?;
                last_storage_delta = storage_report.net_growth_bytes;
            }
            warmup_duration = start.elapsed();
            warmup_complete_emitted = true;
            bench_events::emit(
                ev,
                BenchEvent::ReplayWarmupComplete {
                    warmup_blocks: plan.total_warmup_entries,
                    duration: warmup_duration,
                },
            );
        }

        if !is_warmup {
            Profiler::clear();
            if !params.no_profiler && !params.no_profiler_kv {
                Profiler::enable_record();
            }
        }

        let block_load_start = Instant::now();
        let block = app_db.get_block(&entry.block_id).await?;
        // Only attribute block-load time to the overhead bucket for measured
        // iterations; warmup block-loads are already accounted for in
        // `warmup_duration`. Counting them here too would cause the UI's
        // "Other" sub-line to underflow into a `saturating_sub` (showing 0
        // when the real value is small but positive).
        if !is_warmup {
            total_block_load_duration += block_load_start.elapsed();
        }

        let storage_deltas = params.storage_deltas;
        let mut on_segment = |_: &SegmentReplayInfo, m: Option<&mut BlockMetrics>| -> Result<()> {
            let delta_since_last = if storage_deltas {
                let storage_delta_start = Instant::now();
                let storage_report = shadow_dir.calculate_storage_delta()?;
                total_storage_delta_duration += storage_delta_start.elapsed();
                let current_delta = storage_report.net_growth_bytes;
                let delta = current_delta - last_storage_delta;
                last_storage_delta = current_delta;
                delta
            } else {
                0
            };

            if let Some(m) = m {
                m.total_storage_delta = delta_since_last;
                total_clarity_db_checkpoint_duration += m.clarity_db_checkpoint_duration;
            }
            Ok(())
        };

        let maybe_metrics_vec = stacks_bench::replay::replay_block(
            &mut bench_context,
            &mut chainstate,
            &sortdb,
            stacks_bench::replay::ReplayBlockRequest {
                mode: &entry.replay_mode,
                block_header: &block,
                repetition: entry.repetition,
                sample_metrics: !is_warmup,
            },
            if is_warmup {
                None
            } else {
                Some(&mut on_segment)
            },
        )?;

        if is_warmup {
            warmup_done += 1;
            // Avoid one large WAL flush at the warmup/measured boundary.
            if warmup_done.is_multiple_of(WARMUP_CHECKPOINT_INTERVAL) {
                chainstate.checkpoint_sqlite_dbs()?;
            }
            bench_events::emit(
                ev,
                BenchEvent::ReplayWarmupProgress {
                    completed: warmup_done,
                    total: plan.total_warmup_entries,
                },
            );
            continue;
        }

        completed_measured += 1;

        bench_events::emit(
            ev,
            BenchEvent::ReplayProgress {
                completed: completed_measured,
                total: plan.total_measured_entries,
            },
        );

        let Some(metrics_vec) = maybe_metrics_vec else {
            continue;
        };

        accumulator.add_many(&metrics_vec);
        if !plan.targets.is_empty() {
            target_accumulators[entry.target_index].add_many(&metrics_vec);
            target_measured_counts[entry.target_index] += 1;
        }

        if let Some(batch) = calibration.observe(metrics_vec) {
            let flush_start = Instant::now();
            app_db
                .save_block_metrics(run_model.id, batch.into_iter(), &profiler_policy)
                .await?;
            total_metrics_flush_duration += flush_start.elapsed();
        }
    }

    if !warmup_complete_emitted && warmup_done > 0 {
        warmup_duration = start.elapsed();
        bench_events::emit(
            ev,
            BenchEvent::ReplayWarmupComplete {
                warmup_blocks: plan.total_warmup_entries,
                duration: warmup_duration,
            },
        );
    }

    // Flush remaining metrics. On interruption, skip the last-chance model
    // fit so un-calibrated metrics receive heuristic attribution.
    let was_interrupted = interrupted.load(Ordering::Relaxed);
    let remaining = calibration.finish(!was_interrupted);
    if !remaining.is_empty() {
        bench_events::emit(
            ev,
            BenchEvent::MetricsFlush {
                count: remaining.len(),
            },
        );
        let flush_start = Instant::now();
        app_db
            .save_block_metrics(run_model.id, remaining.into_iter(), &profiler_policy)
            .await?;
        total_metrics_flush_duration += flush_start.elapsed();
    }

    let target_summaries = if plan.targets.len() > 1 {
        let warmup_per_target = if plan.total_warmup_entries > 0 {
            (plan.total_warmup_entries / plan.targets.len()) as u32
        } else {
            0
        };
        let summaries: Vec<TargetSummary> = plan
            .targets
            .iter()
            .zip(target_accumulators.iter())
            .zip(target_measured_counts.iter())
            .map(|((descriptor, accumulator), measured)| {
                let s = accumulator.summary();
                TargetSummary {
                    kind: descriptor.kind,
                    identifier: descriptor.identifier.clone(),
                    parent_block: descriptor.parent_block,
                    warmup_count: warmup_per_target,
                    measured_count: *measured,
                    summary: build_run_summary(&s),
                }
            })
            .collect();
        Some(summaries)
    } else {
        None
    };

    finalize_run(
        app_db,
        ReplayOutcome {
            run_id: run_model.id,
            total_blocks: plan.total_iterations(),
            warmup_blocks: plan.total_warmup_entries,
            completed_measured,
            replay_start: start,
            accumulator,
            target_summaries,
            total_checkpoint_duration: total_clarity_db_checkpoint_duration,
            total_storage_delta_duration,
            total_block_load_duration,
            total_metrics_flush_duration,
            warmup_duration,
            storage_deltas: params.storage_deltas,
            was_interrupted: interrupted.load(Ordering::Relaxed),
        },
        shadow_dir,
        ev,
    )
    .await
}

/// Run a benchmark. Handles block-range, filtered, and (single or multi)
/// transaction modes; mode is determined by [`BenchRunParams::txid`] (empty =
/// range mode, non-empty = txid mode).
///
/// The caller is responsible for:
/// - Wiring the `interrupted` flag to their cancellation source (ctrl-c, MCP
///   session disconnect, etc.)
/// - Spawning a consumer for `ev` (cliclack UI, MCP progress, or silent drain)
/// - Providing an `indexer_ui` spawner for indexer progress events
pub async fn run_benchmark(
    app_db: &mut AppDb,
    params: &BenchRunParams,
    ev: BenchEventSender,
    interrupted: Arc<AtomicBool>,
    indexer_ui: IndexerUiSpawner,
) -> Result<RunResult> {
    Profiler::disable_record();

    // Pre-flight validation — runs before any expensive setup (shadow dir,
    // env, etc.) so the user sees the error immediately.
    validate_run_params(params)?;

    let shadow_dir = create_shadow_dir_with_events(
        &params.source_dir,
        params.include_pre_nakamoto_blocks,
        params.shadow_dir_root.as_deref(),
        params.dangerous_no_chainstate_copy,
        &ev,
    )?;

    if !params.txid.is_empty() {
        run_benchmark_txids(app_db, params, shadow_dir, ev, interrupted, &indexer_ui).await
    } else if !params.block.is_empty() {
        run_benchmark_blocks(app_db, params, shadow_dir, ev, interrupted, &indexer_ui).await
    } else {
        run_benchmark_range(app_db, params, shadow_dir, ev, interrupted, &indexer_ui).await
    }
}

/// Cross-flag validation that clap can't express directly. Runs before any
/// expensive setup so errors surface immediately.
fn validate_run_params(params: &BenchRunParams) -> Result<()> {
    if !params.txid.is_empty() && !params.block.is_empty() {
        bail!("--txid and --block are mutually exclusive");
    }
    if params.no_profiler && !params.profiler_threshold.is_empty() {
        bail!("--no-profiler and --profiler-threshold are mutually exclusive");
    }
    if params.no_profiler && (!params.span.is_empty() || !params.ignore_span.is_empty()) {
        bail!("--no-profiler cannot be combined with --span or --ignore-span");
    }
    if !params.span.is_empty() && !params.ignore_span.is_empty() {
        bail!("--span and --ignore-span are mutually exclusive");
    }
    if params.dangerous_no_chainstate_copy && params.storage_deltas {
        bail!(
            "--dangerous-no-chainstate-copy and --storage-deltas are mutually exclusive: \
             passthrough mode has no base directory to compute per-block storage deltas against"
        );
    }
    if params.dangerous_no_chainstate_copy && params.shadow_dir_root.is_some() {
        bail!(
            "--dangerous-no-chainstate-copy and --shadow-dir-root are mutually exclusive: \
             passthrough mode does not create a shadow directory, so the parent override has no effect"
        );
    }

    // `--contract` is a stricter form of `--filter contract-call` and targets
    // a specific set of contract-call destinations. It is mutually exclusive
    // with the other target/filter modes (clap enforces on the CLI side; this
    // catches MCP and other programmatic callers).
    if !params.contract.is_empty() {
        if params.filter.is_some() {
            bail!("--contract and --filter are mutually exclusive");
        }
        if !params.txid.is_empty() {
            bail!("--contract and --txid are mutually exclusive");
        }
        if !params.block.is_empty() {
            bail!("--contract and --block are mutually exclusive");
        }
    }

    // Reject duplicate --txid values: each target derives synthetic block ids
    // from (origin_block, segment, tx_range, repetition); two identical txids
    // would collide on the `(benchmark_run_id, synthetic_block_id)` unique
    // constraint when persisting metrics. Surface the conflict up front rather
    // than failing mid-run.
    let mut seen_txids: std::collections::HashSet<&[u8]> =
        std::collections::HashSet::with_capacity(params.txid.len());
    for t in &params.txid {
        if !seen_txids.insert(t.as_bytes()) {
            bail!(
                "duplicate --txid: {t} appears more than once. Use --repetitions to repeat the same target."
            );
        }
    }

    // Same rationale for --block: identical block refs would produce
    // identical synthetic block ids and collide. Textual dedup catches the
    // same-form case; cross-form duplicates (e.g. height vs hex of the same
    // canonical block) are caught later, after height resolution.
    let mut seen_blocks: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(params.block.len());
    for b in &params.block {
        if !seen_blocks.insert(b.to_string()) {
            bail!(
                "duplicate --block: {b} appears more than once. Use --repetitions to repeat the same target."
            );
        }
    }
    Ok(())
}

/// Block-range / filtered benchmark mode.
async fn run_benchmark_range(
    app_db: &mut AppDb,
    params: &BenchRunParams,
    shadow_dir: ShadowDir,
    ev: BenchEventSender,
    interrupted: Arc<AtomicBool>,
    indexer_ui: &IndexerUiSpawner,
) -> Result<RunResult> {
    let (env, index_plan) = setup_bench_env_and_plan(&shadow_dir, params).await?;

    bench_events::emit(
        &ev,
        BenchEvent::EnvironmentReady {
            chain_id: env.chain_id,
            network: env.network.to_string(),
            epochs: env.epochs.iter().map(|e| e.to_string()).collect(),
            source_dir: shadow_dir.source().display().to_string(),
            shadow_dir: if shadow_dir.is_passthrough() {
                "<skipped - no copy>".to_string()
            } else {
                shadow_dir.path().display().to_string()
            },
            target_txid: None,
            target_block: None,
            target_block_height: None,
            repetitions: None,
        },
    );

    let (resolved, block_ids) =
        run_indexer_pipeline(app_db, &env, index_plan, &interrupted, indexer_ui).await?;

    let (chainstate_model, _) = app_db
        .get_or_create_chainstate(env.network, env.chain_id, &resolved.anchor_tip, &env.epochs)
        .await?;

    let bench_context = BenchContext::from_env(
        &env,
        resolved.anchor_tip.clone(),
        resolved.start.clone(),
        resolved.end.clone(),
    );

    let target = ResolvedTarget::BlockRange {
        block_ids,
        filter: params.filter.clone(),
    };

    let plan = build_replay_plan(params, target)?;

    execute_replay_plan(
        app_db,
        ReplayPlanExecution {
            plan: &plan,
            params,
            shadow_dir,
            bench_context,
            chainstate_model_id: chainstate_model.id,
            interrupted,
            ev: &ev,
        },
    )
    .await
}

/// Benchmark one or more transaction IDs.
async fn run_benchmark_txids(
    app_db: &mut AppDb,
    params: &BenchRunParams,
    shadow_dir: ShadowDir,
    ev: BenchEventSender,
    interrupted: Arc<AtomicBool>,
    indexer_ui: &IndexerUiSpawner,
) -> Result<RunResult> {
    let (env, anchor_tip) =
        setup_bench_env(&shadow_dir, params.network, params.tip.as_ref()).await?;

    let txid_summary = if params.txid.len() == 1 {
        Some(params.txid[0].to_string())
    } else {
        Some(format!("{} txids", params.txid.len()))
    };

    bench_events::emit(
        &ev,
        BenchEvent::EnvironmentReady {
            chain_id: env.chain_id,
            network: env.network.to_string(),
            epochs: env.epochs.iter().map(|e| e.to_string()).collect(),
            source_dir: shadow_dir.source().display().to_string(),
            shadow_dir: if shadow_dir.is_passthrough() {
                "<skipped - no copy>".to_string()
            } else {
                shadow_dir.path().display().to_string()
            },
            target_txid: txid_summary,
            target_block: None,
            target_block_height: None,
            repetitions: Some(params.repetitions),
        },
    );

    // --- Per-target scan + indexer pipeline ---
    let mut tx_targets: Vec<TxTarget> = Vec::with_capacity(params.txid.len());
    let mut highest_block: Option<BlockRef> = None;
    let mut lowest_block: Option<BlockRef> = None;

    for txid_arg in &params.txid {
        let target_txid = Txid::from_bytes(txid_arg.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("Failed to convert txid bytes to Txid"))?;

        bench_events::emit(
            &ev,
            BenchEvent::TxidScanStarted {
                txid: txid_arg.to_string(),
            },
        );
        let scan_start = Instant::now();

        let scan_result = if let Some(block_header) = app_db
            .find_block_for_tx_hash_on_chain_tip(txid_arg.as_bytes(), &anchor_tip.id)
            .await?
        {
            TxidScanResult {
                block_header,
                tx_index: 0,
            }
        } else {
            let ev_scan = ev.clone();
            scan_for_txid(
                app_db,
                shadow_dir.path(),
                &anchor_tip,
                &target_txid,
                |scanned, height| {
                    bench_events::emit(
                        &ev_scan,
                        BenchEvent::TxidScanProgress {
                            scanned,
                            current_height: height,
                        },
                    );
                },
            )
            .await?
        };

        bench_events::emit(
            &ev,
            BenchEvent::TxidScanComplete {
                txid: txid_arg.to_string(),
                block_id: scan_result.block_header.id.to_string(),
                block_height: scan_result.block_header.height,
                duration: scan_start.elapsed(),
            },
        );

        let target_height = scan_result.block_header.height;
        let index_start = target_height.saturating_sub(1).max(1);
        let index_plan = ChainIndexPlan {
            anchor_tip: anchor_tip.clone(),
            start_height: index_start,
            end_height: target_height,
            expected_start_ids: Vec::new(),
            expected_end_ids: vec![scan_result.block_header.id.clone()],
        };

        // The txid scan already resolved the exact canonical id; use the
        // targeted pipeline so we don't walk the chain from the anchor tip.
        let (_resolved, _block_ids) = run_indexer_pipeline_targeted(
            app_db,
            &env,
            index_plan,
            scan_result.block_header.id.clone(),
            &interrupted,
            indexer_ui,
        )
        .await?;

        let block_ref = BlockRef {
            id: scan_result.block_header.id.clone(),
            height: target_height,
        };
        match &highest_block {
            Some(h) if h.height >= block_ref.height => {}
            _ => highest_block = Some(block_ref.clone()),
        }
        match &lowest_block {
            Some(l) if l.height <= block_ref.height => {}
            _ => lowest_block = Some(block_ref.clone()),
        }

        tx_targets.push(TxTarget {
            txid: target_txid,
            scan: scan_result,
        });
    }

    let (chainstate_model, _) = app_db
        .get_or_create_chainstate(env.network, env.chain_id, &anchor_tip, &env.epochs)
        .await?;

    // Run the baseline once; per-target replays fork from their own parents.
    let end_block = highest_block.expect("non-empty params.txid");
    let start_block = lowest_block.expect("non-empty params.txid");
    let bench_context = BenchContext::from_env(&env, anchor_tip, start_block, end_block);

    let target = ResolvedTarget::Txs {
        targets: tx_targets,
    };
    let plan = build_replay_plan(params, target)?;

    execute_replay_plan(
        app_db,
        ReplayPlanExecution {
            plan: &plan,
            params,
            shadow_dir,
            bench_context,
            chainstate_model_id: chainstate_model.id,
            interrupted,
            ev: &ev,
        },
    )
    .await
}

/// Multi-target block benchmark mode (FR-2 `--block`). Resolves each block
/// ref against the anchor tip via the indexer pipeline, then schedules
/// grouped warmup + measured full-block replay reps per target.
async fn run_benchmark_blocks(
    app_db: &mut AppDb,
    params: &BenchRunParams,
    shadow_dir: ShadowDir,
    ev: BenchEventSender,
    interrupted: Arc<AtomicBool>,
    indexer_ui: &IndexerUiSpawner,
) -> Result<RunResult> {
    let (env, anchor_tip) =
        setup_bench_env(&shadow_dir, params.network, params.tip.as_ref()).await?;

    // Resolve each --block ref to a canonical height under the anchor tip.
    // The indexer pipeline below produces the canonical block at that height
    // and persists the [parent, target] window in the app DB. For hash-form
    // refs we also remember the expected canonical id so we can detect
    // non-canonical (forked-off) inputs after the pipeline resolves them.
    let chainstate_dir = stacks_bench::paths::ChainStateDir::from_node_root(shadow_dir.path());
    let chainstate_db =
        stacks_bench::db::node::ChainStateDb::open_for_read(chainstate_dir.index_db_path()).await?;
    let nakamoto_db = if chainstate_dir.nakamoto_db_path().exists() {
        Some(
            stacks_bench::db::node::NakamotoDb::open_for_read(chainstate_dir.nakamoto_db_path())
                .await?,
        )
    } else {
        None
    };
    let mut resolved_targets: Vec<ResolvedBlockTarget> = Vec::with_capacity(params.block.len());
    for r in &params.block {
        let resolved =
            crate::commands::common::resolve_ref(&chainstate_db, nakamoto_db.as_ref(), r, "block")
                .await?;
        resolved_targets.push(ResolvedBlockTarget {
            ref_text: r.to_string(),
            height: resolved.height,
            expected_ids: resolved.expected_ids,
        });
    }
    drop(chainstate_db);

    // Post-resolve dedup: catches cross-form duplicates (e.g. height N and
    // the hex id that resolves to the same canonical height under this tip).
    let mut seen_heights: std::collections::HashSet<u64> =
        std::collections::HashSet::with_capacity(resolved_targets.len());
    for target in &resolved_targets {
        if !seen_heights.insert(target.height) {
            bail!(
                "--block {} resolves to height {}, which is already targeted by another --block ref",
                target.ref_text,
                target.height
            );
        }
    }

    // For a single --block target, populate the existing block-specific
    // event fields. For multi-target we leave them None (a richer multi-block
    // UI breakdown can come later if needed); the per-target context still
    // surfaces in the post-run `targets` summary.
    let (target_block, target_block_height) = if params.block.len() == 1 {
        match &params.block[0] {
            StacksBlockRef::Hash(hash) => (Some(hash.to_string()), None),
            StacksBlockRef::Height(h) => (None, Some(*h)),
        }
    } else {
        (None, None)
    };

    bench_events::emit(
        &ev,
        BenchEvent::EnvironmentReady {
            chain_id: env.chain_id,
            network: env.network.to_string(),
            epochs: env.epochs.iter().map(|e| e.to_string()).collect(),
            source_dir: shadow_dir.source().display().to_string(),
            shadow_dir: if shadow_dir.is_passthrough() {
                "<skipped - no copy>".to_string()
            } else {
                shadow_dir.path().display().to_string()
            },
            target_txid: None,
            target_block,
            target_block_height,
            repetitions: Some(params.repetitions),
        },
    );

    // --- Per-target indexer pipeline ---
    let mut target_refs: Vec<BlockRef> = Vec::with_capacity(resolved_targets.len());
    let mut highest_block: Option<BlockRef> = None;
    let mut lowest_block: Option<BlockRef> = None;

    for target in &resolved_targets {
        let target_height = target.height;
        let index_start = target_height.saturating_sub(1).max(1);
        let index_plan = ChainIndexPlan {
            anchor_tip: anchor_tip.clone(),
            start_height: index_start,
            end_height: target_height,
            expected_start_ids: Vec::new(),
            expected_end_ids: target.expected_ids.clone(),
        };

        // Single candidate id → use the targeted pipeline (no canonical-tip
        // walk). Multi-candidate (rare cross-fork block_hash collisions) and
        // height-form refs fall back to the range pipeline so the canonical
        // walk can disambiguate.
        let (resolved, _block_ids) = if target.expected_ids.len() == 1 {
            run_indexer_pipeline_targeted(
                app_db,
                &env,
                index_plan,
                target.expected_ids[0].clone(),
                &interrupted,
                indexer_ui,
            )
            .await?
        } else {
            run_indexer_pipeline(app_db, &env, index_plan, &interrupted, indexer_ui).await?
        };

        let block_ref = resolved.end.clone();
        match &highest_block {
            Some(h) if h.height >= block_ref.height => {}
            _ => highest_block = Some(block_ref.clone()),
        }
        match &lowest_block {
            Some(l) if l.height <= block_ref.height => {}
            _ => lowest_block = Some(block_ref.clone()),
        }
        target_refs.push(block_ref);
    }

    let (chainstate_model, _) = app_db
        .get_or_create_chainstate(env.network, env.chain_id, &anchor_tip, &env.epochs)
        .await?;

    let end_block = highest_block.expect("non-empty params.block");
    let start_block = lowest_block.expect("non-empty params.block");
    let bench_context = BenchContext::from_env(&env, anchor_tip, start_block, end_block);

    let target = ResolvedTarget::Blocks { refs: target_refs };
    let plan = build_replay_plan(params, target)?;

    execute_replay_plan(
        app_db,
        ReplayPlanExecution {
            plan: &plan,
            params,
            shadow_dir,
            bench_context,
            chainstate_model_id: chainstate_model.id,
            interrupted,
            ev: &ev,
        },
    )
    .await
}
