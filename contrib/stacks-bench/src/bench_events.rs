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

//! Typed events emitted by benchmark execution for UI/progress rendering.
//!
//! The core benchmark logic emits these events through a channel. Consumers
//! (interactive cliclack UI, silent JSON mode, future MCP progress) subscribe
//! to the channel and render as appropriate. The execution code has zero
//! knowledge of UI.
//!
//! ## Channel design
//!
//! The event sender is an unbounded `tokio::sync::mpsc` channel. This matches
//! the pattern used by [`IndexerEvent`](crate::indexer::IndexerEvent). Per-block
//! progress events are small (~48 bytes each) and the consumer runs on a
//! separate tokio task, so in practice the queue stays shallow. A bounded
//! channel would risk stalling the benchmark execution if the consumer (e.g.
//! a cliclack progress bar poll) temporarily blocks, which would corrupt
//! timing measurements. The tradeoff is: unbounded memory growth is
//! theoretically possible if the consumer stops processing, but the events
//! are lightweight and the consumer is always co-scheduled.

use std::time::Duration;

use crate::metrics::{BlockProcessingBaseline, MetricsSummary};
use crate::shadow::ShadowDirDeltaReport;

/// Events emitted during a `bench run` execution (block-range mode).
#[derive(Debug)]
pub enum BenchEvent {
    // --- Txid scan phase (--txid mode only) ---
    /// Txid chain scan started.
    TxidScanStarted { txid: String },
    /// Txid scan progress update.
    TxidScanProgress { scanned: u64, current_height: u64 },
    /// Txid found in the chain.
    TxidScanComplete {
        txid: String,
        block_id: String,
        block_height: u64,
        duration: Duration,
    },

    // --- Setup phase ---
    /// Shadow directory creation started.
    ShadowDirStarted,
    /// Shadow directory created successfully.
    ShadowDirComplete { duration: Duration },
    /// `--dangerous-no-chainstate-copy` was enabled: no CoW copy was taken
    /// and the bench is running directly against the source chainstate.
    /// UI should render a prominent warning since writes will mutate the
    /// source data permanently.
    ChainstatePassthroughEnabled { source: String },

    /// Environment resolved and ready.
    EnvironmentReady {
        chain_id: u32,
        network: String,
        epochs: Vec<String>,
        source_dir: String,
        shadow_dir: String,
        /// Present in --txid mode only.
        target_txid: Option<String>,
        /// Present in --txid mode only.
        target_block: Option<String>,
        /// Present in --txid mode only.
        target_block_height: Option<u64>,
        /// Present in --txid mode only.
        repetitions: Option<u32>,
    },

    // --- Baseline phase ---
    /// Overhead baseline measurement started. The baseline runs empty blocks
    /// in fixed-size segments and stops once the rolling average over the last
    /// `convergence_window` segments stabilizes within `convergence_threshold`,
    /// or after `max_segments` is reached.
    BaselineStarted {
        segment_size: u32,
        min_segments: u32,
        max_segments: u32,
        convergence_window: u32,
        convergence_threshold: f64,
    },
    /// Per-block progress within the baseline run.
    BaselineProgress {
        blocks_completed: u32,
        max_blocks: u32,
    },
    /// One segment of `segment_size` blocks finished; carries the segment's
    /// per-phase averages and, once enough segments have accumulated, the
    /// rolling-window average and the relative change vs. the prior window
    /// (used by the UI to surface convergence in real time).
    BaselineSegmentComplete {
        segment_index: u32,
        segment_average: BlockProcessingBaseline,
        rolling_window_average: Option<BlockProcessingBaseline>,
        convergence_pct: Option<f64>,
    },
    /// Checkpointing chainstate DBs after the baseline phase.
    BaselineCheckpointStarted,
    /// Checkpointing complete.
    BaselineCheckpointComplete { duration: Duration },
    /// Full baseline measurement complete with results.
    BaselineComplete {
        baseline: BlockProcessingBaseline,
        converged: bool,
        segments_used: u32,
        measurement_window: u32,
        total_blocks: u32,
        duration: Duration,
    },

    // --- Replay phase ---
    /// Replay phase started.
    ReplayStarted {
        total_blocks: usize,
        warmup_blocks: usize,
        mode: String,
    },
    /// Replay warmup progress (block-range mode).
    ReplayWarmupProgress { completed: usize, total: usize },
    /// Replay warmup complete.
    ReplayWarmupComplete {
        warmup_blocks: usize,
        duration: Duration,
    },
    /// Replay measured block progress.
    ReplayProgress { completed: usize, total: usize },
    /// Replay interrupted by Ctrl-C.
    ReplayInterrupted { completed: usize, total: usize },
    /// Replay complete.
    ReplayComplete {
        measured_blocks: usize,
        duration: Duration,
    },

    // --- Metrics flush ---
    /// Flushing remaining metrics from calibration buffer.
    MetricsFlush { count: usize },

    // --- Summary phase ---
    /// Replay summary computed.
    ReplaySummary {
        total_blocks: usize,
        warmup_blocks: usize,
        measured_blocks: usize,
        total_duration: Duration,
        /// Wall time of the warmup phase, including periodic warmup
        /// checkpoints and the warmup→measured boundary checkpoint. Zero
        /// when `--warmup 0`. Bucketed separately so warmup wall time
        /// doesn't get mis-attributed to "Benchmarking Overhead".
        warmup_duration: Duration,
        replay_duration: Duration,
        checkpoint_duration: Duration,
        /// Total benchmarking overhead, computed as
        /// `total_duration - warmup_duration - replay_duration - checkpoint_duration`.
        /// Further broken down by [`Self::ReplaySummary::storage_delta_duration`],
        /// [`Self::ReplaySummary::block_load_duration`], and
        /// [`Self::ReplaySummary::metrics_flush_duration`]. Whatever's left
        /// after subtracting those three is "other" overhead (profiler ops,
        /// loop scaffolding, event channel sends, etc.).
        overhead: Duration,
        /// Cumulative time spent in per-segment `calculate_storage_delta()`
        /// (filesystem walk over the shadow dir).
        storage_delta_duration: Duration,
        /// Cumulative time spent in `AppDb::get_block` (per-block load from
        /// the indexed AppDb).
        block_load_duration: Duration,
        /// Cumulative time spent in `AppDb::save_block_metrics` calls
        /// (batched persistence of measured-block metrics).
        metrics_flush_duration: Duration,
        interrupted: bool,
    },
    /// Benchmark metrics summary computed.
    BenchmarkSummary(MetricsSummary),
    /// Storage delta report computed.
    StorageSummary(ShadowDirDeltaReport),

    // --- Cleanup phase ---
    /// Cleanup started (shadow dir removal + DB checkpoint/vacuum). In
    /// passthrough mode (`--dangerous-no-chainstate-copy`) there is no
    /// shadow dir to remove, so UIs should skip the corresponding spinner.
    CleanupStarted { passthrough: bool },
    /// Shadow directory removed.
    CleanupShadowDirComplete { duration: Duration },
    /// DB checkpoint + vacuum complete.
    CleanupDbComplete { duration: Duration },
    /// DB checkpoint + vacuum failed (non-fatal).
    CleanupDbFailed { error: String, duration: Duration },
    /// Cleanup finished.
    CleanupComplete,
}

/// Convenience type for the event sender.
pub type BenchEventSender = tokio::sync::mpsc::UnboundedSender<BenchEvent>;

/// Send a bench event, ignoring errors (receiver may have been dropped).
#[inline]
pub fn emit(tx: &BenchEventSender, event: BenchEvent) {
    let _ = tx.send(event);
}
