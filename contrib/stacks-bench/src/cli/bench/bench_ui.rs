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

//! Interactive cliclack renderer for [`BenchEvent`]s.
//!
//! Consumes events from a channel and drives spinners, progress bars, notes,
//! and summary tables. The core benchmark logic emits events without any
//! knowledge of this module.

use std::time::Duration;

use anyhow::Result;
use stacks_bench::bench_events::BenchEvent;
use stacks_bench::metrics::{BlockProcessingBaseline, MetricsSummary};
use stacks_bench::shadow::ShadowDirDeltaReport;
use tokio::sync::mpsc;

use crate::cli::common::{Align, Table, fmt_u64_thousands};

const PROGRESS_BAR_TEMPLATE: &str = "{msg:20} {percent:>3}% |{bar:30.cyan/blue}| {pos:>8}/{len} • {per_sec:<6!} blk/s • ETA {eta_precise}";

/// Drive the interactive cliclack UI by consuming [`BenchEvent`]s.
///
/// Holds stateful UI handles (spinners, progress bars) that persist across
/// events. Returns when the channel closes (sender dropped).
pub async fn run_bench_progress_ui(mut rx: mpsc::UnboundedReceiver<BenchEvent>) -> Result<()> {
    let mut renderer = BenchRenderer::default();

    while let Some(event) = rx.recv().await {
        renderer.handle(event)?;
    }

    Ok(())
}

/// Stateful renderer that holds cliclack UI handles across events.
#[derive(Default)]
struct BenchRenderer {
    // Txid scan
    scan_spinner: Option<cliclack::ProgressBar>,

    // Shadow dir
    shadow_spinner: Option<cliclack::ProgressBar>,

    // Baseline phase
    baseline_multi: Option<cliclack::MultiProgress>,
    baseline_pb: Option<cliclack::ProgressBar>,
    baseline_checkpoint_pb: Option<cliclack::ProgressBar>,
    /// Most-recent convergence delta, surfaced in the progress bar label so
    /// users can see the rolling-window stabilization in real time.
    baseline_last_convergence_pct: Option<f64>,

    // Replay phase
    replay_multi: Option<cliclack::MultiProgress>,
    warmup_pb: Option<cliclack::ProgressBar>,
    replay_pb: Option<cliclack::ProgressBar>,

    // Cleanup phase
    cleanup_multi: Option<cliclack::MultiProgress>,
    cleanup_shadow_spinner: Option<cliclack::ProgressBar>,
    cleanup_db_spinner: Option<cliclack::ProgressBar>,
}

impl BenchRenderer {
    fn handle(&mut self, event: BenchEvent) -> Result<()> {
        match event {
            // --- Txid scan ---
            BenchEvent::TxidScanStarted { txid } => {
                let spinner = cliclack::spinner();
                spinner.start(format!("Scanning canonical chain for txid {txid}..."));
                self.scan_spinner = Some(spinner);
            }
            BenchEvent::TxidScanProgress {
                scanned,
                current_height,
            } => {
                if let Some(ref spinner) = self.scan_spinner {
                    spinner.set_message(format!(
                        "Scanning... checked {scanned} blocks (height {current_height})"
                    ));
                }
            }
            BenchEvent::TxidScanComplete {
                txid,
                block_id,
                block_height,
                duration,
            } => {
                if let Some(spinner) = self.scan_spinner.take() {
                    spinner.stop(fmt_success!(
                        "Found txid {txid} in block {block_id} (height {block_height}) — {:.2}s",
                        duration.as_secs_f32()
                    ));
                }
            }

            // --- Shadow dir ---
            BenchEvent::ShadowDirStarted => {
                let spinner = cliclack::spinner();
                spinner.start("Copying source node data directory (this may take some time)...");
                self.shadow_spinner = Some(spinner);
            }
            BenchEvent::ShadowDirComplete { duration } => {
                if let Some(spinner) = self.shadow_spinner.take() {
                    spinner.stop(fmt_success!(
                        "Chainstate copied in {:.2}s [reflink/CoW]",
                        duration.as_secs_f32()
                    ));
                }
            }
            BenchEvent::ChainstatePassthroughEnabled { source } => {
                cliclack::log::warning(format!(
                    "DESTRUCTIVE: --dangerous-no-chainstate-copy is enabled. \
                     Running directly against {source}; writes during the bench will mutate \
                     the source chainstate permanently."
                ))?;
            }

            // --- Environment ---
            BenchEvent::EnvironmentReady {
                chain_id,
                network,
                epochs,
                source_dir,
                shadow_dir,
                target_txid,
                target_block,
                target_block_height,
                repetitions,
            } => {
                let mut lines = format!(
                    "Chain ID:   {chain_id}\n\
                     Network:    {network}\n\
                     Epochs:     {}\n\
                     Source Dir: {source_dir}\n\
                     Shadow Dir: {shadow_dir}",
                    epochs.join(", "),
                );
                if let Some(txid) = target_txid {
                    lines.push_str(&format!("\nTarget Tx:  {txid}"));
                }
                match (target_block, target_block_height) {
                    (Some(block), Some(height)) => {
                        lines.push_str(&format!("\nBlock:      {block} (height {height})"));
                    }
                    (Some(block), None) => {
                        lines.push_str(&format!("\nBlock:      {block}"));
                    }
                    (None, Some(height)) => {
                        lines.push_str(&format!("\nBlock:      height {height}"));
                    }
                    (None, None) => {}
                }
                if let Some(reps) = repetitions {
                    lines.push_str(&format!("\nRepetitions: {reps}"));
                }
                cliclack::note("Environment Summary", lines)?;
            }

            // --- Baseline ---
            BenchEvent::BaselineStarted {
                segment_size,
                max_segments,
                ..
            } => {
                let multi =
                    cliclack::multi_progress("Calculating block processing overhead baseline");

                let max_blocks = u64::from(segment_size) * u64::from(max_segments);
                let pb = multi
                    .add(cliclack::progress_bar(max_blocks).with_template(PROGRESS_BAR_TEMPLATE));
                pb.start("Sampling empty blocks (auto-stops on convergence)");
                self.baseline_pb = Some(pb);
                self.baseline_last_convergence_pct = None;
                self.baseline_multi = Some(multi);
            }
            BenchEvent::BaselineProgress {
                blocks_completed, ..
            } => {
                if let Some(ref pb) = self.baseline_pb {
                    pb.set_position(blocks_completed as u64);
                }
            }
            BenchEvent::BaselineSegmentComplete {
                segment_index,
                convergence_pct,
                ..
            } => {
                if let Some(pct) = convergence_pct {
                    self.baseline_last_convergence_pct = Some(pct);
                }
                if let Some(ref pb) = self.baseline_pb {
                    let msg = match self.baseline_last_convergence_pct {
                        Some(pct) => format!(
                            "Sampling — segment {segment_index}, rolling \u{0394} {:.2}%",
                            pct * 100.0
                        ),
                        None => format!(
                            "Sampling — segment {segment_index} (collecting convergence window)"
                        ),
                    };
                    pb.set_message(msg);
                }
            }
            BenchEvent::BaselineCheckpointStarted => {
                if let Some(pb) = self.baseline_pb.take() {
                    pb.stop(fmt_success!("Baseline sampling complete"));
                }
                if let Some(ref multi) = self.baseline_multi {
                    let spinner = multi.add(cliclack::spinner());
                    spinner.start("Checkpointing chainstate and Clarity DBs...");
                    self.baseline_checkpoint_pb = Some(spinner);
                }
            }
            BenchEvent::BaselineCheckpointComplete { duration } => {
                if let Some(pb) = self.baseline_checkpoint_pb.take() {
                    pb.stop(fmt_success!(
                        "Checkpointing complete ({:.2}s)",
                        duration.as_secs_f32()
                    ));
                }
                if let Some(multi) = self.baseline_multi.take() {
                    multi.stop();
                }
            }
            BenchEvent::BaselineComplete {
                baseline,
                converged,
                segments_used,
                measurement_window,
                total_blocks,
                duration,
            } => {
                cliclack::note(
                    "Block Processing Overhead Baseline",
                    format_baseline_note(
                        &baseline,
                        converged,
                        segments_used,
                        measurement_window,
                        total_blocks,
                        duration,
                    ),
                )?;
            }

            // --- Replay ---
            BenchEvent::ReplayStarted {
                total_blocks,
                warmup_blocks,
                mode,
            } => {
                let measured = total_blocks - warmup_blocks;
                let multi = cliclack::multi_progress(format!(
                    "Re-executing {measured} blocks in {mode} mode"
                ));

                if warmup_blocks > 0 {
                    let pb = multi.add(
                        cliclack::progress_bar(warmup_blocks as u64)
                            .with_template(PROGRESS_BAR_TEMPLATE),
                    );
                    pb.start("Warming up");
                    self.warmup_pb = Some(pb);
                }

                let pb = multi.add(
                    cliclack::progress_bar(measured as u64).with_template(PROGRESS_BAR_TEMPLATE),
                );
                if warmup_blocks == 0 {
                    pb.start("Replaying measured blocks...");
                }
                self.replay_pb = Some(pb);
                self.replay_multi = Some(multi);
            }
            BenchEvent::ReplayWarmupProgress { completed, .. } => {
                if let Some(ref pb) = self.warmup_pb {
                    pb.set_position(completed as u64);
                }
            }
            BenchEvent::ReplayWarmupComplete {
                warmup_blocks,
                duration,
            } => {
                if let Some(pb) = self.warmup_pb.take() {
                    pb.stop(fmt_success!(
                        "Warmup complete ({} blocks in {:.2}s)",
                        warmup_blocks,
                        duration.as_secs_f32()
                    ));
                }
                if let Some(ref pb) = self.replay_pb {
                    pb.start("Replaying measured blocks...");
                }
            }
            BenchEvent::ReplayProgress { completed, .. } => {
                if let Some(ref pb) = self.replay_pb {
                    pb.set_position(completed as u64);
                }
            }
            BenchEvent::ReplayInterrupted { completed, total } => {
                if let Some(pb) = self.replay_pb.take() {
                    pb.cancel(format!("Interrupted ({completed}/{total})"));
                }
                if let Some(multi) = self.replay_multi.take() {
                    multi.cancel();
                }
            }
            BenchEvent::ReplayComplete {
                measured_blocks,
                duration,
            } => {
                if let Some(pb) = self.replay_pb.take() {
                    pb.stop(fmt_success!(
                        "Replayed {} blocks in {:.2}s",
                        measured_blocks,
                        duration.as_secs_f32()
                    ));
                }
                if let Some(multi) = self.replay_multi.take() {
                    multi.stop();
                }
            }

            // --- Metrics flush ---
            BenchEvent::MetricsFlush { count } => {
                cliclack::log::step(format!(
                    "Flushing remaining {count} block metrics from buffer"
                ))?;
            }

            // --- Summary ---
            BenchEvent::ReplaySummary {
                total_blocks,
                warmup_blocks,
                measured_blocks,
                total_duration,
                warmup_duration,
                replay_duration,
                checkpoint_duration,
                overhead,
                storage_delta_duration,
                block_load_duration,
                metrics_flush_duration,
                interrupted,
            } => {
                let mut table = Table::new()
                    .col("Metric", Align::Left)
                    .col("Value", Align::Right);
                table.row(vec![
                    "Blocks".into(),
                    format!("{total_blocks} ({warmup_blocks} warmup + {measured_blocks} measured)"),
                ]);
                table.row(vec![
                    "Total Duration".into(),
                    format!("{total_duration:.2?}"),
                ]);
                if warmup_blocks > 0 {
                    table.row(vec![
                        "Warmup Replay".into(),
                        format!("{warmup_duration:.2?}"),
                    ]);
                }
                table.row(vec![
                    "Block Replay".into(),
                    format!("{replay_duration:.2?}"),
                ]);
                table.row(vec![
                    "Clarity DB Checkpointing".into(),
                    format!("{checkpoint_duration:.2?}"),
                ]);
                table.row(vec![
                    "Benchmarking Overhead".into(),
                    format!("{overhead:.2?}"),
                ]);
                // Sub-breakdown of the overhead bucket. "Other" captures
                // everything left after subtracting the three measured
                // pieces (profiler clear/take, BlockMetrics construction,
                // loop scaffolding, event channel sends).
                let other_overhead = overhead
                    .saturating_sub(storage_delta_duration)
                    .saturating_sub(block_load_duration)
                    .saturating_sub(metrics_flush_duration);
                table.row(vec![
                    "  Storage Delta".into(),
                    format!("{storage_delta_duration:.2?}"),
                ]);
                table.row(vec![
                    "  Block Load".into(),
                    format!("{block_load_duration:.2?}"),
                ]);
                table.row(vec![
                    "  Metrics Flush".into(),
                    format!("{metrics_flush_duration:.2?}"),
                ]);
                table.row(vec!["  Other".into(), format!("{other_overhead:.2?}")]);
                if interrupted {
                    let planned = total_blocks - warmup_blocks;
                    table.row(vec![
                        "Status".into(),
                        format!("INTERRUPTED ({measured_blocks}/{planned} measured blocks)"),
                    ]);
                }
                cliclack::note("Replay Summary", table.to_string())?;
            }
            BenchEvent::BenchmarkSummary(s) => {
                print_benchmark_summary(&s)?;
            }
            BenchEvent::StorageSummary(report) => {
                print_storage_delta_report(&report)?;
            }

            // --- Cleanup ---
            BenchEvent::CleanupStarted { passthrough } => {
                let multi = cliclack::multi_progress("Cleaning up");
                // In passthrough mode there's no shadow dir to remove, so
                // skip its spinner — the matching `CleanupShadowDirComplete`
                // event never fires.
                if !passthrough {
                    let shadow_spinner = multi.add(cliclack::spinner());
                    shadow_spinner.start("Removing shadow directory...");
                    self.cleanup_shadow_spinner = Some(shadow_spinner);
                }
                let db_spinner = multi.add(cliclack::spinner());
                db_spinner.start("Checkpointing database...");
                self.cleanup_db_spinner = Some(db_spinner);
                self.cleanup_multi = Some(multi);
            }
            BenchEvent::CleanupShadowDirComplete { duration } => {
                if let Some(spinner) = self.cleanup_shadow_spinner.take() {
                    spinner.stop(fmt_success!(
                        "Shadow directory removed ({:.2}s)",
                        duration.as_secs_f32()
                    ));
                }
            }
            BenchEvent::CleanupDbComplete { duration } => {
                if let Some(spinner) = self.cleanup_db_spinner.take() {
                    spinner.stop(fmt_success!(
                        "Checkpoint + vacuum complete ({:.2}s)",
                        duration.as_secs_f32()
                    ));
                }
            }
            BenchEvent::CleanupDbFailed { error, duration } => {
                if let Some(spinner) = self.cleanup_db_spinner.take() {
                    spinner.stop(fmt_failure!(
                        "Checkpoint/vacuum failed: {error} ({:.2}s)",
                        duration.as_secs_f32()
                    ));
                }
            }
            BenchEvent::CleanupComplete => {
                if let Some(multi) = self.cleanup_multi.take() {
                    multi.stop();
                }
            }
        }

        Ok(())
    }
}

fn format_baseline_note(
    baseline: &BlockProcessingBaseline,
    converged: bool,
    segments_used: u32,
    measurement_window: u32,
    total_blocks: u32,
    duration: Duration,
) -> String {
    let mut table = Table::new()
        .col("Phase", Align::Left)
        .col("Average", Align::Right);

    let row = |label: &str, v: Duration| vec![label.into(), format!("{v:.2?}")];

    table.row(row("Setup", baseline.avg_setup_duration));
    table.row(row("Finalize", baseline.avg_finalize_duration));
    table.row(row(
        "Clarity commit",
        baseline.avg_clarity_state_commit_duration,
    ));
    table.row(row("Advance tip", baseline.avg_advance_tip_duration));
    table.row(row("Index commit", baseline.avg_index_commit_duration));

    let status = if converged {
        format!("converged after {segments_used} segments")
    } else {
        format!("max segments reached ({segments_used}) without convergence")
    };
    format!(
        "{}\n\n{status}\n{total_blocks} blocks sampled in {:.2}s, last {} segments averaged",
        table,
        duration.as_secs_f32(),
        measurement_window,
    )
}

fn print_benchmark_summary(s: &MetricsSummary) -> Result<()> {
    if s.count == 0 {
        return Ok(());
    }

    let count = s.count as u32;
    let avg_txs = s.txs as f64 / s.count as f64;

    let mut table = Table::new()
        .col("Metric", Align::Left)
        .col("Total", Align::Right)
        .col("Per Block", Align::Right);

    table.row(vec![
        "Blocks".into(),
        fmt_u64_thousands(s.count),
        "\u{2014}".into(),
    ]);
    table.row(vec![
        "Transactions".into(),
        fmt_u64_thousands(s.txs),
        format!("{avg_txs:.1}"),
    ]);
    table.row(vec![
        "Duration".into(),
        format!("{:.2?}", s.duration),
        format!("{:.2?}", s.duration / count),
    ]);
    table.row(vec![
        "  Setup".into(),
        format!("{:.2?}", s.setup),
        format!("{:.2?}", s.setup / count),
    ]);
    table.row(vec![
        "  Execution".into(),
        format!("{:.2?}", s.exec),
        format!("{:.2?}", s.exec / count),
    ]);
    table.row(vec![
        "  Commit".into(),
        format!("{:.2?}", s.commit),
        format!("{:.2?}", s.commit / count),
    ]);
    table.row(vec![
        "Clarity Runtime".into(),
        fmt_u64_thousands(s.runtime),
        fmt_u64_thousands(s.runtime / s.count),
    ]);
    table.row(vec![
        "Write Length".into(),
        fmt_u64_thousands(s.write_len),
        fmt_u64_thousands(s.write_len / s.count),
    ]);
    table.row(vec![
        "Read Length".into(),
        fmt_u64_thousands(s.read_len),
        fmt_u64_thousands(s.read_len / s.count),
    ]);

    cliclack::note("Benchmark Summary", table)?;
    Ok(())
}

fn print_storage_delta_report(report: &ShadowDirDeltaReport) -> Result<()> {
    let growth = report.net_growth_bytes;
    let written = report.estimated_bytes_written;

    let build_summary_table = |min_width: usize| {
        let metric_col_w = "Est. Data Written".len();
        let value_min = min_width.saturating_sub(metric_col_w + 2);
        let mut t = Table::new().col("Metric", Align::Left).col_with(
            "Value",
            Align::Right,
            value_min,
            None,
        );
        t.row(vec![
            "Net Change".into(),
            format!("{:.3} MB", growth as f64 / 1_024.0 / 1_024.0),
        ]);
        t.row(vec![
            "Est. Data Written".into(),
            format!("{:.3} MB", written as f64 / 1_024.0 / 1_024.0),
        ]);
        t
    };

    if report.file_reports.is_empty() {
        cliclack::note("Storage Summary", build_summary_table(0).to_string())?;
        return Ok(());
    }

    let mut table = Table::new()
        .col("Status", Align::Left)
        .col_with("Path", Align::Left, 20, Some(60))
        .col("Delta (MB)", Align::Right);

    for f in &report.file_reports {
        let status = if f.was_modified {
            "MODIFIED"
        } else {
            "CREATED"
        };
        let sign = if f.size_delta_bytes > 0 { "+" } else { "" };
        let delta_mb = f.size_delta_bytes as f64 / 1_024.0 / 1_024.0;
        table.row(vec![
            status.into(),
            f.path.display().to_string(),
            format!("{sign}{delta_mb:.3}"),
        ]);
    }

    let summary_table = build_summary_table(table.display_width());
    cliclack::note("Storage Summary", format!("{table}\n\n{summary_table}"))?;
    Ok(())
}
