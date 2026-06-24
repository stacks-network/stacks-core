use std::io::Write as _;
use std::sync::atomic::Ordering;
use std::time::Duration;

use stacks_bench::bench_events::BenchEvent;
use stacks_bench::indexer::IndexerEvent;
use tokio::sync::mpsc;

use crate::wire::CliProgressEvent;

/// Drive the `--json` stderr progress stream for benchmark runs.
pub async fn run_bench_json_progress(
    mut rx: mpsc::UnboundedReceiver<BenchEvent>,
) -> anyhow::Result<()> {
    let mut last_sent_pct: i32 = -1;
    let mut baseline_progress: Option<(u32, u32)> = None;
    let mut last_txid_scan_bucket: u64 = 0;

    while let Some(event) = rx.recv().await {
        let progress = match &event {
            BenchEvent::TxidScanStarted { txid } => {
                last_txid_scan_bucket = 0;
                Some(progress_event(
                    "txid_scan",
                    0.0,
                    None,
                    Some(format!("Scanning for txid {txid}")),
                ))
            }
            BenchEvent::TxidScanProgress {
                scanned,
                current_height,
            } => {
                let bucket = scanned / 100;
                if *scanned == 1 || bucket != last_txid_scan_bucket {
                    last_txid_scan_bucket = bucket;
                    Some(progress_event(
                        "txid_scan",
                        *scanned as f64,
                        None,
                        Some(format!(
                            "Scanned {scanned} blocks, current height {current_height}"
                        )),
                    ))
                } else {
                    None
                }
            }
            BenchEvent::TxidScanComplete {
                txid,
                block_height,
                duration,
                ..
            } => Some(progress_event(
                "txid_scan",
                1.0,
                Some(1.0),
                Some(format!(
                    "Found txid {txid} at height {block_height} ({:.1}s)",
                    duration.as_secs_f64()
                )),
            )),
            BenchEvent::ShadowDirStarted => {
                last_sent_pct = -1;
                Some(progress_event(
                    "setup",
                    0.0,
                    None,
                    Some("Creating shadow directory...".to_string()),
                ))
            }
            BenchEvent::ShadowDirComplete { duration } => Some(progress_event(
                "setup",
                0.0,
                None,
                Some(format!(
                    "Shadow directory ready ({:.1}s)",
                    duration.as_secs_f64()
                )),
            )),
            BenchEvent::ChainstatePassthroughEnabled { source } => Some(progress_event(
                "setup",
                0.0,
                None,
                Some(format!(
                    "DESTRUCTIVE: --dangerous-no-chainstate-copy enabled; running directly against {source}"
                )),
            )),
            BenchEvent::ModeSummary(summary) => Some(progress_event(
                "planning",
                0.0,
                None,
                Some(format!(
                    "Benchmark plan: mode={} targets={} warmup={} per target ({} total), measured={} per target ({} total), baseline={}, isolation={}",
                    summary.target_mode,
                    summary.logical_targets,
                    summary.warmup_per_target,
                    summary.warmup_entries,
                    summary.measured_per_target,
                    summary.measured_entries,
                    summary.baseline_mode,
                    summary.isolation
                )),
            )),
            BenchEvent::BaselineStarted {
                segment_size,
                max_segments,
                ..
            } => {
                last_sent_pct = -1;
                let max_blocks = *segment_size * *max_segments;
                baseline_progress = Some((0, max_blocks));
                Some(progress_event(
                    "baseline",
                    0.0,
                    Some(max_blocks as f64),
                    Some(format!(
                        "Measuring baseline overhead (up to {max_blocks} blocks; stops on convergence)"
                    )),
                ))
            }
            BenchEvent::BaselineProgress {
                blocks_completed,
                max_blocks,
            } => {
                baseline_progress = Some((*blocks_completed, *max_blocks));
                debounced(
                    &mut last_sent_pct,
                    *blocks_completed as f64,
                    *max_blocks as f64,
                    || {
                        progress_event(
                            "baseline",
                            *blocks_completed as f64,
                            Some(*max_blocks as f64),
                            Some("Baseline sampling".to_string()),
                        )
                    },
                )
            }
            BenchEvent::BaselineSegmentComplete {
                segment_index,
                convergence_pct,
                ..
            } => {
                let msg = match convergence_pct {
                    Some(pct) => format!(
                        "Baseline segment {segment_index}, rolling delta {:.2}%",
                        pct * 100.0
                    ),
                    None => format!("Baseline segment {segment_index}"),
                };
                let (completed, total) = baseline_progress.unwrap_or((0, 0));
                Some(progress_event(
                    "baseline",
                    completed as f64,
                    Some(total as f64),
                    Some(msg),
                ))
            }
            BenchEvent::BaselineComplete {
                converged,
                segments_used,
                total_blocks,
                ..
            } => {
                last_sent_pct = -1;
                let status = if *converged {
                    "converged"
                } else {
                    "max segments"
                };
                Some(progress_event(
                    "baseline",
                    *total_blocks as f64,
                    Some(*total_blocks as f64),
                    Some(format!(
                        "Baseline {status} after {segments_used} segments ({total_blocks} blocks)"
                    )),
                ))
            }
            BenchEvent::BaselineReused {
                calibration_id,
                start_parent_index_hash,
            } => Some(progress_event(
                "baseline",
                1.0,
                Some(1.0),
                Some(format!(
                    "Reusing baseline calibration #{calibration_id} at {start_parent_index_hash}"
                )),
            )),
            BenchEvent::BaselineSkipped => Some(progress_event(
                "baseline",
                1.0,
                Some(1.0),
                Some("Skipped baseline calibration".to_string()),
            )),
            BenchEvent::ReplayStarted {
                total_entries,
                warmup_entries,
                ..
            } => {
                last_sent_pct = -1;
                Some(progress_event(
                    "replay",
                    0.0,
                    Some(*total_entries as f64),
                    Some(format!(
                        "Replaying entries (warmup: {warmup_entries}, measured: {})",
                        total_entries - warmup_entries
                    )),
                ))
            }
            BenchEvent::ReplayWarmupProgress { completed, total } => {
                debounced(&mut last_sent_pct, *completed as f64, *total as f64, || {
                    progress_event(
                        "warmup",
                        *completed as f64,
                        Some(*total as f64),
                        Some("Warmup".to_string()),
                    )
                })
            }
            BenchEvent::ReplayWarmupComplete {
                warmup_entries,
                duration,
            } => {
                last_sent_pct = -1;
                Some(progress_event(
                    "warmup",
                    *warmup_entries as f64,
                    Some(*warmup_entries as f64),
                    Some(format!(
                        "Warmup complete ({warmup_entries} entries in {:.1}s)",
                        duration.as_secs_f64()
                    )),
                ))
            }
            BenchEvent::ReplayProgress { completed, total } => {
                debounced(&mut last_sent_pct, *completed as f64, *total as f64, || {
                    progress_event("replay", *completed as f64, Some(*total as f64), None)
                })
            }
            BenchEvent::ReplayInterrupted { completed, total } => Some(progress_event(
                "replay",
                *completed as f64,
                Some(*total as f64),
                Some("Replay interrupted".to_string()),
            )),
            BenchEvent::ReplayComplete {
                measured_entries,
                duration,
            } => {
                last_sent_pct = -1;
                Some(progress_event(
                    "replay",
                    *measured_entries as f64,
                    Some(*measured_entries as f64),
                    Some(format!("Replay complete ({:.1}s)", duration.as_secs_f64())),
                ))
            }
            BenchEvent::MetricsFlush { count } => Some(progress_event(
                "metrics",
                *count as f64,
                None,
                Some(format!("Flushed {count} sampled metric rows")),
            )),
            BenchEvent::CleanupStarted { .. } => Some(progress_event(
                "cleanup",
                0.0,
                None,
                Some("Cleaning up...".to_string()),
            )),
            BenchEvent::CleanupComplete => Some(progress_event(
                "cleanup",
                1.0,
                Some(1.0),
                Some("Cleanup complete".to_string()),
            )),
            _ => None,
        };

        if let Some(progress) = progress {
            emit(&progress);
        }
    }

    Ok(())
}

/// Drive the `--json` stderr progress stream for chainstate indexing.
pub async fn run_indexer_json_progress(
    mut rx: mpsc::UnboundedReceiver<IndexerEvent>,
    _start_height: u64,
    _end_height: u64,
    _tip_height: u64,
) -> anyhow::Result<()> {
    let mut expected_blocks: usize = 0;

    while let Some(event) = rx.recv().await {
        match event {
            IndexerEvent::AlreadyCached => {
                expected_blocks = 1;
                emit(&progress_event(
                    "indexing",
                    1.0,
                    Some(1.0),
                    Some("Chainstate already indexed".to_string()),
                ));
            }
            IndexerEvent::IndexIncomplete { found, expected } => {
                expected_blocks = expected;
                emit(&progress_event(
                    "indexing",
                    found as f64,
                    Some(expected as f64),
                    Some(format!(
                        "Index incomplete ({found}/{expected}), indexing..."
                    )),
                ));
            }
            IndexerEvent::PipelineStarted { metrics, .. } => {
                // The indexer emits IndexIncomplete before PipelineStarted for
                // real indexing work. Keep a defensive floor to avoid a zero
                // total if that ordering ever changes.
                let total = expected_blocks.max(1) as f64;
                let mut last_pct: i32 = -1;
                emit(&progress_event(
                    "indexing",
                    0.0,
                    Some(total),
                    Some("Indexing blocks...".to_string()),
                ));

                loop {
                    tokio::select! {
                        biased;
                        next = rx.recv() => {
                            match next {
                                Some(IndexerEvent::Finished) => {
                                    emit(&progress_event(
                                        "indexing",
                                        total,
                                        Some(total),
                                        Some("Indexing complete".to_string()),
                                    ));
                                    return Ok(());
                                }
                                Some(IndexerEvent::Interrupted) => {
                                    emit(&progress_event(
                                        "indexing",
                                        total,
                                        Some(total),
                                        Some("Indexing interrupted".to_string()),
                                    ));
                                    return Ok(());
                                }
                                Some(IndexerEvent::MergeStarted) => emit(&progress_event(
                                    "index_merge",
                                    0.0,
                                    None,
                                    Some("Merging indexed batches...".to_string()),
                                )),
                                Some(IndexerEvent::MergeComplete { duration }) => emit(&progress_event(
                                    "index_merge",
                                    1.0,
                                    Some(1.0),
                                    Some(format!("Merge complete ({:.1}s)", duration.as_secs_f64())),
                                )),
                                Some(IndexerEvent::FinalMergeComplete { duration }) => emit(&progress_event(
                                    "index_merge",
                                    1.0,
                                    Some(1.0),
                                    Some(format!("Final merge complete ({:.1}s)", duration.as_secs_f64())),
                                )),
                                Some(IndexerEvent::CheckpointStarted) => emit(&progress_event(
                                    "index_checkpoint",
                                    0.0,
                                    None,
                                    Some("Checkpointing index database...".to_string()),
                                )),
                                Some(IndexerEvent::CheckpointComplete) => emit(&progress_event(
                                    "index_checkpoint",
                                    1.0,
                                    Some(1.0),
                                    Some("Checkpoint complete".to_string()),
                                )),
                                Some(IndexerEvent::VacuumStarted) => emit(&progress_event(
                                    "index_vacuum",
                                    0.0,
                                    None,
                                    Some("Vacuuming index database...".to_string()),
                                )),
                                Some(IndexerEvent::VacuumComplete) => emit(&progress_event(
                                    "index_vacuum",
                                    1.0,
                                    Some(1.0),
                                    Some("Vacuum complete".to_string()),
                                )),
                                Some(IndexerEvent::AlreadyCached)
                                | Some(IndexerEvent::IndexIncomplete { .. })
                                | Some(IndexerEvent::PipelineStarted { .. }) => {}
                                None => return Ok(()),
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {
                            let flushed = metrics.flushed_blocks.load(Ordering::Relaxed) as f64;
                            let pct = ((flushed / total) * 100.0) as i32;
                            if pct != last_pct {
                                last_pct = pct;
                                emit(&progress_event("indexing", flushed, Some(total), None));
                            }
                        }
                    }
                }
            }
            IndexerEvent::MergeStarted => emit(&progress_event(
                "index_merge",
                0.0,
                None,
                Some("Merging indexed batches...".to_string()),
            )),
            IndexerEvent::MergeComplete { duration } => emit(&progress_event(
                "index_merge",
                1.0,
                Some(1.0),
                Some(format!("Merge complete ({:.1}s)", duration.as_secs_f64())),
            )),
            IndexerEvent::FinalMergeComplete { duration } => emit(&progress_event(
                "index_merge",
                1.0,
                Some(1.0),
                Some(format!(
                    "Final merge complete ({:.1}s)",
                    duration.as_secs_f64()
                )),
            )),
            IndexerEvent::CheckpointStarted => emit(&progress_event(
                "index_checkpoint",
                0.0,
                None,
                Some("Checkpointing index database...".to_string()),
            )),
            IndexerEvent::CheckpointComplete => emit(&progress_event(
                "index_checkpoint",
                1.0,
                Some(1.0),
                Some("Checkpoint complete".to_string()),
            )),
            IndexerEvent::VacuumStarted => emit(&progress_event(
                "index_vacuum",
                0.0,
                None,
                Some("Vacuuming index database...".to_string()),
            )),
            IndexerEvent::VacuumComplete => emit(&progress_event(
                "index_vacuum",
                1.0,
                Some(1.0),
                Some("Vacuum complete".to_string()),
            )),
            IndexerEvent::Finished => {
                emit(&progress_event(
                    "indexing",
                    expected_blocks as f64,
                    Some(expected_blocks as f64),
                    Some("Indexing complete".to_string()),
                ));
                return Ok(());
            }
            IndexerEvent::Interrupted => {
                emit(&progress_event(
                    "indexing",
                    expected_blocks as f64,
                    Some(expected_blocks as f64),
                    Some("Indexing interrupted".to_string()),
                ));
                return Ok(());
            }
        }
    }

    Ok(())
}

fn progress_event(
    phase: &'static str,
    progress: f64,
    total: Option<f64>,
    message: Option<String>,
) -> CliProgressEvent {
    CliProgressEvent::progress(phase, progress, total, message)
}

fn emit(event: &CliProgressEvent) {
    let Ok(line) = serde_json::to_string(event) else {
        return;
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
}

/// Only produce a notification when the whole-percent value changes.
fn debounced(
    last_pct: &mut i32,
    completed: f64,
    total: f64,
    make: impl FnOnce() -> CliProgressEvent,
) -> Option<CliProgressEvent> {
    if total <= 0.0 {
        return Some(make());
    }
    let pct = ((completed / total) * 100.0) as i32;
    if pct != *last_pct {
        *last_pct = pct;
        Some(make())
    } else {
        None
    }
}
