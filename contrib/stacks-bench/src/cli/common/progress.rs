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

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Result;
use stacks_bench::indexer::{IndexerEvent, IndexerMetrics};
use tokio::sync::mpsc;

const INDEXER_PROGRESS_TEMPLATE: &str =
    "{msg:24} {percent:>3}% |{bar:30.cyan/blue}| {pos:>8}/{len}";

/// Drives cliclack progress UI by consuming [`IndexerEvent`]s and polling
/// [`IndexerMetrics`].
///
/// Runs until a `Finished` event is received or the channel closes (sender
/// dropped, e.g. on indexer error). In the latter case, returns `Ok(())`
/// so the actual error propagates via `try_join!` from the indexer future.
pub async fn run_indexer_progress_ui(
    mut event_rx: mpsc::UnboundedReceiver<IndexerEvent>,
    start_height: u64,
    end_height: u64,
    tip_height: u64,
) -> Result<()> {
    while let Some(event) = event_rx.recv().await {
        match event {
            IndexerEvent::Finished => break,

            IndexerEvent::AlreadyCached => {
                cliclack::log::step("Chainstate already indexed")?;
            }

            IndexerEvent::IndexIncomplete { found, expected } => {
                cliclack::log::step(format!(
                    "Index incomplete ({found}/{expected} blocks cached). Indexing from node DB..."
                ))?;
            }

            IndexerEvent::PipelineStarted {
                metrics,
                walk_progress,
            } => {
                run_pipeline_progress(
                    &mut event_rx,
                    &metrics,
                    &walk_progress,
                    start_height,
                    end_height,
                    tip_height,
                )
                .await?;
                // run_pipeline_progress returns when it receives Finished or
                // the channel closes — either way, we're done.
                return Ok(());
            }

            // Shouldn't arrive before PipelineStarted, but handle gracefully.
            IndexerEvent::Interrupted
            | IndexerEvent::CheckpointStarted
            | IndexerEvent::CheckpointComplete
            | IndexerEvent::VacuumStarted
            | IndexerEvent::VacuumComplete
            | IndexerEvent::MergeStarted
            | IndexerEvent::MergeComplete { .. }
            | IndexerEvent::FinalMergeComplete { .. } => {}
        }
    }

    Ok(())
}

/// Runs the metrics-polling + event-handling loop for the pipeline phase.
///
/// This handles the walk progress bar, block loading progress bar, merge
/// status spinner, and post-pipeline cleanup (checkpoint + vacuum) UI.
///
/// The indexing multi_progress is stopped exactly once — either when a
/// post-pipeline event (e.g. `CheckpointStarted`) arrives, or when
/// `Finished`/channel-close occurs. Post-pipeline cleanup is rendered in
/// a separate "Cleaning up" multi_progress.
async fn run_pipeline_progress(
    event_rx: &mut mpsc::UnboundedReceiver<IndexerEvent>,
    metrics: &IndexerMetrics,
    walk_progress: &std::sync::atomic::AtomicU64,
    start_height: u64,
    end_height: u64,
    tip_height: u64,
) -> Result<()> {
    // Include the indexer's hidden "start - 1" helper block in the visible
    // count. The indexer always stages `[start - 1, start, end]` (or the
    // genesis-clamped equivalent) so that the AppDb's recursive parent-chain
    // query has a valid anchor below `start`. Counting only `[start, end]`
    // makes the cache check report "0/3" while the progress bar fills to
    // "Indexed 2 blocks" — same work, two different numbers.
    let index_start_height = start_height.saturating_sub(1);
    let total_blocks = end_height - index_start_height + 1;
    let walk_distance = tip_height.saturating_sub(end_height);
    let has_walk_phase = walk_distance > 0;

    let multi = cliclack::multi_progress("Indexing chainstate");

    // Walk progress bar (only if tip is above end_height)
    let walk_pb = if has_walk_phase {
        let pb = multi
            .add(cliclack::progress_bar(walk_distance).with_template(INDEXER_PROGRESS_TEMPLATE));
        pb.start("Walking chain");
        Some(pb)
    } else {
        None
    };

    // Block loading/flushing progress bar
    let load_pb =
        multi.add(cliclack::progress_bar(total_blocks).with_template(INDEXER_PROGRESS_TEMPLATE));

    // Merge status spinner — a single spinner added when loading starts.
    // We use set_message() for intermediate state changes because cliclack's
    // stop() sets an internal `stopped` flag that can't be reset, making
    // stop/start cycling impossible. stop() is only called once, on the
    // final merge or during cleanup.
    let mut merge_pb: Option<cliclack::ProgressBar> = None;

    // Post-pipeline "Cleaning up" multi for checkpoint + vacuum.
    let mut cleanup_multi: Option<cliclack::MultiProgress> = None;
    let mut cleanup_multi_stopped = false;
    let mut checkpoint_pb: Option<cliclack::ProgressBar> = None;
    let mut vacuum_pb: Option<cliclack::ProgressBar> = None;

    let mut walk_complete = false;
    let mut loading_started = false;
    let mut load_complete = false;
    let mut multi_stopped = false;
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let poll_start = Instant::now();

    // Stops all progress bars and the indexing multi. Safe to call multiple
    // times (individual pb.stop() is a no-op once stopped; the multi_stopped
    // flag prevents calling multi.stop() more than once).
    macro_rules! finalize_multi {
        () => {
            if !multi_stopped {
                if !walk_complete {
                    if let Some(ref pb) = walk_pb {
                        pb.stop(fmt_success!("Chain walk complete"));
                    }
                }
                if !load_complete {
                    if !loading_started {
                        load_pb.start("Loading & indexing blocks");
                    }
                    let flushed = metrics.flushed_blocks.load(Ordering::Relaxed) as u64;
                    load_pb.set_position(flushed.min(total_blocks));
                    load_pb.stop(fmt_success!(
                        "Indexed {} blocks ({:.1}s)",
                        flushed.min(total_blocks),
                        poll_start.elapsed().as_secs_f32()
                    ));
                }
                // Stop merge spinner (no-op if already stopped or never created)
                if let Some(ref pb) = merge_pb {
                    pb.stop(fmt_success!("Merge complete"));
                }
                multi.stop();
                multi_stopped = true;
            }
        };
    }

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if multi_stopped { continue; }

                let loaded = metrics.loaded_blocks.load(Ordering::Relaxed) as u64;
                let flushed = metrics.flushed_blocks.load(Ordering::Relaxed) as u64;

                if !walk_complete && loaded > 0 {
                    // Walk is done, loading has begun
                    walk_complete = true;
                    if let Some(ref pb) = walk_pb {
                        pb.stop(fmt_success!(
                            "Chain walk complete ({:.1}s)",
                            poll_start.elapsed().as_secs_f32()
                        ));
                    }
                    load_pb.start("Loading & indexing blocks");
                    loading_started = true;

                    // Add merge status spinner below the loading bar
                    let spinner = multi.add(cliclack::spinner());
                    spinner.start("Merge & checkpoint: waiting");
                    merge_pb = Some(spinner);
                }

                if !walk_complete {
                    // Update walk progress
                    if let Some(ref pb) = walk_pb {
                        let current_walk_height = walk_progress.load(Ordering::Relaxed);
                        if current_walk_height > 0 && current_walk_height <= tip_height {
                            let walked = tip_height - current_walk_height;
                            pb.set_position(walked.min(walk_distance));
                        }
                    }
                } else if loading_started && !load_complete {
                    // Update loading progress
                    load_pb.set_position(flushed.min(total_blocks));

                    if flushed >= total_blocks {
                        load_pb.stop(fmt_success!(
                            "Indexed {total_blocks} blocks ({:.1}s)",
                            poll_start.elapsed().as_secs_f32()
                        ));
                        load_complete = true;
                    }
                }
            }

            event = event_rx.recv() => {
                match event {
                    Some(IndexerEvent::Finished) | None => {
                        finalize_multi!();
                        // Also finalize cleanup multi if active
                        if !cleanup_multi_stopped {
                            if let Some(ref pb) = checkpoint_pb {
                                pb.stop(fmt_success!("Checkpoint complete"));
                            }
                            if let Some(ref pb) = vacuum_pb {
                                pb.stop(fmt_success!("Vacuum complete"));
                            }
                            if let Some(ref m) = cleanup_multi {
                                m.stop();
                            }
                            cleanup_multi_stopped = true;
                        }
                        break;
                    }

                    Some(IndexerEvent::MergeStarted) => {
                        if let Some(ref pb) = merge_pb {
                            pb.set_message("Merge & checkpoint: merging...");
                        }
                    }

                    Some(IndexerEvent::MergeComplete { duration }) => {
                        if let Some(ref pb) = merge_pb {
                            pb.set_message(format!(
                                "Merge & checkpoint: idle (last in {duration:.2?})"
                            ));
                        }
                    }

                    Some(IndexerEvent::FinalMergeComplete { duration }) => {
                        if let Some(ref pb) = merge_pb {
                            pb.stop(fmt_success!(
                                "Final merge complete ({duration:.2?})"
                            ));
                        }
                    }

                    Some(IndexerEvent::CheckpointStarted) => {
                        finalize_multi!();
                        let m = cliclack::multi_progress("Cleaning up");
                        let s = m.add(cliclack::spinner());
                        s.start("Checkpointing database...");
                        checkpoint_pb = Some(s);
                        cleanup_multi = Some(m);
                    }

                    Some(IndexerEvent::CheckpointComplete) => {
                        if let Some(ref pb) = checkpoint_pb {
                            pb.stop(fmt_success!("Checkpoint complete"));
                        }
                    }

                    Some(IndexerEvent::VacuumStarted) => {
                        if let Some(ref m) = cleanup_multi {
                            let s = m.add(cliclack::spinner());
                            s.start("Vacuuming database...");
                            vacuum_pb = Some(s);
                        }
                    }

                    Some(IndexerEvent::VacuumComplete) => {
                        if let Some(ref pb) = vacuum_pb {
                            pb.stop(fmt_success!("Vacuum complete"));
                        }
                        if !cleanup_multi_stopped {
                            if let Some(ref m) = cleanup_multi {
                                m.stop();
                            }
                            cleanup_multi_stopped = true;
                        }
                    }

                    // These shouldn't arrive during pipeline, ignore.
                    Some(IndexerEvent::AlreadyCached)
                    | Some(IndexerEvent::Interrupted)
                    | Some(IndexerEvent::IndexIncomplete { .. })
                    | Some(IndexerEvent::PipelineStarted { .. }) => {}
                }
            }
        }
    }

    // Suppress unused_assignments warning: the macro's final `multi_stopped = true`
    // is dead on the `break` path but needed for the CheckpointStarted path.
    _ = multi_stopped;
    _ = cleanup_multi_stopped;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    use stacks_bench::indexer::{IndexerEvent, IndexerMetrics};
    use tokio::sync::mpsc;

    use super::run_indexer_progress_ui;

    #[tokio::test]
    async fn already_cached_then_finished() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(IndexerEvent::AlreadyCached).unwrap();
        tx.send(IndexerEvent::Finished).unwrap();
        drop(tx);

        let result = run_indexer_progress_ui(rx, 100, 200, 200).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn pipeline_started_then_finished() {
        let (tx, rx) = mpsc::unbounded_channel();
        let metrics = Arc::new(IndexerMetrics::default());
        let walk_progress = Arc::new(AtomicU64::new(0));

        tx.send(IndexerEvent::PipelineStarted {
            metrics,
            walk_progress,
        })
        .unwrap();
        tx.send(IndexerEvent::Finished).unwrap();
        drop(tx);

        let result = run_indexer_progress_ui(rx, 100, 200, 200).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn channel_close_without_finished() {
        let (tx, rx) = mpsc::unbounded_channel();
        // Simulate indexer error: drop sender without sending Finished
        drop(tx);

        let result = run_indexer_progress_ui(rx, 100, 200, 200).await;
        assert!(result.is_ok(), "UI should exit gracefully on channel close");
    }
}
