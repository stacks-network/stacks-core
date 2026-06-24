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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use blockstack_lib::chainstate::stacks::StacksTransaction;
use futures::StreamExt;
use stacks_common::types::chainstate::StacksBlockId;
use tokio::sync::mpsc;

use crate::blocks::{BlockHeaderProvider, BlockRef, ChainCache as _};
use crate::context::BenchEnv;
use crate::db::app::{AppDb, CheckpointMode, ForeignKeyMode, SynchronizationMode};
use crate::{Network, StacksBlockHeader, StacksBlockLoader, StacksEpoch};

pub struct ChainIndexPlan {
    pub anchor_tip: BlockRef,
    pub start_height: u64,
    pub end_height: u64,
    pub expected_start_ids: Vec<StacksBlockId>,
    pub expected_end_ids: Vec<StacksBlockId>,
}

pub struct ResolvedRange {
    pub anchor_tip: BlockRef,
    pub start: BlockRef,
    pub end: BlockRef,
}

fn format_expected_ids(ids: &[StacksBlockId]) -> String {
    const MAX_DISPLAY: usize = 4;

    let shown = ids
        .iter()
        .take(MAX_DISPLAY)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if ids.len() > MAX_DISPLAY {
        format!("{shown}, ... ({} total)", ids.len())
    } else {
        shown
    }
}

/// Discrete events emitted by the indexer for UI rendering.
///
/// The `Finished` variant is a terminal event: the UI must exit upon receiving it.
/// If the indexer errors before sending `Finished`, the channel closes (sender dropped)
/// and the UI should handle `None` from `recv()` gracefully.
#[derive(Debug)]
pub enum IndexerEvent {
    /// The requested range is already fully indexed; no pipeline needed.
    AlreadyCached,
    /// The AppDb index is incomplete; pipeline will run.
    IndexIncomplete { found: usize, expected: usize },
    /// Pipeline started — includes shared metrics handle for polling and
    /// a walk-progress tracker (current height during the pre-range chain walk).
    PipelineStarted {
        metrics: Arc<IndexerMetrics>,
        walk_progress: Arc<AtomicU64>,
    },
    /// A merge operation has started (incremental or final).
    MergeStarted,
    /// An incremental merge completed.
    MergeComplete { duration: Duration },
    /// The final merge completed.
    FinalMergeComplete { duration: Duration },
    /// Checkpoint started (after pipeline).
    CheckpointStarted,
    /// Checkpoint finished.
    CheckpointComplete,
    /// Vacuum started.
    VacuumStarted,
    /// Vacuum finished.
    VacuumComplete,
    /// Indexing was interrupted by the caller (cancellation / ctrl-c).
    Interrupted,
    /// Indexing is complete (terminal event). UI must exit on receiving this.
    Finished,
}

#[derive(Debug, Default)]
pub struct IndexerMetrics {
    pub loaded_blocks: AtomicUsize,
    pub loaded_txs: AtomicUsize,
    pub last_loaded_height: AtomicU64,
    pub flushed_blocks: AtomicUsize,
    pub flushed_txs: AtomicUsize,
}

impl IndexerMetrics {
    fn record_loaded_block(&self, height: u64, tx_count: usize) {
        self.loaded_blocks.fetch_add(1, Ordering::Relaxed);
        self.loaded_txs.fetch_add(tx_count, Ordering::Relaxed);
        self.last_loaded_height.store(height, Ordering::Relaxed);
    }

    fn record_flush(&self, block_count: usize, tx_count: usize) {
        self.flushed_blocks
            .fetch_add(block_count, Ordering::Relaxed);
        self.flushed_txs.fetch_add(tx_count, Ordering::Relaxed);
    }
}

pub struct ChainstateIndexer<'a> {
    app_db: &'a mut AppDb,
    env: &'a BenchEnv,
    batch_size: usize,
    merge_threshold: usize,
    channel_buffer_size: usize,
    event_tx: Option<mpsc::UnboundedSender<IndexerEvent>>,
    interrupted: Option<Arc<AtomicBool>>,
}

impl<'a> ChainstateIndexer<'a> {
    pub const DEFAULT_BATCH_SIZE: usize = 1_000;
    pub const DEFAULT_MERGE_THRESHOLD: usize = 100_000;
    pub const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 5_000;

    pub fn new(app_db: &'a mut AppDb, env: &'a BenchEnv) -> Self {
        Self {
            app_db,
            env,
            batch_size: Self::DEFAULT_BATCH_SIZE,
            merge_threshold: Self::DEFAULT_MERGE_THRESHOLD,
            channel_buffer_size: Self::DEFAULT_CHANNEL_BUFFER_SIZE,
            event_tx: None,
            interrupted: None,
        }
    }

    pub fn with_events(mut self, tx: mpsc::UnboundedSender<IndexerEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    pub fn with_interrupted(mut self, flag: Arc<AtomicBool>) -> Self {
        self.interrupted = Some(flag);
        self
    }

    fn is_interrupted(&self) -> bool {
        self.interrupted
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }

    pub fn set_batch_size(&mut self, batch_size: usize) {
        self.batch_size = batch_size;
    }

    fn send_event(&self, event: IndexerEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }

    async fn try_get_cached_id_at_height(
        &mut self,
        anchor_tip_id: &StacksBlockId,
        target_height: u64,
    ) -> Result<Option<StacksBlockId>> {
        match self
            .app_db
            .find_closest_ancestor(anchor_tip_id, target_height)
            .await?
        {
            Some((id, h)) if h == target_height => Ok(Some(id)),
            _ => Ok(None),
        }
    }

    async fn build_resolved_from_ids(
        &mut self,
        anchor_tip: BlockRef,
        start_id: StacksBlockId,
        start_height: u64,
        end_id: StacksBlockId,
        end_height: u64,
    ) -> Result<ResolvedRange> {
        Ok(ResolvedRange {
            anchor_tip,
            start: BlockRef {
                id: start_id,
                height: start_height,
            },
            end: BlockRef {
                id: end_id,
                height: end_height,
            },
        })
    }

    fn verify_resolved_range(
        resolved: &ResolvedRange,
        expected_start_ids: &[StacksBlockId],
        expected_end_ids: &[StacksBlockId],
    ) -> Result<()> {
        if !expected_start_ids.is_empty() && !expected_start_ids.contains(&resolved.start.id) {
            return Err(anyhow!(
                "start block is not on the canonical history of the selected tip \
                 (resolved canonical block at height {} is {}, expected one of {})",
                resolved.start.height,
                resolved.start.id,
                format_expected_ids(expected_start_ids)
            ));
        }

        if !expected_end_ids.is_empty() && !expected_end_ids.contains(&resolved.end.id) {
            return Err(anyhow!(
                "end block is not on the canonical history of the selected tip \
                 (resolved canonical block at height {} is {}, expected one of {})",
                resolved.end.height,
                resolved.end.id,
                format_expected_ids(expected_end_ids)
            ));
        }

        Ok(())
    }

    async fn resolve_range_ids_via_node_walk(
        &mut self,
        anchor_tip: BlockRef,
        start_height: u64,
        end_height: u64,
    ) -> Result<ResolvedRange> {
        let chainstate_db = self.env.open_chainstate_db_for_read().await?;

        let mut resolved_start: Option<StacksBlockHeader> = None;
        let mut resolved_end: Option<StacksBlockHeader> = None;

        let mut stream = chainstate_db.canonical_block_stream_from_tip(
            anchor_tip.id.clone(),
            start_height,
            end_height,
            None,
        );

        while let Some(hdr) = stream.next().await {
            let hdr = hdr?;
            if hdr.height == end_height && resolved_end.is_none() {
                resolved_end = Some(hdr.clone());
            }
            if hdr.height == start_height && resolved_start.is_none() {
                resolved_start = Some(hdr.clone());
            }
            if resolved_start.is_some() && resolved_end.is_some() {
                break;
            }
        }

        let start_hdr = resolved_start.ok_or_else(|| anyhow!("Failed to resolve start height"))?;
        let end_hdr = resolved_end.ok_or_else(|| anyhow!("Failed to resolve end height"))?;

        Ok(ResolvedRange {
            anchor_tip,
            start: BlockRef {
                id: start_hdr.id,
                height: start_hdr.height,
            },
            end: BlockRef {
                id: end_hdr.id,
                height: end_hdr.height,
            },
        })
    }

    pub async fn index_chainstate_range(
        &mut self,
        network: Network,
        chain_id: u32,
        epochs: &[StacksEpoch],
        plan: ChainIndexPlan,
    ) -> Result<(ResolvedRange, Vec<StacksBlockId>)> {
        let expected_start_ids = plan.expected_start_ids.clone();
        let expected_end_ids = plan.expected_end_ids.clone();
        let index_start_height = if plan.start_height > 0 {
            plan.start_height - 1
        } else {
            plan.start_height
        };

        let (_chainstate_model, _) = self
            .app_db
            .get_or_create_chainstate(network, chain_id, &plan.anchor_tip, epochs)
            .await?;

        let expected_indexed_count = (plan.end_height - index_start_height + 1) as usize;

        let cached_end_id = self
            .try_get_cached_id_at_height(&plan.anchor_tip.id, plan.end_height)
            .await?;

        let indexed_ids = if let Some(end_id) = &cached_end_id {
            self.app_db
                .get_indexed_chain_block_ids(end_id, index_start_height, plan.end_height)
                .await?
        } else {
            self.app_db
                .get_indexed_chain_block_ids(
                    &plan.anchor_tip.id,
                    index_start_height,
                    plan.end_height,
                )
                .await?
        };

        if indexed_ids.len() == expected_indexed_count {
            if let Some(end_id) = cached_end_id {
                let mut ids = self
                    .app_db
                    .get_chain_block_ids(&end_id, index_start_height, plan.end_height)
                    .await?;

                if plan.start_height > 0 && !ids.is_empty() {
                    ids.remove(0);
                }

                if ids.is_empty() {
                    return Err(anyhow!(
                        "Indexed chain query returned no ids for range {index_start_height}..={}",
                        plan.end_height
                    ));
                }

                let start_id = ids
                    .first()
                    .cloned()
                    .ok_or_else(|| anyhow!("Missing first id in resolved id list"))?;

                let resolved = self
                    .build_resolved_from_ids(
                        plan.anchor_tip,
                        start_id,
                        plan.start_height,
                        end_id,
                        plan.end_height,
                    )
                    .await?;
                Self::verify_resolved_range(&resolved, &expected_start_ids, &expected_end_ids)?;

                self.send_event(IndexerEvent::AlreadyCached);
                self.send_event(IndexerEvent::Finished);
                return Ok((resolved, ids));
            }

            // Already indexed but no cached end_id: fall back to node-walk to get ids
            // (this will get cheaper once caching has been built by at least one run).
            let resolved = self
                .resolve_range_ids_via_node_walk(
                    plan.anchor_tip.clone(),
                    plan.start_height,
                    plan.end_height,
                )
                .await?;
            Self::verify_resolved_range(&resolved, &expected_start_ids, &expected_end_ids)?;

            let mut ids = self
                .app_db
                .get_chain_block_ids(&resolved.end.id, index_start_height, plan.end_height)
                .await?;

            if plan.start_height > 0 && !ids.is_empty() {
                ids.remove(0);
            }

            self.send_event(IndexerEvent::AlreadyCached);
            self.send_event(IndexerEvent::Finished);
            return Ok((resolved, ids));
        }

        self.send_event(IndexerEvent::IndexIncomplete {
            found: indexed_ids.len(),
            expected: expected_indexed_count,
        });

        // Slow path: run the real pipeline (single canonical walk + tx loading)
        let resolved = self
            .run_indexing_pipeline(plan.anchor_tip.clone(), index_start_height, plan.end_height)
            .await?;
        Self::verify_resolved_range(&resolved, &expected_start_ids, &expected_end_ids)?;

        if self.is_interrupted() {
            self.send_event(IndexerEvent::Interrupted);
            self.send_event(IndexerEvent::Finished);
            return Err(anyhow!("Indexing interrupted"));
        }

        self.send_event(IndexerEvent::CheckpointStarted);
        self.app_db.checkpoint(CheckpointMode::Truncate).await?;
        self.send_event(IndexerEvent::CheckpointComplete);

        self.send_event(IndexerEvent::VacuumStarted);
        self.app_db.vacuum().await?;
        self.send_event(IndexerEvent::VacuumComplete);

        let mut ids = self
            .app_db
            .get_chain_block_ids(&resolved.end.id, index_start_height, plan.end_height)
            .await?;

        if plan.start_height > 0 && !ids.is_empty() {
            ids.remove(0);
        }

        self.send_event(IndexerEvent::Finished);
        Ok((resolved, ids))
    }

    /// Index a known single-block window without walking from the anchor tip.
    ///
    /// `--block <hash>` and `--txid` resolve the target ID first, so this path
    /// walks only the replay window instead of O(tip_height - target_height).
    ///
    /// # Anchor-tip canonicality is not verified
    ///
    /// Unlike [`Self::index_chainstate_range`], this method does **not**
    /// verify that `target_id` lies on the canonical history of `anchor_tip`.
    /// Parent links inside chainstate are followed unconditionally, so a
    /// caller that passes the id of a forked-off block will benchmark that
    /// fork block rather than the canonical block at the same height. This
    /// is intentional: a hash-form `--block <block_hash>` (or `--txid`)
    /// names a specific block, so "specific block means specific block."
    ///
    /// Callers that have multiple candidate ids (rare cross-fork `block_hash`
    /// collisions) must fall back to [`Self::index_chainstate_range`] so the
    /// canonical walk can disambiguate.
    pub async fn index_targeted_block_window(
        &mut self,
        network: Network,
        chain_id: u32,
        epochs: &[StacksEpoch],
        plan: ChainIndexPlan,
        target_id: StacksBlockId,
    ) -> Result<(ResolvedRange, Vec<StacksBlockId>)> {
        if plan.end_height < plan.start_height {
            return Err(anyhow!(
                "targeted indexing: end_height ({}) below start_height ({})",
                plan.end_height,
                plan.start_height
            ));
        }

        let index_start_height = if plan.start_height > 0 {
            plan.start_height - 1
        } else {
            plan.start_height
        };
        let expected_indexed_count = (plan.end_height - index_start_height + 1) as usize;

        let (_chainstate_model, _) = self
            .app_db
            .get_or_create_chainstate(network, chain_id, &plan.anchor_tip, epochs)
            .await?;

        let cached = self
            .app_db
            .get_indexed_chain_block_ids(&target_id, index_start_height, plan.end_height)
            .await?;
        if cached.len() == expected_indexed_count {
            // Cached ids are in ascending height order; the entry at index
            // (start_height - index_start_height) is the parent we report
            // as `resolved.start`. The leading helper (if any) is then
            // dropped from the returned id list.
            let start_offset = (plan.start_height - index_start_height) as usize;
            let start_id = cached.get(start_offset).cloned().ok_or_else(|| {
                anyhow!("targeted indexing: cached id list shorter than expected")
            })?;
            let mut ids = cached;
            if plan.start_height > 0 {
                // Drop the start-1 helper block used for parent context.
                ids.remove(0);
            }
            let resolved = ResolvedRange {
                anchor_tip: plan.anchor_tip,
                start: BlockRef {
                    id: start_id,
                    height: plan.start_height,
                },
                end: BlockRef {
                    id: target_id,
                    height: plan.end_height,
                },
            };
            self.send_event(IndexerEvent::AlreadyCached);
            self.send_event(IndexerEvent::Finished);
            return Ok((resolved, ids));
        }

        self.send_event(IndexerEvent::IndexIncomplete {
            found: cached.len(),
            expected: expected_indexed_count,
        });

        // Walk parent_block_id from target back through chainstate.
        let chainstate_db = self.env.open_chainstate_db_for_read().await?;
        let mut nakamoto_db = self.env.open_nakamoto_db_for_read().await?;
        let min_naka_height = nakamoto_db
            .get_min_block_height()
            .await?
            .unwrap_or(u64::MAX);
        let blocks_dir = self.env.chainstate_dir.blocks_dir();

        let mut headers: Vec<StacksBlockHeader> = Vec::with_capacity(expected_indexed_count);
        let mut headers_with_txs: Vec<(StacksBlockHeader, Vec<StacksTransaction>)> =
            Vec::with_capacity(expected_indexed_count);

        let mut current_id = target_id.clone();
        for _ in 0..expected_indexed_count {
            if self.is_interrupted() {
                self.send_event(IndexerEvent::Interrupted);
                self.send_event(IndexerEvent::Finished);
                return Err(anyhow!("Indexing interrupted"));
            }

            let header = chainstate_db
                .get_header(&current_id)
                .await?
                .ok_or_else(|| anyhow!("targeted indexing: header not found for {current_id}"))?;
            let next_parent = header.parent_id.clone();

            let mut loader = StacksBlockLoader::new(&blocks_dir, &mut nakamoto_db, min_naka_height);
            let block = loader.load_block(&header).await.with_context(|| {
                format!("Failed to load transactions for block {}", header.height)
            })?;
            let txs = block.into_transactions_vec();

            headers.push(header.clone());
            headers_with_txs.push((header, txs));

            current_id = next_parent;
        }

        // Walked tip-first; persist in ascending-height order.
        headers.reverse();
        headers_with_txs.reverse();

        self.app_db.stage_blocks(&headers).await?;
        self.app_db.stage_transactions(headers_with_txs).await?;
        self.app_db.stage_indexed_blocks(&headers).await?;
        self.app_db.merge_staging().await?;

        self.send_event(IndexerEvent::CheckpointStarted);
        self.app_db.checkpoint(CheckpointMode::Truncate).await?;
        self.send_event(IndexerEvent::CheckpointComplete);

        // headers is ascending-height; start_offset points to `resolved.start`.
        let start_offset = (plan.start_height - index_start_height) as usize;
        let start_id = headers
            .get(start_offset)
            .map(|h| h.id.clone())
            .ok_or_else(|| anyhow!("targeted indexing: loaded headers shorter than expected"))?;

        let mut ids: Vec<StacksBlockId> = headers.iter().map(|h| h.id.clone()).collect();
        if plan.start_height > 0 && !ids.is_empty() {
            // Drop the start-1 helper block used for parent context.
            ids.remove(0);
        }

        let resolved = ResolvedRange {
            anchor_tip: plan.anchor_tip,
            start: BlockRef {
                id: start_id,
                height: plan.start_height,
            },
            end: BlockRef {
                id: target_id,
                height: plan.end_height,
            },
        };

        self.send_event(IndexerEvent::Finished);
        Ok((resolved, ids))
    }

    async fn run_indexing_pipeline(
        &mut self,
        anchor_tip: BlockRef,
        start_height: u64,
        end_height: u64,
    ) -> Result<ResolvedRange> {
        // Channel for passing loaded blocks to the writer
        let (tx_sender, tx_receiver) =
            mpsc::channel::<Result<(StacksBlockHeader, Vec<StacksTransaction>)>>(100);

        let metrics = Arc::new(IndexerMetrics::default());
        let walk_progress = Arc::new(AtomicU64::new(0));

        self.send_event(IndexerEvent::PipelineStarted {
            metrics: metrics.clone(),
            walk_progress: walk_progress.clone(),
        });

        let loader_task = Self::run_loader(
            self.env,
            anchor_tip.clone(),
            start_height,
            end_height,
            self.channel_buffer_size,
            tx_sender,
            metrics.clone(),
            walk_progress,
            self.interrupted.clone(),
        );

        let writer_task = Self::run_writer(
            self.app_db,
            tx_receiver,
            &anchor_tip,
            start_height,
            end_height,
            self.batch_size,
            self.merge_threshold,
            metrics.clone(),
            self.event_tx.clone(),
            self.interrupted.clone(),
        );

        let (resolved, _) = tokio::try_join!(loader_task, writer_task)?;

        Ok(resolved)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_loader(
        env: &BenchEnv,
        anchor_tip: BlockRef,
        start_height: u64,
        end_height: u64,
        channel_buffer_size: usize,
        tx_sender: mpsc::Sender<Result<(StacksBlockHeader, Vec<StacksTransaction>)>>,
        metrics: Arc<IndexerMetrics>,
        walk_progress: Arc<AtomicU64>,
        interrupted: Option<Arc<AtomicBool>>,
    ) -> Result<ResolvedRange> {
        let blocks_dir = env.chainstate_dir.blocks_dir();
        let nakamoto_db = env.open_nakamoto_db_for_read().await?;
        let min_naka_height = nakamoto_db
            .get_min_block_height()
            .await?
            .unwrap_or(u64::MAX);

        let available_parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let worker_count = available_parallelism * 2;

        let (work_tx, work_rx) = mpsc::channel::<StacksBlockHeader>(channel_buffer_size);
        let work_rx = Arc::new(tokio::sync::Mutex::new(work_rx));

        let mut handles = Vec::new();
        for _ in 0..worker_count {
            let rx = work_rx.clone();
            let tx = tx_sender.clone();
            let b_dir = blocks_dir.clone();
            let metrics = metrics.clone();
            let mut naka_db = nakamoto_db.clone();

            handles.push(tokio::spawn(async move {
                loop {
                    let header = {
                        let mut locked_rx = rx.lock().await;
                        match locked_rx.recv().await {
                            Some(h) => h,
                            None => break,
                        }
                    };

                    let mut loader = StacksBlockLoader::new(&b_dir, &mut naka_db, min_naka_height);
                    let load_res = loader.load_block(&header).await.with_context(|| {
                        format!("Failed to load transactions for block {}", header.height)
                    });

                    match load_res {
                        Ok(block) => {
                            metrics.record_loaded_block(header.height, block.transactions().len());
                            if tx
                                .send(Ok((header, block.into_transactions_vec())))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            break;
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            }));
        }

        let chainstate_db = env.open_chainstate_db_for_read().await?;

        let mut resolved_start: Option<StacksBlockHeader> = None;
        let mut resolved_end: Option<StacksBlockHeader> = None;

        let mut stream = chainstate_db.canonical_block_stream_from_tip(
            anchor_tip.id.clone(),
            start_height,
            end_height,
            Some(walk_progress),
        );

        while let Some(block_res) = stream.next().await {
            if tx_sender.is_closed() {
                break;
            }

            if interrupted
                .as_ref()
                .is_some_and(|f| f.load(Ordering::Relaxed))
            {
                break;
            }

            let header = block_res?;

            if header.height == end_height && resolved_end.is_none() {
                resolved_end = Some(header.clone());
            }
            if header.height == start_height && resolved_start.is_none() {
                resolved_start = Some(header.clone());
            }

            if work_tx.send(header).await.is_err() {
                break;
            }
        }

        drop(work_tx);

        for handle in handles {
            match handle.await {
                Ok(res) => res?,
                Err(e) => return Err(anyhow!("Worker task panicked: {}", e)),
            }
        }

        let start_hdr = resolved_start.ok_or_else(|| anyhow!("Failed to resolve start height"))?;
        let end_hdr = resolved_end.ok_or_else(|| anyhow!("Failed to resolve end height"))?;

        Ok(ResolvedRange {
            anchor_tip,
            start: BlockRef {
                id: start_hdr.id,
                height: start_hdr.height,
            },
            end: BlockRef {
                id: end_hdr.id,
                height: end_hdr.height,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_writer(
        app_db: &mut AppDb,
        mut tx_receiver: mpsc::Receiver<Result<(StacksBlockHeader, Vec<StacksTransaction>)>>,
        anchor_tip: &BlockRef,
        start_height: u64,
        end_height: u64,
        batch_size: usize,
        merge_threshold: usize,
        metrics: Arc<IndexerMetrics>,
        event_tx: Option<mpsc::UnboundedSender<IndexerEvent>>,
        interrupted: Option<Arc<AtomicBool>>,
    ) -> Result<()> {
        let send_event = |event: IndexerEvent| {
            if let Some(tx) = &event_tx {
                let _ = tx.send(event);
            }
        };

        app_db
            .set_synchronization_mode(SynchronizationMode::Off)
            .await?;
        app_db
            .set_foreign_key_enforcement(ForeignKeyMode::Off)
            .await?;
        let mut batch = Vec::with_capacity(batch_size);

        let mut txs_since_last_merge: usize = 0;
        let mut blocks_since_last_merge: usize = 0;

        async fn cache_points(
            app_db: &mut AppDb,
            anchor_tip_id: &StacksBlockId,
            headers: &[StacksBlockHeader],
            start_height: u64,
            end_height: u64,
        ) {
            if headers.is_empty() {
                return;
            }

            // Cache every 1000 blocks (aggressive, bounded write rate).
            for h in headers.iter().filter(|h| h.height % 1_000 == 0) {
                let _ = app_db.cache_ancestor(anchor_tip_id, h.height, &h.id).await;
            }

            // Cache batch edges to densify quickly.
            let first = &headers[0];
            let last = &headers[headers.len() - 1];
            let _ = app_db
                .cache_ancestor(anchor_tip_id, first.height, &first.id)
                .await;
            let _ = app_db
                .cache_ancestor(anchor_tip_id, last.height, &last.id)
                .await;

            // Cache exact query-critical heights if present in this batch.
            for h in headers {
                if h.height == end_height
                    || h.height == start_height
                    || h.height + 1 == start_height
                {
                    let _ = app_db.cache_ancestor(anchor_tip_id, h.height, &h.id).await;
                }
            }
        }

        while let Some(res) = tx_receiver.recv().await {
            if interrupted
                .as_ref()
                .is_some_and(|f| f.load(Ordering::Relaxed))
            {
                break;
            }

            let (header, transactions) = res?;
            batch.push((header, transactions));

            if batch.len() >= batch_size {
                let block_count = batch.len();
                let headers: Vec<_> = batch.iter().map(|(h, _)| h.clone()).collect();
                let tx_count: usize = batch.iter().map(|(_, txs)| txs.len()).sum();

                app_db.stage_blocks(&headers).await?;
                app_db.stage_transactions(batch.drain(..)).await?;
                app_db.stage_indexed_blocks(&headers).await?;

                cache_points(app_db, &anchor_tip.id, &headers, start_height, end_height).await;

                blocks_since_last_merge += block_count;
                txs_since_last_merge += tx_count;
                metrics.record_flush(block_count, tx_count);

                if txs_since_last_merge >= merge_threshold {
                    send_event(IndexerEvent::MergeStarted);
                    let start = Instant::now();
                    app_db.merge_staging().await?;
                    app_db.checkpoint(CheckpointMode::Passive).await?;
                    send_event(IndexerEvent::MergeComplete {
                        duration: start.elapsed(),
                    });

                    txs_since_last_merge = 0;
                    blocks_since_last_merge = 0;
                }
            }
        }

        if !batch.is_empty() {
            let block_count = batch.len();
            let headers: Vec<_> = batch.iter().map(|(h, _)| h.clone()).collect();
            let tx_count: usize = batch.iter().map(|(_, txs)| txs.len()).sum();

            app_db.stage_blocks(&headers).await?;
            app_db.stage_transactions(batch).await?;
            app_db.stage_indexed_blocks(&headers).await?;

            cache_points(app_db, &anchor_tip.id, &headers, start_height, end_height).await;

            blocks_since_last_merge += block_count;
            metrics.record_flush(block_count, tx_count);
        }

        if blocks_since_last_merge > 0 {
            send_event(IndexerEvent::MergeStarted);
            let start = Instant::now();
            app_db.merge_staging().await?;
            app_db.checkpoint(CheckpointMode::Truncate).await?;
            send_event(IndexerEvent::FinalMergeComplete {
                duration: start.elapsed(),
            });
        }

        app_db
            .set_synchronization_mode(SynchronizationMode::Normal)
            .await?;
        app_db
            .set_foreign_key_enforcement(ForeignKeyMode::Enforced)
            .await?;

        Ok(())
    }
}
