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

use std::ops::Range;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::burn::db::sortdb::{SortitionDB, get_ancestor_sort_id};
use blockstack_lib::chainstate::nakamoto::NakamotoChainState;
use blockstack_lib::chainstate::nakamoto::miner::{MinerTenureInfoCause, NakamotoBlockBuilder};
use blockstack_lib::chainstate::stacks::db::StacksChainState;
use blockstack_lib::chainstate::stacks::miner::{
    BlockBuilder, BlockLimitFunction, TransactionResult,
};
use blockstack_lib::config::DEFAULT_MAX_TENURE_BYTES;
use clarity::vm::costs::ExecutionCost;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};

use crate::context::BenchContext;
use crate::metrics::{BlockMetrics, TransactionMetrics};
use crate::{BlockEra, ResolveEpochFromHeight, StacksBlockHeader};

#[derive(Debug, Clone)]
pub enum ReplayMode {
    Miner,
    Follower,
    Ephemeral,
    /// Execute via replay_nakamoto_by_segments() using build_segments_filtered()
    SegmentedFiltered(crate::filter::TxFilter),
    /// Single-tx mode: segments are built using build_segments_for_txid(),
    /// which produces prefix (unmeasured) + target (measured) only — no
    /// suffix transactions after the target are executed.
    SingleTx(crate::filter::TxFilter),
}

pub struct ReplayBlockRequest<'a> {
    pub mode: &'a ReplayMode,
    pub block_header: &'a StacksBlockHeader,
    pub repetition: u32,
    pub sample_metrics: bool,
}

impl std::fmt::Display for ReplayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayMode::Miner => write!(f, "Miner"),
            ReplayMode::Follower => write!(f, "Follower"),
            ReplayMode::Ephemeral => write!(f, "Ephemeral"),
            ReplayMode::SegmentedFiltered(_) => write!(f, "SegmentedFiltered"),
            ReplayMode::SingleTx(_) => write!(f, "SingleTx"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentReplayInfo {
    /// The index of the segment, in relation to other segments which may have
    /// been created/executed from the origin block.
    pub seg_ix: usize,
    /// The range of transactions from the origin block's transaction list which
    /// were executed as part of this segment.
    pub tx_range: Range<usize>,
    /// Whether this segment is sampled or not.
    pub sampled: bool,
}

#[derive(Clone, Debug)]
struct TxSegment {
    /// Contiguous tx range in `block.txs`
    range: Range<usize>,

    /// Whether to sample per-tx metrics and include in totals
    sampled: bool,
}

fn build_segments_full(
    block: &blockstack_lib::chainstate::nakamoto::NakamotoBlock,
) -> Vec<TxSegment> {
    vec![TxSegment {
        range: 0..block.txs.len(),
        sampled: true,
    }]
}

fn build_segments_filtered(
    block: &blockstack_lib::chainstate::nakamoto::NakamotoBlock,
    filter: &crate::filter::TxFilter,
) -> Vec<TxSegment> {
    let n = block.txs.len();
    if n == 0 {
        return vec![];
    }

    let mut out = Vec::new();
    let mut run_start = 0usize; // start of current "unmeasured run"

    for i in 0..n {
        let is_match = filter.matches(&block.txs[i]);
        if !is_match {
            continue;
        }

        // segment 1: unmeasured run [run_start..i) (may be empty)
        if run_start < i {
            out.push(TxSegment {
                range: run_start..i,
                sampled: false,
            });
        }

        // segment 2: measured singleton [i..i+1)
        out.push(TxSegment {
            range: i..(i + 1),
            sampled: true,
        });

        run_start = i + 1;
    }

    // trailing unmeasured run after last match
    if run_start < n {
        out.push(TxSegment {
            range: run_start..n,
            sampled: false,
        });
    }

    out
}

/// Build segments for single-tx replay mode: prefix (unmeasured) + target
/// (measured). Unlike `build_segments_filtered()`, no suffix transactions
/// after the target are executed since they are irrelevant to the measurement.
fn build_segments_for_txid(
    block: &blockstack_lib::chainstate::nakamoto::NakamotoBlock,
    filter: &crate::filter::TxFilter,
) -> Vec<TxSegment> {
    let n = block.txs.len();
    if n == 0 {
        return vec![];
    }

    // Find the first matching transaction
    let match_idx = block.txs.iter().position(|tx| filter.matches(tx));
    let Some(idx) = match_idx else {
        return vec![];
    };

    let mut out = Vec::new();

    // Prefix: unmeasured transactions before the target
    if idx > 0 {
        out.push(TxSegment {
            range: 0..idx,
            sampled: false,
        });
    }

    // Target: the single measured transaction
    out.push(TxSegment {
        range: idx..(idx + 1),
        sampled: true,
    });

    // No suffix — we don't execute transactions after the target
    out
}

fn compute_synthetic_id(
    origin: &StacksBlockId,
    seg_ix: usize,
    range: &std::ops::Range<usize>,
    repetition: u32,
) -> StacksBlockId {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"stacks-bench:synth-block:v1");
    hasher.update(origin.as_bytes());
    hasher.update((seg_ix as u64).to_le_bytes());
    hasher.update((range.start as u64).to_le_bytes());
    hasher.update((range.end as u64).to_le_bytes());
    hasher.update(repetition.to_le_bytes());

    let digest = hasher.finalize();
    let bytes = digest[..32].to_vec();
    StacksBlockId::from_vec(&bytes).expect("sha256 yields 32 bytes")
}

/// Re-execute all transactions in a block to measure execution performance.
///
/// Segmented mode returns 0..N measurement units (one per recorded segment).
///
/// `sample_metrics = false` disables profiler spans, per-phase timing,
/// metrics construction, and per-segment SQLite checkpoints.
pub fn replay_block<F>(
    context: &mut BenchContext,
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    request: ReplayBlockRequest<'_>,
    on_segment: Option<&mut F>,
) -> Result<Option<Vec<BlockMetrics>>>
where
    F: FnMut(&SegmentReplayInfo, Option<&mut BlockMetrics>) -> Result<()>,
{
    let ReplayBlockRequest {
        mode,
        block_header,
        repetition,
        sample_metrics,
    } = request;
    let block_height = block_header.height;
    let epoch = context
        .resolve_stacks_epoch(block_height)
        .ok_or_else(|| anyhow!("Failed to resolve epoch for height {}", block_height))?;

    let metrics: Option<Vec<BlockMetrics>> = match context.resolve_block_era(epoch) {
        BlockEra::Nakamoto => {
            let (naka_block, _) = chainstate
                .nakamoto_blocks_db()
                .get_nakamoto_block(&block_header.id)?
                .ok_or_else(|| anyhow!("Nakamoto block not found"))?;

            match mode {
                ReplayMode::Miner => bail!("Nakamoto Miner replay not implemented"),
                ReplayMode::Ephemeral => bail!("Nakamoto Ephemeral replay not implemented"),

                ReplayMode::Follower => {
                    let segments = build_segments_full(&naka_block);

                    let seg_metrics = replay_nakamoto_by_segments(
                        chainstate,
                        sortdb,
                        &naka_block,
                        &segments,
                        repetition,
                        sample_metrics,
                        on_segment,
                    )?;

                    if seg_metrics.is_empty() {
                        None
                    } else {
                        Some(seg_metrics)
                    }
                }

                ReplayMode::SegmentedFiltered(filter) => {
                    let segments = build_segments_filtered(&naka_block, filter);

                    // No recorded segments => no metrics.
                    if segments.is_empty() || segments.iter().all(|s| !s.sampled) {
                        return Ok(None);
                    }

                    // Do not wrap this in stacks_profiler::measure!: this path
                    // clears and drains profiler results per recorded segment.
                    let seg_metrics = replay_nakamoto_by_segments(
                        chainstate,
                        sortdb,
                        &naka_block,
                        &segments,
                        repetition,
                        sample_metrics,
                        on_segment,
                    )?;

                    if seg_metrics.is_empty() {
                        None
                    } else {
                        Some(seg_metrics)
                    }
                }

                ReplayMode::SingleTx(filter) => {
                    let segments = build_segments_for_txid(&naka_block, filter);

                    if segments.is_empty() || segments.iter().all(|s| !s.sampled) {
                        return Ok(None);
                    }

                    let seg_metrics = replay_nakamoto_by_segments(
                        chainstate,
                        sortdb,
                        &naka_block,
                        &segments,
                        repetition,
                        sample_metrics,
                        on_segment,
                    )?;

                    if seg_metrics.is_empty() {
                        None
                    } else {
                        Some(seg_metrics)
                    }
                }
            }
        }

        BlockEra::PreNakamoto => None,
    };

    Ok(metrics)
}

fn replay_nakamoto_by_segments<F>(
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    block: &blockstack_lib::chainstate::nakamoto::NakamotoBlock,
    segments: &[TxSegment],
    repetition: u32,
    sample_metrics: bool,
    mut on_segment: Option<&mut F>,
) -> Result<Vec<BlockMetrics>>
where
    F: FnMut(&SegmentReplayInfo, Option<&mut BlockMetrics>) -> Result<()>,
{
    let origin_id = block.block_id();

    if segments.is_empty() {
        return Ok(vec![]);
    }

    let parent_block_id = block.header.parent_block_id.clone();
    let parent_info = NakamotoChainState::get_block_header(chainstate.db(), &parent_block_id)?
        .ok_or_else(|| anyhow!("Parent header not found"))?;

    let mut cur_parent_info = parent_info.clone();

    let mut out: Vec<BlockMetrics> = Vec::new();
    let mut last_state_index_root = None;

    for (seg_ix, seg) in segments.iter().enumerate() {
        if seg.range.is_empty() && !seg.sampled {
            continue;
        }

        let measure = sample_metrics && seg.sampled;

        let segment_txs = &block.txs[seg.range.clone()];

        let _suppression = if sample_metrics && !seg.sampled {
            Some(stacks_profiler::Profiler::begin_suppression())
        } else {
            None
        };

        if measure {
            stacks_profiler::Profiler::clear();
        }

        let _segment_root = if measure {
            stacks_profiler::span!("Segment", seg_ix)
        } else {
            None
        };

        // Setup
        let setup_start = if measure { Some(Instant::now()) } else { None };

        let _setup_guard = if measure {
            stacks_profiler::span!("Segment: Setup", seg_ix)
        } else {
            None
        };

        let segment_tenure_change_tx: Option<
            &blockstack_lib::chainstate::stacks::StacksTransaction,
        > = segment_txs
            .iter()
            .find(|tx| tx.try_as_tenure_change().is_some());

        let segment_coinbase_tx: Option<&blockstack_lib::chainstate::stacks::StacksTransaction> =
            segment_txs.iter().find(|tx| tx.try_as_coinbase().is_some());

        let segment_cause = if let Some(tc_tx) = segment_tenure_change_tx {
            let tc_payload = tc_tx.try_as_tenure_change().expect("checked above");
            MinerTenureInfoCause::from(tc_payload.cause)
        } else {
            MinerTenureInfoCause::NoTenureChange
        };

        drop(_setup_guard);

        let exec_result = execute_segment(
            chainstate,
            sortdb,
            SegmentExecutionInput {
                cur_parent_info: &cur_parent_info,
                block,
                seg,
                seg_ix,
                segment_tenure_change_tx,
                segment_coinbase_tx,
                segment_cause,
                setup_start,
                repetition,
                measure,
            },
        )
        .with_context(|| {
            format!("Failed to replay segment {seg_ix} from origin block {origin_id}")
        })?;

        drop(_segment_root);

        last_state_index_root = Some(exec_result.state_index_root);

        let segment_profiler_roots = if measure {
            stacks_profiler::Profiler::take_results()
                .with_context(|| {
                    format!(
                        "Failed to drain profiler results for segment {seg_ix} from origin block {origin_id}"
                    )
                })?
        } else {
            vec![]
        };

        // Warmup skips per-segment checkpoints. The caller flushes once before
        // measurement so warmup WAL writes do not skew the first measured block.
        let clarity_db_checkpoint_duration = if sample_metrics {
            let checkpoint_start = Instant::now();
            chainstate.checkpoint_sqlite_dbs()?;
            checkpoint_start.elapsed()
        } else {
            Duration::ZERO
        };

        // Advance parent for burn_view inheritance in the next segment.
        cur_parent_info = exec_result.new_tip_info;

        let info = SegmentReplayInfo {
            seg_ix,
            tx_range: seg.range.clone(),
            sampled: seg.sampled,
        };

        if measure {
            let synthetic_id = compute_synthetic_id(&origin_id, seg_ix, &seg.range, repetition);

            let mut m = BlockMetrics::new_default(origin_id.clone(), synthetic_id.clone());
            m.setup_duration = exec_result.setup_duration;
            m.execution_duration = exec_result.execution_duration;
            m.commit_duration = exec_result.commit_duration;
            m.total_duration = exec_result.setup_duration
                + exec_result.execution_duration
                + exec_result.commit_duration;
            m.total_clarity_cost = exec_result.segment_total_clarity_cost;
            m.profiler_roots = segment_profiler_roots;
            m.clarity_db_checkpoint_duration = clarity_db_checkpoint_duration;

            for (txid, dur, cost) in exec_result.segment_tx_metrics {
                m.transactions.push(TransactionMetrics {
                    txid,
                    duration: dur,
                    cost,
                    profiler_roots: vec![],
                });
            }

            if let Some(cb) = on_segment.as_deref_mut() {
                cb(&info, Some(&mut m))?;
            }

            out.push(m);
        } else if let Some(cb) = on_segment.as_deref_mut() {
            cb(&info, None)?;
        }
    }

    // Validate state root only for canonical-equivalent replays — i.e. a
    // single segment covering every transaction in the block, executed at
    // `repetition == 0`. Two cases break the comparison even though Clarity
    // execution is bit-identical:
    //   * Multi-segment replays commit intermediate state under synthetic
    //     block IDs, altering the MARF trie structure.
    //   * `repetition > 0` synthesizes a shifted timestamp (see
    //     `execute_segment`) to avoid header-table collisions, which changes
    //     the block hash and therefore the MARF entries committed under it.
    if repetition == 0
        && segments.len() == 1
        && segments[0].range == (0..block.txs.len())
        && let Some(replayed_root) = last_state_index_root
        && replayed_root != block.header.state_index_root
    {
        let tenure_tx = block.get_tenure_tx_payload();
        let tenure_cause = tenure_tx.as_ref().map(|t| format!("{:?}", t.cause));
        bail!(
            "State root mismatch for block {origin_id} \
             (height={}, consensus_hash={}, parent={}, \
             tenure={}, txs={}): \
             expected {}, got {replayed_root}",
            block.header.chain_length,
            block.header.consensus_hash,
            block.header.parent_block_id,
            tenure_cause.as_deref().unwrap_or("none"),
            block.txs.len(),
            block.header.state_index_root,
        );
    }

    Ok(out)
}

struct SegmentExecResult {
    new_tip_info: blockstack_lib::chainstate::stacks::db::StacksHeaderInfo,
    commit_duration: Duration,
    setup_duration: Duration,
    execution_duration: Duration,
    segment_total_clarity_cost: ExecutionCost,
    segment_tx_metrics: Vec<(Txid, Duration, ExecutionCost)>,
    state_index_root: TrieHash,
}

struct SegmentExecutionInput<'a> {
    cur_parent_info: &'a blockstack_lib::chainstate::stacks::db::StacksHeaderInfo,
    block: &'a blockstack_lib::chainstate::nakamoto::NakamotoBlock,
    seg: &'a TxSegment,
    seg_ix: usize,
    segment_tenure_change_tx: Option<&'a blockstack_lib::chainstate::stacks::StacksTransaction>,
    segment_coinbase_tx: Option<&'a blockstack_lib::chainstate::stacks::StacksTransaction>,
    segment_cause: MinerTenureInfoCause,
    setup_start: Option<Instant>,
    repetition: u32,
    measure: bool,
}

fn execute_segment(
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    input: SegmentExecutionInput<'_>,
) -> Result<SegmentExecResult> {
    let SegmentExecutionInput {
        cur_parent_info,
        block,
        seg,
        seg_ix,
        segment_tenure_change_tx,
        segment_coinbase_tx,
        segment_cause,
        setup_start,
        repetition,
        measure,
    } = input;

    // Keep repeated synthetic blocks from colliding in MARF/header tables.
    // Clarity reads block/burn height from parent state, not this timestamp.
    let synth_timestamp = block
        .header
        .timestamp
        .checked_add(repetition as u64)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "timestamp overflow: base {} + repetition {repetition} exceeds u64::MAX",
                block.header.timestamp
            )
        })?;

    let mut builder = NakamotoBlockBuilder::new(
        cur_parent_info,
        &block.header.consensus_hash,
        block.header.burn_spent,
        segment_tenure_change_tx,
        segment_coinbase_tx,
        block.header.pox_treatment.len(),
        None,
        None,
        Some(synth_timestamp),
        DEFAULT_MAX_TENURE_BYTES,
    )?;

    let cur_parent_block_id = StacksBlockId::new(
        &cur_parent_info.consensus_hash,
        &cur_parent_info.anchored_header.block_hash(),
    );

    // Tenure-change blocks execute against the burn view named by the payload.
    let burn_dbconn = if let Some(tenure_change_tx) = segment_tenure_change_tx {
        let tenure_change = tenure_change_tx
            .try_as_tenure_change()
            .expect("tenure change tx checked by caller");

        if let Some(ref parent_burn_view) = cur_parent_info.burn_view {
            let parent_burn_view_sn =
                SortitionDB::get_block_snapshot_consensus(sortdb.conn(), parent_burn_view)?
                    .ok_or_else(|| {
                        anyhow!(
                            "parent block burn view {parent_burn_view} was not found while replaying tenure-change block {}",
                            block.block_id()
                        )
                    })?;
            let handle = sortdb.index_handle_at_ch(&tenure_change.burn_view_consensus_hash)?;
            let connected_sort_id = get_ancestor_sort_id(
                &handle,
                parent_burn_view_sn.block_height,
                &handle.context.chain_tip,
            )?
            .ok_or_else(|| {
                anyhow!(
                    "tenure-change burn view {} does not descend from parent burn view {parent_burn_view} while replaying block {}",
                    tenure_change.burn_view_consensus_hash,
                    block.block_id()
                )
            })?;
            if connected_sort_id != parent_burn_view_sn.sortition_id {
                bail!(
                    "tenure-change burn view {} is not connected to parent burn view {parent_burn_view} while replaying block {}",
                    tenure_change.burn_view_consensus_hash,
                    block.block_id()
                );
            }

            handle
        } else {
            sortdb.index_handle_at_ch(&tenure_change.burn_view_consensus_hash)?
        }
    } else {
        sortdb.index_handle_at_block(chainstate, &cur_parent_block_id)?
    };

    let mut miner_tenure_info =
        builder.load_tenure_info(chainstate, &burn_dbconn, segment_cause)?;

    let burn_chain_height = miner_tenure_info.burn_tip_height;
    let coinbase_height = miner_tenure_info.coinbase_height;
    let is_new_tenure = segment_cause.is_new_tenure();
    let mut clarity_tx = builder.tenure_begin(&burn_dbconn, &mut miner_tenure_info)?;

    let setup_duration = setup_start.map(|s| s.elapsed()).unwrap_or(Duration::ZERO);

    // Transaction execution
    let exec_start = if measure { Some(Instant::now()) } else { None };

    let _exec_guard = if measure {
        stacks_profiler::span!("Segment: Tx Execution", seg_ix)
    } else {
        None
    };

    let mut segment_tx_metrics: Vec<(Txid, Duration, ExecutionCost)> = Vec::new();
    let mut segment_total_clarity_cost = ExecutionCost::ZERO;
    let mut total_receipts_size = 0u64;

    let starting_cost = clarity_tx.cost_so_far();

    for i in seg.range.clone() {
        let tx = &block.txs[i];
        let tx_len = tx.tx_len();

        let tx_start = if measure { Some(Instant::now()) } else { None };

        let rel_i = i - seg.range.start;

        let _tx_guard = if measure {
            stacks_profiler::span!("Transaction", rel_i)
        } else {
            None
        };

        let res = builder.try_mine_tx_with_len(
            &mut clarity_tx,
            tx,
            tx_len,
            &BlockLimitFunction::NO_LIMIT_HIT,
            None,
            &mut total_receipts_size,
        );

        drop(_tx_guard);

        let dur = tx_start.map(|s| s.elapsed()).unwrap_or(Duration::ZERO);

        let success = match res {
            TransactionResult::Success(ref s) => s,
            _ => {
                clarity_tx.rollback_block();
                return Err(anyhow!(
                    "Tx #{i} (0x{}) failed while executing segment #{seg_ix} ({:?})",
                    tx.txid(),
                    seg.range
                ));
            }
        };

        if measure {
            let cost = success.receipt.execution_cost.clone();
            segment_total_clarity_cost.add(&cost)?;
            segment_tx_metrics.push((tx.txid(), dur, cost));
        }
    }

    drop(_exec_guard);

    let execution_duration = exec_start.map(|s| s.elapsed()).unwrap_or(Duration::ZERO);

    // Commit
    let commit_start = if measure { Some(Instant::now()) } else { None };

    let total_tenure_cost = clarity_tx.cost_so_far();
    let mut block_execution_cost = clarity_tx.cost_so_far();
    block_execution_cost.sub(&starting_cost)?;

    let segment_block_size = builder.get_bytes_so_far();

    let _finalize_guard = if measure {
        stacks_profiler::span!("Segment: Finalize (merkle+seal)", seg_ix)
    } else {
        None
    };

    let mined_block = builder.mine_nakamoto_block(&mut clarity_tx, burn_chain_height);
    let mined_block_hash = mined_block.header.block_hash();
    let mined_state_index_root = mined_block.header.state_index_root;
    let mined_consensus_hash = mined_block.header.consensus_hash.clone();
    let evaluated_epoch = clarity_tx.get_epoch();

    drop(_finalize_guard);

    let _clarity_commit_guard = if measure {
        stacks_profiler::span!("Segment: Clarity State Commit", seg_ix)
    } else {
        None
    };

    clarity_tx.commit_to_block(&mined_consensus_hash, &mined_block_hash);

    drop(_clarity_commit_guard);

    let burn_view = NakamotoChainState::get_block_burn_view(sortdb, &mined_block, cur_parent_info)?;

    let sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &mined_consensus_hash)?
        .ok_or_else(|| anyhow!("Snapshot not found for {}", mined_consensus_hash))?;

    let block_fees: u128 = seg
        .range
        .clone()
        .map(|i| block.txs[i].get_tx_fee() as u128)
        .sum();

    // Tenure-start blocks need scheduled rewards for later matured-reward lookups.
    let scheduled_miner_reward = if is_new_tenure {
        let parent_coinbase_height = coinbase_height
            .checked_sub(1)
            .expect("coinbase_height underflow on tenure-start block");
        let (commit_burn, sortition_burn) = {
            let block_commit = SortitionDB::get_block_commit(
                sortdb.conn(),
                &sn.winning_block_txid,
                &sn.sortition_id,
            )?
            .ok_or_else(|| {
                anyhow!(
                    "No block-commit for tenure-start snapshot {}",
                    sn.sortition_id,
                )
            })?;
            let sort_burn = SortitionDB::get_block_burn_amount(sortdb.conn(), &sn)?;
            (block_commit.burn_fee, sort_burn)
        };
        Some(NakamotoChainState::calculate_scheduled_tenure_reward(
            &mut miner_tenure_info.chainstate_tx,
            &burn_dbconn,
            &mined_block,
            evaluated_epoch,
            parent_coinbase_height,
            burn_chain_height.into(),
            commit_burn,
            sortition_burn,
        )?)
    } else {
        None
    };

    let _advance_chain_tip_guard = if measure {
        stacks_profiler::span!("Segment: Advance Chain Tip", seg_ix)
    } else {
        None
    };

    let new_tip_info = NakamotoChainState::advance_tip(
        &mut miner_tenure_info.chainstate_tx.tx,
        &cur_parent_info.anchored_header,
        &cur_parent_info.consensus_hash,
        &mined_block,
        None,
        &sn.burn_header_hash,
        sn.block_height as u32,
        sn.burn_header_timestamp,
        scheduled_miner_reward.as_ref(),
        None,
        &block_execution_cost,
        &total_tenure_cost,
        segment_block_size,
        false,
        vec![],
        vec![],
        vec![],
        vec![],
        is_new_tenure,
        coinbase_height,
        block_fees,
        &burn_view,
    )?;

    drop(_advance_chain_tip_guard);

    let _index_commit_guard = if measure {
        stacks_profiler::span!("Segment: Index Commit", seg_ix)
    } else {
        None
    };

    let blockstack_lib::chainstate::nakamoto::miner::MinerTenureInfo { chainstate_tx, .. } =
        miner_tenure_info;
    chainstate_tx.commit()?;

    drop(builder);

    let commit_duration = commit_start.map(|s| s.elapsed()).unwrap_or(Duration::ZERO);

    Ok(SegmentExecResult {
        new_tip_info,
        commit_duration,
        setup_duration,
        execution_duration,
        segment_total_clarity_cost,
        segment_tx_metrics,
        state_index_root: mined_state_index_root,
    })
}
