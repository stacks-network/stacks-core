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

use std::time::Duration;

use blockstack_lib::burnchains::Txid;
use clarity::vm::costs::ExecutionCost;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_profiler::ProfileStats;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ModelSource {
    LinearRegression,
    MinAnchor,
    SingleBlock,
    Default,
}

#[derive(Debug, Clone, Copy)]
pub struct CostModel {
    pub static_overhead: Duration,
    pub time_per_byte: f64, // Seconds per byte
    pub source: ModelSource,
}

impl Default for CostModel {
    fn default() -> Self {
        Self {
            static_overhead: Duration::ZERO,
            time_per_byte: 0.0,
            source: ModelSource::Default,
        }
    }
}

impl CostModel {
    /// Compute a cost model from block metrics.
    /// Tries Linear Regression first, falls back to Min-Anchor, then Single Block.
    pub fn compute(metrics: &[BlockMetrics]) -> Self {
        // If we have enough data (e.g. > 5 blocks), skip the first few to avoid cold-cache skew.
        // We skip the first 2 blocks or 10%, whichever is larger, but cap it at 5.
        let skip_count = if metrics.len() >= 10 {
            let pct = metrics.len() / 10; // 10%
            pct.clamp(2, 5)
        } else if metrics.len() > 3 {
            1
        } else {
            0
        };

        let data = &metrics[skip_count..];

        if data.is_empty() {
            return CostModel::default();
        }

        if data.len() >= 3
            && let Some(model) = Self::compute_regression(data)
        {
            return model;
        }

        Self::compute_min_anchor(data)
    }

    fn compute_regression(data: &[BlockMetrics]) -> Option<Self> {
        let n = data.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_xx = 0.0;

        for m in data {
            let x = m.total_clarity_cost.write_length as f64;
            let y = m.commit_duration.as_secs_f64();

            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_xx += x * x;
        }

        let denominator = n * sum_xx - sum_x * sum_x;
        if denominator.abs() <= f64::EPSILON {
            return None;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / denominator;
        let intercept = (sum_y - slope * sum_x) / n;

        // If regression yields negative values, it's invalid for our physical model
        if slope < 0.0 || intercept < 0.0 {
            return None;
        }

        Some(CostModel {
            static_overhead: Duration::from_secs_f64(intercept),
            time_per_byte: slope,
            source: ModelSource::LinearRegression,
        })
    }

    fn compute_min_anchor(data: &[BlockMetrics]) -> Self {
        let mut min_block = &data[0];
        let mut max_block = &data[0];

        for m in data {
            if m.total_clarity_cost.write_length < min_block.total_clarity_cost.write_length {
                min_block = m;
            }
            if m.total_clarity_cost.write_length > max_block.total_clarity_cost.write_length {
                max_block = m;
            }
        }

        if min_block.total_clarity_cost.write_length == max_block.total_clarity_cost.write_length {
            return CostModel {
                static_overhead: min_block.commit_duration,
                time_per_byte: 0.0,
                source: ModelSource::SingleBlock,
            };
        }

        let dy = (max_block.commit_duration.as_secs_f64()
            - min_block.commit_duration.as_secs_f64())
        .max(0.0);
        let dx = (max_block.total_clarity_cost.write_length
            - min_block.total_clarity_cost.write_length) as f64;

        let slope = dy / dx;

        // Static overhead is the min block's time minus its variable byte cost.
        let min_bytes = min_block.total_clarity_cost.write_length as f64;
        let intercept = (min_block.commit_duration.as_secs_f64() - (slope * min_bytes)).max(0.0);

        CostModel {
            static_overhead: Duration::from_secs_f64(intercept),
            time_per_byte: slope,
            source: ModelSource::MinAnchor,
        }
    }
}

/// Manages the calibration lifecycle during benchmark replay.
///
/// Absorbs [`BlockMetrics`] and returns flush-ready batches once a cost model
/// has been fitted (or the sample budget is exhausted). The caller is
/// responsible for persisting the returned batches — this type never touches
/// the database.
///
/// Lifecycle:
/// 1. **Pre-calibration** — metrics are buffered until enough samples exist to
///    fit a [`CostModel`]. Once a model is accepted (or the hard cap is hit),
///    the model is applied to *all* buffered metrics at once and the batch is
///    returned.
/// 2. **Post-calibration** — each incoming metric is immediately model-applied
///    and added to an internal write buffer. A batch is returned whenever the
///    buffer exceeds the flush threshold.
/// 3. **Finish** — any remaining metrics are drained. If calibration never
///    completed, a final fit attempt is made; otherwise a heuristic is applied.
pub struct CalibrationState {
    buffer: Vec<BlockMetrics>,
    model: CostModel,
    calibrated: bool,
    min_samples: usize,
    max_samples: usize,
    flush_threshold: usize,
}

impl CalibrationState {
    const DEFAULT_MAX_SAMPLES: usize = 500;
    const DEFAULT_FLUSH_THRESHOLD: usize = 250;

    pub fn new(needs_calibration: bool, min_samples: usize) -> Self {
        Self {
            buffer: Vec::new(),
            model: CostModel::default(),
            calibrated: !needs_calibration,
            min_samples,
            max_samples: Self::DEFAULT_MAX_SAMPLES,
            flush_threshold: Self::DEFAULT_FLUSH_THRESHOLD,
        }
    }

    /// Ingest metrics from one block replay. Returns a flush-ready batch when
    /// enough data has accumulated.
    pub fn observe(&mut self, metrics: Vec<BlockMetrics>) -> Option<Vec<BlockMetrics>> {
        if !self.calibrated {
            self.observe_uncalibrated(metrics)
        } else {
            self.observe_calibrated(metrics)
        }
    }

    /// Drain any remaining buffered metrics.
    ///
    /// When `completed_normally` is true and calibration never completed, a
    /// final model fit is attempted from the buffered samples. When false
    /// (e.g. interrupted runs), the fit is skipped and all remaining metrics
    /// receive heuristic attribution — matching the pre-refactor behavior.
    ///
    /// Consumes `self` — no further observations are possible.
    pub fn finish(mut self, completed_normally: bool) -> Vec<BlockMetrics> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        if !self.calibrated && completed_normally {
            // Last-chance model fit (only on clean completion).
            if self.buffer.len() >= self.min_samples {
                self.model = CostModel::compute(&self.buffer);
            }
            // If the model has no useful slope the per-metric
            // apply_model_to_buffer falls through to `apply_heuristic`.
        }

        self.apply_model_to_buffer();
        self.buffer
    }

    pub fn model(&self) -> &CostModel {
        &self.model
    }

    pub fn is_calibrated(&self) -> bool {
        self.calibrated
    }

    // -- private -----------------------------------------------------------

    fn observe_uncalibrated(&mut self, metrics: Vec<BlockMetrics>) -> Option<Vec<BlockMetrics>> {
        self.buffer.extend(metrics);

        if self.buffer.len() < self.min_samples {
            return None;
        }

        let candidate = CostModel::compute(&self.buffer);
        let is_good =
            candidate.source != ModelSource::SingleBlock && candidate.time_per_byte > f64::EPSILON;

        if !is_good && self.buffer.len() < self.max_samples {
            return None;
        }

        // Accept this model.
        self.model = candidate;
        self.calibrated = true;
        self.apply_model_to_buffer();
        Some(self.buffer.drain(..).collect())
    }

    fn observe_calibrated(&mut self, metrics: Vec<BlockMetrics>) -> Option<Vec<BlockMetrics>> {
        for mut m in metrics {
            self.apply_to_single(&mut m);
            self.buffer.push(m);
        }

        if self.buffer.len() >= self.flush_threshold {
            Some(self.buffer.drain(..).collect())
        } else {
            None
        }
    }

    fn apply_model_to_buffer(&mut self) {
        let model = &self.model;
        for m in self.buffer.iter_mut() {
            if model.time_per_byte > f64::EPSILON {
                m.apply_cost_model(model);
            } else {
                m.apply_heuristic();
            }
        }
    }

    fn apply_to_single(&self, m: &mut BlockMetrics) {
        if self.model.time_per_byte > f64::EPSILON {
            m.apply_cost_model(&self.model);
        } else {
            m.apply_heuristic();
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BlockProcessingBaseline {
    pub avg_setup_duration: Duration,
    pub avg_finalize_duration: Duration,
    pub avg_clarity_state_commit_duration: Duration,
    pub avg_advance_tip_duration: Duration,
    pub avg_index_commit_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct BlockMetrics {
    pub id: StacksBlockId,
    pub synthetic_id: StacksBlockId,
    pub total_duration: Duration,
    pub setup_duration: Duration,
    pub execution_duration: Duration,
    pub commit_duration: Duration,
    pub total_clarity_cost: ExecutionCost,
    pub transactions: Vec<TransactionMetrics>,
    pub commit_overhead_baseline: Duration,
    pub total_storage_delta: i64,
    pub clarity_db_checkpoint_duration: Duration,
    /// Block-associated profiler roots
    pub profiler_roots: Vec<ProfileStats>,
}

impl BlockMetrics {
    pub fn new_default(id: StacksBlockId, synthetic_id: StacksBlockId) -> Self {
        Self {
            id,
            synthetic_id,
            total_duration: Duration::ZERO,
            setup_duration: Duration::ZERO,
            execution_duration: Duration::ZERO,
            commit_duration: Duration::ZERO,
            total_clarity_cost: ExecutionCost::ZERO,
            transactions: vec![],
            commit_overhead_baseline: Duration::ZERO,
            total_storage_delta: 0,
            clarity_db_checkpoint_duration: Duration::ZERO,
            profiler_roots: vec![],
        }
    }

    /// Apply a predictive cost model to attribute commit times.
    /// Now only computes block-level `commit_overhead_baseline`.
    pub fn apply_cost_model(&mut self, model: &CostModel) {
        let total_write_len = self.total_clarity_cost.write_length;

        let weight_static = model.static_overhead.as_secs_f64();
        let weight_variable = total_write_len as f64 * model.time_per_byte;
        let total_weight = weight_static + weight_variable;

        if total_weight <= f64::EPSILON {
            self.commit_overhead_baseline = self.commit_duration;
            return;
        }

        // Distribute actual commit duration into static vs variable (block-level only)
        let actual_seconds = self.commit_duration.as_secs_f64();
        let allocated_static = actual_seconds * (weight_static / total_weight);

        self.commit_overhead_baseline = Duration::from_secs_f64(allocated_static);
    }

    /// Apply a heuristic when no model is available.
    pub fn apply_heuristic(&mut self) {
        self.commit_overhead_baseline = self.commit_duration;
    }
}

#[derive(Debug, Clone)]
pub struct TransactionMetrics {
    pub txid: Txid,
    pub duration: Duration,
    pub cost: ExecutionCost,
    /// Tx-associated profiler roots
    pub profiler_roots: Vec<ProfileStats>,
}

/// Read-only snapshot of accumulated benchmark metrics.
#[derive(Debug)]
pub struct MetricsSummary {
    pub count: u64,
    pub txs: u64,
    pub duration: Duration,
    pub setup: Duration,
    pub exec: Duration,
    pub commit: Duration,
    pub runtime: u64,
    pub write_len: u64,
    pub read_len: u64,
}

#[derive(Default)]
pub struct MetricsAccumulator {
    count: u64,
    txs: u64,
    duration: Duration,
    setup: Duration,
    exec: Duration,
    commit: Duration,
    runtime: u64,
    write_len: u64,
    read_len: u64,
}

impl MetricsAccumulator {
    pub fn add(&mut self, m: &BlockMetrics) {
        self.count += 1;
        self.txs += m.transactions.len() as u64;
        self.duration += m.total_duration;
        self.setup += m.setup_duration;
        self.exec += m.execution_duration;
        self.commit += m.commit_duration;
        self.runtime += m.total_clarity_cost.runtime;
        self.write_len += m.total_clarity_cost.write_length;
        self.read_len += m.total_clarity_cost.read_length;
    }

    pub fn add_many(&mut self, ms: &[BlockMetrics]) {
        for m in ms {
            self.add(m);
        }
    }

    pub fn summary(&self) -> MetricsSummary {
        MetricsSummary {
            count: self.count,
            txs: self.txs,
            duration: self.duration,
            setup: self.setup,
            exec: self.exec,
            commit: self.commit,
            runtime: self.runtime,
            write_len: self.write_len,
            read_len: self.read_len,
        }
    }
}
