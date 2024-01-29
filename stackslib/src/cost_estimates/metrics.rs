use std::cmp;

use clarity::vm::costs::ExecutionCost;

/// This trait defines metrics used to convert `ExecutionCost` and tx_len usage into single-dimensional
/// metrics that can be used to compute a fee rate.
pub trait CostMetric: Send {
    fn from_cost_and_len(
        &self,
        cost: &ExecutionCost,
        block_limit: &ExecutionCost,
        tx_len: u64,
    ) -> u64;
    fn from_len(&self, tx_len: u64) -> u64;
    /// Should return the amount that a metric result will change per
    ///  additional byte in the transaction length
    fn change_per_byte(&self) -> f64;
}

impl CostMetric for Box<dyn CostMetric> {
    fn from_cost_and_len(
        &self,
        cost: &ExecutionCost,
        block_limit: &ExecutionCost,
        tx_len: u64,
    ) -> u64 {
        self.as_ref().from_cost_and_len(cost, block_limit, tx_len)
    }

    fn from_len(&self, tx_len: u64) -> u64 {
        self.as_ref().from_len(tx_len)
    }

    fn change_per_byte(&self) -> f64 {
        self.as_ref().change_per_byte()
    }
}

pub const PROPORTION_RESOLUTION: u64 = 10_000;

/// This metric calculates a single dimensional value for a transaction's
/// consumption by summing the proportion of each of the block limit's dimensions
/// that the transaction consumed.
///
/// The maximum scalar value for an execution cost that = the block limit is
/// 6 * `PROPORTION_RESOLUTION`.
pub struct ProportionalDotProduct {
    block_size_limit: u64,
}

/// This metric always returns a unit value for all execution costs and tx lengths.
/// When used, this metric will cause block assembly to consider transactions based
/// solely on their raw transaction fee, not any kind of rate estimation.
pub struct UnitMetric;

impl ProportionalDotProduct {
    pub fn new(block_size_limit: u64) -> ProportionalDotProduct {
        ProportionalDotProduct { block_size_limit }
    }

    fn calculate_len_proportion(&self, tx_len: u64) -> u64 {
        //  use MAX(1, block_limit) to guard against divide by zero
        //  use MIN(1, self/block_limit) to guard against self > block_limit
        let len_proportion = PROPORTION_RESOLUTION as f64
            * 1_f64.min(tx_len as f64 / 1_f64.max(self.block_size_limit as f64));
        cmp::max(len_proportion as u64, 1)
    }
}

impl CostMetric for ProportionalDotProduct {
    fn from_cost_and_len(
        &self,
        cost: &ExecutionCost,
        block_limit: &ExecutionCost,
        tx_len: u64,
    ) -> u64 {
        let exec_proportion = cost.proportion_dot_product(block_limit, PROPORTION_RESOLUTION);
        let len_proportion = self.calculate_len_proportion(tx_len);
        exec_proportion + len_proportion
    }

    fn from_len(&self, tx_len: u64) -> u64 {
        self.calculate_len_proportion(tx_len)
    }

    fn change_per_byte(&self) -> f64 {
        (PROPORTION_RESOLUTION as f64) / 1_f64.max(self.block_size_limit as f64)
    }
}

impl CostMetric for UnitMetric {
    fn from_cost_and_len(
        &self,
        _cost: &ExecutionCost,
        _block_limit: &ExecutionCost,
        _tx_len: u64,
    ) -> u64 {
        1
    }

    fn from_len(&self, _tx_len: u64) -> u64 {
        1
    }

    fn change_per_byte(&self) -> f64 {
        0f64
    }
}
