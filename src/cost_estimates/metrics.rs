use std::cmp;

use crate::vm::costs::ExecutionCost;
use crate::vm::costs::ExecutionCostSchedule;

/// This trait defines metrics used to convert `ExecutionCost` and tx_len usage into single-dimensional
/// metrics that can be used to compute a fee rate.
pub trait CostMetric {
    fn from_cost_and_len(&self, cost: &ExecutionCost, tx_len: u64) -> u64;
    fn from_len(&self, tx_len: u64) -> u64;
}

pub const PROPORTION_RESOLUTION: u64 = 10_000;

/// This metric calculates a single dimensional value for a transaction's
/// consumption by summing the proportion of each of the block limit's dimensions
/// that the transaction consumed.
///
/// The maximum scalar value for an execution cost that = the block limit is
/// 6 * `PROPORTION_RESOLUTION`.
pub struct ProportionalDotProduct {
    block_execution_limit: ExecutionCostSchedule,
    block_size_limit: u64,
}

impl ProportionalDotProduct {
    pub fn new(
        block_size_limit: u64,
        block_execution_limit: ExecutionCostSchedule,
    ) -> ProportionalDotProduct {
        ProportionalDotProduct {
            block_execution_limit,
            block_size_limit,
        }
    }

    fn calculate_len_proportion(&self, tx_len: u64) -> u64 {
        //  use MAX(1, block_limit) to guard against divide by zero
        //  use MIN(1, self/block_limit) to guard against self > block_limit
        let len_proportion = PROPORTION_RESOLUTION as f64
            * 1_f64.min(tx_len as f64 / 1_f64.max(self.block_size_limit as f64));
        len_proportion as u64
    }
}

impl CostMetric for ProportionalDotProduct {
    fn from_cost_and_len(&self, cost: &ExecutionCost, tx_len: u64) -> u64 {
        let exec_proportion = cost.proportion_dot_product(
            &self.block_execution_limit.cost_limit[0],
            PROPORTION_RESOLUTION,
        );
        let len_proportion = self.calculate_len_proportion(tx_len);
        exec_proportion + len_proportion
    }

    fn from_len(&self, tx_len: u64) -> u64 {
        self.calculate_len_proportion(tx_len)
    }
}
