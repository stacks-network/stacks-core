use std::cmp;

use crate::vm::costs::ExecutionCost;

/// This trait defines metrics used to convert `ExecutionCost` and tx_len usage into single-dimensional
/// metrics that can be used to compute a fee rate.
pub trait CostMetric {
    fn from_cost_and_len(&self, cost: &ExecutionCost, tx_len: u64) -> u64;
    fn from_len(&self, tx_len: u64) -> u64;
}

/// This metric calculates a single dimensional value for a transaction's
/// consumption by summing the proportion of each of the block limit's dimensions
/// that the transaction consumed.
pub struct ProportionalDotProduct {
    block_execution_limit: ExecutionCost,
    block_size_limit: u64,
}

impl ProportionalDotProduct {
    pub fn new(
        block_size_limit: u64,
        block_execution_limit: ExecutionCost,
    ) -> ProportionalDotProduct {
        ProportionalDotProduct {
            block_execution_limit,
            block_size_limit,
        }
    }
}

impl CostMetric for ProportionalDotProduct {
    fn from_cost_and_len(&self, cost: &ExecutionCost, tx_len: u64) -> u64 {
        let exec_proportion = cost.proportion_dot_product(&self.block_execution_limit);
        let len_proportion = tx_len / cmp::max(1, self.block_size_limit / 1000);
        exec_proportion + len_proportion
    }

    fn from_len(&self, tx_len: u64) -> u64 {
        let len_proportion = tx_len / cmp::max(1, self.block_size_limit / 1000);
        len_proportion
    }
}
