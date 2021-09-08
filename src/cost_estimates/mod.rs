use std::collections::HashMap;
use std::iter::FromIterator;
use std::ops::{Add, Div, Mul, Sub};
use std::path::Path;
use std::{error::Error, fmt::Display};

use chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use chainstate::stacks::{StacksBlock, TransactionPayload};
use rusqlite::Error as SqliteError;
use vm::costs::ExecutionCost;

use burnchains::Txid;
use chainstate::stacks::db::StacksEpochReceipt;

pub mod fee_scalar;
pub mod metrics;
pub mod pessimistic;

pub use self::pessimistic::PessimisticEstimator;

/// This trait is for implementation of *fee rate* estimation: estimators should
///  track the actual paid fee rate for transactions in blocks, and use that to
///  provide estimates for block inclusion.
pub trait FeeEstimator {
    /// This method is invoked by the `stacks-node` to update the fee estimator with a new
    ///  block receipt.
    fn notify_block(&mut self, receipt: &StacksEpochReceipt) -> Result<(), EstimatorError>;
    /// Get the current estimates for fee rate
    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError>;
}

#[derive(Clone)]
/// This struct is returned from fee rate estimators as the current best estimate for
/// fee rates to include a transaction in a block.
pub struct FeeRateEstimate {
    fast: u64,
    medium: u64,
    slow: u64,
}

impl Mul<u16> for FeeRateEstimate {
    type Output = FeeRateEstimate;

    fn mul(self, rhs: u16) -> FeeRateEstimate {
        FeeRateEstimate {
            fast: self.fast * (rhs as u64),
            medium: self.medium * (rhs as u64),
            slow: self.slow * (rhs as u64),
        }
    }
}

impl Div<u16> for FeeRateEstimate {
    type Output = FeeRateEstimate;

    fn div(self, rhs: u16) -> FeeRateEstimate {
        FeeRateEstimate {
            fast: self.fast / (rhs as u64),
            medium: self.medium / (rhs as u64),
            slow: self.slow / (rhs as u64),
        }
    }
}

impl Add for FeeRateEstimate {
    type Output = FeeRateEstimate;

    fn add(self, rhs: Self) -> FeeRateEstimate {
        FeeRateEstimate {
            fast: self.fast + rhs.fast,
            medium: self.medium + rhs.medium,
            slow: self.slow + rhs.slow,
        }
    }
}

pub trait CostEstimator {
    /// This method is invoked by the `stacks-node` to update the cost estimator with a new
    ///  cost measurement. The given `tx` had a measured cost of `actual_cost`.
    fn notify_event(
        &mut self,
        tx: &TransactionPayload,
        actual_cost: &ExecutionCost,
    ) -> Result<(), EstimatorError>;

    /// This method is used by a stacks-node to obtain an estimate for a given transaction payload.
    /// If the estimator cannot provide an accurate estimate for a given payload, it should return
    /// `EstimatorError::NoEstimateAvailable`
    fn estimate_cost(&self, tx: &TransactionPayload) -> Result<ExecutionCost, EstimatorError>;

    /// This method is invoked by the `stacks-node` to notify the estimator of all the transaction
    /// receipts in a given block.
    ///
    /// A default implementation is provided to implementing structs that processes the transaction
    /// receipts by feeding them into `CostEstimator::notify_event()`
    fn notify_block(&mut self, block: &StacksBlock, receipts: &[StacksTransactionReceipt]) {
        // create a Map from txid -> index in block
        let tx_index: HashMap<Txid, usize> = HashMap::from_iter(
            block
                .txs
                .iter()
                .enumerate()
                .map(|(tx_ix, tx)| (tx.txid(), tx_ix)),
        );
        // iterate over receipts, and for all the tx receipts, notify the event
        for current_receipt in receipts.iter() {
            let current_txid = match current_receipt.transaction {
                TransactionOrigin::Burn(_) => continue,
                TransactionOrigin::Stacks(ref tx) => tx.txid(),
            };
            let tx_payload = match tx_index.get(&current_txid) {
                Some(block_index) => &block.txs[*block_index].payload,
                None => continue,
            };

            if let Err(e) = self.notify_event(tx_payload, &current_receipt.execution_cost) {
                info!("CostEstimator failed to process event";
                      "txid" => %current_txid,
                      "stacks_block" => %block.header.block_hash(),
                      "error" => %e,
                      "execution_cost" => %current_receipt.execution_cost);
            }
        }
    }
}

#[derive(Debug)]
pub enum EstimatorError {
    NoEstimateAvailable,
    SqliteError(SqliteError),
}

impl Error for EstimatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EstimatorError::SqliteError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl Display for EstimatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EstimatorError::NoEstimateAvailable => {
                write!(f, "No estimate available for the provided payload.")
            }
            EstimatorError::SqliteError(e) => {
                write!(f, "Sqlite error from estimator: {}", e)
            }
        }
    }
}

/// Null `CostEstimator` implementation: this is useful in rust typing when supplying
/// a `None` value to the `ChainsCoordinator` estimator field.
impl CostEstimator for () {
    fn notify_event(
        &mut self,
        _tx: &TransactionPayload,
        _actual_cost: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        Ok(())
    }

    fn estimate_cost(&self, _tx: &TransactionPayload) -> Result<ExecutionCost, EstimatorError> {
        Err(EstimatorError::NoEstimateAvailable)
    }
}

/// Null `FeeEstimator` implementation: this is useful in rust typing when supplying
/// a `None` value to the `ChainsCoordinator` estimator field.
impl FeeEstimator for () {
    fn notify_block(&mut self, _receipt: &StacksEpochReceipt) -> Result<(), EstimatorError> {
        Ok(())
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        Err(EstimatorError::NoEstimateAvailable)
    }
}
