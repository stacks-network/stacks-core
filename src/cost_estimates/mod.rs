use std::cmp;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::ops::{Add, Div, Mul, Rem, Sub};
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

#[cfg(test)]
pub mod tests;

pub use self::pessimistic::PessimisticEstimator;

/// This trait is for implementation of *fee rate* estimation: estimators should
///  track the actual paid fee rate for transactions in blocks, and use that to
///  provide estimates for block inclusion. Fee rate estimators provide an estimate
///  for the amount of microstx per unit of the block limit occupied that must be
///  paid for miners to consider the transaction for inclusion in a block.
///
/// Note: `CostEstimator` and `FeeRateEstimator` implementations do two very different
///  tasks. `CostEstimator` implementations estimate the `ExecutionCost` for a transaction
///  payload. `FeeRateEstimator` implementations estimate the network's current fee rate.
///  Clients interested in determining the fee to be paid for a transaction must used both
///  whereas miners only need to use a `CostEstimator`
pub trait FeeEstimator {
    /// This method is invoked by the `stacks-node` to update the fee estimator with a new
    ///  block receipt.
    fn notify_block(&mut self, receipt: &StacksEpochReceipt) -> Result<(), EstimatorError>;
    /// Get the current estimates for fee rate
    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError>;
}

#[derive(Clone, Debug, PartialEq)]
/// This struct is returned from fee rate estimators as the current best estimate for
/// fee rates to include a transaction in a block.
pub struct FeeRateEstimate {
    pub fast: f64,
    pub medium: f64,
    pub slow: f64,
}

fn saturating_f64_math(res: f64) -> f64 {
    if res.is_finite() {
        res
    } else if res.is_infinite() && res.is_sign_positive() {
        f64::MAX
    } else if res.is_infinite() && res.is_sign_negative() {
        f64::MIN
    } else {
        1f64
    }
}

impl Mul<f64> for FeeRateEstimate {
    type Output = FeeRateEstimate;

    fn mul(self, rhs: f64) -> FeeRateEstimate {
        FeeRateEstimate {
            fast: saturating_f64_math(self.fast * rhs),
            medium: saturating_f64_math(self.medium * rhs),
            slow: saturating_f64_math(self.slow * rhs),
        }
    }
}

impl Add for FeeRateEstimate {
    type Output = FeeRateEstimate;

    fn add(self, rhs: Self) -> FeeRateEstimate {
        FeeRateEstimate {
            fast: saturating_f64_math(self.fast + rhs.fast),
            medium: saturating_f64_math(self.medium + rhs.medium),
            slow: saturating_f64_math(self.slow + rhs.slow),
        }
    }
}

/// This trait is for implementation of *execution cost* estimation. CostEstimators
///  provide the estimated `ExecutionCost` for a given `TransactionPayload`.
///
/// Note: `CostEstimator` and `FeeRateEstimator` implementations do two very different
///  tasks. `CostEstimator` implementations estimate the `ExecutionCost` for a transaction
///  payload. `FeeRateEstimator` implementations estimate the network's current fee rate.
///  Clients interested in determining the fee to be paid for a transaction must used both
///  whereas miners only need to use a `CostEstimator`
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
    fn notify_block(&mut self, receipts: &[StacksTransactionReceipt]) {
        // iterate over receipts, and for all the tx receipts, notify the event
        for current_receipt in receipts.iter() {
            let current_txid = match current_receipt.transaction {
                TransactionOrigin::Burn(_) => continue,
                TransactionOrigin::Stacks(ref tx) => tx.txid(),
            };
            let tx_payload = match current_receipt.transaction {
                TransactionOrigin::Burn(_) => continue,
                TransactionOrigin::Stacks(ref tx) => &tx.payload,
            };

            if let Err(e) = self.notify_event(tx_payload, &current_receipt.execution_cost) {
                info!("CostEstimator failed to process event";
                      "txid" => %current_txid,
                      "error" => %e,
                      "execution_cost" => %current_receipt.execution_cost);
            }
        }
    }
}

#[derive(Debug, PartialEq)]
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
