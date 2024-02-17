use std::cmp;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::ops::{Add, Div, Mul, Rem, Sub};
use std::path::Path;

use clarity::vm::costs::ExecutionCost;
use rusqlite::Error as SqliteError;
use serde_json::json;

use crate::burnchains::Txid;
use crate::chainstate::stacks::db::StacksEpochReceipt;
use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use crate::chainstate::stacks::{StacksBlock, TransactionPayload};

pub mod fee_medians;
pub mod fee_rate_fuzzer;
pub mod fee_scalar;
pub mod metrics;
pub mod pessimistic;

#[cfg(test)]
pub mod tests;

use self::metrics::CostMetric;
pub use self::pessimistic::PessimisticEstimator;
use crate::chainstate::stacks::StacksTransaction;
use crate::core::StacksEpochId;

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
    fn notify_block(
        &mut self,
        receipt: &StacksEpochReceipt,
        block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError>;
    /// Get the current estimates for fee rate
    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError>;
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
/// This struct is returned from fee rate estimators as the current best estimate for
/// fee rates to include a transaction in a block.
pub struct FeeRateEstimate {
    pub high: f64,
    pub middle: f64,
    pub low: f64,
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

impl FeeRateEstimate {
    pub fn to_vec(self) -> Vec<f64> {
        vec![self.low, self.middle, self.high]
    }
}

impl Mul<f64> for FeeRateEstimate {
    type Output = FeeRateEstimate;

    fn mul(self, rhs: f64) -> FeeRateEstimate {
        FeeRateEstimate {
            high: saturating_f64_math(self.high * rhs),
            middle: saturating_f64_math(self.middle * rhs),
            low: saturating_f64_math(self.low * rhs),
        }
    }
}

impl Add for FeeRateEstimate {
    type Output = FeeRateEstimate;

    fn add(self, rhs: Self) -> FeeRateEstimate {
        FeeRateEstimate {
            high: saturating_f64_math(self.high + rhs.high),
            middle: saturating_f64_math(self.middle + rhs.middle),
            low: saturating_f64_math(self.low + rhs.low),
        }
    }
}

/// Given a cost estimator and a scalar metric, estimate the fee rate for
///  the provided transaction
pub fn estimate_fee_rate<CE: CostEstimator + ?Sized, CM: CostMetric + ?Sized>(
    tx: &StacksTransaction,
    estimator: &CE,
    metric: &CM,
    block_limit: &ExecutionCost,
    stacks_epoch_id: &StacksEpochId,
) -> Result<f64, EstimatorError> {
    let cost_estimate = estimator.estimate_cost(&tx.payload, stacks_epoch_id)?;
    let metric_estimate = metric.from_cost_and_len(&cost_estimate, block_limit, tx.tx_len());
    Ok(tx.get_tx_fee() as f64 / metric_estimate as f64)
}

/// This trait is for implementation of *execution cost* estimation. CostEstimators
///  provide the estimated `ExecutionCost` for a given `TransactionPayload`.
///
/// Note: `CostEstimator` and `FeeRateEstimator` implementations do two very different
///  tasks. `CostEstimator` implementations estimate the `ExecutionCost` for a transaction
///  payload. `FeeRateEstimator` implementations estimate the network's current fee rate.
///  Clients interested in determining the fee to be paid for a transaction must used both
///  whereas miners only need to use a `CostEstimator`
pub trait CostEstimator: Send {
    /// This method is invoked by the `stacks-node` to update the cost estimator with a new
    ///  cost measurement. The given `tx` had a measured cost of `actual_cost`.
    fn notify_event(
        &mut self,
        tx: &TransactionPayload,
        actual_cost: &ExecutionCost,
        block_limit: &ExecutionCost,
        evaluated_epoch: &StacksEpochId,
    ) -> Result<(), EstimatorError>;

    /// This method is used by a stacks-node to obtain an estimate for a given transaction payload.
    /// If the estimator cannot provide an accurate estimate for a given payload, it should return
    /// `EstimatorError::NoEstimateAvailable`
    fn estimate_cost(
        &self,
        tx: &TransactionPayload,
        evaluated_epoch: &StacksEpochId,
    ) -> Result<ExecutionCost, EstimatorError>;

    /// This method is invoked by the `stacks-node` to notify the estimator of all the transaction
    /// receipts in a given block.
    ///
    /// A default implementation is provided to implementing structs that processes the transaction
    /// receipts by feeding them into `CostEstimator::notify_event()`
    fn notify_block(
        &mut self,
        receipts: &[StacksTransactionReceipt],
        block_limit: &ExecutionCost,
        stacks_epoch_id: &StacksEpochId,
    ) {
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

            if let Err(e) = self.notify_event(
                tx_payload,
                &current_receipt.execution_cost,
                block_limit,
                stacks_epoch_id,
            ) {
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

impl EstimatorError {
    pub fn into_json(&self) -> serde_json::Value {
        let (reason_code, reason_data) = match self {
            EstimatorError::NoEstimateAvailable => (
                "NoEstimateAvailable",
                Some(json!({"message": self.to_string()})),
            ),
            EstimatorError::SqliteError(_) => {
                ("DatabaseError", Some(json!({"message": self.to_string()})))
            }
        };
        let mut result = json!({
            "error": "Estimation could not be performed",
            "reason": reason_code,
        });
        if let Some(reason_data) = reason_data {
            result
                .as_object_mut()
                .unwrap()
                .insert("reason_data".to_string(), reason_data);
        }
        result
    }
}

/// Null `CostEstimator` implementation: this is useful in rust typing when supplying
/// a `None` value to the `ChainsCoordinator` estimator field.
impl CostEstimator for () {
    fn notify_event(
        &mut self,
        _tx: &TransactionPayload,
        _actual_cost: &ExecutionCost,
        _block_limit: &ExecutionCost,
        _evaluated_epoch: &StacksEpochId,
    ) -> Result<(), EstimatorError> {
        Ok(())
    }

    fn estimate_cost(
        &self,
        _tx: &TransactionPayload,
        _evaluated_epoch: &StacksEpochId,
    ) -> Result<ExecutionCost, EstimatorError> {
        Err(EstimatorError::NoEstimateAvailable)
    }
}

/// Null `FeeEstimator` implementation: this is useful in rust typing when supplying
/// a `None` value to the `ChainsCoordinator` estimator field.
impl FeeEstimator for () {
    fn notify_block(
        &mut self,
        _receipt: &StacksEpochReceipt,
        _block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        Ok(())
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        Err(EstimatorError::NoEstimateAvailable)
    }
}

/// This estimator always returns a unit estimate in all dimensions.
/// This can be paired with the UnitMetric to cause block assembly to consider
/// *only* transaction fees, not performing any kind of rate estimation.
pub struct UnitEstimator;

impl CostEstimator for UnitEstimator {
    fn notify_event(
        &mut self,
        _tx: &TransactionPayload,
        _actual_cost: &ExecutionCost,
        _block_limit: &ExecutionCost,
        _evaluated_epoch: &StacksEpochId,
    ) -> Result<(), EstimatorError> {
        Ok(())
    }

    fn estimate_cost(
        &self,
        _tx: &TransactionPayload,
        _evaluated_epoch: &StacksEpochId,
    ) -> Result<ExecutionCost, EstimatorError> {
        Ok(ExecutionCost {
            write_length: 1,
            write_count: 1,
            read_length: 1,
            read_count: 1,
            runtime: 1,
        })
    }
}
