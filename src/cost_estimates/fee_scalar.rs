use std::cmp;
use std::convert::TryFrom;
use std::{iter::FromIterator, path::Path};

use rusqlite::Transaction as SqlTransaction;
use rusqlite::{
    types::{FromSql, FromSqlError},
    Connection, Error as SqliteError, OptionalExtension, ToSql,
};
use serde_json::Value as JsonValue;

use chainstate::stacks::TransactionPayload;
use util::db::sqlite_open;
use util::db::tx_begin_immediate_sqlite;
use util::db::u64_to_sql;

use vm::costs::ExecutionCost;

use chainstate::stacks::db::StacksEpochReceipt;
use chainstate::stacks::events::TransactionOrigin;

use crate::util::db::sql_pragma;
use crate::util::db::table_exists;

use super::metrics::CostMetric;
use super::FeeRateEstimate;
use super::{EstimatorError, FeeEstimator};

use super::metrics::PROPORTION_RESOLUTION;
use cost_estimates::StacksTransactionReceipt;

const SINGLETON_ROW_ID: i64 = 1;
const CREATE_TABLE: &'static str = "
CREATE TABLE scalar_fee_estimator (
    estimate_key NUMBER PRIMARY KEY,
    high NUMBER NOT NULL,
    middle NUMBER NOT NULL,
    low NUMBER NOT NULL
)";

/// This struct estimates fee rates by translating a transaction's `ExecutionCost`
/// into a scalar using `ExecutionCost::proportion_dot_product` and computing
/// the subsequent fee rate using the actual paid fee. The 5th, 50th and 95th
/// percentile fee rates for each block are used as the low, middle, and high
/// estimates. Estimates are updated via exponential decay windowing.
pub struct ScalarFeeRateEstimator<M: CostMetric> {
    db: Connection,
    /// We only look back `window_size` fee rates when averaging past estimates.
    window_size: u32,
    metric: M,
}

/// Pair of "fee rate" and a "weight". The "weight" is a non-negative integer for a transaction
/// that gets its meaning relative to the other weights in the block.
struct FeeRateAndWeight {
    pub fee_rate: f64,
    pub weight: u64,
}

impl<M: CostMetric> ScalarFeeRateEstimator<M> {
    /// Open a fee rate estimator at the given db path. Creates if not existent.
    pub fn open(p: &Path, metric: M) -> Result<Self, SqliteError> {
        let db =
            sqlite_open(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE, false).or_else(|e| {
                if let SqliteError::SqliteFailure(ref internal, _) = e {
                    if let rusqlite::ErrorCode::CannotOpen = internal.code {
                        let mut db = sqlite_open(
                            p,
                            rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                                | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                            false,
                        )?;
                        let tx = tx_begin_immediate_sqlite(&mut db)?;
                        Self::instantiate_db(&tx)?;
                        tx.commit()?;
                        Ok(db)
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            })?;

        Ok(Self {
            db,
            metric,
            window_size: 5,
        })
    }

    /// Check if the SQL database was already created. Necessary to avoid races if
    ///  different threads open an estimator at the same time.
    fn db_already_instantiated(tx: &SqlTransaction) -> Result<bool, SqliteError> {
        table_exists(tx, "scalar_fee_estimator")
    }

    fn instantiate_db(tx: &SqlTransaction) -> Result<(), SqliteError> {
        if !Self::db_already_instantiated(tx)? {
            tx.execute(CREATE_TABLE, rusqlite::NO_PARAMS)?;
        }

        Ok(())
    }

    fn update_estimate_local(
        &self,
        new_measure: &FeeRateEstimate,
        old_estimate: &FeeRateEstimate,
    ) -> FeeRateEstimate {
        // TODO: use a window (part 1)
        // compute the exponential windowing:
        // estimate = (a/b * old_estimate) + ((1 - a/b) * new_estimate)
        let prior_component = old_estimate.clone();
        let next_component = new_measure.clone();
        let mut next_computed = prior_component + next_component;

        // because of integer math, we can end up with some edge effects
        // when the estimate is < decay_rate_fraction.1, so just saturate
        // on the low end at a rate of "1"
        next_computed.high = if next_computed.high >= 1f64 {
            next_computed.high
        } else {
            1f64
        };
        next_computed.middle = if next_computed.middle >= 1f64 {
            next_computed.middle
        } else {
            1f64
        };
        next_computed.low = if next_computed.low >= 1f64 {
            next_computed.low
        } else {
            1f64
        };

        next_computed
    }

    fn update_estimate(&mut self, new_measure: FeeRateEstimate) {
        let next_estimate = match self.get_rate_estimates() {
            Ok(old_estimate) => self.update_estimate_local(&new_measure, &old_estimate),
            Err(EstimatorError::NoEstimateAvailable) => new_measure.clone(),
            Err(e) => {
                warn!("Error in fee estimator fetching current estimates"; "err" => ?e);
                return;
            }
        };

        debug!("Updating fee rate estimate for new block";
               "new_measure_high" => new_measure.high,
               "new_measure_middle" => new_measure.middle,
               "new_measure_low" => new_measure.low,
               "new_estimate_high" => next_estimate.high,
               "new_estimate_middle" => next_estimate.middle,
               "new_estimate_low" => next_estimate.low);

        let sql = "INSERT OR REPLACE INTO scalar_fee_estimator
                     (estimate_key, high, middle, low) VALUES (?, ?, ?, ?)";

        let tx = tx_begin_immediate_sqlite(&mut self.db).expect("SQLite failure");

        tx.execute(
            sql,
            rusqlite::params![
                SINGLETON_ROW_ID,
                next_estimate.high,
                next_estimate.middle,
                next_estimate.low,
            ],
        )
        .expect("SQLite failure");

        tx.commit().expect("SQLite failure");
    }
}

impl<M: CostMetric> FeeEstimator for ScalarFeeRateEstimator<M> {
    /// Compute a FeeRateEstimate for this block. Update the
    /// running estimate using this rounds estimate.
    fn notify_block(
        &mut self,
        receipt: &StacksEpochReceipt,
        block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        // Calculate sorted fee rate for each transaction in the block.
        let mut working_fee_rates: Vec<FeeRateAndWeight> = receipt
            .tx_receipts
            .iter()
            .filter_map(|tx_receipt| {
                fee_rate_and_weight_from_receipt(&self.metric, &tx_receipt, block_limit)
            })
            .collect();

        // If necessary, add the "minimum" fee rate to fill the block.
        maybe_add_minimum_fee_rate(&mut working_fee_rates, PROPORTION_RESOLUTION);

        // Compute a FeeRateEstimate from the sorted, adjusted fee rates.
        let block_estimate = fee_rate_esimate_from_sorted_weights(&working_fee_rates);

        // Update the running estimate using this rounds estimate.
        self.update_estimate(block_estimate);

        Ok(())
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        let sql = "SELECT high, middle, low FROM scalar_fee_estimator WHERE estimate_key = ?";
        self.db
            .query_row(sql, &[SINGLETON_ROW_ID], |row| {
                let high: f64 = row.get(0)?;
                let middle: f64 = row.get(1)?;
                let low: f64 = row.get(2)?;
                Ok((high, middle, low))
            })
            .optional()
            .expect("SQLite failure")
            .map(|(high, middle, low)| FeeRateEstimate { high, middle, low })
            .ok_or_else(|| EstimatorError::NoEstimateAvailable)
    }
}

fn fee_rate_esimate_from_sorted_weights(
    sorted_fee_rates: &Vec<FeeRateAndWeight>,
) -> FeeRateEstimate {
    let mut total_weight = 0u64;
    for rate_and_weight in sorted_fee_rates {
        total_weight += rate_and_weight.weight;
    }
    let mut cumulative_weight = 0u64;
    let mut percentiles = Vec::new();
    for rate_and_weight in sorted_fee_rates {
        cumulative_weight += rate_and_weight.weight;
        let percentile_n: f64 =
            (cumulative_weight as f64 - rate_and_weight.weight as f64 / 2f64) / total_weight as f64;
        percentiles.push(percentile_n);
    }

    let target_percentiles = vec![0.05, 0.5, 0.95];
    let mut fees_index = 1; // index into `sorted_fee_rates`
    let mut values_at_target_percentiles = Vec::new();
    for target_percentile in target_percentiles {
        while fees_index < percentiles.len() && percentiles[fees_index] < target_percentile {
            fees_index += 1;
        }
        // TODO: use an interpolation
        values_at_target_percentiles.push(&sorted_fee_rates[fees_index - 1]);
    }

    FeeRateEstimate {
        high: values_at_target_percentiles[2].fee_rate,
        middle: values_at_target_percentiles[1].fee_rate,
        low: values_at_target_percentiles[0].fee_rate,
    }
}
fn maybe_add_minimum_fee_rate(working_rates: &mut Vec<FeeRateAndWeight>, full_block_weight: u64) {
    let mut total_weight = 0u64;
    for rate_and_weight in working_rates.into_iter() {
        total_weight += rate_and_weight.weight;
    }

    if total_weight < full_block_weight {
        working_rates.push(FeeRateAndWeight {
            fee_rate: 1f64,
            weight: total_weight,
        })
    }
}

/// The fee rate is the `fee_paid/cost_metric_used`
fn fee_rate_and_weight_from_receipt(
    metric: &dyn CostMetric,
    tx_receipt: &StacksTransactionReceipt,
    block_limit: &ExecutionCost,
) -> Option<FeeRateAndWeight> {
    let (payload, fee, tx_size) = match tx_receipt.transaction {
        TransactionOrigin::Stacks(ref tx) => Some((&tx.payload, tx.get_tx_fee(), tx.tx_len())),
        TransactionOrigin::Burn(_) => None,
    }?;
    let scalar_cost = match payload {
        TransactionPayload::TokenTransfer(_, _, _) => {
            // TokenTransfers *only* contribute tx_len, and just have an empty ExecutionCost.
            metric.from_len(tx_size)
        }
        TransactionPayload::Coinbase(_) => {
            // Coinbase txs are "free", so they don't factor into the fee market.
            return None;
        }
        TransactionPayload::PoisonMicroblock(_, _)
        | TransactionPayload::ContractCall(_)
        | TransactionPayload::SmartContract(_) => {
            // These transaction payload types all "work" the same: they have associated ExecutionCosts
            // and contibute to the block length limit with their tx_len
            metric.from_cost_and_len(&tx_receipt.execution_cost, &block_limit, tx_size)
        }
    };
    let denominator = if scalar_cost >= 1 {
        scalar_cost as f64
    } else {
        1f64
    };
    let fee_rate = fee as f64 / denominator;
    if fee_rate >= 1f64 && fee_rate.is_finite() {
        Some(FeeRateAndWeight {
            fee_rate,
            weight: scalar_cost,
        })
    } else {
        Some(FeeRateAndWeight {
            fee_rate: 1f64,
            weight: scalar_cost,
        })
    }
}
