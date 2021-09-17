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
use util::db::tx_begin_immediate_sqlite;
use util::db::u64_to_sql;

use vm::costs::ExecutionCost;

use core::BLOCK_LIMIT_MAINNET;

use chainstate::stacks::db::StacksEpochReceipt;
use chainstate::stacks::events::TransactionOrigin;

use super::metrics::CostMetric;
use super::FeeRateEstimate;
use super::{EstimatorError, FeeEstimator};

const SINGLETON_ROW_ID: i64 = 1;
const CREATE_TABLE: &'static str = "
CREATE TABLE scalar_fee_estimator (
    estimate_key NUMBER PRIMARY KEY,
    fast NUMBER NOT NULL,
    medium NUMBER NOT NULL,
    slow NUMBER NOT NULL
)";

/// This struct estimates fee rates by translating a transaction's `ExecutionCost`
/// into a scalar using `ExecutionCost::proportion_dot_product` and computing
/// the subsequent fee rate using the actual paid fee. The 5th, 50th and 95th
/// percentile fee rates for each block are used as the slow, medium, and fast
/// estimates. Estimates are updated via exponential decay windowing.
pub struct ScalarFeeRateEstimator<M: CostMetric> {
    db: Connection,
    /// how quickly does the current estimate decay
    /// compared to the newly received block estimate
    ///      new_estimate := (decay_rate) * old_estimate + (1 - decay_rate) * new_measure
    decay_rate: f64,
    metric: M,
}

impl<M: CostMetric> ScalarFeeRateEstimator<M> {
    /// Open a fee rate estimator at the given db path. Creates if not existent.
    pub fn open(p: &Path, metric: M) -> Result<Self, SqliteError> {
        let db = Connection::open_with_flags(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .or_else(|e| {
                if let SqliteError::SqliteFailure(ref internal, _) = e {
                    if let rusqlite::ErrorCode::CannotOpen = internal.code {
                        let mut db = Connection::open(p)?;
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
            decay_rate: 0.5_f64,
        })
    }

    fn instantiate_db(c: &SqlTransaction) -> Result<(), SqliteError> {
        c.execute(CREATE_TABLE, rusqlite::NO_PARAMS)?;
        Ok(())
    }

    fn update_estimate(&mut self, new_measure: FeeRateEstimate) {
        let next_estimate = match self.get_rate_estimates() {
            Ok(old_estimate) => {
                // compute the exponential windowing:
                // estimate = (a/b * old_estimate) + ((1 - a/b) * new_estimate)
                let prior_component = old_estimate.clone() * self.decay_rate;
                let next_component = new_measure.clone() * (1_f64 - self.decay_rate);
                let mut next_computed = prior_component + next_component;

                // because of integer math, we can end up with some edge effects
                // when the estimate is < decay_rate_fraction.1, so just saturate
                // on the low end at a rate of "1"
                next_computed.fast = cmp::max(next_computed.fast, 1);
                next_computed.medium = cmp::max(next_computed.medium, 1);
                next_computed.slow = cmp::max(next_computed.slow, 1);

                next_computed
            }
            Err(EstimatorError::NoEstimateAvailable) => new_measure.clone(),
            Err(e) => {
                warn!("Error in fee estimator fetching current estimates"; "err" => ?e);
                return;
            }
        };

        debug!("Updating fee rate estimate for new block";
               "new_measure_fast" => new_measure.fast,
               "new_measure_medium" => new_measure.medium,
               "new_measure_slow" => new_measure.slow,
               "new_estimate_fast" => next_estimate.fast,
               "new_estimate_medium" => next_estimate.medium,
               "new_estimate_slow" => next_estimate.slow);

        let sql = "INSERT OR REPLACE INTO scalar_fee_estimator
                     (estimate_key, fast, medium, slow) VALUES (?, ?, ?, ?)";

        let tx = tx_begin_immediate_sqlite(&mut self.db).expect("SQLite failure");

        tx.execute(
            sql,
            rusqlite::params![
                SINGLETON_ROW_ID,
                u64_to_sql(next_estimate.fast).unwrap_or(i64::MAX),
                u64_to_sql(next_estimate.medium).unwrap_or(i64::MAX),
                u64_to_sql(next_estimate.slow).unwrap_or(i64::MAX)
            ],
        )
        .expect("SQLite failure");

        tx.commit().expect("SQLite failure");
    }
}

impl<M: CostMetric> FeeEstimator for ScalarFeeRateEstimator<M> {
    fn notify_block(&mut self, receipt: &StacksEpochReceipt) -> Result<(), EstimatorError> {
        let mut all_fee_rates: Vec<_> = receipt
            .tx_receipts
            .iter()
            .filter_map(|tx_receipt| {
                let (payload, fee, tx_size) = match tx_receipt.transaction {
                    TransactionOrigin::Stacks(ref tx) => {
                        Some((&tx.payload, tx.get_tx_fee(), tx.tx_len()))
                    }
                    TransactionOrigin::Burn(_) => None,
                }?;
                let scalar_cost = match payload {
                    TransactionPayload::TokenTransfer(_, _, _) => {
                        // TokenTransfers *only* contribute tx_len, and just have an empty ExecutionCost.
                        self.metric.from_len(tx_size)
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
                        self.metric
                            .from_cost_and_len(&tx_receipt.execution_cost, tx_size)
                    }
                };
                let fee_rate = cmp::max(1, fee / cmp::max(1, scalar_cost));
                Some(fee_rate)
            })
            .collect();
        all_fee_rates.sort();

        let measures_len = all_fee_rates.len();
        if measures_len > 0 {
            // use 5th, 50th, and 95th percentiles from block
            let fastest_index = measures_len - cmp::max(1, measures_len / 20);
            let median_index = measures_len / 2;
            let slowest_index = measures_len / 20;
            let block_estimate = FeeRateEstimate {
                fast: all_fee_rates[fastest_index],
                medium: all_fee_rates[median_index],
                slow: all_fee_rates[slowest_index],
            };

            self.update_estimate(block_estimate);
        }

        Ok(())
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        let sql = "SELECT fast, medium, slow FROM scalar_fee_estimator WHERE estimate_key = ?";
        self.db
            .query_row(sql, &[SINGLETON_ROW_ID], |row| {
                let fast: i64 = row.get(0)?;
                let medium: i64 = row.get(1)?;
                let slow: i64 = row.get(2)?;
                Ok((fast, medium, slow))
            })
            .optional()
            .expect("SQLite failure")
            .map(|(fast, medium, slow)| FeeRateEstimate {
                fast: u64::try_from(fast).expect("DB corrupt, non-u64-valid estimate was stored"),
                medium: u64::try_from(medium)
                    .expect("DB corrupt, non-u64-valid estimate was stored"),
                slow: u64::try_from(slow).expect("DB corrupt, non-u64-valid estimate was stored"),
            })
            .ok_or_else(|| EstimatorError::NoEstimateAvailable)
    }
}
