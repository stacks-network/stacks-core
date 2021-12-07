use std::cmp;
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::{iter::FromIterator, path::Path};

use rusqlite::AndThenRows;
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

const CREATE_TABLE: &'static str = "
CREATE TABLE median_fee_estimator (
    measure_key INTEGER PRIMARY KEY AUTOINCREMENT,
    high NUMBER NOT NULL,
    middle NUMBER NOT NULL,
    low NUMBER NOT NULL
)";

/// This struct estimates fee rates by translating a transaction's `ExecutionCost`
/// into a scalar using a `CostMetric` (type parameter `M`) and computing
/// the subsequent fee rate using the actual paid fee. The *weighted* 5th, 50th and 95th
/// percentile fee rates for each block are used as the low, middle, and high
/// estimates. The fee rates are weighted by the scalar value for each transaction.
/// Blocks which do not exceed at least 1-dimension of the block limit are filled
/// with a rate = 1.0 transaction. Estimates are updated via the median value over
/// a parameterized window.
pub struct WeightedMedianFeeRateEstimator<M: CostMetric> {
    db: Connection,
    window_size: u32,
    metric: M,
}

impl<M: CostMetric> WeightedMedianFeeRateEstimator<M> {
    /// Open a fee rate estimator at the given db path. Creates if not existent.
    pub fn open(p: &Path, metric: M) -> Result<Self, SqliteError> {
        let mut db = sqlite_open(
            p,
            rusqlite::OpenFlags::SQLITE_OPEN_CREATE | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            false,
        )?;

        // check if the db needs to be instantiated regardless of whether or not
        //  it was newly created: the db itself may be shared with other fee estimators,
        //  which would not have created the necessary table for this estimator.
        let tx = tx_begin_immediate_sqlite(&mut db)?;
        Self::instantiate_db(&tx)?;
        tx.commit()?;

        Ok(Self {
            db,
            metric,
            window_size: 5,
        })
    }

    /// Check if the SQL database was already created. Necessary to avoid races if
    ///  different threads open an estimator at the same time.
    fn db_already_instantiated(tx: &SqlTransaction) -> Result<bool, SqliteError> {
        table_exists(tx, "median_fee_estimator")
    }

    fn instantiate_db(tx: &SqlTransaction) -> Result<(), SqliteError> {
        if !Self::db_already_instantiated(tx)? {
            tx.execute(CREATE_TABLE, rusqlite::NO_PARAMS)?;
        }

        Ok(())
    }

    fn get_rate_estimates_from_sql(
        conn: &Connection,
        window_size: u32,
    ) -> Result<FeeRateEstimate, EstimatorError> {
        let sql =
            "SELECT high, middle, low FROM median_fee_estimator ORDER BY measure_key DESC LIMIT ?";
        let mut stmt = conn.prepare(sql).expect("SQLite failure");

        // shuttle high, low, middle estimates into these lists, and then sort and find median.
        let mut highs = Vec::with_capacity(window_size as usize);
        let mut mids = Vec::with_capacity(window_size as usize);
        let mut lows = Vec::with_capacity(window_size as usize);
        let results = stmt
            .query_and_then::<_, SqliteError, _, _>(&[window_size], |row| {
                let high: f64 = row.get(0)?;
                let middle: f64 = row.get(1)?;
                let low: f64 = row.get(2)?;
                Ok((low, middle, high))
            })
            .expect("SQLite failure");

        for result in results {
            let (low, middle, high) = result.expect("SQLite failure");
            highs.push(high);
            mids.push(middle);
            lows.push(low);
        }

        if highs.is_empty() || mids.is_empty() || lows.is_empty() {
            return Err(EstimatorError::NoEstimateAvailable);
        }

        fn median(len: usize, l: Vec<f64>) -> f64 {
            if len % 2 == 1 {
                l[len / 2]
            } else {
                // note, measures_len / 2 - 1 >= 0, because
                //  len % 2 == 0 and emptiness is checked above
                (l[len / 2] + l[len / 2 - 1]) / 2f64
            }
        }

        // sort our float arrays. for float values that do not compare easily,
        //  treat them as equals.
        highs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        mids.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        lows.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

        Ok(FeeRateEstimate {
            high: median(highs.len(), highs),
            middle: median(mids.len(), mids),
            low: median(lows.len(), lows),
        })
    }

    fn update_estimate(&mut self, new_measure: FeeRateEstimate) {
        let tx = tx_begin_immediate_sqlite(&mut self.db).expect("SQLite failure");

        let insert_sql = "INSERT INTO median_fee_estimator
                          (high, middle, low) VALUES (?, ?, ?)";

        let deletion_sql = "DELETE FROM median_fee_estimator
                            WHERE measure_key <= (
                               SELECT MAX(measure_key) - ?
                               FROM median_fee_estimator )";

        tx.execute(
            insert_sql,
            rusqlite::params![new_measure.high, new_measure.middle, new_measure.low,],
        )
        .expect("SQLite failure");

        tx.execute(deletion_sql, rusqlite::params![self.window_size])
            .expect("SQLite failure");

        let estimate = Self::get_rate_estimates_from_sql(&tx, self.window_size);

        tx.commit().expect("SQLite failure");

        if let Ok(next_estimate) = estimate {
            debug!("Updating fee rate estimate for new block";
                   "new_measure_high" => new_measure.high,
                   "new_measure_middle" => new_measure.middle,
                   "new_measure_low" => new_measure.low,
                   "new_estimate_high" => next_estimate.high,
                   "new_estimate_middle" => next_estimate.middle,
                   "new_estimate_low" => next_estimate.low);
        }
    }
}

impl<M: CostMetric> FeeEstimator for WeightedMedianFeeRateEstimator<M> {
    fn notify_block(
        &mut self,
        receipt: &StacksEpochReceipt,
        block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
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
                        self.metric.from_cost_and_len(
                            &tx_receipt.execution_cost,
                            &block_limit,
                            tx_size,
                        )
                    }
                };
                let fee_rate = fee as f64
                    / if scalar_cost >= 1 {
                        scalar_cost as f64
                    } else {
                        1f64
                    };
                if fee_rate >= 1f64 && fee_rate.is_finite() {
                    Some(fee_rate)
                } else {
                    Some(1f64)
                }
            })
            .collect();
        all_fee_rates.sort_by(|a, b| {
            a.partial_cmp(b)
                .expect("BUG: Fee rates should be orderable: NaN and infinite values are filtered")
        });

        // TODO: implement block fill and weighted percentile

        Ok(())
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        Self::get_rate_estimates_from_sql(&self.db, self.window_size)
    }
}
