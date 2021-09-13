use std::cmp;
use std::convert::TryFrom;
use std::{iter::FromIterator, path::Path};

use rusqlite::{
    types::{FromSql, FromSqlError},
    Connection, Error as SqliteError, OptionalExtension, ToSql, Transaction as SqliteTransaction,
};
use serde_json::Value as JsonValue;

use chainstate::stacks::TransactionPayload;
use util::db::u64_to_sql;
use vm::costs::ExecutionCost;

use core::BLOCK_LIMIT_MAINNET;

use crate::util::db::tx_begin_immediate_sqlite;

use super::{CostEstimator, EstimatorError};

pub struct PessimisticEstimator {
    db: Connection,
    log_error: bool,
}

#[derive(Debug)]
struct Samples {
    items: Vec<u64>,
}

const SAMPLE_SIZE: usize = 10;
const CREATE_TABLE: &'static str = "
CREATE TABLE pessimistic_estimator (
    estimate_key TEXT PRIMARY KEY,
    current_value NUMBER NOT NULL,
    samples TEXT NOT NULL
)";

iterable_enum!(CostField {
    RuntimeCost,
    WriteLength,
    WriteCount,
    ReadLength,
    ReadCount,
});

impl CostField {
    /// Select `self` out of the given ExecutionCost
    fn select_key(&self, from_cost: &ExecutionCost) -> u64 {
        match self {
            CostField::RuntimeCost => from_cost.runtime,
            CostField::WriteLength => from_cost.write_length,
            CostField::WriteCount => from_cost.write_count,
            CostField::ReadLength => from_cost.read_length,
            CostField::ReadCount => from_cost.read_count,
        }
    }
}

impl std::fmt::Display for CostField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CostField::RuntimeCost => write!(f, "runtime"),
            CostField::WriteLength => write!(f, "write-length"),
            CostField::WriteCount => write!(f, "write-count"),
            CostField::ReadLength => write!(f, "read-length"),
            CostField::ReadCount => write!(f, "read-count"),
        }
    }
}

impl FromSql for Samples {
    fn column_result(
        sql_value: rusqlite::types::ValueRef<'_>,
    ) -> rusqlite::types::FromSqlResult<Self> {
        let json_value = JsonValue::column_result(sql_value)?;
        let items = serde_json::from_value(json_value).map_err(|_e| {
            error!("Failed to parse PessimisticEstimator sample from SQL");
            FromSqlError::InvalidType
        })?;
        Ok(Samples { items })
    }
}

impl Samples {
    fn to_json(&self) -> JsonValue {
        JsonValue::from(self.items.as_slice())
    }

    /// Add a new sample to this struct. The pessimistic sampler only adds to the sample set
    ///  if the sample set is less than SAMPLE_SIZE or the new sample is greater than the current min.
    /// Boolean return indicates whether or not the sample was included.
    fn update_with(&mut self, sample: u64) -> bool {
        if self.items.len() < SAMPLE_SIZE {
            self.items.push(sample);
            return true;
        }

        let (min_index, min_val) = match self
            .items
            .iter()
            .enumerate()
            .min_by_key(|(_i, value)| *value)
        {
            None => {
                unreachable!("Should find minimum if len() >= SAMPLE_SIZE");
            }
            Some(x) => x,
        };

        if sample > *min_val {
            self.items[min_index] = sample;
            return true;
        }

        return false;
    }

    /// Return the integer mean of the sample, uses iterative
    /// algorithm to avoid overflow. The iterative algorithm
    /// does have some error around *underflows* on the update,
    /// but only when the new value is close to the average relative
    /// to the window size.
    fn mean(&self) -> u64 {
        self.items
            .iter()
            .enumerate()
            .fold(0, |avg, (index, value)| {
                if *value > avg {
                    // cannot underflow: value <= avg because of if branch
                    let update_main = (value - avg) / (index as u64 + 1);
                    let update_remainder_component =
                        if ((value - avg) % (index as u64 + 1)) > ((index as u64 + 1) / 2) {
                            1
                        } else {
                            0
                        };
                    avg + update_main + update_remainder_component
                } else {
                    // cannot underflow: avg >= avg - value is always true because these are unsigned ints,
                    //                   and value <= avg because of if branch
                    let update_main = (avg - value) / (index as u64 + 1);
                    let update_remainder_component =
                        if ((avg - value) % (index as u64 + 1)) > ((index as u64 + 1) / 2) {
                            1
                        } else {
                            0
                        };
                    avg - update_main - update_remainder_component
                }
            })
    }

    fn flush_sqlite(&self, tx: &SqliteTransaction, identifier: &str) {
        let sql = "INSERT OR REPLACE INTO pessimistic_estimator
                     (estimate_key, current_value, samples) VALUES (?, ?, ?)";
        let current_value = u64_to_sql(self.mean()).unwrap_or_else(|_| i64::max_value());
        tx.execute(
            sql,
            rusqlite::params![identifier, current_value, self.to_json()],
        )
        .expect("SQLite failure");
    }

    fn get_sqlite(conn: &Connection, identifier: &str) -> Samples {
        let sql = "SELECT samples FROM pessimistic_estimator WHERE estimate_key = ?";
        conn.query_row(sql, &[identifier], |row| row.get(0))
            .optional()
            .expect("SQLite failure")
            .unwrap_or_else(|| Samples { items: vec![] })
    }

    fn get_estimate_sqlite(conn: &Connection, identifier: &str) -> Option<u64> {
        let sql = "SELECT current_value FROM pessimistic_estimator WHERE estimate_key = ?";
        conn.query_row::<i64, _, _>(sql, &[identifier], |row| row.get(0))
            .optional()
            .expect("SQLite failure")
            .map(|x_i64| {
                u64::try_from(x_i64).expect("DB corrupt, non-u64-valid estimate was stored")
            })
    }
}

impl PessimisticEstimator {
    pub fn open(p: &Path, log_error: bool) -> Result<PessimisticEstimator, EstimatorError> {
        let db = Connection::open_with_flags(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .or_else(|e| {
                if let SqliteError::SqliteFailure(ref internal, _) = e {
                    if let rusqlite::ErrorCode::CannotOpen = internal.code {
                        let mut db = Connection::open(p)?;
                        let tx = tx_begin_immediate_sqlite(&mut db)?;
                        PessimisticEstimator::instantiate_db(&tx)?;
                        tx.commit()?;
                        Ok(db)
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            })?;
        Ok(PessimisticEstimator { db, log_error })
    }

    fn instantiate_db(tx: &SqliteTransaction) -> Result<(), SqliteError> {
        tx.execute(CREATE_TABLE, rusqlite::NO_PARAMS)?;
        Ok(())
    }

    fn get_estimate_key(tx: &TransactionPayload, field: &CostField) -> String {
        let tx_descriptor = match tx {
            TransactionPayload::TokenTransfer(..) => "stx-transfer".to_string(),
            TransactionPayload::ContractCall(cc) => {
                format!("cc:{}.{}", cc.contract_name, cc.function_name)
            }
            TransactionPayload::SmartContract(_sc) => "contract-publish".to_string(),
            TransactionPayload::PoisonMicroblock(_, _) => "poison-ublock".to_string(),
            TransactionPayload::Coinbase(_) => "coinbase".to_string(),
        };

        format!("{}:{}", &tx_descriptor, field)
    }
}

impl From<SqliteError> for EstimatorError {
    fn from(e: SqliteError) -> Self {
        EstimatorError::SqliteError(e)
    }
}

impl CostEstimator for PessimisticEstimator {
    fn notify_event(
        &mut self,
        tx: &TransactionPayload,
        actual_cost: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        if self.log_error {
            // only log the estimate error if an estimate could be constructed
            if let Ok(estimated_cost) = self.estimate_cost(tx) {
                let estimated_scalar =
                    estimated_cost.proportion_dot_product(&BLOCK_LIMIT_MAINNET, 1_000);
                let actual_scalar = actual_cost.proportion_dot_product(&BLOCK_LIMIT_MAINNET, 1_000);
                info!("PessimisticEstimator received event";
                      "key" => %PessimisticEstimator::get_estimate_key(tx, &CostField::RuntimeCost),
                      "estimate" => estimated_scalar,
                      "actual" => actual_scalar,
                      "estimate_err" => (estimated_scalar as i64 - actual_scalar as i64),
                      "estimate_err_pct" => (estimated_scalar as i64 - actual_scalar as i64)/(cmp::max(1, actual_scalar as i64)),);
                for field in CostField::ALL.iter() {
                    info!("New data event received";
                          "key" => %PessimisticEstimator::get_estimate_key(tx, field),
                          "value" => field.select_key(actual_cost));
                }
            }
        }

        let sql_tx = tx_begin_immediate_sqlite(&mut self.db)?;
        for field in CostField::ALL.iter() {
            let key = PessimisticEstimator::get_estimate_key(tx, field);
            let field_cost = field.select_key(actual_cost);
            let mut current_sample = Samples::get_sqlite(&sql_tx, &key);
            current_sample.update_with(field_cost);
            current_sample.flush_sqlite(&sql_tx, &key);
        }
        sql_tx.commit()?;
        Ok(())
    }

    fn estimate_cost(&self, tx: &TransactionPayload) -> Result<ExecutionCost, EstimatorError> {
        let runtime = Samples::get_estimate_sqlite(
            &self.db,
            &PessimisticEstimator::get_estimate_key(tx, &CostField::RuntimeCost),
        )
        .ok_or_else(|| EstimatorError::NoEstimateAvailable)?;
        let read_count = Samples::get_estimate_sqlite(
            &self.db,
            &PessimisticEstimator::get_estimate_key(tx, &CostField::ReadCount),
        )
        .ok_or_else(|| EstimatorError::NoEstimateAvailable)?;
        let read_length = Samples::get_estimate_sqlite(
            &self.db,
            &PessimisticEstimator::get_estimate_key(tx, &CostField::ReadLength),
        )
        .ok_or_else(|| EstimatorError::NoEstimateAvailable)?;
        let write_count = Samples::get_estimate_sqlite(
            &self.db,
            &PessimisticEstimator::get_estimate_key(tx, &CostField::WriteCount),
        )
        .ok_or_else(|| EstimatorError::NoEstimateAvailable)?;
        let write_length = Samples::get_estimate_sqlite(
            &self.db,
            &PessimisticEstimator::get_estimate_key(tx, &CostField::WriteLength),
        )
        .ok_or_else(|| EstimatorError::NoEstimateAvailable)?;

        Ok(ExecutionCost {
            runtime,
            read_count,
            read_length,
            write_count,
            write_length,
        })
    }
}
