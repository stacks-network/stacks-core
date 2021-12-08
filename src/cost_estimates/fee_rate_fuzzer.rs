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

pub struct FeeRateFuzzer {
    underlying: FeeEstimator,
}

fn fuzz_esimate(input:&FeeRateEstimate) -> FeeRateEstimate {
    input.clone()
}

impl FeeEstimator for FeeRateFuzzer {
    /// Just passes the information straight to `underlying`.
    fn notify_block(
        &mut self,
        receipt: &StacksEpochReceipt,
        block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        self.underlying.notify_block(receipt, block_limit)
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        match self.underlying.get_rate_estimates() {
            Ok(underlying_estimate) => {
                Ok(fuzz_esimate(&underlying_estimate))
            }
            Err(e) => {
                Err(e)
            }
        }
    }
}
