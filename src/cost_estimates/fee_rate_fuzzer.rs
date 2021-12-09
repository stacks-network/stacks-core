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

use rand::distributions::{Distribution, Uniform};
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::RngCore;
use rand::SeedableRng;

/// The FeeRateFuzzer wraps an underlying FeeEstimator. It passes `notify_block` calls to the
/// underlying estimator. On `get_rate_estimates` calls, it adds a random fuzz to the result coming
/// back from the underlying estimator.
pub struct FeeRateFuzzer {
    /// We will apply a random "fuzz" on top of the estimates given by this.
    underlying: Box<dyn FeeEstimator>,
    /// Creator function for a new random generator. For prod, use `thread_rng`. For test,
    /// pass in a contrived generator.
    rng_creator: Box<dyn Fn() -> Box<dyn RngCore>>,
    /// The bound used for the uniform random fuzz.
    uniform_bound: f64,
}

impl FeeRateFuzzer {
    pub fn new(underlying: Box<dyn FeeEstimator>, uniform_bound: f64) -> Box<FeeRateFuzzer> {
        let rng_creator = Box::new(|| {
            let r: Box<dyn RngCore> = Box::new(thread_rng());
            r
        });
        Box::new(Self {
            underlying,
            rng_creator,
            uniform_bound,
        })
    }
    pub fn new_custom_creator(
        underlying: Box<dyn FeeEstimator>,
        rng_creator: Box<dyn Fn() -> Box<dyn RngCore>>,
        uniform_bound: f64,
    ) -> Box<FeeRateFuzzer> {
        Box::new(Self {
            underlying,
            rng_creator,
            uniform_bound,
        })
    }

    /// Add a uniform fuzz to input.
    ///
    /// Note: We use "uniform" instead of "normal" distribution to avoid importing a new crate
    /// just for this.
    fn fuzz_estimate(&self, input: &FeeRateEstimate) -> FeeRateEstimate {
        let mut rng: Box<dyn RngCore> = (self.rng_creator)();
        let normal = Uniform::new(-self.uniform_bound, self.uniform_bound);
        FeeRateEstimate {
            high: input.high + normal.sample(&mut rng),
            middle: input.middle + normal.sample(&mut rng),
            low: input.low + normal.sample(&mut rng),
        }
    }
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

    /// Call underlying estimator and add some fuzz.
    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        match self.underlying.get_rate_estimates() {
            Ok(underlying_estimate) => Ok(self.fuzz_estimate(&underlying_estimate)),
            Err(e) => Err(e),
        }
    }
}
