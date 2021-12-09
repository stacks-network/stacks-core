use vm::costs::ExecutionCost;

use super::FeeRateEstimate;
use super::{EstimatorError, FeeEstimator};
use chainstate::stacks::db::StacksEpochReceipt;
use rand::distributions::{Distribution, Uniform};
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::RngCore;
use rand::SeedableRng;

/// The FeeRateFuzzer wraps an underlying FeeEstimator. It passes `notify_block` calls to the
/// underlying estimator. On `get_rate_estimates` calls, it adds a random fuzz to the result coming
/// back from the underlying estimator.
///
/// Note: We currently use "uniform" random noise instead of "normal" distributed noise to avoid
/// importing a new crate just for this.
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
    /// Constructor for production. It uses `thread_rng()` as the random number generator,
    /// to get truly pseudo-random numbers.
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

    /// Constructor meant for test. The user can pass in a contrived random number generator
    /// factory function, so that the test is repeatable.
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
