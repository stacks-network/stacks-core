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
pub struct FeeRateFuzzer<UnderlyingEstimator: FeeEstimator> {
    /// We will apply a random "fuzz" on top of the estimates given by this.
    underlying: UnderlyingEstimator,
    /// Creator function for a new random generator. For prod, use `thread_rng`. For test,
    /// pass in a contrived generator.
    rng_creator: Box<dyn Fn() -> Box<dyn RngCore>>,
    /// The fuzzed rate will be `R * (1 + alpha)`, where `R` is the original rate, and `alpha` is a
    /// random number in `[-uniform_fuzz_bound, uniform_fuzz_bound]`.
    /// Note: Must be `0 < uniform_fuzz_bound < 1`.
    uniform_fuzz_bound: f64,
}

impl<UnderlyingEstimator: FeeEstimator> FeeRateFuzzer<UnderlyingEstimator> {
    /// Constructor for production. It uses `thread_rng()` as the random number generator,
    /// to get truly pseudo-random numbers.
    pub fn new(
        underlying: UnderlyingEstimator,
        uniform_fuzz_bound: f64,
    ) -> FeeRateFuzzer<UnderlyingEstimator> {
        assert!(0.0 < uniform_fuzz_bound && uniform_fuzz_bound < 1.0);
        let rng_creator = Box::new(|| {
            let r: Box<dyn RngCore> = Box::new(thread_rng());
            r
        });
        Self {
            underlying,
            rng_creator,
            uniform_fuzz_bound,
        }
    }

    /// Constructor meant for test. The user can pass in a contrived random number generator
    /// factory function, so that the test is repeatable.
    pub fn new_custom_creator(
        underlying: UnderlyingEstimator,
        rng_creator: Box<dyn Fn() -> Box<dyn RngCore>>,
        uniform_fuzz_bound: f64,
    ) -> FeeRateFuzzer<UnderlyingEstimator> {
        assert!(0.0 < uniform_fuzz_bound && uniform_fuzz_bound < 1.0);
        Self {
            underlying,
            rng_creator,
            uniform_fuzz_bound,
        }
    }

    /// Fuzzes an individual number.  The fuzzed rate will be `R * (1 + alpha)`, where `R` is the
    /// original rate, and `alpha` is a random number in `[-uniform_fuzz_bound,
    /// uniform_fuzz_bound]`.
    fn fuzz_individual_scalar(&self, original: f64) -> f64 {
        let mut rng: Box<dyn RngCore> = (self.rng_creator)();
        let uniform = Uniform::new(-self.uniform_fuzz_bound, self.uniform_fuzz_bound);
        let fuzz_fraction = uniform.sample(&mut rng);
        original * (1f64 + fuzz_fraction)
    }

    /// Add a uniform fuzz to input.
    fn fuzz_estimate(&self, input: &FeeRateEstimate) -> FeeRateEstimate {
        FeeRateEstimate {
            high: self.fuzz_individual_scalar(input.high),
            middle: self.fuzz_individual_scalar(input.middle),
            low: self.fuzz_individual_scalar(input.low),
        }
    }
}

impl<T: FeeEstimator> FeeEstimator for FeeRateFuzzer<T> {
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
