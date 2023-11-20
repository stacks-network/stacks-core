use clarity::vm::costs::ExecutionCost;
use rand::distributions::{Distribution, Uniform};
use rand::rngs::StdRng;
use rand::{thread_rng, RngCore, SeedableRng};

use super::{EstimatorError, FeeEstimator, FeeRateEstimate};
use crate::chainstate::stacks::db::StacksEpochReceipt;

/// The FeeRateFuzzer wraps an underlying FeeEstimator. It passes `notify_block` calls to the
/// underlying estimator. On `get_rate_estimates` calls, it adds a random fuzz to the result coming
/// back from the underlying estimator. The fuzz applied is as a random fraction of the base value.
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
    /// random number in `[-uniform_fuzz_fraction, uniform_fuzz_fraction]`.
    /// Note: Must be `0 <= uniform_fuzz_fraction < 1`.
    uniform_fuzz_fraction: f64,
}

impl<UnderlyingEstimator: FeeEstimator> FeeRateFuzzer<UnderlyingEstimator> {
    /// Constructor for production. It uses `thread_rng()` as the random number generator,
    /// to get truly pseudo-random numbers.
    pub fn new(
        underlying: UnderlyingEstimator,
        uniform_fuzz_fraction: f64,
    ) -> FeeRateFuzzer<UnderlyingEstimator> {
        assert!(0.0 <= uniform_fuzz_fraction && uniform_fuzz_fraction < 1.0);
        let rng_creator = Box::new(|| {
            let r: Box<dyn RngCore> = Box::new(thread_rng());
            r
        });
        Self {
            underlying,
            rng_creator,
            uniform_fuzz_fraction,
        }
    }

    /// Constructor meant for test. The user can pass in a contrived random number generator
    /// factory function, so that the test is repeatable.
    pub fn new_custom_creator(
        underlying: UnderlyingEstimator,
        rng_creator: Box<dyn Fn() -> Box<dyn RngCore>>,
        uniform_fuzz_fraction: f64,
    ) -> FeeRateFuzzer<UnderlyingEstimator> {
        assert!(0.0 <= uniform_fuzz_fraction && uniform_fuzz_fraction < 1.0);
        Self {
            underlying,
            rng_creator,
            uniform_fuzz_fraction,
        }
    }

    /// Add a uniform fuzz to input. Each element is multiplied by the same random factor.
    fn fuzz_estimate(&self, input: FeeRateEstimate) -> FeeRateEstimate {
        if self.uniform_fuzz_fraction > 0f64 {
            let mut rng = (self.rng_creator)();
            let uniform = Uniform::new(-self.uniform_fuzz_fraction, self.uniform_fuzz_fraction);
            let fuzz_scale = 1f64 + uniform.sample(&mut rng);
            input * fuzz_scale
        } else {
            input
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
        let underlying_estimate = self.underlying.get_rate_estimates()?;
        Ok(self.fuzz_estimate(underlying_estimate))
    }
}
