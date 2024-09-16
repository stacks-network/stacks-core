use crate::cost_estimates::FeeRateEstimate;

pub mod common;
pub mod cost_estimators;
pub mod fee_medians;
pub mod fee_rate_fuzzer;
pub mod fee_scalar;
pub mod metrics;

#[test]
fn fee_rate_estimate_math_units() {
    let maximal_estimate = FeeRateEstimate {
        high: f64::MAX,
        middle: f64::MAX,
        low: f64::MAX,
    };

    assert_eq!(
        maximal_estimate,
        maximal_estimate.clone() * f64::MAX,
        "Fee rate estimate math should saturate"
    );
    assert_eq!(
        maximal_estimate,
        maximal_estimate.clone() + maximal_estimate.clone(),
        "Fee rate estimate math should saturate"
    );
}
