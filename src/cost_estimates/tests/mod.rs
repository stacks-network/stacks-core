use cost_estimates::FeeRateEstimate;

pub mod cost_estimators;
pub mod fee_scalar;
pub mod metrics;

#[test]
fn fee_rate_estimate_math_units() {
    let maximal_estimate = FeeRateEstimate {
        fast: u64::MAX,
        medium: u64::MAX,
        slow: u64::MAX,
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
