use cost_estimates::FeeRateEstimate;

pub mod cost_estimators;
pub mod fee_scalar;

#[test]
fn fee_rate_estimate_math_units() {
    let maximal_estimate = FeeRateEstimate {
        fast: u64::MAX,
        medium: u64::MAX,
        slow: u64::MAX,
    };

    assert_eq!(
        maximal_estimate,
        maximal_estimate.clone() * 3,
        "Fee rate estimate math should saturate"
    );
    assert_eq!(
        maximal_estimate,
        maximal_estimate.clone() + maximal_estimate.clone(),
        "Fee rate estimate math should saturate"
    );

    let estimate = FeeRateEstimate {
        fast: 1,
        medium: 1,
        slow: 1,
    };

    assert_eq!(
        estimate,
        estimate.clone() / 0,
        "Fee rate estimate division is just an identity operation."
    );
}
