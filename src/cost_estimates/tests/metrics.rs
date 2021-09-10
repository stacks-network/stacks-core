use chainstate::stacks::MAX_BLOCK_LEN;
use core::BLOCK_LIMIT_MAINNET;
use cost_estimates::metrics::{CostMetric, ProportionalDotProduct};
use vm::costs::ExecutionCost;

#[test]
fn test_proportional_dot_product() {
    let metric = ProportionalDotProduct::new(
        10_000,
        ExecutionCost {
            write_length: 5_000,
            write_count: 6_000,
            read_length: 7_000,
            read_count: 8_000,
            runtime: 9_000,
        },
    );

    // an execution cost equal to the limit should be maxed in each dimension,
    // and the maximum value for the metric is 6_000.
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 5_000,
                write_count: 6_000,
                read_length: 7_000,
                read_count: 8_000,
                runtime: 9_000,
            },
            10_000
        ),
        6_000
    );

    // an execution cost equal to the limit should be maxed in each dimension,
    // and the maximum value for the metric is 6_000.
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 5_000,
                write_count: 6_000,
                read_length: 7_000,
                read_count: 8_000,
                runtime: 9_000,
            },
            10_000
        ),
        6_000
    );

    // 400 / 5 = 80
    // 200 / 6 = 33
    // 100 / 7 = 14
    // 200 / 8 = 25
    // 50 / 9 =   5
    // 100 / 10 = 10
    // Expected scalar = 167
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 400,
                write_count: 200,
                read_length: 100,
                read_count: 200,
                runtime: 50,
            },
            100
        ),
        167
    );
}

#[test]
fn test_proportional_dot_product_with_mainnet_lims() {
    let metric = ProportionalDotProduct::new(MAX_BLOCK_LEN as u64, BLOCK_LIMIT_MAINNET.clone());

    // an execution cost equal to the limit should be maxed in each dimension,
    // and the maximum value for the metric is 6_000.
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 15_000_000,
                write_count: 7_750,
                read_length: 100_000_000,
                read_count: 7_750,
                runtime: 5_000_000_000,
            },
            2 * 1024 * 1024
        ),
        6_000
    );

    // should be: 100 + 100 + 1 + 100 + 1 + 0 = 302
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 1_500_000,
                write_count: 775,
                read_length: 100_000,
                read_count: 775,
                runtime: 5_000_000,
            },
            1024
        ),
        302
    );

    // defend against costs > limit, should max to 6_000
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 35_000_000,
                write_count: 8_750,
                read_length: 100_000_001,
                read_count: 7_751,
                runtime: 50_000_000_000,
            },
            2 * 1024 * 1024 + 1
        ),
        6_000
    );
}
