use clarity::vm::costs::ExecutionCost;

use crate::chainstate::stacks::MAX_BLOCK_LEN;
use crate::core::BLOCK_LIMIT_MAINNET_20;
use crate::cost_estimates::metrics::{CostMetric, ProportionalDotProduct};

#[test]
// Test that when dimensions of the execution cost are near "zero",
//  that the metric always returns a number greater than zero.
fn test_proportional_dot_product_near_zero() {
    let metric = ProportionalDotProduct::new(12_000);
    let block_limit = ExecutionCost {
        write_length: 50_000,
        write_count: 60_000,
        read_length: 70_000,
        read_count: 80_000,
        runtime: 90_000,
    };
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 1,
                write_count: 1,
                read_length: 1,
                read_count: 1,
                runtime: 1,
            },
            &block_limit,
            1
        ),
        6
    );

    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 0,
                write_count: 0,
                read_length: 0,
                read_count: 0,
                runtime: 0,
            },
            &block_limit,
            0
        ),
        6
    );
}

#[test]
fn test_proportional_dot_product() {
    let metric = ProportionalDotProduct::new(10_000);
    let block_limit = ExecutionCost {
        write_length: 5_000,
        write_count: 6_000,
        read_length: 7_000,
        read_count: 8_000,
        runtime: 9_000,
    };

    // an execution cost equal to the limit should be maxed in each dimension,
    // and the maximum value for the metric is 60_000.
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 5_000,
                write_count: 6_000,
                read_length: 7_000,
                read_count: 8_000,
                runtime: 9_000,
            },
            &block_limit,
            10_000
        ),
        60_000
    );

    // an execution cost equal to the limit should be maxed in each dimension,
    // and the maximum value for the metric is 60_000.
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 5_000,
                write_count: 6_000,
                read_length: 7_000,
                read_count: 8_000,
                runtime: 9_000,
            },
            &block_limit,
            10_000
        ),
        60_000
    );

    // 4000 / 5 =  800
    // 2000 / 6 =  333
    // 1000 / 7 =  142
    // 2000 / 8 =  250
    // 500 / 9 =    55
    // 1000 / 10 = 100
    // Expected scalar = 1680
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 400,
                write_count: 200,
                read_length: 100,
                read_count: 200,
                runtime: 50,
            },
            &block_limit,
            100
        ),
        1680
    );
}

#[test]
fn test_proportional_dot_product_with_mainnet_lims() {
    let metric = ProportionalDotProduct::new(MAX_BLOCK_LEN as u64);

    // an execution cost equal to the limit should be maxed in each dimension,
    // and the maximum value for the metric is 60_000.
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 15_000_000,
                write_count: 7_750,
                read_length: 100_000_000,
                read_count: 7_750,
                runtime: 5_000_000_000,
            },
            &BLOCK_LIMIT_MAINNET_20,
            2 * 1024 * 1024
        ),
        60_000
    );

    // should be: 1000 + 1000 + 10 + 1000 + 10 + 4 = 3024
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 1_500_000,
                write_count: 775,
                read_length: 100_000,
                read_count: 775,
                runtime: 5_000_000,
            },
            &BLOCK_LIMIT_MAINNET_20,
            1024
        ),
        3024
    );

    // defend against costs > limit, should max to 60_000
    assert_eq!(
        metric.from_cost_and_len(
            &ExecutionCost {
                write_length: 35_000_000,
                write_count: 8_750,
                read_length: 100_000_001,
                read_count: 7_751,
                runtime: 50_000_000_000,
            },
            &BLOCK_LIMIT_MAINNET_20,
            2 * 1024 * 1024 + 1
        ),
        60_000
    );
}
