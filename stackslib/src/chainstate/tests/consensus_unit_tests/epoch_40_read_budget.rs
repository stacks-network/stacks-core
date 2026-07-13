// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! End-to-end consensus tests proving that Epoch 4.0 actually enforces a
//! doubled Clarity read budget (`read_count`), via real contract calls,
//! rather than just asserting on the [`BLOCK_LIMIT_MAINNET_40`] constant.

use clarity::types::StacksEpochId;
use clarity::vm::{ClarityVersion, Value};

use crate::chainstate::tests::consensus::contract_call_consensus_unit_test;
use crate::core::{BLOCK_LIMIT_MAINNET_21, BLOCK_LIMIT_MAINNET_40};

/// A contract whose public function performs `read_count` `var-get` reads,
/// then returns `(ok u0)`. Each `var-get` costs exactly one unit of
/// `read_count`, so this drives the cost tracker's read budget directly.
fn many_reads_contract(function_name: &str, read_count: u64) -> String {
    format!(
        "(define-data-var foo int 1)\n(define-public ({function_name}) (ok (begin {} u0)))",
        "(var-get foo)\n".repeat(read_count as usize),
    )
}

/// A call needing one more read than the pre-4.0 budget allows (15,001) must be
/// rejected in Epoch 3.4, but accepted from Epoch 4.0 on, since Epoch 4.0 doubles
/// the read budget to 30,000. This proves the doubled budget is actually enforced
/// end-to-end through a real contract call, not just declared in the constant.
#[test]
fn epoch_40_read_budget_accepts_calls_that_exceed_the_old_limit() {
    let read_count = BLOCK_LIMIT_MAINNET_21.read_count + 1;
    assert!(read_count <= BLOCK_LIMIT_MAINNET_40.read_count);

    // Deploy a single instance (at Epoch 3.4) and call it at both Epoch 3.4 and
    // Epoch 4.0. Deploying a second instance at Epoch 4.0 would cause the Epoch
    // 4.0 call round to call *both* instances in the same block (one call per
    // previously-deployed instance), stacking two ~15,001-read calls into a
    // single block and overflowing even the doubled budget for an unrelated
    // reason (cumulative block cost, not per-call cost).
    let report = contract_call_consensus_unit_test!(
        contract_name: "e40rb-ok",
        contract_code: &many_reads_contract("trigger", read_count),
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch34],
        call_epochs: &[StacksEpochId::Epoch34, StacksEpochId::Epoch40],
        clarity_versions: &[ClarityVersion::Clarity2],
    );

    let calls = report.contract_calls();
    assert!(!calls.is_empty(), "expected at least one call");

    for tx in calls {
        if tx.block_epoch() < &StacksEpochId::Epoch40 {
            assert!(
                tx.block_rejected(),
                "a call needing {read_count} reads should exceed the pre-4.0 read budget for {tx:?}"
            );
        } else {
            assert!(
                tx.executed(),
                "a call needing {read_count} reads should fit the doubled Epoch 4.0 read budget for {tx:?}"
            );
            assert_eq!(
                &Value::okay(Value::UInt(0)).unwrap(),
                tx.return_value(),
                "unexpected return value for {tx:?}"
            );
        }
    }
}

/// A call needing more reads than *double* the pre-4.0 budget (30,001) must still be
/// rejected at Epoch 4.0: the read budget increase is exactly 2x, not unbounded.
#[test]
fn epoch_40_read_budget_still_rejects_calls_beyond_double_the_old_limit() {
    let read_count = BLOCK_LIMIT_MAINNET_40.read_count + 1;

    let report = contract_call_consensus_unit_test!(
        contract_name: "e40rb-over",
        contract_code: &many_reads_contract("trigger", read_count),
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch40],
        call_epochs: &[StacksEpochId::Epoch40],
        clarity_versions: &[ClarityVersion::Clarity6],
    );

    let calls = report.contract_calls();
    assert!(!calls.is_empty(), "expected at least one call");

    for tx in calls {
        assert!(
            tx.block_rejected(),
            "a call needing {read_count} reads should exceed even the doubled Epoch 4.0 read budget for {tx:?}"
        );
    }
}
