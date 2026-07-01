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

//! End-to-end consensus tests for the epoch-gated `map` off-by-one fix.
//!
//! `map` over sequences of unequal length must stop at the *shortest* sequence.
//! The legacy implementation (`special_map_v200`) had an off-by-one that,
//! when an empty sequence was mixed with a non-empty one, iterated one step too
//! far — emitting a spurious element or applying the mapped function with too
//! few arguments. The fix (`special_map_v400`) is consensus-breaking, so it
//! is gated to Clarity 6 / Epoch 4.0 ([`MAP_FIX_EPOCH`]); earlier epochs must
//! preserve the buggy behavior.

use clarity::types::{StacksEpochId, StacksEpochRangeTestExt as _};
use clarity::vm::{ClarityVersion, Value};

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
};

/// Epoch in which the `map` off-by-one fix activates (Clarity 6).
/// Executions strictly before this epoch use the buggy `special_map_v200`;
/// from this epoch on they use the fixed `special_map_v400`.
const MAP_FIX_EPOCH: StacksEpochId = StacksEpochId::Epoch40;

/// A `map` where the shorter sequence is an *empty literal* never reaches the
/// runtime: the analysis pass rejects it in every epoch and Clarity version,
/// because an empty `(list)` literal has element type `UnknownType`, which the
/// mapped function's argument type (`int`) does not admit.
///
/// This is the consensus-consistent counterpart to
/// [`map_runtime_empty_native_fn_diverges_at_clarity6`]: the off-by-one is only
/// reachable when the empty sequence is empty *at runtime* while carrying a
/// concrete static type (see that test).
#[test]
fn map_empty_literal_sequence_is_rejected_by_analysis_in_all_epochs() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "map_empty_literal",
        contract_code: "(map + (list) (list 10 20))",
        deploy_epochs: (StacksEpochId::Epoch20..).as_slice(),
        clarity_versions: ClarityVersion::ALL,
    );

    assert!(report.all_blocks_accepted());

    let deploys = report.contract_deploys();
    assert!(!deploys.is_empty(), "expected at least one deploy");

    for tx in deploys {
        assert_eq!(
            &Value::error(Value::none()).unwrap(),
            tx.return_value(),
            "deploy should abort on analysis error for {tx:?}"
        );
        assert_eq!(
            ":0:0: expecting expression of type 'int' or 'uint', found 'UnknownType'",
            tx.vm_error().expect("expected an analysis error"),
            "unexpected analysis error for {tx:?}"
        );
    }
}

/// `map` with a native function (`+`) over a sequence that is empty *at runtime*
/// but statically typed `(list 10 int)`.
///
/// - Before [`MAP_FIX_EPOCH`]: the off-by-one steps past the empty `xs` and
///   applies `(+ 10)`, yielding a spurious `(list 10)`.
/// - From [`MAP_FIX_EPOCH`] on: iteration stops at the empty sequence, yielding
///   `(list)`.
///
/// Deploy and call happen in every epoch/version to prove the divergence is
/// gated purely on the *execution* epoch.
#[test]
fn map_runtime_empty_native_fn_diverges_at_clarity6() {
    let report = contract_call_consensus_unit_test!(
        contract_name: "map_empty_plus",
        contract_code: "
            (define-data-var xs (list 10 int) (list))
            (define-data-var ys (list 10 int) (list 10 20))
            (define-public (trigger)
                (ok (map + (var-get xs) (var-get ys))))
        ",
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: (StacksEpochId::Epoch20..).as_slice(),
        call_epochs: (StacksEpochId::Epoch20..).as_slice(),
        clarity_versions: ClarityVersion::ALL,
    );

    assert!(report.all_blocks_accepted());

    let calls = report.contract_calls();
    assert!(!calls.is_empty(), "expected at least one call");

    for tx in calls {
        assert!(
            tx.executed(),
            "call should execute without error for {tx:?}"
        );

        let expected = if tx.block_epoch() < &MAP_FIX_EPOCH {
            // Legacy off-by-one: spurious single element from `(+ 10)`.
            Value::okay(Value::list_from(vec![Value::Int(10)]).unwrap()).unwrap()
        } else {
            // Fixed: stops at the empty sequence.
            Value::okay(Value::list_from(vec![]).unwrap()).unwrap()
        };

        assert_eq!(&expected, tx.return_value(), "wrong return for {tx:?}");
    }
}

/// `map` with a strict-arity user function (`area`, two `int` params) over a
/// sequence that is empty *at runtime* but statically typed `(list 10 int)`.
///
/// The off-by-one here is more severe than the native-function case: instead of
/// a spurious value, it applies `area` with a single argument, which is a
/// runtime arity error. Its consensus-visible effect has three regimes, all
/// gated purely on the *execution* epoch:
///
/// - Before `Epoch21` (`Epoch20`, `Epoch2_05`): the arity error
///   cannot be mined into a block, so the *entire block* is rejected.
/// - From `Epoch21` up to (but excluding) [`MAP_FIX_EPOCH`]: the
///   error rolls back only the transaction, which is mined into the block and
///   returns `(err none)`.
/// - From [`MAP_FIX_EPOCH`] on: iteration stops at the empty sequence, so no
///   error occurs and the call succeeds with `(ok (list))`.
#[test]
fn map_runtime_empty_strict_arity_fn_diverges_at_clarity6() {
    let report = contract_call_consensus_unit_test!(
        contract_name: "map_empty_area",
        contract_code: "
            (define-data-var xs (list 10 int) (list))
            (define-data-var ys (list 10 int) (list 10 20))
            (define-private (area (w int) (h int)) (* w h))
            (define-public (trigger)
                (ok (map area (var-get xs) (var-get ys))))
        ",
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: (StacksEpochId::Epoch20..).as_slice(),
        call_epochs: (StacksEpochId::Epoch20..).as_slice(),
        clarity_versions: ClarityVersion::ALL,
    );

    let calls = report.contract_calls();
    assert!(!calls.is_empty(), "expected at least one call");

    for tx in calls {
        let block_epoch = tx.block_epoch();
        if block_epoch < &StacksEpochId::Epoch21 {
            // Legacy off-by-one, pre-rollback: the failing transaction cannot be
            // mined, so the whole block is rejected.
            assert!(tx.block_rejected(), "block should be rejected for {tx:?}");
        } else if block_epoch < &MAP_FIX_EPOCH {
            // Legacy off-by-one, post-rollback: `area` applied with a single
            // argument aborts just the transaction.
            assert!(tx.failed(), "call should abort at runtime for {tx:?}");
            assert_eq!(
                &Value::error(Value::none()).unwrap(),
                tx.return_value(),
                "wrong aborted return for {tx:?}"
            );
        } else {
            // Fixed: stops at the empty sequence and returns an empty list.
            assert!(tx.executed(), "call should execute cleanly for {tx:?}");
            assert_eq!(
                &Value::okay(Value::list_from(vec![]).unwrap()).unwrap(),
                tx.return_value(),
                "wrong return for {tx:?}"
            );
        }
    }
}
