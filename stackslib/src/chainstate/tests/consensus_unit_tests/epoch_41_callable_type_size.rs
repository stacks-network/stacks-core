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

//! From Epoch 4.1, cost and memory charges count the contract and trait
//! identifiers that callable types hold.

use clarity::types::StacksEpochId;
use clarity::vm::{ClarityVersion, Value};
use rstest::rstest;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
    setup_contract_principal, SetupContract,
};

const BOTH_SIDES: &[StacksEpochId] = &[StacksEpochId::Epoch40, StacksEpochId::Epoch41];
const VERSIONS: &[ClarityVersion] = &[ClarityVersion::Clarity2, ClarityVersion::Clarity7];

const TRAITS: &str = "
    (define-trait trait-a ((f () (response bool uint))))";

/// Each trait function has a `uint` twin of the same shape as a control.
/// `trait-list` binds a list of trait values and prints it.
/// `nested-trait` runs `slice?`, `append` and `replace-at?` over a list of trait
/// lists.
const CALLER: &str = "
    (use-trait trait-a .traits.trait-a)
    (define-public (trait-list (a <trait-a>))
      (let ((as (list a a)))
        (print as)
        (ok (len as))))
    (define-public (uint-list (a uint))
      (let ((as (list a a)))
        (print as)
        (ok (len as))))
    (define-public (nested-trait (a <trait-a>))
      (let ((nested (list (list a) (list a)))
            (sliced (unwrap-panic (slice? nested u0 u1)))
            (appended (append sliced (list a)))
            (replaced (unwrap-panic (replace-at? appended u0 (list a)))))
        (ok (len replaced))))
    (define-public (nested-uint (a uint))
      (let ((nested (list (list a) (list a)))
            (sliced (unwrap-panic (slice? nested u0 u1)))
            (appended (append sliced (list a)))
            (replaced (unwrap-panic (replace-at? appended u0 (list a)))))
        (ok (len replaced))))";

/// Calls `function_name` on `CALLER` deployed at 4.0 and 4.1, checks every call
/// returns `expected`, and returns the runtime cost of the contract stored at
/// 4.0 when called at 4.0 and at 4.1.
fn stored_call_runtimes(
    function_name: &str,
    function_args: &[Value],
    expected: &Value,
) -> (u64, u64) {
    let setup_contracts = [
        SetupContract::new("traits", TRAITS)
            .with_epoch(StacksEpochId::Epoch40)
            .with_clarity_version(ClarityVersion::Clarity2),
        SetupContract::new("impl", "(define-public (f) (ok true))")
            .with_epoch(StacksEpochId::Epoch40)
            .with_clarity_version(ClarityVersion::Clarity2),
    ];
    let report = contract_call_consensus_unit_test!(
        contract_name: "caller",
        contract_code: CALLER,
        function_name: function_name,
        function_args: function_args,
        deploy_epochs: BOTH_SIDES,
        call_epochs: BOTH_SIDES,
        clarity_versions: VERSIONS,
        setup_contracts: &setup_contracts,
    );
    assert!(report.all_blocks_accepted());
    for deploy in report.contract_deploys() {
        assert!(deploy.executed(), "{deploy:?}");
    }
    let calls = report.contract_calls();
    // Deployed at 4.0 and called at 4.0 and 4.1, plus deployed and called at 4.1.
    assert_eq!(calls.len(), 3);
    for call in &calls {
        assert!(call.executed(), "{call:?}");
        assert_eq!(call.return_value(), expected, "{call:?}");
    }

    let runtime_when_called_at = |epoch: StacksEpochId| {
        calls
            .iter()
            .find(|call| {
                *call.contract_epoch() == StacksEpochId::Epoch40 && *call.block_epoch() == epoch
            })
            .expect("call of the contract stored at 4.0")
            .cost()
            .runtime
    };
    (
        runtime_when_called_at(StacksEpochId::Epoch40),
        runtime_when_called_at(StacksEpochId::Epoch41),
    )
}

/// Calls return the same values on both sides of the boundary. A contract
/// stored at 4.0 is charged more from 4.1 for its trait values, through the
/// block epoch, compared with the `uint` twin.
#[rstest]
#[case::let_print(
    "trait-list",
    &[setup_contract_principal("impl")],
    "uint-list",
    &[Value::UInt(1)],
    Value::okay(Value::UInt(2)).unwrap()
)]
#[case::slice_append_replace_at(
    "nested-trait",
    &[setup_contract_principal("impl")],
    "nested-uint",
    &[Value::UInt(1)],
    Value::okay(Value::UInt(2)).unwrap()
)]
fn test_epoch41_stored_trait_values_charged_more(
    #[case] trait_function: &str,
    #[case] trait_args: &[Value],
    #[case] uint_function: &str,
    #[case] uint_args: &[Value],
    #[case] expected: Value,
) {
    let (trait_40, trait_41) = stored_call_runtimes(trait_function, trait_args, &expected);
    let (uint_40, uint_41) = stored_call_runtimes(uint_function, uint_args, &expected);
    let extra_40 = i128::from(trait_40) - i128::from(uint_40);
    let extra_41 = i128::from(trait_41) - i128::from(uint_41);
    assert!(extra_41 > extra_40, "{extra_41} should exceed {extra_40}");
}

/// A contract with trait-typed arguments, or its `uint` twin.
fn typed_arguments_contract(arg_type: &str) -> String {
    format!(
        "(define-trait trait-a ((f () (response bool uint))))
         (define-private (id (t {arg_type})) t)
         (define-private (pair (t {arg_type}))
           (let ((ts (list t t)))
             (len ts)))"
    )
}

/// Runtime cost of deploying `contract_code` at 4.0 and at 4.1.
fn deploy_runtimes(contract_code: &str) -> (u64, u64) {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "typed-arguments",
        contract_code: contract_code,
        deploy_epochs: BOTH_SIDES,
        clarity_versions: VERSIONS,
    );
    assert!(report.all_blocks_accepted());
    let deploys = report.contract_deploys();
    // One deploy per epoch: 4.0 takes Clarity 2, and 4.1 only Clarity 7.
    assert_eq!(deploys.len(), 2);
    let runtime_at = |epoch: StacksEpochId| {
        let deploy = deploys
            .iter()
            .find(|deploy| *deploy.block_epoch() == epoch)
            .expect("deploy at epoch");
        assert!(deploy.executed(), "{deploy:?}");
        deploy.cost().runtime
    };
    (
        runtime_at(StacksEpochId::Epoch40),
        runtime_at(StacksEpochId::Epoch41),
    )
}

/// Deploying a contract with trait-typed arguments costs more to analyze from
/// 4.1, compared with its `uint` twin.
#[test]
fn test_epoch41_trait_arguments_analysis_charged_more() {
    let (trait_40, trait_41) = deploy_runtimes(&typed_arguments_contract("<trait-a>"));
    let (uint_40, uint_41) = deploy_runtimes(&typed_arguments_contract("uint"));
    let extra_40 = i128::from(trait_40) - i128::from(uint_40);
    let extra_41 = i128::from(trait_41) - i128::from(uint_41);
    assert!(extra_41 > extra_40, "{extra_41} should exceed {extra_40}");
}
