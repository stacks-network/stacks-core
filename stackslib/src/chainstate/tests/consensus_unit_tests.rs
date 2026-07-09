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

use std::collections::HashMap;

use clarity::types::{StacksEpochId, StacksEpochRangeTestExt as _};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::{ClarityVersion, ContractName, Value};
use rstest::rstest;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
    ConsensusMacroUnitReport, ConsensusTest, ConsensusUtils, ExpectedResult, SetupContract,
    TestBlock, FAUCET_ADDRESS,
};

/// Asserts that every block in `report` was accepted and that every
/// contract-call transaction returned `expected`.
fn assert_all_calls_return(report: &ConsensusMacroUnitReport, expected: &Value) {
    assert!(report.all_blocks_accepted());
    let txs = report.contract_calls();
    assert!(!txs.is_empty(), "expected at least one contract call");
    for each in txs {
        assert_eq!(expected, each.return_value(), "wrong return for {each:?}");
    }
}

/// A Clarity 1 trait deployed at Epoch 3.4 whose method name (`slice?`) is now
/// a reserved native - the shape the tests below rely on: only a trait that
/// predates the name's reservation makes the name implementable.
fn legacy_ops_setup() -> SetupContract {
    SetupContract::new(
        "legacy-ops",
        "(define-trait ops ((slice? (int int) (response int int))))",
    )
    .with_epoch(StacksEpochId::Epoch34)
    .with_clarity_version(ClarityVersion::Clarity1)
}

/// A legacy Clarity 1 implementation of [`legacy_ops_setup`]'s trait.
fn shadow_target_setup() -> SetupContract {
    SetupContract::new(
        "shadow-target",
        "
        (impl-trait .legacy-ops.ops)
        (define-public (slice? (a int) (b int)) (ok (+ a b)))
        ",
    )
    .with_epoch(StacksEpochId::Epoch34)
    .with_clarity_version(ClarityVersion::Clarity1)
}

/// Principal of the [`shadow_target_setup`] contract, for dynamic dispatch.
fn shadow_target_principal() -> Value {
    Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
        StandardPrincipalData::from(FAUCET_ADDRESS.clone()),
        ContractName::from_literal("shadow-target"),
    )))
}

#[test]
fn test_example_1_cdeploy() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "map_empty",
        contract_code: "(map + (list) (list 10 20))",
        deploy_epochs: (StacksEpochId::Epoch20..).as_slice(),
        clarity_versions: ClarityVersion::ALL,
    );

    assert!(report.all_blocks_accepted());

    let txs = report.contract_deploys();

    for each in txs {
        let expected = Value::error(Value::none()).unwrap();
        assert_eq!(&expected, each.return_value(), "wrong return for {each:?}");

        assert_eq!(
            ":0:0: expecting expression of type 'int' or 'uint', found 'UnknownType'",
            each.vm_error().unwrap(),
            "wrong error for {each:?}"
        );
    }
}

#[test]
fn test_example_2_ccall() {
    let report = contract_call_consensus_unit_test!(
        contract_name: "map_empty",
        contract_code: "
            (define-data-var xs (list 10 int) (list))
            (define-data-var ys (list 10 int) (list 10 20))
            (define-public (trigger)
                (ok (map + (var-get xs) (var-get ys))))
        ",
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: (StacksEpochId::Epoch20..).as_slice(),
        clarity_versions: ClarityVersion::ALL,
    );

    assert!(report.all_blocks_accepted());

    let txs = report.contract_calls();

    for each in txs {
        let expected = if each.block_epoch() <= &StacksEpochId::Epoch34 {
            Value::okay(Value::list_from(vec![Value::Int(10)]).unwrap()).unwrap()
        } else {
            Value::okay(Value::list_from(vec![]).unwrap()).unwrap()
        };

        assert_eq!(&expected, each.return_value(), "wrong return for {each:?}");
    }
}

/// A contract that defines `slice?` - a name that is a native function from
/// Clarity 2 on - to implement a Clarity 1 trait method. The name was free at
/// Clarity 1 and, from Clarity 6, a public or read-only function may take it
/// again when it implements a declared trait method (reachable by literal-name
/// lookup only; bare references keep meaning the native). At Clarity 2..=5 the
/// name is reserved and the deploy is rejected at initialization.
#[test]
fn test_clarity6_shadow_deploy() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "shadow_slice",
        contract_code: "
            (impl-trait .legacy-ops.ops)
            (define-public (slice? (a int) (b int)) (ok (+ a b)))
        ",
        deploy_epochs: (StacksEpochId::Epoch20..).as_slice(),
        clarity_versions: ClarityVersion::ALL,
        setup_contracts: &[SetupContract::new(
            "legacy-ops",
            "(define-trait ops ((slice? (int int) (response int int))))",
        )],
    );

    // Every deploy is a *valid* transaction (older versions are no longer
    // offered at Epoch 4.0, so nothing is rejected at pre-check); the
    // reserved-name conflict surfaces as a VM error at initialization.
    assert!(report.all_blocks_accepted());

    for each in report.contract_deploys() {
        match each.contract_clarity() {
            ClarityVersion::Clarity1 | ClarityVersion::Clarity6 => {
                assert!(
                    each.vm_error().is_none(),
                    "expected a clean deploy for {each:?}"
                );
            }
            _ => {
                let err = each
                    .vm_error()
                    .unwrap_or_else(|| panic!("expected a reserved-name error for {each:?}"));
                assert!(
                    err.contains("slice?"),
                    "unexpected error for {each:?}: {err}"
                );
            }
        }
    }
}

/// Without a declared trait method for it, defining a shadowable reserved
/// name stays illegal at Clarity 6 - failing with the same `NameAlreadyUsed`
/// as in earlier versions. (Referenced by the `RuntimeCheckErrorKind`
/// variant-coverage report in `runtime_analysis_tests.rs`.)
#[test]
pub(crate) fn test_clarity6_unscoped_shadow_deploy_rejected() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "unscoped_shadow",
        contract_code: "(define-public (slice? (a int) (b int)) (ok (+ a b)))",
        deploy_epochs: &[StacksEpochId::Epoch40],
        clarity_versions: &[ClarityVersion::Clarity6],
    );

    assert!(report.all_blocks_accepted());

    for each in report.contract_deploys() {
        let err = each
            .vm_error()
            .unwrap_or_else(|| panic!("expected a reserved-name error for {each:?}"));
        assert!(
            err.contains("slice?"),
            "unexpected error for {each:?}: {err}"
        );
    }
}

/// Full-pipeline interop of a Clarity 6 contract with a legacy Clarity 1
/// trait whose method name (`slice?`) is reserved now. Every case must pass
/// deploy analysis (incl. trait compliance) and return `(ok 9)` when called:
/// - `implements_trait`: implements the legacy trait; the implementing
///   function is directly callable by its literal name.
/// - `static_call`: statically calls a legacy contract's reserved-named
///   function - resolved by literal name in the callee's analysis, never
///   against the native.
/// - `dynamic_dispatch`: dispatches the legacy trait to a legacy
///   implementation - the method resolves by literal name in the trait
///   signature.
#[rstest]
#[case::implements_trait(
    "impl_legacy",
    "(impl-trait .legacy-ops.ops)
     (define-public (slice? (a int) (b int)) (ok (+ a b)))",
    "slice?",
    &[Value::Int(4), Value::Int(5)],
    &[legacy_ops_setup()]
)]
#[case::static_call(
    "static_caller",
    "(define-public (trigger)
        (contract-call? .shadow-target slice? 4 5))",
    "trigger",
    &[],
    &[legacy_ops_setup(), shadow_target_setup()]
)]
#[case::dynamic_dispatch(
    "dispatcher",
    "(use-trait ops-alias .legacy-ops.ops)
     (define-public (trigger (t <ops-alias>))
        (contract-call? t slice? 4 5))",
    "trigger",
    &[shadow_target_principal()],
    &[legacy_ops_setup(), shadow_target_setup()]
)]
fn test_clarity6_legacy_trait_interop(
    #[case] contract_name: &str,
    #[case] contract_code: &str,
    #[case] function_name: &str,
    #[case] function_args: &[Value],
    #[case] setup_contracts: &[SetupContract],
) {
    let report = contract_call_consensus_unit_test!(
        contract_name: contract_name,
        contract_code: contract_code,
        function_name: function_name,
        function_args: function_args,
        deploy_epochs: (StacksEpochId::Epoch34..).as_slice(),
        call_epochs: &[StacksEpochId::Epoch40],
        clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity6],
        setup_contracts: setup_contracts,
    );

    assert_all_calls_return(&report, &Value::okay(Value::Int(9)).unwrap());
}

/// Implementing a legacy trait method does not bypass trait compliance: a
/// contract that defines `slice?` for the legacy trait method but with the
/// wrong signature is rejected at analysis - before the VM's name-matching
/// (or, at Clarity 2..=5, reserved-name) check ever runs - at every Clarity
/// version. Deploys start at Epoch 3.4: the legacy trait is pinned there, and
/// pre-2.1 epochs reject analysis-failing transactions outright instead of
/// including them with an error.
#[test]
fn test_clarity6_shadow_impl_wrong_signature_rejected() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "bad_signature",
        contract_code: "
            (impl-trait .legacy-ops.ops)
            (define-public (slice? (a int)) (ok a))
        ",
        deploy_epochs: (StacksEpochId::Epoch34..).as_slice(),
        clarity_versions: ClarityVersion::ALL,
        setup_contracts: &[legacy_ops_setup()],
    );

    assert!(report.all_blocks_accepted());
    for each in report.contract_deploys() {
        let err = each
            .vm_error()
            .unwrap_or_else(|| panic!("expected a trait-compliance error for {each:?}"));
        assert!(
            err.contains("invalid signature for method 'slice?'"),
            "unexpected error for {each:?}: {err}"
        );
    }
}

/// Full-pipeline enforcement: a deploy pinning Clarity 5 at Epoch 4.0 makes
/// the whole block invalid at `process_transaction_precheck`.
#[test]
fn test_epoch40_rejects_older_version_deploy_block() {
    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch40,
        vec![TestBlock {
            transactions: vec![ConsensusUtils::new_deploy_tx(
                0,
                "c5-pinned",
                "(define-public (ping) (ok true))",
                Some(ClarityVersion::Clarity5),
            )],
        }],
    );
    let results = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();

    assert_eq!(results.len(), 1);
    match &results[0] {
        ExpectedResult::Failure(failure) => {
            assert_eq!(StacksEpochId::Epoch40, failure.evaluated_epoch);
            assert!(
                failure.error.contains("requires contracts to use"),
                "unexpected error: {}",
                failure.error
            );
        }
        r => panic!("expected block rejection, got {r:?}"),
    }
}

/// Adversarial: the native `slice?` is read-only, but a *shadowed* `slice?`
/// can be a writing public function. A read-only function statically calling
/// it must be classified by the CALLEE's actual function (literal-name lookup
/// in its analysis), not by the native - so this deploy must fail the
/// read-only check. This pins the analysis/runtime resolution symmetry that
/// prevents writes from escaping read-only contexts via shadowed names.
#[test]
fn test_clarity6_shadowed_writer_rejected_in_read_only() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "ro_probe",
        contract_code: "
            (define-read-only (probe)
                (contract-call? .shadow-writer slice? 4 5))
        ",
        deploy_epochs: (StacksEpochId::Epoch34..).as_slice(),
        clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity6],
        // A legacy Clarity 1 contract may freely define a *writing* `slice?`.
        setup_contracts: &[SetupContract::new(
            "shadow-writer",
            "
            (define-data-var counter int 0)
            (define-public (slice? (a int) (b int))
                (begin (var-set counter a) (ok (+ a b))))
            ",
        )
        .with_epoch(StacksEpochId::Epoch34)
        .with_clarity_version(ClarityVersion::Clarity1)],
    );

    assert!(report.all_blocks_accepted());

    for each in report.contract_deploys() {
        let err = each
            .vm_error()
            .unwrap_or_else(|| panic!("expected a read-only violation for {each:?}"));
        assert!(
            err.contains("read-only"),
            "unexpected error for {each:?}: {err}"
        );
    }
}
