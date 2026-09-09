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

//! End-to-end tests for the Epoch 4.1 force-latest deploy rule and Clarity 7
//! reserved-name trait implementations (see `is_shadowable_reserved`).

use clarity::types::{StacksEpochId, StacksEpochRangeTestExt as _};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::{ClarityVersion, ContractName, Value};
use rstest::rstest;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
    ConsensusMacroUnitReport, SetupContract, FAUCET_ADDRESS,
};

/// Every block accepted and every contract call returned `expected`.
fn assert_all_calls_return(report: &ConsensusMacroUnitReport, expected: &Value) {
    assert!(report.all_blocks_accepted());
    let txs = report.contract_calls();
    assert!(!txs.is_empty(), "expected at least one contract call");
    for each in txs {
        assert_eq!(expected, each.return_value(), "wrong return for {each:?}");
    }
}

/// A Clarity 1 trait (Epoch 3.4) whose method name `slice?` is now reserved.
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

/// A Clarity 7 implementation of the legacy trait, deployed at Epoch 4.1.
fn c7_shadow_target_setup() -> SetupContract {
    SetupContract::new(
        "shadow-target-c7",
        "
        (impl-trait .legacy-ops.ops)
        (define-public (slice? (a int) (b int)) (ok (+ a b)))
        ",
    )
    .with_epoch(StacksEpochId::Epoch41)
    .with_clarity_version(ClarityVersion::Clarity7)
}

/// Principal of a setup contract deployed by the faucet, for dynamic dispatch.
fn setup_contract_principal(name: &'static str) -> Value {
    Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
        StandardPrincipalData::from(FAUCET_ADDRESS.clone()),
        ContractName::from_literal(name),
    )))
}

/// Implementing a Clarity 1 trait's `slice?` (reserved since Clarity 2): free
/// at Clarity 1, allowed again from Clarity 7, rejected at initialization in
/// between.
#[test]
fn test_clarity7_shadow_deploy() {
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

    // Nothing is rejected at precheck (Epoch 4.1 offers only Clarity 7); the
    // conflict surfaces as a VM error.
    assert!(report.all_blocks_accepted());

    for each in report.contract_deploys() {
        match each.contract_clarity() {
            ClarityVersion::Clarity1 | ClarityVersion::Clarity7 => {
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

/// Without a legacy trait method the name stays illegal at Clarity 7.
#[test]
fn test_clarity7_unscoped_shadow_deploy_rejected() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "unscoped_shadow",
        contract_code: "(define-public (slice? (a int) (b int)) (ok (+ a b)))",
        deploy_epochs: &[StacksEpochId::Epoch41],
        clarity_versions: &[ClarityVersion::Clarity7],
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

/// Interop with a legacy trait whose method name is now reserved; every case
/// passes analysis and returns `(ok 9)`:
/// - `implements_trait`: the implementation is callable by literal name.
/// - `static_call` / `dynamic_dispatch`: a legacy implementation, reached by
///   literal name in the callee's analysis and in the trait signature.
/// - `static_call_c7_target` / `dynamic_dispatch_c7_target`: the Clarity 7
///   implementation, from a Clarity 7 caller and from dispatchers of every
///   version since Epoch 3.4.
#[rstest]
#[case::implements_trait(
    "impl_legacy",
    "(impl-trait .legacy-ops.ops)
     (define-public (slice? (a int) (b int)) (ok (+ a b)))",
    "slice?",
    &[Value::Int(4), Value::Int(5)],
    (StacksEpochId::Epoch34..).as_slice(),
    &[legacy_ops_setup()]
)]
#[case::static_call(
    "static_caller",
    "(define-public (trigger)
        (contract-call? .shadow-target slice? 4 5))",
    "trigger",
    &[],
    (StacksEpochId::Epoch34..).as_slice(),
    &[legacy_ops_setup(), shadow_target_setup()]
)]
#[case::dynamic_dispatch(
    "dispatcher",
    "(use-trait ops-alias .legacy-ops.ops)
     (define-public (trigger (t <ops-alias>))
        (contract-call? t slice? 4 5))",
    "trigger",
    &[setup_contract_principal("shadow-target")],
    (StacksEpochId::Epoch34..).as_slice(),
    &[legacy_ops_setup(), shadow_target_setup()]
)]
#[case::static_call_c7_target(
    "static_caller_c7",
    "(define-public (trigger)
        (contract-call? .shadow-target-c7 slice? 4 5))",
    "trigger",
    &[],
    &[StacksEpochId::Epoch41],
    &[legacy_ops_setup(), c7_shadow_target_setup()]
)]
#[case::dynamic_dispatch_c7_target(
    "dispatcher",
    "(use-trait ops-alias .legacy-ops.ops)
     (define-public (trigger (t <ops-alias>))
        (contract-call? t slice? 4 5))",
    "trigger",
    &[setup_contract_principal("shadow-target-c7")],
    (StacksEpochId::Epoch34..).as_slice(),
    &[legacy_ops_setup(), c7_shadow_target_setup()]
)]
fn test_clarity7_legacy_trait_interop(
    #[case] contract_name: &str,
    #[case] contract_code: &str,
    #[case] function_name: &str,
    #[case] function_args: &[Value],
    #[case] deploy_epochs: &[StacksEpochId],
    #[case] setup_contracts: &[SetupContract],
) {
    let report = contract_call_consensus_unit_test!(
        contract_name: contract_name,
        contract_code: contract_code,
        function_name: function_name,
        function_args: function_args,
        deploy_epochs: deploy_epochs,
        call_epochs: &[StacksEpochId::Epoch41],
        clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity7],
        setup_contracts: setup_contracts,
    );

    assert_all_calls_return(&report, &Value::okay(Value::Int(9)).unwrap());
}

/// Trait compliance still applies: a wrong signature is rejected at analysis
/// at every version. Deploys start at Epoch 3.4 because pre-2.1 epochs reject
/// analysis failures outright instead of including them.
#[test]
fn test_clarity7_shadow_impl_wrong_signature_rejected() {
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

/// The native `slice?` is read-only but a shadowed `slice?` may write; a
/// read-only caller must be classified by the callee's actual function, so
/// this deploy must fail the read-only check.
#[test]
fn test_clarity7_shadowed_writer_rejected_in_read_only() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "ro_probe",
        contract_code: "
            (define-read-only (probe)
                (contract-call? .shadow-writer slice? 4 5))
        ",
        deploy_epochs: (StacksEpochId::Epoch34..).as_slice(),
        clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity7],
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
