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

//! Epoch 4.1 rejects new contracts whose static types do not admit their runtime
//! values: tuples unified across different fields, and `fold` results narrower
//! than the initial value. Stored contracts keep executing as deployed, including
//! trait dispatch.

use clarity::types::StacksEpochId;
use clarity::vm::{ClarityVersion, Value};
use rstest::rstest;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
    setup_contract_principal, ConsensusMacroUnitReport, SetupContract,
};

const TUPLE_TRAIT: &str = "(define-trait t ((fetch () (response {a: uint} uint))))";

/// `fetch` returns a wider tuple than its inferred type `{a: uint}`. `probe`
/// shows the hidden field flowing through `merge`, `is-eq` and list construction.
const PROVIDER: &str = "
    (define-data-var counter uint u0)
    (define-public (fetch)
      (ok (if false
            (begin (var-set counter (+ (var-get counter) u1)) {a: u1})
            {a: u1, b: true})))
    (define-public (probe)
      (let ((hidden (unwrap-panic (fetch))))
        (ok {
          merged: (get b (merge {b: u0} hidden)),
          equal: (is-eq hidden {a: u1}),
          items: (list {a: u1} hidden),
          counter: (var-get counter)})))";

/// Reaches the same hidden field without unifying tuples: an empty `fold`
/// returns its initial value, which pre-4.1 analysis left out of the result type.
const FOLD_PROVIDER: &str = "
    (define-private (keep-none (x (buff 1)) (acc (optional {a: uint, b: bool}))) none)
    (define-public (fetch)
      (ok (default-to {a: u1} (fold keep-none 0x (some {a: u1, b: true})))))";

const CALLER: &str = "
    (use-trait t .tuple-trait.t)
    (define-public (direct) (contract-call? .provider fetch))
    (define-public (dynamic (target <t>)) (contract-call? target fetch))
    (define-public (join)
      (ok (list {a: u1} (unwrap-panic (contract-call? .provider fetch)))))";

const HIDDEN_TUPLE: &str = "(ok (tuple (a u1) (b true)))";
const BOTH_SIDES: &[StacksEpochId] = &[StacksEpochId::Epoch40, StacksEpochId::Epoch41];
const VERSIONS: &[ClarityVersion] = &[ClarityVersion::Clarity2, ClarityVersion::Clarity7];

fn stored_at_40(name: &str, code: &str) -> SetupContract {
    SetupContract::new(name, code)
        .with_epoch(StacksEpochId::Epoch40)
        .with_clarity_version(ClarityVersion::Clarity2)
}

/// The trait, its implementation, and the fold provider, all stored before the
/// boundary.
fn stored_contracts() -> Vec<SetupContract> {
    vec![
        stored_at_40("tuple-trait", TUPLE_TRAIT),
        stored_at_40(
            "provider",
            &format!("(impl-trait .tuple-trait.t) {PROVIDER}"),
        ),
        stored_at_40("fold-provider", FOLD_PROVIDER),
    ]
}

/// Every block accepted and every deploy executed.
fn assert_all_deploys_executed(report: &ConsensusMacroUnitReport) {
    assert!(report.all_blocks_accepted());
    for deploy in report.contract_deploys() {
        assert!(deploy.executed(), "{deploy:?}");
    }
}

/// Both providers deploy at 4.0 and fail analysis at 4.1 with the error of the
/// operation that would hide the field.
#[rstest]
#[case::tuple_join("provider", PROVIDER, "arms of 'if' must match")]
#[case::fold_initial_value(
    "fold-provider",
    FOLD_PROVIDER,
    "expression types passed in 'default-to' must match"
)]
fn test_epoch41_rejects_hidden_field_providers(
    #[case] contract_name: &str,
    #[case] contract_code: &str,
    #[case] rejection: &str,
) {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: contract_name,
        contract_code: contract_code,
        deploy_epochs: BOTH_SIDES,
        clarity_versions: VERSIONS,
    );
    assert!(report.all_blocks_accepted());
    let deploys = report.contract_deploys();
    assert_eq!(deploys.len(), 2);
    for deploy in deploys {
        match deploy.contract_epoch() {
            StacksEpochId::Epoch40 => assert!(deploy.executed(), "{deploy:?}"),
            StacksEpochId::Epoch41 => {
                assert_eq!(deploy.return_value(), &Value::error(Value::none()).unwrap());
                assert!(deploy.vm_error().unwrap().contains(rejection), "{deploy:?}");
            }
            other => panic!("unexpected deploy epoch {other}"),
        }
    }
}

/// Stored contracts return the same values on both sides of the boundary, and a
/// caller deployed at 4.1 consumes the legacy provider's hidden field the same
/// way: the runtime does not check returned values against the stored type.
#[rstest]
#[case::provider_probe(
    "probe-provider", PROVIDER, "probe", &[], &[StacksEpochId::Epoch40],
    "(ok (tuple (counter u0) (equal false) (items ((tuple (a u1)) (tuple (a u1)))) (merged true)))"
)]
#[case::fold_provider(
    "probe-fold", FOLD_PROVIDER, "fetch", &[], &[StacksEpochId::Epoch40], HIDDEN_TUPLE
)]
#[case::direct_call("caller", CALLER, "direct", &[], BOTH_SIDES, HIDDEN_TUPLE)]
#[case::dynamic_dispatch(
    "caller", CALLER, "dynamic", &[setup_contract_principal("provider")], BOTH_SIDES, HIDDEN_TUPLE
)]
#[case::join_with_literal(
    "caller", CALLER, "join", &[], BOTH_SIDES, "(ok ((tuple (a u1)) (tuple (a u1))))"
)]
fn test_epoch41_stored_contracts_execute_unchanged(
    #[case] contract_name: &str,
    #[case] contract_code: &str,
    #[case] function_name: &str,
    #[case] function_args: &[Value],
    #[case] deploy_epochs: &[StacksEpochId],
    #[case] expected: &str,
) {
    let report = contract_call_consensus_unit_test!(
        contract_name: contract_name,
        contract_code: contract_code,
        function_name: function_name,
        function_args: function_args,
        deploy_epochs: deploy_epochs,
        call_epochs: BOTH_SIDES,
        clarity_versions: VERSIONS,
        setup_contracts: &stored_contracts(),
    );
    assert_all_deploys_executed(&report);
    let calls = report.contract_calls();
    // One call per deploy epoch and each call epoch at or after it; `VERSIONS`
    // leaves a single Clarity version per epoch.
    let expected_calls: usize = deploy_epochs
        .iter()
        .map(|deployed| {
            BOTH_SIDES
                .iter()
                .filter(|called| *called >= deployed)
                .count()
        })
        .sum();
    assert_eq!(calls.len(), expected_calls);
    for call in calls {
        assert!(call.executed(), "{call:?}");
        assert_eq!(call.return_value().to_string(), expected, "{call:?}");
    }
}
