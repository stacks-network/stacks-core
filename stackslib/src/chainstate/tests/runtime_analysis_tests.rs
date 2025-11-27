// Copyright (C) 2025 Stacks Open Internet Foundation
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

#[allow(unused_imports)]
use clarity::vm::analysis::CheckErrorKind;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::Value as ClarityValue;

use crate::chainstate::tests::consensus::{
    clarity_versions_for_epoch, contract_call_consensus_test, contract_deploy_consensus_test,
    ConsensusTest, ConsensusUtils, SetupContract, TestBlock, EPOCHS_TO_TEST, FAUCET_PRIV_KEY,
};
use crate::core::test_util::to_addr;

/// TODO: Documentation to be added to the enum
/// - PublicFunctionNotReadOnly. Functionally Unreachable. Environment::inner_execute_contract is invoked with read_only = false on the relevant code path, causing PublicFunctionNotReadOnly check to be skipped.
/// - NoSuchPublicFunction  Tested. Possible only during contract call. On contract deploy checked during static analysis
/// - CircularReference. Tested. Possible only during contract call. On contract deploy checked during parsing.

/// CheckErrorKind: [`CheckErrorKind::NoSuchPublicFunction`]
/// Caused by: Attempted to invoke a private function from outside the contract.
/// Outcome: block accepted
#[test]
fn check_error_kind_no_such_public_function_ccall() {
    contract_call_consensus_test!(
        contract_name: "target-contract",
        contract_code: "(define-private (get-one) (ok u1))",
        function_name: "get-one",
        function_args: &[],
    );
}

/// CheckErrorKind: [`CheckErrorKind::CircularReference`]
/// Caused by: circular reference forcing a contract calling itself using a contract call.
/// Outcome: block accepted
#[test]
fn check_error_kind_circular_reference_ccall() {
    let trait_contract = SetupContract::new(
        "trait-contract",
        "(define-trait trait-1 (
                (get-1 (uint) (response uint uint))))",
    );

    let dispatching_contract = SetupContract::new(
        "dispatch-contract",
        "(use-trait trait-1 .trait-contract.trait-1)
            (define-public (wrapped-get-1 (contract <trait-1>))
                (contract-call? contract get-1 u0))
            (define-public (get-1 (x uint)) (ok u1))",
    );

    let dispatch_principal = QualifiedContractIdentifier::parse(&format!(
        "{}.dispatch-contract",
        to_addr(&FAUCET_PRIV_KEY)
    ))
    .unwrap();

    // The main contract is required because `contract_call_consensus_test!` needs a deployed contract.
    // As a result, `dispatch-contract` cannot be used directly, because need to be passed as `function_args`,
    // and the consensus test mangles the `contract_name`.
    let main_contract = "(use-trait trait-1 .trait-contract.trait-1)
            (define-public (main-get-1 (contract <trait-1>))
            (contract-call? .dispatch-contract wrapped-get-1 contract))";

    contract_call_consensus_test!(
        contract_name: "main-contract",
        contract_code: main_contract,
        function_name: "main-get-1",
        function_args: &[ClarityValue::from(dispatch_principal)],
        setup_contracts: &[trait_contract, dispatching_contract],
    );
}
