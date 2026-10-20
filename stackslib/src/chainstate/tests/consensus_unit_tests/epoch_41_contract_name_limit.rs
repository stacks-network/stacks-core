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

//! Consensus unit tests for the Epoch 4.1 contract-name length limit (see
//! `StacksEpochId::enforces_contract_name_length_limit`).
//!
//! Deployed contracts have always been limited to 40-byte names, but before
//! Epoch 4.1 a contract principal *inside a Clarity value* could carry a name of
//! up to 128 bytes.

use std::collections::HashMap;

use clarity::types::{StacksEpochId, StacksEpochRangeTestExt as _};
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TupleData,
};
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, ConsensusTest, ConsensusUtils, ExpectedResult, TestBlock,
};

/// Epoch in which the contract-name limit activates.
const LIMIT_EPOCH: StacksEpochId = StacksEpochId::Epoch41;

/// Name length used for over-long principals.
const LONG_NAME_LEN: usize = 100;

/// Start of the `principal-destruct?` runtime error for an over-long name.
const CONTRACT_NAME_TYPE_ERROR: &str =
    "TypeValueError(SequenceType(StringType(ASCII(BufferLength(40)))), ";

/// Every Clarity version that has `from-consensus-buff?` and `principal-destruct?`.
fn clarity2_and_later() -> &'static [ClarityVersion] {
    &ClarityVersion::ALL[1..]
}

fn contract_principal(name_len: usize) -> Value {
    Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
        StandardPrincipalData::transient(),
        ContractName::try_from("a".repeat(name_len)).unwrap(),
    )))
}

/// Consensus serialization of [`contract_principal`], as a Clarity buffer literal.
fn serialized_contract_principal(name_len: usize) -> String {
    format!(
        "0x{}",
        contract_principal(name_len).serialize_to_hex().unwrap()
    )
}

/// `from-consensus-buff?` decodes a 100-byte contract name before Epoch 4.1 and
/// returns `none` from 4.1. A 40-byte name decodes in every epoch.
#[test]
fn from_consensus_buff_rejects_long_contract_names_from_epoch41() {
    let contract_code = format!(
        "(define-public (trigger)
            (ok {{
                long: (is-some (from-consensus-buff? principal {long})),
                max: (is-some (from-consensus-buff? principal {max})),
            }}))",
        long = serialized_contract_principal(LONG_NAME_LEN),
        max = serialized_contract_principal(40),
    );
    let report = contract_call_consensus_unit_test!(
        contract_name: "fcb_name_limit",
        contract_code: &contract_code,
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch21],
        call_epochs: (StacksEpochId::Epoch21..).as_slice(),
        clarity_versions: clarity2_and_later(),
    );

    assert!(report.all_blocks_accepted());
    for tx in report.contract_calls() {
        let long_decodes = tx.block_epoch() < &LIMIT_EPOCH;
        let expected = Value::okay(Value::from(
            TupleData::from_data(vec![
                (ClarityName::from_literal("long"), Value::Bool(long_decodes)),
                (ClarityName::from_literal("max"), Value::Bool(true)),
            ])
            .unwrap(),
        ))
        .unwrap();
        assert_eq!(&expected, tx.return_value(), "wrong return for {tx:?}");
    }
}

/// A long-name principal stored before Epoch 4.1 stays readable, but from 4.1
/// `principal-destruct?` refuses to return its name as a `(string-ascii 40)`,
/// failing the transaction instead. A contract deployed at 4.1 cannot store the
/// principal in the first place.
#[test]
fn principal_destruct_rejects_stored_long_name_from_epoch41() {
    let contract_code = format!(
        "(define-data-var legacy (optional principal)
            (from-consensus-buff? principal {long}))
        (define-public (trigger)
            (ok (match (var-get legacy)
                p (some (get name (match (principal-destruct? p) v v v v)))
                none)))",
        long = serialized_contract_principal(LONG_NAME_LEN),
    );
    let report = contract_call_consensus_unit_test!(
        contract_name: "destruct_name_limit",
        contract_code: &contract_code,
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch21, LIMIT_EPOCH],
        call_epochs: (StacksEpochId::Epoch21..).as_slice(),
        clarity_versions: clarity2_and_later(),
    );

    assert!(report.all_blocks_accepted());
    for tx in report.contract_calls() {
        if tx.contract_epoch() >= &LIMIT_EPOCH {
            assert_eq!(
                &Value::okay(Value::none()).unwrap(),
                tx.return_value(),
                "nothing should be stored for {tx:?}"
            );
        } else if tx.block_epoch() < &LIMIT_EPOCH {
            let name =
                Value::string_ascii_from_bytes("a".repeat(LONG_NAME_LEN).into_bytes()).unwrap();
            let expected = Value::okay(Value::some(Value::some(name).unwrap()).unwrap()).unwrap();
            assert_eq!(&expected, tx.return_value(), "wrong return for {tx:?}");
        } else {
            let err = tx
                .vm_error()
                .unwrap_or_else(|| panic!("expected a runtime type error for {tx:?}"));
            assert!(
                err.starts_with(CONTRACT_NAME_TYPE_ERROR),
                "unexpected error for {tx:?}: {err}"
            );
        }
    }
}

/// A contract-call argument carrying a long-name principal is accepted at
/// Epoch 4.0 and makes the block fail static validation from 4.1. A 40-byte
/// name is still accepted at 4.1.
#[test]
fn test_epoch41_rejects_long_contract_name_call_args() {
    let take = |nonce, name_len| TestBlock {
        transactions: vec![ConsensusUtils::new_call_tx_with_args(
            nonce,
            "take",
            "take",
            &[contract_principal(name_len)],
        )],
    };

    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch40,
        vec![
            TestBlock {
                transactions: vec![ConsensusUtils::new_deploy_tx(
                    0,
                    "take",
                    "(define-public (take (p principal)) (ok true))",
                    None,
                )],
            },
            take(1, LONG_NAME_LEN),
        ],
    );
    // Rejected blocks leave the faucet nonce untouched.
    epoch_blocks.insert(LIMIT_EPOCH, vec![take(2, LONG_NAME_LEN), take(2, 40)]);
    let results = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();

    let [deploy, long_at_40, long_at_41, max_at_41] = results.as_slice() else {
        panic!("expected 4 block results, got {results:?}");
    };
    for (result, epoch) in [
        (deploy, StacksEpochId::Epoch40),
        (long_at_40, StacksEpochId::Epoch40),
        (max_at_41, LIMIT_EPOCH),
    ] {
        let ExpectedResult::Success(output) = result else {
            panic!("expected block acceptance at {epoch}, got {result:?}");
        };
        assert_eq!(epoch, output.evaluated_epoch);
        assert!(
            output.transactions[0].vm_error.is_none(),
            "unexpected vm error at {epoch}: {:?}",
            output.transactions[0].vm_error
        );
    }
    let ExpectedResult::Failure(failure) = long_at_41 else {
        panic!("expected block rejection, got {long_at_41:?}");
    };
    assert_eq!(LIMIT_EPOCH, failure.evaluated_epoch);
    assert!(
        failure.error.contains("failed static checks"),
        "unexpected error: {}",
        failure.error
    );
}
