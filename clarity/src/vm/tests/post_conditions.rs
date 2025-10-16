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

//! This module contains unit tests for the `as-contract?` and
//! `restrict-assets?` expressions. The `with-stacking` allowances are tested
//! in integration tests, since they require changes made outside of the VM.

use clarity_types::errors::{Error as ClarityError, InterpreterResult, ShortReturnType};
use clarity_types::types::{
    CharType, PrincipalData, QualifiedContractIdentifier, SequenceData, StandardPrincipalData,
    TypeSignature, UTF8Data,
};
use clarity_types::{ContractName, Value};
use proptest::array::uniform20;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use proptest::string::string_regex;
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::type_checker::v2_1::natives::post_conditions::MAX_ALLOWANCES;
use crate::vm::contexts::AssetMap;
use crate::vm::database::STXBalance;
use crate::vm::{
    execute_call_in_global_context_and_return_asset_map,
    execute_with_parameters_and_call_in_global_context, ClarityVersion,
};

fn execute(snippet: &str) -> InterpreterResult<Option<Value>> {
    execute_with_parameters_and_call_in_global_context(
        snippet,
        ClarityVersion::Clarity4,
        StacksEpochId::Epoch33,
        false,
        |g| {
            // Setup initial balances for the sender and the contract
            let sender_principal = PrincipalData::Standard(StandardPrincipalData::transient());
            let contract_id = QualifiedContractIdentifier::transient();
            let contract_principal = PrincipalData::Contract(contract_id);
            let balance = STXBalance::initial(1000000);
            let mut snapshot = g
                .database
                .get_stx_balance_snapshot_genesis(&sender_principal)
                .unwrap();
            snapshot.set_balance(balance.clone());
            snapshot.save().unwrap();
            let mut snapshot = g
                .database
                .get_stx_balance_snapshot_genesis(&contract_principal)
                .unwrap();
            snapshot.set_balance(balance);
            snapshot.save().unwrap();
            g.database.increment_ustx_liquid_supply(2000000).unwrap();
            Ok(())
        },
    )
}

fn execute_and_return_asset_map(snippet: &str) -> InterpreterResult<(Option<Value>, AssetMap)> {
    execute_and_return_asset_map_versioned(snippet, ClarityVersion::Clarity4)
}

fn execute_and_return_asset_map_versioned(
    snippet: &str,
    version: ClarityVersion,
) -> InterpreterResult<(Option<Value>, AssetMap)> {
    execute_call_in_global_context_and_return_asset_map(
        snippet,
        version,
        StacksEpochId::Epoch33,
        false,
        |g| {
            // Setup initial balances for the sender and the contract
            let sender_principal = PrincipalData::Standard(StandardPrincipalData::transient());
            let contract_id = QualifiedContractIdentifier::transient();
            let contract_principal = PrincipalData::Contract(contract_id);
            let balance = STXBalance::initial(1000000);
            let mut snapshot = g
                .database
                .get_stx_balance_snapshot_genesis(&sender_principal)
                .unwrap();
            snapshot.set_balance(balance.clone());
            snapshot.save().unwrap();
            let mut snapshot = g
                .database
                .get_stx_balance_snapshot_genesis(&contract_principal)
                .unwrap();
            snapshot.set_balance(balance);
            snapshot.save().unwrap();
            g.database.increment_ustx_liquid_supply(2000000).unwrap();
            Ok(())
        },
    )
}

// ---------- Tests for as-contract? ----------

#[test]
fn test_as_contract_with_stx_ok() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u100))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_exceeds() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u10))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_no_allowance() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ()
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_all() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-all-assets-unsafe))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_other_allowances() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" (list 123)))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_burn_ok() {
    let snippet = r#"
(as-contract? ((with-stx u100))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_burn_exceeds() {
    let snippet = r#"
(as-contract? ((with-stx u10))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_burn_no_allowance() {
    let snippet = r#"
(as-contract? ()
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_burn_all() {
    let snippet = r#"
(as-contract? ((with-all-assets-unsafe))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_burn_other_allowances() {
    let snippet = r#"
(as-contract? ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" (list 123)))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_multiple_allowances_both_low() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u30) (with-stx u20))
    (try! (stx-transfer? u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_multiple_allowances_both_ok() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u300) (with-stx u200))
    (try! (stx-transfer? u40 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_multiple_allowances_one_low() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u100) (with-stx u20))
    (try! (stx-transfer? u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "stackaroo" u100))
    (try! (ft-transfer? stackaroo u100 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_exceeds() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "stackaroo" u10))
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_no_allowance() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ()
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_all() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-all-assets-unsafe))
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_other_allowances() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract?
    (
      (with-stx u200)
      (with-ft .other "stackaroo" u100) ;; other contract, same token name
      (with-ft current-contract "other" u100) ;; same contract, different token name
      (with-nft .token "stackaroo" (list 123))
    )
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_multiple_allowances_both_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "stackaroo" u30) (with-ft current-contract "stackaroo" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_multiple_allowances_both_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "stackaroo" u300) (with-ft current-contract "stackaroo" u200))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_multiple_allowances_one_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "stackaroo" u100) (with-ft current-contract "stackaroo" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "*" u100))
    (try! (ft-transfer? stackaroo u100 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_exceeds() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "*" u10))
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_other_allowances() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract?
    (
      (with-stx u200)
      (with-ft .other "*" u100) ;; other contract, same token name
      (with-ft current-contract "other" u100) ;; same contract, different token name
      (with-nft .token "*" (list 123))
    )
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_multiple_allowances_both_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "*" u30) (with-ft current-contract "*" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_multiple_allowances_both_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "*" u300) (with-ft current-contract "*" u200))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_multiple_allowances_one_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "*" u100) (with-ft current-contract "*" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_multiple_allowances_low1() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "*" u20) (with-ft current-contract "stackaroo" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_ft_wildcard_multiple_allowances_low2() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-ft current-contract "stackaroo" u20) (with-ft current-contract "*" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_ok() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_not_allowed() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list u122)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_no_allowance() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ()
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_all() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-all-assets-unsafe))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_other_allowances() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract?
    (
      (with-stx u123)
      (with-nft .other "stackaroo" (list u123)) ;; other contract, same token name
      (with-nft current-contract "other" (list u123)) ;; same contract, different token name
      (with-ft .token "stackaroo" u123)
    )
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_multiple_allowances_both_different() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list u122)) (with-nft current-contract "stackaroo" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_multiple_allowances_including() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list u122)) (with-nft current-contract "stackaroo" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_multiple_allowances_in_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list u122 u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_empty_id_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wrong_type() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list 123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_ok() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "*" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_not_allowed() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "*" (list u122)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_other_allowances() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract?
    (
      (with-stx u123)
      (with-nft .other "*" (list u123)) ;; other contract, same token name
      (with-nft current-contract "other" (list u123)) ;; same contract, different token name
      (with-ft .token "*" u123)
    )
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_multiple_allowances_both_different() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "*" (list u122)) (with-nft current-contract "*" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_multiple_allowances_including() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "*" (list u122)) (with-nft current-contract "*" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_multiple_allowances_in_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "*" (list u122 u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_empty_id_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "*" (list)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_multiple_allowances_order1() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "*" (list u122)) (with-nft current-contract "stackaroo" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_nft_wildcard_multiple_allowances_order2() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 current-contract)
(nft-mint? stackaroo u123 current-contract)
(let ((recipient tx-sender))
  (as-contract? ((with-nft current-contract "stackaroo" (list u122)) (with-nft current-contract "*" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_error_in_body() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ()
    (try! (if false (ok true) (err u200)))
    true
  )
)"#;
    let expected_err = Value::error(Value::UInt(200)).unwrap();
    let short_return =
        ClarityError::ShortReturn(ShortReturnType::ExpectedValue(expected_err.into()));
    assert_eq!(short_return, execute(snippet).unwrap_err());
}

// ---------- Tests for restrict-assets? ----------

#[test]
fn test_restrict_assets_with_stx_ok() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u100))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_exceeds() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u10))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_no_allowance() {
    let snippet = r#"
(restrict-assets? tx-sender ()
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_all() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-all-assets-unsafe))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_other_allowances() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" (list 123)))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_burn_ok() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u100))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_burn_exceeds() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u10))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_burn_no_allowance() {
    let snippet = r#"
(restrict-assets? tx-sender ()
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_burn_all() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-all-assets-unsafe))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_burn_other_allowances() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" (list 123)))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_multiple_allowances_both_low() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u30) (with-stx u20))
  (try! (stx-transfer? u40 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_multiple_allowances_both_ok() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u300) (with-stx u200))
  (try! (stx-transfer? u40 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_multiple_allowances_one_low() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u100) (with-stx u20))
  (try! (stx-transfer? u40 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::UInt(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "stackaroo" u100))
    (try! (ft-transfer? stackaroo u100 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_exceeds() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "stackaroo" u10))
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_no_allowance() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ()
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_all() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-all-assets-unsafe))
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_other_allowances() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender
    (
      (with-stx u200)
      (with-ft .other "stackaroo" u100) ;; other contract, same token name
      (with-ft current-contract "other" u100) ;; same contract, different token name
      (with-nft .token "stackaroo" (list 123))
    )
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_multiple_allowances_both_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "stackaroo" u30) (with-ft current-contract "stackaroo" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_multiple_allowances_both_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "stackaroo" u300) (with-ft current-contract "stackaroo" u200))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_multiple_allowances_one_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "stackaroo" u100) (with-ft current-contract "stackaroo" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "*" u100))
    (try! (ft-transfer? stackaroo u100 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_exceeds() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "*" u10))
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_other_allowances() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender
    (
      (with-stx u200)
      (with-ft .other "*" u100) ;; other contract, same token name
      (with-ft current-contract "other" u100) ;; same contract, different token name
      (with-nft .token "*" (list 123))
    )
    (try! (ft-transfer? stackaroo u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_multiple_allowances_both_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "*" u30) (with-ft current-contract "*" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_multiple_allowances_both_ok() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "*" u300) (with-ft current-contract "*" u200))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_multiple_allowances_one_low() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "*" u100) (with-ft current-contract "*" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_multiple_allowances_low1() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "*" u20) (with-ft current-contract "stackaroo" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_ft_wildcard_multiple_allowances_low2() {
    let snippet = r#"
(define-fungible-token stackaroo)
(ft-mint? stackaroo u200 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-ft current-contract "stackaroo" u20) (with-ft current-contract "*" u20))
    (try! (ft-transfer? stackaroo u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_ok() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_not_allowed() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list u122)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_no_allowance() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ()
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_all() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-all-assets-unsafe))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_other_allowances() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender
    (
      (with-stx u123)
      (with-nft .other "stackaroo" (list u123)) ;; other contract, same token name
      (with-nft current-contract "other" (list u123)) ;; same contract, different token name
      (with-ft .token "stackaroo" u123)
    )
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_multiple_allowances_both_different() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list u122)) (with-nft current-contract "stackaroo" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_multiple_allowances_including() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list u122)) (with-nft current-contract "stackaroo" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_multiple_allowances_in_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list u122 u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_empty_id_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_ok() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "*" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_not_allowed() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "*" (list u122)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_other_allowances() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender
    (
      (with-stx u123)
      (with-nft .other "*" (list u123)) ;; other contract, same token name
      (with-nft current-contract "other" (list u123)) ;; same contract, different token name
      (with-ft .token "*" u123)
    )
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(MAX_ALLOWANCES as u128)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_multiple_allowances_both_different() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "*" (list u122)) (with-nft current-contract "*" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_multiple_allowances_including() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "*" (list u122)) (with-nft current-contract "*" (list u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_multiple_allowances_in_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "*" (list u122 u123)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_empty_id_list() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "*" (list)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_multiple_allowances_order1() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "*" (list u122)) (with-nft current-contract "stackaroo" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_nft_wildcard_multiple_allowances_order2() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list u122)) (with-nft current-contract "*" (list u124)))
    (try! (nft-transfer? stackaroo u123 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_error_in_body() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ()
    (try! (if false (ok true) (err u200)))
    true
  )
)"#;
    let expected_err = Value::error(Value::UInt(200)).unwrap();
    let short_return =
        ClarityError::ShortReturn(ShortReturnType::ExpectedValue(expected_err.into()));
    assert_eq!(short_return, execute(snippet).unwrap_err());
}

// ---------- Property Tests ----------

/// Builds a strategy that produces arbitrary Clarity values.
fn clarity_values_inner(include_responses: bool) -> BoxedStrategy<Value> {
    let ascii_strings = string_regex("[A-Za-z0-9 \\-_=+*/?!]{0,1024}")
        .unwrap()
        .prop_map(|s| {
            Value::string_ascii_from_bytes(s.into_bytes())
                .expect("ASCII literal within allowed character set")
        });

    let utf8_strings =
        string_regex(r#"[\u{00A1}-\u{024F}\u{0370}-\u{03FF}\u{1F300}-\u{1F64F}]{0,1024}"#)
            .unwrap()
            .prop_map(|s| {
                Value::string_utf8_from_bytes(s.into_bytes())
                    .expect("UTF-8 literal within allowed character set")
            });

    let standard_principal_data = (any::<u8>(), uniform20(any::<u8>()))
        .prop_filter_map("Invalid standard principal", |(version, bytes)| {
            let version = version % 32;
            StandardPrincipalData::new(version, bytes).ok()
        })
        .boxed();

    let standard_principals = standard_principal_data
        .clone()
        .prop_map(|principal| Value::Principal(PrincipalData::Standard(principal)))
        .boxed();

    let contract_name_strings = prop_oneof![
        string_regex("[a-tv-z][a-z0-9-?!]{0,39}").unwrap(),
        string_regex("u[a-z-?!][a-z0-9-?!]{0,38}").unwrap(),
    ]
    .boxed();

    let contract_names = contract_name_strings
        .prop_filter_map("Invalid contract name", |name| {
            ContractName::try_from(name).ok()
        })
        .boxed();

    let contract_principals = (standard_principal_data, contract_names)
        .prop_map(|(issuer, name)| {
            Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
                issuer, name,
            )))
        })
        .boxed();

    let principal_values = prop_oneof![standard_principals, contract_principals];

    let buffer_values = vec(any::<u8>(), 0..1024).prop_map(|bytes| {
        Value::buff_from(bytes).expect("Buffer construction should succeed with any byte data")
    });

    let base_values = prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|v| Value::Int(v as i128)),
        any::<u64>().prop_map(|v| Value::UInt(v as u128)),
        ascii_strings,
        utf8_strings,
        Just(Value::none()),
        principal_values,
        buffer_values,
    ];

    base_values
        .prop_recursive(
            3,  // max nesting depth
            64, // total size budget (unused but required)
            6,  // branching factor
            move |inner| {
                let option_values = inner
                    .clone()
                    .prop_filter_map("Option construction failed", |v| Value::some(v).ok())
                    .boxed();

                let inner_for_lists = inner.clone();
                let lists_from_inner = inner
                    .clone()
                    .prop_flat_map(move |prototype| {
                        let sig = TypeSignature::type_of(&prototype)
                            .expect("Values generated by strategy should have a type signature");
                        let sig_for_filter = sig.clone();
                        let prototype_for_elements = prototype.clone();
                        let element_strategy = inner_for_lists.clone().prop_map(move |candidate| {
                            if TypeSignature::type_of(&candidate)
                                .ok()
                                .is_some_and(|t| t == sig_for_filter)
                            {
                                candidate
                            } else {
                                prototype_for_elements.clone()
                            }
                        });
                        let prototype_for_list = prototype.clone();
                        vec(element_strategy, 0..3).prop_map(move |rest| {
                            let mut values = Vec::with_capacity(rest.len() + 1);
                            values.push(prototype_for_list.clone());
                            values.extend(rest);
                            Value::list_from(values)
                                .expect("List construction should succeed with homogeneous values")
                        })
                    })
                    .boxed();

                let bool_lists = vec(any::<bool>().prop_map(Value::Bool), 1..4)
                    .prop_filter_map("List<bool> construction failed", |values| {
                        Value::list_from(values).ok()
                    })
                    .boxed();

                let uint_lists = vec(any::<u64>().prop_map(|v| Value::UInt(v as u128)), 1..4)
                    .prop_filter_map("List<uint> construction failed", |values| {
                        Value::list_from(values).ok()
                    })
                    .boxed();

                if include_responses {
                    let ok_responses = inner
                        .clone()
                        .prop_filter_map("Response(ok) construction failed", |v| {
                            Value::okay(v).ok()
                        })
                        .boxed();

                    let err_responses = inner
                        .clone()
                        .prop_filter_map("Response(err) construction failed", |v| {
                            Value::error(v).ok()
                        })
                        .boxed();

                    prop_oneof![
                        option_values,
                        ok_responses,
                        err_responses,
                        lists_from_inner,
                        bool_lists,
                        uint_lists,
                    ]
                    .boxed()
                } else {
                    prop_oneof![option_values, lists_from_inner, bool_lists, uint_lists,].boxed()
                }
            },
        )
        .boxed()
}

/// Generates Clarity values, including response values.
fn clarity_values() -> impl Strategy<Value = Value> {
    clarity_values_inner(true)
}

/// Generates Clarity values but excludes responses.
fn clarity_values_no_response() -> impl Strategy<Value = Value> {
    clarity_values_inner(false)
}

/// Generates STX transfer expressions with random amounts.
fn stx_transfer_expressions() -> impl Strategy<Value = String> {
    (1u64..1_000_000u64).prop_map(|amount| {
        format!("(try! (stx-transfer? u{amount} tx-sender 'SP000000000000000000002Q6VF78))")
    })
}

/// Generates a `begin` block with a random number of random expressions.
fn begin_block() -> impl Strategy<Value = String> {
    vec(
        prop_oneof![
            clarity_values_no_response().prop_map(|value| value_to_string(&value)),
            stx_transfer_expressions(),
        ],
        1..8,
    )
    .prop_shuffle()
    .prop_map(|expressions| {
        let body = expressions.join(" ");
        format!("(begin {body})")
    })
}

/// Produces a Clarity string literal for the given UTF-8 data.
fn utf8_string_literal(data: &UTF8Data) -> String {
    let mut literal = String::from("u\"");
    for bytes in &data.data {
        if bytes.len() == 1 {
            for escaped in std::ascii::escape_default(bytes[0]) {
                literal.push(escaped as char);
            }
        } else {
            let ch = std::str::from_utf8(bytes)
                .expect("UTF-8 data should decode to a scalar value")
                .chars()
                .next()
                .expect("UTF-8 data should contain at least one scalar");
            literal.push_str(&format!("\\u{{{:X}}}", ch as u32));
        }
    }
    literal.push('"');
    literal
}

/// Converts a Clarity `Value` into its Clarity literal representation.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::Sequence(SequenceData::List(list_data)) => {
            let items: Vec<_> = list_data.data.iter().map(value_to_string).collect();
            if items.is_empty() {
                "(list)".to_string()
            } else {
                format!("(list {})", items.join(" "))
            }
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(data))) => format!("{data}"),
        Value::Sequence(SequenceData::String(CharType::UTF8(data))) => utf8_string_literal(data),
        Value::Optional(optional) => match optional.data.as_deref() {
            Some(inner) => format!("(some {})", value_to_string(inner)),
            None => "none".to_string(),
        },
        Value::Response(response) => {
            let inner = value_to_string(response.data.as_ref());
            if response.committed {
                format!("(ok {})", inner)
            } else {
                format!("(err {})", inner)
            }
        }
        Value::Principal(principal) => format!("'{}", principal),
        Value::Tuple(tuple) => {
            let mut literal = String::from("(tuple");
            for (name, field) in tuple.data_map.iter() {
                literal.push(' ');
                literal.push('(');
                literal.push_str(&name.to_string());
                literal.push(' ');
                literal.push_str(&value_to_string(field));
                literal.push(')');
            }
            literal.push(')');
            literal
        }
        _ => format!("{value}"),
    }
}

proptest! {
    /// Property: restrict-assets? should return `(ok <value>)` where `<value>` is the
    /// result of evaluating the body if no assets are moved in the body.
    #[test]
    fn prop_restrict_assets_returns_body_value_when_pure(body_value in clarity_values_no_response()) {
      let body_literal = value_to_string(&body_value);
      let snippet = format!("(restrict-assets? tx-sender () {body_literal})");

      let evaluation = execute(&snippet)
        .unwrap_or_else(|e| panic!("Execution failed for snippet `{snippet}`: {e:?}"))
        .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

      let expected = Value::okay(body_value.clone())
        .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

      prop_assert!(evaluation == expected);
    }

    /// Property: restrict-assets? should return an error if there are no
    /// allowances and the body moves assets
    #[test]
    fn prop_restrict_assets_errors_when_no_allowances_and_body_moves_assets(body in begin_block()) {
      let snippet = format!("(restrict-assets? tx-sender () {body})");

      let body_execution = execute_and_return_asset_map(&body);
      let snippet_execution = execute_and_return_asset_map(&snippet);

      match (body_execution, snippet_execution) {
        (Err(body_err), snippet_outcome) => {
          match snippet_outcome {
            Err(snippet_err) => {
              prop_assert_eq!(snippet_err, body_err);
            }
            Ok((Some(result_value), _)) => {
              if let ClarityError::ShortReturn(ShortReturnType::ExpectedValue(expected)) = &body_err {
                prop_assert_eq!(result_value, *expected.clone());
              } else {
                panic!("Body `{body}` failed with {body_err:?} but snippet `{snippet}` returned value {result_value:?}");
              }
            }
            Ok((None, _)) => {
              panic!("Snippet `{snippet}` returned no value while body `{body}` failed with {body_err:?}");
            }
          }
        }
        (Ok(_), Err(snippet_err)) => {
          panic!("Body `{body}` succeeded but snippet `{snippet}` failed with {snippet_err:?}");
        }
        (Ok((body_result, unrestricted_asset_map)), Ok((result, asset_map))) => {
          let body_value = body_result
            .unwrap_or_else(|| panic!("Execution returned no value for body `{body}`"));
          let result_value = result
            .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

          // If the body moves any STX from the sender, the restricted version should error
          let sender = PrincipalData::Standard(StandardPrincipalData::transient());
          if let Some(stx_moved) = unrestricted_asset_map.get_stx(&sender) {
            let expected_err = Value::error(Value::UInt(MAX_ALLOWANCES as u128))
              .unwrap_or_else(|e| panic!("Wrapping expected error failed for snippet `{snippet}`: {e:?}"));

            prop_assert_eq!(result_value, expected_err);

            // And the asset map should show that no STX was moved
            let stx_moved_in_restricted = asset_map.get_stx(&sender).unwrap_or(0);
            prop_assert_eq!(stx_moved_in_restricted, 0);
          } else {
            // If the body doesn't move any STX, the restricted version should return the same value as the body
            let expected = Value::okay(body_value.clone())
              .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

            prop_assert_eq!(result_value, expected);

            // And the asset maps should be identical
            prop_assert_eq!(asset_map, unrestricted_asset_map);
          }
        }
      }
    }

    /// Property: as-contract? should return `(ok <value>)` where `<value>` is the
    /// result of evaluating the body if no assets are moved in the body.
    #[test]
    fn prop_as_contract_returns_body_value_when_pure(body_value in clarity_values_no_response()) {
      let body_literal = value_to_string(&body_value);
      let snippet = format!("(as-contract? () {body_literal})");

      let evaluation = execute(&snippet)
        .unwrap_or_else(|e| panic!("Execution failed for snippet `{snippet}`: {e:?}"))
        .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

      let expected = Value::okay(body_value.clone())
        .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

      prop_assert!(evaluation == expected);
    }

    /// Property: as-contract? should return an error if there are no
    /// allowances and the body moves assets
    #[test]
    fn prop_as_contract_errors_when_no_allowances_and_body_moves_assets(body in begin_block()) {
      let snippet = format!("(as-contract? () {body})");
      let c3_snippet = format!("(as-contract {body})");

      let body_execution = execute_and_return_asset_map_versioned(&c3_snippet, ClarityVersion::Clarity3);
      let snippet_execution = execute_and_return_asset_map(&snippet);

      match (body_execution, snippet_execution) {
        (Err(body_err), snippet_outcome) => {
          match snippet_outcome {
            Err(snippet_err) => {
              prop_assert_eq!(snippet_err, body_err);
            }
            Ok((Some(result_value), _)) => {
              if let ClarityError::ShortReturn(ShortReturnType::ExpectedValue(expected)) = &body_err {
                prop_assert_eq!(result_value, *expected.clone());
              } else {
                panic!("Body `{body}` failed with {body_err:?} but snippet `{snippet}` returned value {result_value:?}");
              }
            }
            Ok((None, _)) => {
              panic!("Snippet `{snippet}` returned no value while body `{body}` failed with {body_err:?}");
            }
          }
        }
        (Ok(_), Err(snippet_err)) => {
          panic!("Body `{body}` succeeded but snippet `{snippet}` failed with {snippet_err:?}");
        }
        (Ok((body_result, unrestricted_asset_map)), Ok((result, asset_map))) => {
          let body_value = body_result
            .unwrap_or_else(|| panic!("Execution returned no value for body `{body}`"));
          let result_value = result
            .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

          // If the body moves any STX from the contract, the restricted version should error
          let contract_id = QualifiedContractIdentifier::transient();
          let contract_principal = PrincipalData::Contract(contract_id);
          if let Some(stx_moved) = unrestricted_asset_map.get_stx(&contract_principal) {
            let expected_err = Value::error(Value::UInt(MAX_ALLOWANCES as u128))
              .unwrap_or_else(|e| panic!("Wrapping expected error failed for snippet `{snippet}`: {e:?}"));

            prop_assert_eq!(result_value, expected_err);

            // And the asset map should show that no STX was moved
            let stx_moved_in_restricted = asset_map.get_stx(&contract_principal).unwrap_or(0);
            prop_assert_eq!(stx_moved_in_restricted, 0);
          } else {
            // If the body doesn't move any STX, the restricted version should return the same value as the body
            let expected = Value::okay(body_value.clone())
              .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

            prop_assert_eq!(result_value, expected);

            // And the asset maps should be identical
            prop_assert_eq!(asset_map, unrestricted_asset_map);
          }
        }
      }
    }

    /// Property: as-contract? with `with-all-assets-unsafe` should always return the
    /// same as the Clarity3 `as-contract`.
    #[test]
    fn prop_as_contract_with_all_assets_unsafe_matches_clarity3(body in begin_block()) {
      let snippet = format!("(as-contract? ((with-all-assets-unsafe)) {body})");
      let c3_snippet = format!("(as-contract {body})");

      let c3_execution = execute_and_return_asset_map_versioned(&c3_snippet, ClarityVersion::Clarity3);
      let snippet_execution = execute_and_return_asset_map(&snippet);

      match (c3_execution, snippet_execution) {
        (Err(body_err), snippet_outcome) => {
          match snippet_outcome {
            Err(snippet_err) => {
              prop_assert_eq!(snippet_err, body_err);
            }
            Ok((Some(result_value), _)) => {
              if let ClarityError::ShortReturn(ShortReturnType::ExpectedValue(expected)) = &body_err {
                prop_assert_eq!(result_value, *expected.clone());
              } else {
                panic!("Body `{body}` failed with {body_err:?} but snippet `{snippet}` returned value {result_value:?}");
              }
            }
            Ok((None, _)) => {
              panic!("Snippet `{snippet}` returned no value while body `{body}` failed with {body_err:?}");
            }
          }
        }
        (Ok(_), Err(snippet_err)) => {
          panic!("Body `{body}` succeeded but snippet `{snippet}` failed with {snippet_err:?}");
        }
        (Ok((body_result, unrestricted_asset_map)), Ok((result, asset_map))) => {
          let body_value = body_result
            .unwrap_or_else(|| panic!("Execution returned no value for body `{body}`"));
          let result_value = result
            .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

          let expected = Value::okay(body_value.clone())
            .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

          prop_assert_eq!(result_value, expected);

          // And the asset maps should be identical
          prop_assert_eq!(asset_map, unrestricted_asset_map);
        }
      }
    }
}
