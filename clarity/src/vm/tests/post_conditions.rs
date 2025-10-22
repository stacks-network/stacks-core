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

use clarity_types::errors::{EarlyReturnError, InterpreterResult, VmExecutionError};
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity_types::Value;
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::type_checker::v2_1::natives::post_conditions::MAX_ALLOWANCES;
use crate::vm::database::STXBalance;
use crate::vm::{execute_with_parameters_and_call_in_global_context, ClarityVersion};

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
            let balance = STXBalance::initial(1000);
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
            g.database.increment_ustx_liquid_supply(2000).unwrap();
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
        VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(expected_err.into()));
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
        VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(expected_err.into()));
    assert_eq!(short_return, execute(snippet).unwrap_err());
}
