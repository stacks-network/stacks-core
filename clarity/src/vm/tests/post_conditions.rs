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

use std::convert::TryFrom;

use clarity_types::errors::{EarlyReturnError, RuntimeAnalysisError, VmExecutionError};
use clarity_types::types::{
    AssetIdentifier, PrincipalData, QualifiedContractIdentifier, StandardPrincipalData,
};
use clarity_types::{ClarityName, Value};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestCaseResult};

use crate::vm::analysis::type_checker::v2_1::natives::post_conditions::MAX_ALLOWANCES;
use crate::vm::contexts::AssetMap;
use crate::vm::tests::proptest_utils::{
    allowance_list_snippets, begin_block, body_with_allowances_snippets,
    clarity_values_no_response, execute, execute_and_check, execute_and_check_versioned,
    ft_mint_snippets, ft_transfer_snippets, match_response_snippets, nft_mint_snippets,
    nft_transfer_snippets, standard_principal_strategy, try_response_snippets,
    value_to_clarity_literal,
};
use crate::vm::ClarityVersion;

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

/// Test that when an error occurs in the body of an `as-contract?` call, the
/// post-condition check still checks the allowances.
#[test]
fn test_as_contract_bad_transfer_with_short_return_in_body() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (as-contract? ((with-stx u100))
    (try! (stx-transfer? u150 tx-sender recipient))
    (try! (if false (ok true) (err u200)))
    true
  )
)"#;
    let sender = StandardPrincipalData::transient();
    let contract_id = QualifiedContractIdentifier::new(sender.clone(), "contract".into());
    let contract = PrincipalData::Contract(contract_id);
    let expected = Value::error(Value::UInt(0)).unwrap();
    let opt_value = execute_and_check(snippet, sender.clone(), |g| {
        let assets = g.get_readonly_asset_map().expect("failed to get asset map");
        let stx_moved = assets.get_stx(&contract);
        assert!(stx_moved.is_none(), "STX should not have moved");
        Ok(())
    })
    .expect("execution failed");
    assert_eq!(expected, opt_value.expect("no value returned"));
}

/// Test that when an error occurs in the body of an `as-contract?` call, the
/// error is passed up if no allowances are violated.
#[test]
fn test_as_contract_good_transfer_with_short_return_in_body() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (as-contract? ((with-stx u100))
    (try! (stx-transfer? u50 tx-sender recipient))
    (try! (if false (ok true) (err u200)))
    true
  )
)"#;
    let sender = StandardPrincipalData::transient();
    let expected_err = Value::error(Value::UInt(200)).unwrap();
    let short_return =
        VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(expected_err.into()));
    let res = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(short_return, res);
}

/// Test that when a short-return of an ok value occurs in the body of an
/// `as-contract?` call, the post-condition check still checks the allowances
/// and returns an error if violated.
#[test]
fn test_as_contract_bad_transfer_with_early_return_ok_in_body() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (as-contract? ((with-stx u100))
    (try! (stx-transfer? u150 tx-sender recipient))
    (asserts! false (ok false))
    true
  )
)"#;
    let sender = StandardPrincipalData::transient();
    let contract_id = QualifiedContractIdentifier::new(sender.clone(), "contract".into());
    let contract = PrincipalData::Contract(contract_id);
    let expected = Value::error(Value::UInt(0)).unwrap();
    let opt_value = execute_and_check(snippet, sender.clone(), |g| {
        let assets = g.get_readonly_asset_map().expect("failed to get asset map");
        let stx_moved = assets.get_stx(&contract);
        assert!(stx_moved.is_none(), "STX should not have moved");
        Ok(())
    })
    .expect("execution failed");
    assert_eq!(expected, opt_value.expect("no value returned"));
}

/// Test that when a short-return of an ok value occurs in the body of an
/// `as-contract?` call, the ok value is returned.
#[test]
fn test_as_contract_good_transfer_with_early_return_ok_in_body() {
    let snippet = r#"
(as-contract? ((with-stx u100))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
  (asserts! false (ok false))
  true
)"#;
    let expected_err = Value::okay(Value::Bool(false)).unwrap();
    let short_return =
        VmExecutionError::EarlyReturn(EarlyReturnError::AssertionFailed(expected_err.into()));
    let err = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(short_return, err);
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

#[test]
fn test_restrict_assets_with_receiving_principal() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? 'SP000000000000000000002Q6VF78 ()
    (try! (stx-transfer? u10 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_other_principal() {
    let snippet = r#"
(let ((recipient 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5))
  (restrict-assets? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM ()
    (try! (stx-transfer? u10 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_nested_outer_restrict_assets_with_stx_exceeds() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u10))
  (try! (restrict-assets? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM ()
    (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
  ))
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_multiple_violations_different_kinds() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-nft current-contract "stackaroo" (list u122)) (with-stx u10))
    (begin
      (try! (stx-transfer? u50 tx-sender recipient))
      (try! (nft-transfer? stackaroo u123 tx-sender recipient))
    )
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_multiple_violations_different_kinds_order_2() {
    let snippet = r#"
(define-non-fungible-token stackaroo uint)
(nft-mint? stackaroo u122 tx-sender)
(nft-mint? stackaroo u123 tx-sender)
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-stx u10) (with-nft current-contract "stackaroo" (list u122)))
    (begin
      (try! (nft-transfer? stackaroo u123 tx-sender recipient))
      (try! (stx-transfer? u50 tx-sender recipient))
    )
  )
)"#;
    let expected = Value::error(Value::UInt(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_nested_inner_restrict_assets_with_stx_exceeds() {
    let snippet = r#"
(restrict-assets? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM ()
  (try! (restrict-assets? tx-sender ((with-stx u10))
    (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
  ))
)"#;
    let expected_err = Value::error(Value::UInt(0)).unwrap();
    let short_return =
        VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(expected_err.into()));
    assert_eq!(short_return, execute(snippet).unwrap_err());
}

/// Test that when an error occurs in the body of a restrict-assets? call, the
/// post-condition check still checks the allowances.
#[test]
fn test_restrict_assets_bad_transfer_with_short_return_in_body() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-stx u100))
    (try! (stx-transfer? u150 tx-sender recipient))
    (try! (if false (ok true) (err u200)))
    true
  )
)"#;
    let sender = StandardPrincipalData::transient();
    let expected = Value::error(Value::UInt(0)).unwrap();
    let opt_value = execute_and_check(snippet, sender.clone(), |g| {
        let assets = g.get_readonly_asset_map().expect("failed to get asset map");
        let stx_moved = assets.get_stx(&sender.clone().into());
        assert!(stx_moved.is_none(), "STX should not have moved");
        Ok(())
    })
    .expect("execution failed");
    assert_eq!(expected, opt_value.expect("no value returned"));
}

/// Test that when an error occurs in the body of a restrict-assets? call, the
/// error is passed up if no allowances are violated.
#[test]
fn test_restrict_assets_good_transfer_with_short_return_in_body() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-stx u100))
    (try! (stx-transfer? u50 tx-sender recipient))
    (try! (if false (ok true) (err u200)))
    true
  )
)"#;
    let sender = StandardPrincipalData::transient();
    let expected_err = Value::error(Value::UInt(200)).unwrap();
    let short_return =
        VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(expected_err.into()));
    let res = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(short_return, res);
}

/// Test that when a short-return of an ok value occurs in the body of a
/// restrict-assets? call, the post-condition check still checks the allowances
/// and returns an error if violated.
#[test]
fn test_restrict_assets_bad_transfer_with_short_return_ok_in_body() {
    let snippet = r#"
(let ((recipient 'SP000000000000000000002Q6VF78))
  (restrict-assets? tx-sender ((with-stx u100))
    (try! (stx-transfer? u150 tx-sender recipient))
    (asserts! false (ok false))
    true
  )
)"#;
    let sender = StandardPrincipalData::transient();
    let expected = Value::error(Value::UInt(0)).unwrap();
    let opt_value = execute_and_check(snippet, sender.clone(), |g| {
        let assets = g.get_readonly_asset_map().expect("failed to get asset map");
        let stx_moved = assets.get_stx(&sender.clone().into());
        assert!(stx_moved.is_none(), "STX should not have moved");
        Ok(())
    })
    .expect("execution failed");
    assert_eq!(expected, opt_value.expect("no value returned"));
}

/// Test that when a short-return of an ok value occurs in the body of a
/// restrict-assets? call, the ok value is returned.
#[test]
fn test_restrict_assets_good_transfer_with_short_return_ok_in_body() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u100))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
  (asserts! false (ok false))
  true
)"#;
    let expected_err = Value::okay(Value::Bool(false)).unwrap();
    let short_return =
        VmExecutionError::EarlyReturn(EarlyReturnError::AssertionFailed(expected_err.into()));
    let err = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(short_return, err);
}

/// Test that when a too many allowances are passed to restrict-assets? call, the post-condition
/// check returns an error if it exceeds MAX_ALLOWANCES. Note that this is not reachable during
/// normal clarity execution. Static checks would trigger first.
#[test]
fn restrict_assets_too_many_allowances() {
    let snippet = format!(
        "(restrict-assets? tx-sender ({} ) true)",
        std::iter::repeat_n("(with-stx u1)", MAX_ALLOWANCES + 1)
            .collect::<Vec<_>>()
            .join(" ")
    );
    let max_allowances_err = VmExecutionError::Unchecked(RuntimeAnalysisError::TooManyAllowances(
        MAX_ALLOWANCES,
        MAX_ALLOWANCES + 1,
    ));
    let err = execute(&snippet).expect_err("execution passed unexpectedly");
    assert_eq!(err, max_allowances_err);
}

/// Test that passing a non-allowance expression to `restrict-assets?` triggers
/// the `ExpectedAllowanceExpr` runtime error. Normally, static analysis would prevent
/// invalid expressions, so this only occurs in artificial or host-level test scenarios.
#[test]
fn expected_allowance_expr_error() {
    // Construct a "fake" allowance expression that is invalid
    let snippet = "(restrict-assets? tx-sender ((bad-fn u1)) true)";

    let expected_error = VmExecutionError::Unchecked(RuntimeAnalysisError::ExpectedAllowanceExpr(
        "bad-fn".to_string(),
    ));

    // Execute and verify that the error is raised
    let err = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(err, expected_error);
}

/// Test that passing an invalid native function to `restrict-assets?` triggers
/// the `ExpectedAllowanceExpr` runtime error. Normally, static analysis would prevent
/// invalid expressions, so this only occurs in artificial or host-level test scenarios.
#[test]
fn expected_allowance_expr_error_unhandled_native() {
    // Use a native function that exists but is not handled in eval_allowance
    // For example: `tx-sender` (or `caller`), which is a native function but not a handled allowance
    let snippet = "(restrict-assets? tx-sender ((tx-sender u1)) true)";

    let expected_error = VmExecutionError::Unchecked(RuntimeAnalysisError::ExpectedAllowanceExpr(
        "tx-sender".to_string(),
    ));

    let err = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(err, expected_error);
}

/// Directly call an allowance function outside of restrict-assets? or as-contract?
/// This forces the VM to route evaluation through special_allowance(),
/// which always returns AllowanceExprNotAllowed.
#[test]
fn allowance_expr_not_allowed() {
    let snippet = "(with-stx u1)";

    let expected = VmExecutionError::Unchecked(RuntimeAnalysisError::AllowanceExprNotAllowed);

    let err = execute(snippet).expect_err("execution unexpectedly succeeded");

    assert_eq!(err, expected);
}

/// Test that passing an invalid second argument to `restrict-assets?` triggers
/// the `ExpectedListOfAllowances` runtime error. Normally, static analysis would prevent
/// invalid expressions, so this only occurs in artificial or host-level test scenarios.
#[test]
fn restrict_assets_expected_list_of_allowances() {
    let snippet = r#"
        (restrict-assets? tx-sender
            42
            (ok u1)
        )
    "#;

    let expected_error = VmExecutionError::Unchecked(
        RuntimeAnalysisError::ExpectedListOfAllowances("restrict-assets?".into(), 2),
    );

    let err = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(err, expected_error);
}

/// Test that passing an invalid argument to `as-contract?` triggers
/// the `ExpectedListOfAllowances` runtime error. Normally, static analysis would prevent
/// invalid expressions, so this only occurs in artificial or host-level test scenarios.
#[test]
fn as_contract_expected_list_of_allowances() {
    // Construct a as-contract? call where the argument is NOT a list
    let snippet = r#"
        (as-contract? u42
            (ok u1)
        )
    "#;

    // The argument is `u42` (not a list), so we expect this error
    let expected_error = VmExecutionError::Unchecked(
        RuntimeAnalysisError::ExpectedListOfAllowances("as-contract?".to_string(), 1),
    );

    let err = execute(snippet).expect_err("execution passed unexpectedly");
    assert_eq!(err, expected_error);
}

// ---------- Property Tests ----------

fn execute_with_assets_for_version(
    program: &str,
    version: ClarityVersion,
    sender: StandardPrincipalData,
) -> (Result<Option<Value>, VmExecutionError>, Option<AssetMap>) {
    let mut assets: Option<AssetMap> = None;

    let result = execute_and_check_versioned(program, version, sender, |g| {
        assets = Some(g.get_readonly_asset_map()?.clone());
        Ok(())
    });

    (result, assets)
}

/// Execute two snippets—one unrestricted and one restricted—using the same
/// sender, then compare their results and asset movements. If `error_allowed`
/// is true, both executions may fail as long as the errors match; otherwise,
/// both executions must succeed.
/// `asset_check` is a closure that takes the unrestricted and restricted asset
/// maps and returns a `Result<Option<Value>, TestCaseError>`. If it returns
/// `Ok(Some(value))`, the restricted execution is expected to return that
/// value. If it returns `Ok(None)`, the restricted execution is expected to
/// mirror the unrestricted execution's `(ok ...)` result. If it returns `Err`,
/// the property test fails with the provided error.
fn assert_results_match<F>(
    unrestricted: (&str, ClarityVersion),
    restricted: (&str, ClarityVersion),
    sender: StandardPrincipalData,
    asset_check: F,
    error_allowed: bool,
) -> TestCaseResult
where
    F: Fn(&AssetMap, &AssetMap) -> Result<Option<Value>, TestCaseError>,
{
    let (unrestricted_result, unrestricted_assets) =
        execute_with_assets_for_version(unrestricted.0, unrestricted.1, sender.clone());
    let (restricted_result, restricted_assets) =
        execute_with_assets_for_version(restricted.0, restricted.1, sender);

    let unrestricted_assets = unrestricted_assets
        .ok_or_else(|| TestCaseError::fail("Unrestricted execution returned no asset map"))?;
    let restricted_assets = restricted_assets
        .ok_or_else(|| TestCaseError::fail("Restricted execution returned no asset map"))?;

    match (unrestricted_result, restricted_result) {
        (Err(unrestricted_err), Err(restricted_err)) => {
            if error_allowed {
                prop_assert_eq!(unrestricted_err, restricted_err);
                Ok(())
            } else {
                Err(TestCaseError::fail(format!(
                    "Both unrestricted and restricted execution failed, but errors are not allowed. Unrestricted error: {unrestricted_err:?}, Restricted error: {restricted_err:?}"
                )))
            }
        }
        (Err(_unrestricted_err), Ok(restricted_value_opt)) => {
            if !error_allowed {
                return Err(TestCaseError::fail(
                    "Unrestricted execution failed but errors are not allowed",
                ));
            }
            let restricted_value = restricted_value_opt
                .ok_or_else(|| TestCaseError::fail("Restricted execution returned no value"))?;
            let expected_value = asset_check(&unrestricted_assets, &restricted_assets)?;
            if let Some(expected_value) = expected_value {
                prop_assert_eq!(expected_value, restricted_value);
                Ok(())
            } else {
                Err(TestCaseError::fail(
                    "Unrestricted execution failed but asset check expected success",
                ))
            }
        }
        (Ok(_), Err(restricted_err)) => Err(TestCaseError::fail(format!(
            "Unrestricted execution succeeded but restricted execution failed with {restricted_err:?}"
        ))),
        (Ok(unrestricted_value_opt), Ok(restricted_value_opt)) => {
            let unrestricted_value = unrestricted_value_opt
                .ok_or_else(|| TestCaseError::fail("Unrestricted execution returned no value"))?;
            let restricted_value = restricted_value_opt
                .ok_or_else(|| TestCaseError::fail("Restricted execution returned no value"))?;
            let expected_value = asset_check(&unrestricted_assets, &restricted_assets)?;
            if let Some(expected_value) = expected_value {
                prop_assert_eq!(expected_value, restricted_value);
            } else {
                let expected = Value::okay(unrestricted_value)
                    .unwrap_or_else(|e| panic!("Wrapping value failed: {e:?}"));
                prop_assert_eq!(expected, restricted_value);
            }
            Ok(())
        }
    }
}

/// Construct the error value returned when assets move without matching
/// allowances.
fn no_allowance_error() -> Value {
    Value::error(Value::UInt(MAX_ALLOWANCES as u128))
        .expect("error response construction never fails")
}

const TOKEN_DEFINITIONS: &str = r#"
(define-fungible-token stackos)
(define-non-fungible-token stackaroo uint)
"#;

proptest! {
    #[test]
    fn prop_restrict_assets_returns_body_value_when_pure(
        body_value in clarity_values_no_response(),
    ) {
        let body_literal = value_to_clarity_literal(&body_value);
        let snippet = format!("(restrict-assets? tx-sender () {body_literal})");

        let evaluation = execute(&snippet)
            .unwrap_or_else(|e| panic!("Execution failed for snippet `{snippet}`: {e:?}"))
            .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

        let expected = Value::okay(body_value.clone())
            .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

        prop_assert_eq!(expected, evaluation);
    }

    #[test]
    fn prop_restrict_assets_returns_value_with_allowances(
        allowances in allowance_list_snippets(),
        body_value in clarity_values_no_response(),
    ) {
        let body_literal = value_to_clarity_literal(&body_value);
        let snippet = format!("{TOKEN_DEFINITIONS}(restrict-assets? tx-sender {allowances} {body_literal})");

        let evaluation = execute(&snippet)
            .unwrap_or_else(|e| panic!("Execution failed for snippet `{snippet}`: {e:?}"))
            .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

        let expected = Value::okay(body_value.clone())
            .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

        prop_assert_eq!(expected, evaluation);
    }

    #[test]
    fn prop_restrict_assets_errors_when_no_allowances_and_body_moves_stx(
        sender in standard_principal_strategy(),
        body in begin_block(),
    ) {
        let snippet = format!("(restrict-assets? tx-sender () {body})");
        let sender_principal = sender.clone().into();
        assert_results_match(
            (body.as_str(), ClarityVersion::Clarity4),
            (snippet.as_str(), ClarityVersion::Clarity4),
            sender,
            |unrestricted_assets, restricted_assets| {
                let stx_moved = unrestricted_assets.get_stx(&sender_principal).unwrap_or(0);
                if stx_moved > 0 {
                    prop_assert_eq!(&AssetMap::new(), restricted_assets);
                    Ok(Some(no_allowance_error()))
                } else {
                    prop_assert_eq!(unrestricted_assets, restricted_assets);
                    Ok(None)
                }
            },
            true,
        )
        .unwrap();
    }

    #[test]
    fn prop_restrict_assets_errors_when_no_ft_allowance(
        sender in standard_principal_strategy(),
        ft_mint in match_response_snippets(ft_mint_snippets("tx-sender".into())), ft_transfer in try_response_snippets(ft_transfer_snippets())
    ) {
        let setup_code = format!("{TOKEN_DEFINITIONS} {ft_mint}");
        let body_program = format!(
            "{setup_code} {ft_transfer}",
        );
        let wrapper_program = format!(
            "{setup_code} (restrict-assets? tx-sender () {ft_transfer})",
        );
        let sender_principal = sender.clone().into();
        let asset_identifier = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                sender.clone(),
                "contract".into(),
            ),
            asset_name: ClarityName::try_from("stackos".to_string())
                .expect("valid fungible token name"),
        };

        assert_results_match(
            (body_program.as_str(), ClarityVersion::Clarity4),
            (wrapper_program.as_str(), ClarityVersion::Clarity4),
            sender,
            move |unrestricted_assets, restricted_assets| {
                let moved = unrestricted_assets
                    .get_fungible_tokens(&sender_principal, &asset_identifier)
                    .unwrap_or(0);
                if moved > 0 {
                    prop_assert_eq!(&AssetMap::new(), restricted_assets);
                    Ok(Some(no_allowance_error()))
                } else {
                    prop_assert_eq!(unrestricted_assets, restricted_assets);
                    Ok(None)
                }
            },
            true,
        )
        .unwrap();
    }

    #[test]
    fn prop_restrict_assets_errors_when_no_nft_allowance(
        sender in standard_principal_strategy(),
        nft_mint in match_response_snippets(nft_mint_snippets("tx-sender".into())), nft_transfer in try_response_snippets(nft_transfer_snippets())
    ) {
        let setup_code = format!("{TOKEN_DEFINITIONS} {nft_mint}");
        let body_program = format!(
            "{setup_code} {nft_transfer}",
        );
        let wrapper_program = format!(
            "{setup_code} (restrict-assets? tx-sender () {nft_transfer})",
        );
        let sender_principal = sender.clone().into();
        let asset_identifier = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                sender.clone(),
                "contract".into(),
            ),
            asset_name: ClarityName::try_from("stackaroo".to_string())
                .expect("valid non-fungible token name"),
        };

        assert_results_match(
            (body_program.as_str(), ClarityVersion::Clarity4),
            (wrapper_program.as_str(), ClarityVersion::Clarity4),
            sender,
            move |unrestricted_assets, restricted_assets| {
                let moved = unrestricted_assets
                    .get_nonfungible_tokens(&sender_principal, &asset_identifier)
                    .map(|l| l.len())
                    .unwrap_or(0);
                if moved > 0 {
                    prop_assert_eq!(&AssetMap::new(), restricted_assets);
                    Ok(Some(no_allowance_error()))
                } else {
                    prop_assert_eq!(unrestricted_assets, restricted_assets);
                    Ok(None)
                }
            },
            true,
        )
        .unwrap();
    }

    #[test]
    fn prop_as_contract_returns_body_value_when_pure(
        body_value in clarity_values_no_response(),
    ) {
        let body_literal = value_to_clarity_literal(&body_value);
        let snippet = format!("(as-contract? () {body_literal})");

        let evaluation = execute(&snippet)
            .unwrap_or_else(|e| panic!("Execution failed for snippet `{snippet}`: {e:?}"))
            .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

        let expected = Value::okay(body_value.clone())
            .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

        prop_assert_eq!(expected, evaluation);
    }

    #[test]
    fn prop_as_contract_returns_value_with_allowances(
        allowances in allowance_list_snippets(),
        body_value in clarity_values_no_response(),
    ) {
        let body_literal = value_to_clarity_literal(&body_value);
        let snippet = format!("{TOKEN_DEFINITIONS}(as-contract? {allowances} {body_literal})");

        let evaluation = execute(&snippet)
            .unwrap_or_else(|e| panic!("Execution failed for snippet `{snippet}`: {e:?}"))
            .unwrap_or_else(|| panic!("Execution returned no value for snippet `{snippet}`"));

        let expected = Value::okay(body_value.clone())
            .unwrap_or_else(|e| panic!("Wrapping body value failed for snippet `{snippet}`: {e:?}"));

        prop_assert_eq!(expected, evaluation);
    }

    #[test]
    fn prop_as_contract_errors_when_no_allowances_and_body_moves_stx(
        sender in standard_principal_strategy(),
        body in begin_block(),
    ) {
        let snippet = format!("(as-contract? () {body})");
        let c3_snippet = format!("(as-contract {body})");
        let contract_id = QualifiedContractIdentifier::new(sender.clone(), "contract".into());
        let contract = PrincipalData::Contract(contract_id);
        assert_results_match(
            (c3_snippet.as_str(), ClarityVersion::Clarity3),
            (snippet.as_str(), ClarityVersion::Clarity4),
            sender,
            |unrestricted_assets, restricted_assets| {
                let stx_moved = unrestricted_assets.get_stx(&contract).unwrap_or(0);
                if stx_moved > 0 {
                    prop_assert_eq!(&AssetMap::new(), restricted_assets);
                    Ok(Some(no_allowance_error()))
                } else {
                    prop_assert_eq!(unrestricted_assets, restricted_assets);
                    Ok(None)
                }
            },
            true,
        )
        .unwrap();
    }

    #[test]
    fn prop_as_contract_with_all_assets_unsafe_matches_clarity3(
        sender in standard_principal_strategy(),
        body in begin_block(),
    ) {
        let snippet = format!("(as-contract? ((with-all-assets-unsafe)) {body})");
        let c3_snippet = format!("(as-contract {body})");
        assert_results_match(
            (c3_snippet.as_str(), ClarityVersion::Clarity3),
            (snippet.as_str(), ClarityVersion::Clarity4),
            sender,
            |unrestricted_assets, restricted_assets| {
                prop_assert_eq!(unrestricted_assets, restricted_assets);
                Ok(None)
            },
            true,
        )
        .unwrap();
    }

    #[test]
    fn prop_as_contract_with_transfers_and_allowances_matches_clarity3(
        sender in standard_principal_strategy(),
        allowances_and_body in body_with_allowances_snippets(),
        ft_mint in match_response_snippets(ft_mint_snippets("tx-sender".into())),
        nft_mint in match_response_snippets(nft_mint_snippets("tx-sender".into())),
    ) {
        let (allowances, body) = allowances_and_body;
        let snippet =
            format!("{TOKEN_DEFINITIONS}(as-contract? {allowances} {ft_mint} {nft_mint} {body})");
        let c3_snippet =
            format!("{TOKEN_DEFINITIONS}(as-contract (begin {ft_mint} {nft_mint} {body}))");
        assert_results_match(
            (c3_snippet.as_str(), ClarityVersion::Clarity3),
            (snippet.as_str(), ClarityVersion::Clarity4),
            sender,
            |unrestricted_assets, restricted_assets| {
                prop_assert_eq!(unrestricted_assets, restricted_assets);
                Ok(None)
            },
            false,
        )
        .unwrap();
    }

    #[test]
    fn prop_restrict_assets_with_transfers_and_allowances_ok(
        sender in standard_principal_strategy(),
        allowances_and_body in body_with_allowances_snippets(),
        ft_mint in match_response_snippets(ft_mint_snippets("tx-sender".into())),
        nft_mint in match_response_snippets(nft_mint_snippets("tx-sender".into())),
    ) {
        let (allowances, body) = allowances_and_body;
       let snippet = format!("{TOKEN_DEFINITIONS}(restrict-assets? tx-sender {allowances} {ft_mint} {nft_mint} {body})");
       let simple_snippet = format!("{TOKEN_DEFINITIONS}(begin {ft_mint} {nft_mint} {body})");
       assert_results_match(
            (simple_snippet.as_str(), ClarityVersion::Clarity3),
            (snippet.as_str(), ClarityVersion::Clarity4),
            sender,
            |unrestricted_assets, restricted_assets| {
                prop_assert_eq!(unrestricted_assets, restricted_assets);
                Ok(None)
            },
            false,
        )
        .unwrap();
    }
}
