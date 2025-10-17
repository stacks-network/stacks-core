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

use clarity_types::errors::{Error as ClarityError, InterpreterResult, ShortReturnType};
use clarity_types::types::{
    AssetIdentifier, PrincipalData, QualifiedContractIdentifier, StandardPrincipalData,
};
use clarity_types::{ClarityName, Value};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestCaseResult};

use super::proptest_utils::{
    begin_block, clarity_values_no_response, execute, execute_and_return_asset_map,
    execute_and_return_asset_map_versioned, value_to_clarity_literal,
};
use crate::vm::analysis::type_checker::v2_1::natives::post_conditions::MAX_ALLOWANCES;
use crate::vm::contexts::AssetMap;
use crate::vm::tests::proptest_utils::{
    allowance_list_snippets, ft_mint_snippets, ft_transfer_snippets, match_response_snippets,
    nft_mint_snippets, nft_transfer_snippets, try_response_snippets,
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

/// Given the results of running a snippet with and without asset restrictions,
/// assert that the results match and verify that the asset movements are as
/// expected. `asset_check` is a closure that takes the unrestricted and
/// restricted asset maps and returns a `Result<Option<Value>, TestCaseError>`.
/// If it returns `Ok(Some(value))`, the test will assert that the restricted
/// execution returned that value. If it returns `Ok(None)`, the test will
/// assert that the restricted execution returned the same value as the
/// unrestricted execution. If it returns `Err`, the test will fail with the
/// provided error.
fn assert_results_match<F>(
    unrestricted_result: InterpreterResult<(Option<Value>, AssetMap)>,
    restricted_result: InterpreterResult<(Option<Value>, AssetMap)>,
    asset_check: F,
) -> TestCaseResult
where
    F: Fn(&AssetMap, &AssetMap) -> Result<Option<Value>, TestCaseError>,
{
    match (unrestricted_result, restricted_result) {
        (Err(unrestricted_err), Err(restricted_err)) => {
            prop_assert_eq!(unrestricted_err, restricted_err);
            Ok(())
        }
        (Err(unrestricted_err), Ok((restricted_result, _))) => {
            let detail = match restricted_result {
                Some(result_value) => format!(
                    "Unrestricted execution failed with {unrestricted_err:?} but restricted execution successfully returned value {result_value:?}"
                ),
                None => format!(
                    "Unrestricted execution failed with {unrestricted_err:?} but restricted execution successfully returned no value"
                ),
            };
            Err(TestCaseError::fail(detail))
        }
        (Ok(_), Err(restricted_err)) => Err(TestCaseError::fail(format!(
            "Unrestricted execution succeeded but restricted execution failed with {restricted_err:?}"
        ))),
        (
            Ok((unrestricted_value, unrestricted_assets)),
            Ok((restricted_value, restricted_assets)),
        ) => {
            let Some(unrestricted_value) = unrestricted_value else {
                panic!("Unrestricted execution returned no value");
            };
            let Some(restricted_value) = restricted_value else {
                panic!("Restricted execution returned no value");
            };

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
        body in begin_block(),
    ) {
        let snippet = format!("(restrict-assets? tx-sender () {body})");
        assert_results_match(
            execute_and_return_asset_map(&body),
            execute_and_return_asset_map(&snippet),
            |unrestricted_assets, restricted_assets| {
                let sender = PrincipalData::Standard(StandardPrincipalData::transient());
                let stx_moved = unrestricted_assets.get_stx(&sender).unwrap_or(0);
                if stx_moved > 0 {
                    prop_assert_eq!(&AssetMap::new(), restricted_assets);
                    Ok(Some(no_allowance_error()))
                } else {
                    prop_assert_eq!(unrestricted_assets, restricted_assets);
                    Ok(None)
                }
            },
        )
        .unwrap();
    }

    #[test]
    fn prop_restrict_assets_errors_when_no_ft_allowance(
        ft_mint in match_response_snippets(ft_mint_snippets()), ft_transfer in try_response_snippets(ft_transfer_snippets())
    ) {
        let setup_code = format!("{TOKEN_DEFINITIONS} {ft_mint}");
        let body_program = format!(
            "{setup_code} {ft_transfer}",
        );
        let wrapper_program = format!(
            "{setup_code} (restrict-assets? tx-sender () {ft_transfer})",
        );
        let asset_identifier = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::transient(),
            asset_name: ClarityName::try_from("stackos".to_string())
                .expect("valid fungible token name"),
        };

        assert_results_match(
            execute_and_return_asset_map(&body_program),
            execute_and_return_asset_map(&wrapper_program),
            move |unrestricted_assets, restricted_assets| {
                let sender = PrincipalData::Standard(StandardPrincipalData::transient());
                let moved = unrestricted_assets
                    .get_fungible_tokens(&sender, &asset_identifier)
                    .unwrap_or(0);
                if moved > 0 {
                    prop_assert_eq!(&AssetMap::new(), restricted_assets);
                    Ok(Some(no_allowance_error()))
                } else {
                    prop_assert_eq!(unrestricted_assets, restricted_assets);
                    Ok(None)
                }
            },
        )
        .unwrap();
    }

    #[test]
    fn prop_restrict_assets_errors_when_no_nft_allowance(
        nft_mint in match_response_snippets(nft_mint_snippets()), nft_transfer in try_response_snippets(nft_transfer_snippets())
    ) {
        let setup_code = format!("{TOKEN_DEFINITIONS} {nft_mint}");
        let body_program = format!(
            "{setup_code} {nft_transfer}",
        );
        let wrapper_program = format!(
            "{setup_code} (restrict-assets? tx-sender () {nft_transfer})",
        );
        let asset_identifier = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::transient(),
            asset_name: ClarityName::try_from("stackaroo".to_string())
                .expect("valid non-fungible token name"),
        };

        assert_results_match(
            execute_and_return_asset_map(&body_program),
            execute_and_return_asset_map(&wrapper_program),
            move |unrestricted_assets, restricted_assets| {
                let sender = PrincipalData::Standard(StandardPrincipalData::transient());
                let moved = unrestricted_assets
                    .get_nonfungible_tokens(&sender, &asset_identifier)
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
        body in begin_block(),
    ) {
        let snippet = format!("(as-contract? () {body})");
        let c3_snippet = format!("(as-contract {body})");
        assert_results_match(
            execute_and_return_asset_map_versioned(&c3_snippet, ClarityVersion::Clarity3),
            execute_and_return_asset_map(&snippet),
            |unrestricted_assets, restricted_assets| {
                let contract = PrincipalData::Contract(QualifiedContractIdentifier::transient());
                let stx_moved = unrestricted_assets.get_stx(&contract).unwrap_or(0);
                if stx_moved > 0 {
                    prop_assert_eq!(&AssetMap::new(), restricted_assets);
                    Ok(Some(no_allowance_error()))
                } else {
                    prop_assert_eq!(unrestricted_assets, restricted_assets);
                    Ok(None)
                }
            },
        )
        .unwrap();
    }

    #[test]
    fn prop_as_contract_with_all_assets_unsafe_matches_clarity3(
        body in begin_block(),
    ) {
        let snippet = format!("(as-contract? ((with-all-assets-unsafe)) {body})");
        let c3_snippet = format!("(as-contract {body})");
        assert_results_match(
            execute_and_return_asset_map_versioned(&c3_snippet, ClarityVersion::Clarity3),
            execute_and_return_asset_map(&snippet),
            |unrestricted_assets, restricted_assets| {
                prop_assert_eq!(unrestricted_assets, restricted_assets);
                Ok(None)
            },
        )
        .unwrap();
    }
}
