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

//! This module contains consensus tests related to Clarity Parse errors.

use std::collections::HashMap;

use clarity::types::chainstate::StacksPrivateKey;
use clarity::types::StacksEpochId;
#[allow(unused_imports)]
use clarity::vm::errors::RuntimeError;
use clarity::vm::types::PrincipalData;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, ConsensusChain, SK_1, SK_2,
};
use crate::core::test_util::to_addr;

/// RuntimeError: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `pow` arithmetic operation
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_overflow_pow() {
    contract_call_consensus_test!(
        contract_name: "overflow-pow",
        contract_code: &{
        r#"
    (define-public (trigger-overflow-pow)
    (ok (pow 2 128))
    )
        "#
        },
        function_name: "trigger-overflow-pow",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `mul`` arithmetic operation
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_oveflow_mul() {
    contract_call_consensus_test!(
        contract_name: "overflow-mul",
        contract_code: &{
            format!(
        r#"
    (define-public (trigger-overflow-mul)
    (ok (* u{} u2))
    )
        "#, u128::MAX)
        },
        function_name: "trigger-overflow-mul",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `add` arithmetic operation
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_overflow_add() {
    contract_call_consensus_test!(
        contract_name: "overflow-add",
        contract_code: &{
            format!(
        r#"
    (define-public (trigger-overflow-add)
    (ok (+ u{} u1))
    )
        "#, u128::MAX)
        },
        function_name: "trigger-overflow-add",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `add` arithmetic operation
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_overflow_to_int() {
    contract_call_consensus_test!(
        contract_name: "overflow-to-int",
        contract_code: &{
            format!(
        r#"
    (define-public (overflow-to-int-large)
    (ok (to-int u{}))
    )
        "#, u128::MAX)
        },
        function_name: "overflow-to-int-large",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing two successive fungible token
/// mints, but it ultimately calls the `add` arithmetic operation
/// Outcome: block accepted.
#[test]
fn runtime_error_ft_mint_overflow() {
    contract_call_consensus_test!(
        contract_name: "ft-mint-overflow",
        contract_code: &{
            format!(
            r#"
    (define-fungible-token token)

    (define-public (trigger-ft-mint-overflow)
    (begin
        (try! (ft-mint? token u{} tx-sender))
        (ft-mint? token u1 tx-sender)
    )
    )
    "#, u128::MAX)},
        function_name: "trigger-ft-mint-overflow",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::SupplyOverflow`]
/// Caused by: minting more than the declared `total-supply` (1_000_000),
/// triggering the cap check in `checked_increase_token_supply`.
/// Outcome: block accepted.
#[test]
fn runtime_error_ft_mint_supply_overflow() {
    contract_call_consensus_test!(
        contract_name: "ft-supply-overflow",
        contract_code: &{
            r#"
    (define-fungible-token token u1000000)
    (define-public (trigger-ft-supply-overflow)
    (begin
        (try! (ft-mint? token u500000 tx-sender))
        (ft-mint? token u600000 tx-sender)
    )
    )
    "#
        },
        function_name: "trigger-ft-supply-overflow",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: `native_to_uint` conversion of a negative number.
/// Outcome: block accepted.
#[test]
fn runtime_error_to_uint_underflow() {
    contract_call_consensus_test!(
        contract_name: "to-uint-negative",
        contract_code: &{
            r#"
    (define-read-only (trigger-underflow)
    (to-uint -10)
    )
    "#
        },
        function_name: "trigger-underflow",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: subtraction.
/// Outcome: block accepted.
#[test]
fn runtime_error_sub_underflow() {
    contract_call_consensus_test!(
        contract_name: "sub-underflow",
        contract_code: &{
            r#"
    (define-read-only (trigger-underflow)
    (- u10 u11)
    )
    "#
        },
        function_name: "trigger-underflow",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::DivisionByZero`]
/// Caused by: modulo.
/// Outcome: block accepted.
#[test]
fn runtime_error_division_by_zero_mod() {
    contract_call_consensus_test!(
        contract_name: "division-by-zero-mod",
        contract_code: &{
            r#"
    (define-read-only (trigger)
    (mod 10 0)
    )
    "#
        },
        function_name: "trigger",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::DivisionByZero`]
/// Caused by: division.
/// Outcome: block accepted.
#[test]
fn runtime_error_division_by_zero() {
    contract_call_consensus_test!(
        contract_name: "division-by-zero",
        contract_code: &{
            r#"
    (define-read-only (trigger)
    (/ 10 0)
    )
    "#
        },
        function_name: "trigger",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::Arithmetic(String)`]
/// Caused by: sqrt of a negative integer.
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_sqrti_neg() {
    contract_call_consensus_test!(
        contract_name: "sqrti-neg",
        contract_code: &{
            r#"
    (define-read-only (trigger)
    (sqrti -1)
    )
    "#
        },
        function_name: "trigger",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::Arithmetic(String)`]
/// Caused by: log2 of a negative integer.
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_log2_neg() {
    contract_call_consensus_test!(
        contract_name: "log2-neg",
        contract_code: &{
            r#"
    (define-read-only (trigger)
    (log2 -8)
    )
    "#
        },
        function_name: "trigger",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::Arithmetic(String)`]
/// Caused by: pow of too large a number
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_pow_large() {
    contract_call_consensus_test!(
        contract_name: "pow-large",
        contract_code: &{
            format!(
            r#"
    (define-read-only (trigger)
    (pow 2 {})
    )
    "#, u64::from(u32::MAX) + 1)
        },
        function_name: "trigger",
        function_args: &[],
    );
}

/// RuntimeError: [`RuntimeError::Arithmetic(String)`]
/// Caused by: pow of negative number
/// Outcome: block accepted.
#[test]
fn runtime_error_arithmetic_pow_neg() {
    contract_call_consensus_test!(
        contract_name: "pow-neg",
        contract_code: &{
            r#"
    (define-read-only (trigger)
    (pow 2 (- 1))
    )
    "#
        },
        function_name: "trigger",
        function_args: &[],
    );
}

// Caused by: overflow when attempting to increment the liquid stx supply over u128 when initializing the chainstate
#[test]
#[should_panic(expected = "FATAL: liquid STX overflow")]
fn runtime_error_arithmetic_overflows_based_on_liquid_supply() {
    let privk1 = StacksPrivateKey::from_hex(SK_1).unwrap();
    let principal1: PrincipalData = to_addr(&privk1).into();

    let privk2 = StacksPrivateKey::from_hex(SK_2).unwrap();
    let principal2: PrincipalData = to_addr(&privk2).into();

    let initial_balances = vec![(principal1, u128::MAX), (principal2, 1)];
    // Just make sure we have a single block and epoch to pass initial checks
    let mut num_blocks_per_epoch = HashMap::new();
    num_blocks_per_epoch.insert(StacksEpochId::Epoch20, 1);

    // The chain will fail to init since the stacks chainstate does not allow a liquid supply > MAX::u128
    ConsensusChain::new(function_name!(), initial_balances, num_blocks_per_epoch);
}
