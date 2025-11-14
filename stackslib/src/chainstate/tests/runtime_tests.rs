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
use clarity::vm::errors::RuntimeError;
use clarity::vm::types::PrincipalData;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, contract_deploy_consensus_test, ConsensusChain, SK_1, SK_2,
};
use crate::chainstate::tests::parse_tests;
use crate::core::test_util::to_addr;

/// Generates a coverage classification report for a specific [`RuntimeError`] variant.
///
/// This method exists purely for **documentation and tracking purposes**.
/// It helps maintainers understand which error variants have been:
///
/// - ✅ **Tested** — verified through consensus tests.
/// - ⚙️ **Ignored** — not tested on purpose. (e.g. parser v1 errors).
/// - 🚫 **Unreachable** — not testable from consensus test side for reasons.
#[allow(dead_code)]
fn variant_coverage_report(variant: RuntimeError) {
    enum VariantCoverage {
        // Cannot occur through valid execution. The string is to explain the reason.
        Unreachable_Functionally(&'static str),
        // Unexpected error, that should never happen
        Unreachable_ExpectLike,
        // Defined but never used
        Unreachable_NotUsed,
        // Not tested on purpose. The string is to explain the reason.
        Ignored(&'static str),
        // Covered by consensus tests. The func lists is for to link the variant with the related tests
        Tested(Vec<fn()>),
    }

    use RuntimeError::*;
    use VariantCoverage::*;

    _ = match variant {
        Arithmetic(_) => Tested(vec![
            arithmetic_sqrti_neg,
            arithmetic_log2_neg,
            arithmetic_pow_large,
            arithmetic_pow_neg,
        ]),
        ArithmeticOverflow => Tested(vec![
            arithmetic_overflow_pow,
            arithmetic_oveflow_mul,
            arithmetic_overflow_add,
            arithmetic_overflow_to_int,
            ft_mint_overflow,
        ]),
        ArithmeticUnderflow => Tested(vec![to_uint_underflow, sub_underflow]),
        SupplyOverflow(_, _) => Tested(vec![ft_mint_supply_overflow]),
        SupplyUnderflow(_, _) => Unreachable_Functionally(
            "Will fail balance checks first, returning insufficient balance",
        ),
        DivisionByZero => Tested(vec![division_by_zero_mod, division_by_zero]),
        TypeParseFailure(_) => Tested(vec![
            parse_tests::test_invalid_principal_literal,
            principal_wrong_byte_length,
        ]),
        ASTError(_) => todo!(),
        MaxStackDepthReached => todo!(),
        MaxContextDepthReached => todo!(),
        BadTypeConstruction => todo!(),
        BadBlockHeight(_) => todo!(),
        NoSuchToken => todo!(),
        NotImplemented => todo!(),
        NoCallerInContext => todo!(),
        NoSenderInContext => todo!(),
        BadNameValue(_, _) => todo!(),
        UnknownBlockHeaderHash(_) => todo!(),
        BadBlockHash(_) => todo!(),
        UnwrapFailure => todo!(),
        MetadataAlreadySet => todo!(),
        DefunctPoxContract => todo!(),
        PoxAlreadyLocked => todo!(),
        BlockTimeNotAvailable => todo!(),
    }
}

/// RuntimeError: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `pow` arithmetic operation
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_pow() {
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
fn arithmetic_oveflow_mul() {
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
fn arithmetic_overflow_add() {
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
fn arithmetic_overflow_to_int() {
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
fn ft_mint_overflow() {
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
fn ft_mint_supply_overflow() {
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
fn to_uint_underflow() {
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
fn sub_underflow() {
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
fn division_by_zero_mod() {
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
fn division_by_zero() {
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

/// RuntimeError: [`RuntimeError::Arithmetic`]
/// Caused by: sqrt of a negative integer.
/// Outcome: block accepted.
#[test]
fn arithmetic_sqrti_neg() {
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

/// RuntimeError: [`RuntimeError::Arithmetic`]
/// Caused by: log2 of a negative integer.
/// Outcome: block accepted.
#[test]
fn arithmetic_log2_neg() {
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

/// RuntimeError: [`RuntimeError::Arithmetic`]
/// Caused by: pow of too large a number
/// Outcome: block accepted.
#[test]
fn arithmetic_pow_large() {
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

/// RuntimeError: [`RuntimeError::Arithmetic`]
/// Caused by: pow of negative number
/// Outcome: block accepted.
#[test]
fn arithmetic_pow_neg() {
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

/// TypeParseFailure: [`RuntimeError::TypeParseFailure`]
/// Caused by: invalid standard principal literal (wrong byte length)
/// Outcome: block accepted.
/// Note: Gets converted into [`clarity::vm::ast::errors::ParseErrorKind::InvalidPrincipalLiteral`]
#[test]
pub fn principal_wrong_byte_length() {
    contract_deploy_consensus_test!(
        contract_name: "wrong-byte-length",
        contract_code: &{
            r#"
    ;; This literal decodes via c32 but has the wrong byte length
    (define-constant my-principal 'S162RK3CHJPCSSK6BM757FW) 
    "#
        },
    );
}

// Caused by: overflow when attempting to increment the liquid stx supply over u128 when initializing the chainstate
#[test]
#[should_panic(expected = "FATAL: liquid STX overflow")]
fn arithmetic_overflows_based_on_liquid_supply() {
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
