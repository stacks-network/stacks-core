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
use clarity::vm::Value as ClarityValue;
use clarity::vm::errors::RuntimeError;
use clarity::vm::types::{PrincipalData, ResponseData};

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, contract_deploy_consensus_test, ConsensusChain,
    SK_1, SK_2,
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
        SupplyUnderflow(_, _) => Unreachable_Functionally("
        Token supply cannot overflow in Clarity: \
        balance checks and checked arithmetic prevent exceeding total supply.
        "),
        DivisionByZero => Tested(vec![division_by_zero_mod, division_by_zero]),
        TypeParseFailure(_) => Tested(vec![
            parse_tests::test_invalid_principal_literal,
            principal_wrong_byte_length,
        ]),
        ASTError(_) => Ignored("Tested by parse_tests."),
        MaxStackDepthReached => Tested(vec![stack_depth_too_deep_call_chain_at_call, stack_depth_too_deep_call_chain_at_deploy]),
        MaxContextDepthReached => Unreachable_Functionally("
        Max context depth cannot be reached in normal Clarity execution: \
        call-stack depth and parser expression-depth limits trigger first, \
        so only Rust-level tests can hit this error."
    ),
        BadTypeConstruction => Unreachable_Functionally("
        BadTypeConstruction cannot be triggered in normal Clarity execution: \
        any code that would cause this runtime error is already rejected \
        by static analysis during contract deployment."
    ),
        BadBlockHeight(_) => Unreachable_Functionally("
        BadBlockHeight cannot occur during normal Clarity contract execution: \
        all block heights referenced by the VM exist in the backing store, \
        so this error would only arise if the node's historical state were missing, \
        corrupted, or incomplete."
    ),
        NoSuchToken => Unreachable_Functionally("
            NoSuchToken cannot occur during normal Clarity contract execution: \
            all NFT queries in public functions are either validated at runtime or \
            return `none` if the token does not exist. This error would only arise \
            if the underlying VM storage were manually corrupted or a token was \
            deleted unexpectedly in the backing store."
        ),
        NotImplemented => Unreachable_Functionally("
        NotImplemented cannot occur during normal Clarity contract execution \
        unless you corrupt the VM or manually invoke Rust \
        internals outside the normal Clarity runtime"
        ),
        NoCallerInContext => Unreachable_Functionally(
            "NoCallerInContext cannot occur during normal Clarity contract execution: \
            all public and private function calls have a caller context supplied by the VM, \
            so this error would only arise if the environment were manually constructed incorrectly."
        ),
        NoSenderInContext => Unreachable_Functionally(
            "NoSenderInContext cannot occur during normal Clarity contract execution: \
            every transaction and contract call executed on-chain has a sender, \
            so this error would only arise if the environment were manually constructed incorrectly."
        ),
        BadNameValue(_, _) => Unreachable_Functionally("
            BadNameValue cannot occur during normal Clarity execution: 
            all contract, trait, and function names are validated at deployment time. 
            The runtime only encounters valid names. This error would only arise 
            from corrupted or manually constructed state in a test harness.
        "),
        UnknownBlockHeaderHash(_) => Tested(vec![unknown_block_header_hash_fork]),
        BadBlockHash(_) => Tested(vec![bad_block_hash]),
        UnwrapFailure => Tested(vec![unwrap_err_panic_on_ok_runtime, unwrap_panic_on_err_runtime]),
        MetadataAlreadySet => todo!(),
        DefunctPoxContract => todo!(),
        PoxAlreadyLocked => todo!(),
        BlockTimeNotAvailable => todo!(),
    }
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
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

/// Error: [`RuntimeError::ArithmeticOverflow`]
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

/// Error: [`RuntimeError::ArithmeticOverflow`]
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

/// Error: [`RuntimeError::ArithmeticOverflow`]
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

/// Error: [`RuntimeError::ArithmeticOverflow`]
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

/// Error: [`RuntimeError::SupplyOverflow`]
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

/// Error: [`RuntimeError::ArithmeticUnderflow`]
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

/// Error: [`RuntimeError::ArithmeticUnderflow`]
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

/// Error: [`RuntimeError::DivisionByZero`]
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

/// Error: [`RuntimeError::DivisionByZero`]
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

/// Error: [`RuntimeError::Arithmetic`]
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

/// Error: [`RuntimeError::Arithmetic`]
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

/// Error: [`RuntimeError::Arithmetic`]
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

/// Error: [`RuntimeError::Arithmetic`]
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

/// Error: [`RuntimeError::TypeParseFailure`]
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

/// Error: [RuntimeError::MaxStackDepthReached]
/// Caused by: private function call chain exceeding runtime stack depth
/// Outcome: block accepted
#[test]
fn stack_depth_too_deep_call_chain_at_deploy() {
    // Build a chain of private functions foo-0 → foo-1 → ... → foo-63
    // Each foo-i calls foo-(i-1), so calling foo-63 triggers 64 nested calls.
    let mut defs = Vec::new();
    // Base function
    defs.push("(define-private (foo-0 (x int)) (+ 1 x))".to_string());
    // Generate foo-1 through foo-63
    for i in 1..=63 {
        defs.push(format!(
            "(define-private (foo-{i} (x int)) (foo-{} (+ 1 x)))",
            i - 1
        ));
    }
    // The top-level expression we want to trigger evaluation of foo-63
    defs.push("(foo-63 1)".into());
    let contract_code = defs.join("\n");
    contract_deploy_consensus_test!(
        contract_name: "max-stack-depth",
        contract_code: &contract_code,
    );
}

/// Error: [`RuntimeError::MaxStackDepthReached`]
/// Caused by: private function call chain exceeding runtime stack depth at function call
/// Outcome: block accepted, execution rejected when function is called
#[test]
fn stack_depth_too_deep_call_chain_at_call() {
    // Build 65 private functions: foo-0 → foo-64
    let mut defs = Vec::new();

    // Base function: depth = 1
    defs.push("(define-private (foo-0 (x int)) (let ((y (+ x 1))) y))".to_string());

    // Chain functions: each adds 1 to local context via let
    for i in 1..65 {
        let prev = i - 1;
        defs.push(format!(
            "(define-private (foo-{i} (x int)) (let ((y (foo-{prev} x))) (+ y 1)))"
        ));
    }

    // Public function triggers the runtime error by calling foo-64
    defs.push("(define-public (trigger) (ok (foo-64 0)))".into());

    let contract_code = defs.join("\n");

    // Call the public function via the consensus test macro
    contract_call_consensus_test!(
        contract_name: "context-depth",
        contract_code: &contract_code,
        function_name: "trigger",
        function_args: &[],
    );
}



/// Error: [`RuntimeError::UnknownBlockHeaderHash`]
/// Caused by: calling `at-block` with a block hash that doesn't exist on the current fork
/// Outcome: block accepted
#[test]
fn unknown_block_header_hash_fork() {
    contract_call_consensus_test!(
        contract_name: "unknown-hash",
        contract_code: r#"
(define-public (trigger)
  (ok
    (at-block 
      0x0202020202020202020202020202020202020202020202020202020202020202
      (+ 1 2))))
"#,
        function_name: "trigger",
        function_args: &[],
    );
}


/// Error: [`RuntimeError::BadBlockHash`]
/// Caused by: calling `at-block` with a 31-byte block hash
/// Outcome: block accepted
#[test]
fn bad_block_hash() {
    contract_call_consensus_test!(
        contract_name: "bad-block-hash",
        contract_code: r#"
(define-public (trigger)
  (ok
    (at-block 
      0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e
      (+ 1 2))))
"#,
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::UnwrapFailure`]
/// Caused by: calling `unwrap-err-panic` on an `(ok ...)` value at runtime
/// Outcome: block accepted
#[test]
fn unwrap_err_panic_on_ok_runtime() {
    contract_call_consensus_test!(
        contract_name: "unwrap-ok",
        contract_code: r#"
(define-public (trigger (input (response uint uint))) 
    (ok (unwrap-err-panic input))
)
"#,
        function_name: "trigger",
        // Pass a real (ok ...) response as the argument
        function_args: &[
            ClarityValue::Response(ResponseData {
                committed: true,
                data: Box::new(ClarityValue::UInt(3)),
            })
        ],
    );
}

/// Error: [`RuntimeError::UnwrapFailure`]
/// Caused by: calling `unwrap-panic` (or `unwrap!`) on an `(err ...)` response value at runtime
/// Outcome: block accepted
#[test]
fn unwrap_panic_on_err_runtime() {
    contract_call_consensus_test!(
        contract_name: "unwrap-err",
        contract_code: r#"
(define-public (trigger (input (response uint uint)))
    (ok (unwrap-panic input))
)
"#,
        function_name: "trigger",
        function_args: &[
            ClarityValue::Response(ResponseData {
                committed: false,
                data: Box::new(ClarityValue::UInt(3)),
            })
        ],
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
