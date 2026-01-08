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

//! This module contains consensus tests related to Runtime errors.

use std::collections::HashMap;

use clarity::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use clarity::types::StacksEpochId;
use clarity::vm::errors::RuntimeError;
use clarity::vm::types::{PrincipalData, ResponseData};
use clarity::vm::{ClarityVersion, Value as ClarityValue};
use stacks_common::address::AddressHashMode;

use crate::chainstate::nakamoto::tests::node::TestStacker;
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::test::{
    make_pox_2_lockup, make_pox_3_lockup, make_pox_4_lockup, make_pox_lockup,
    make_signer_key_signature,
};
use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, contract_deploy_consensus_test, ConsensusTest, TestBlock, SK_1,
};
use crate::chainstate::tests::parse_tests;
use crate::core::test_util::to_addr;
use crate::util_lib::signed_structured_data::pox4::Pox4SignatureTopic;

/// Generates a coverage classification report for a specific [`RuntimeError`] variant.
///
/// This method exists purely for **documentation and tracking purposes**.
/// It helps maintainers understand which error variants have been:
///
/// - ✅ **Tested** — verified through consensus tests.
/// - ⚙️ **Ignored** — not tested on purpose..
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
                arithmetic_sqrti_neg_cdeploy,
                arithmetic_sqrti_neg_ccall,
                arithmetic_log2_neg_cdeploy,
                arithmetic_log2_neg_ccall,
                arithmetic_pow_large_cdeploy,
                arithmetic_pow_large_ccall,
                arithmetic_pow_neg_cdeploy,
                arithmetic_pow_neg_ccall,
                arithmetic_zero_n_log_n_cdeploy,
                arithmetic_zero_n_log_n_ccall,
            ]),
        ArithmeticOverflow => Tested(vec![
                arithmetic_overflow_pow_at_cdeploy,
                arithmetic_overflow_pow_ccall,
                arithmetic_overflow_mul_cdeploy,
                arithmetic_overflow_mul_ccall,
                arithmetic_overflow_add_cdeploy,
                arithmetic_overflow_add_ccall,
                arithmetic_overflow_to_int_cdeploy,
                arithmetic_overflow_to_int_ccall,
                ft_mint_overflow,
            ]),
        ArithmeticUnderflow => Tested(vec![
                to_uint_underflow_cdeploy,
                to_uint_underflow_ccall,
                sub_underflow_cdeploy,
                sub_underflow_ccall,
                sub_arg_len_underflow_cdeploy,
                sub_arg_len_underflow_ccall,
            ]),
        SupplyOverflow(_, _) => Tested(vec![ft_mint_supply_overflow]),
        SupplyUnderflow(_, _) => Unreachable_Functionally("
            Token supply underflow is prevented by design in Clarity. \
            All transfer/mint/burn operations use checked arithmetic and balance \
            validation, so negative supply is impossible without manual database corruption."
            ),
        DivisionByZero => Tested(vec![
                division_by_zero_mod_cdeploy,
                division_by_zero_mod_ccall,
                division_by_zero_cdeploy,
                division_by_zero_ccall,
            ]),
        TypeParseFailure(_) => Tested(vec![
                parse_tests::test_invalid_principal_literal,
                principal_wrong_byte_length,
            ]),
        ASTError(_) => Unreachable_Functionally(
                "AST errors cannot occur through normal Clarity operations. \
            They exist only for CLI and testing functions that bypass AST parsing \
            that occurs during a typical contract deploy. These wrapped `ParseError` \
            are exhaustively covered by (`parse_tests`)."
            ),
        MaxStackDepthReached => Tested(vec![
                stack_depth_too_deep_call_chain_ccall,
                stack_depth_too_deep_call_chain_cdeploy
            ]),
        MaxContextDepthReached => Unreachable_Functionally(
                "The maximum context depth limit cannot be reached through normal Clarity code. \
            Both the call-stack depth limit and the parser's expression-depth limit \
            are significantly lower and will trigger first. Only low-level Rust unit tests \
            can construct a context deep enough to hit this error."
            ),
        BadTypeConstruction => Unreachable_Functionally(
                "BadTypeConstruction is rejected during static analysis at contract-publish time. \
            Any value construction that would produce an ill-formed type fails parsing or \
            type-checking before the contract is stored on-chain."
            ),
        BadBlockHeight(_) => Unreachable_Functionally(
                "All block heights referenced via `at-block` or `get-block-info?` are guaranteed \
            to exist in the node's historical database during normal execution. \
            This error only surfaces if the chainstate is missing blocks or corrupted."
            ),
        NoSuchToken => Unreachable_Functionally(
                "NFT operations return `none` when an instance does not exist. \
            The `NoSuchToken` runtime error is only emitted from internal VM assertions \
            and cannot be triggered by regular Clarity code unless storage is manually corrupted."
            ),
        NotImplemented => Unreachable_Functionally(
                "Indicates use of an unimplemented VM feature. \
            Can only be hit by directly invoking unfinished Rust internals – not reachable from Clarity."
            ),
        NoCallerInContext => Unreachable_Functionally(
                "Every function call (public, private, or trait) is executed with a valid caller context. \
            This error only appears when the execution environment is manually constructed incorrectly."
            ),
        NoSenderInContext => Unreachable_Functionally(
                "Every on-chain transaction and contract-call has a well-defined sender. \
            This error only occurs in malformed test harnesses."
            ),
        BadNameValue(_, _) => Unreachable_Functionally(
                "Contract, function, trait, and variable names are fully validated during static analysis at publish time. \
            The runtime only ever encounters already-validated names. \
            Only corrupted state or manual VM manipulation can produce this error."
            ),
        UnknownBlockHeaderHash(_) => Tested(vec![unknown_block_header_hash_fork]),
        BadBlockHash(_) => Tested(vec![bad_block_hash]),
        UnwrapFailure => Tested(vec![
                unwrap_err_panic_on_ok_runtime,
                unwrap_panic_on_err_runtime
            ]),
        DefunctPoxContract => Tested(vec![defunct_pox_contracts]),
        PoxAlreadyLocked => Ignored(
                "The active PoX contract already returns ERR_STACKING_ALREADY_STACKED for double-locking attempts. \
            The VM-level PoxAlreadyLocked error is only triggerable if locking occurs across PoX boundaries. \
            This is better suited for unit testing."
            ),
        BlockTimeNotAvailable => Tested(vec![block_time_not_available]),
        BadTokenName(_) => Ignored("Error variant tests should be added"),
    }
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `pow` arithmetic operation at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_pow_at_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "overflow-pow",
        contract_code: "(define-constant overflow (pow 2 128))",
    );
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `pow` arithmetic operation at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_pow_ccall() {
    contract_call_consensus_test!(
        contract_name: "overflow-pow",
        contract_code: "
(define-public (trigger-overflow-pow)
  (ok (pow 2 128))
)",
        function_name: "trigger-overflow-pow",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `mul` arithmetic operation at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_mul_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "overflow-mul",
        contract_code: &format!("(define-constant overflow (* u{} u2))", u128::MAX),
    );
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `mul` arithmetic operation at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_mul_ccall() {
    contract_call_consensus_test!(
        contract_name: "overflow-mul",
        contract_code: &format!("
(define-public (trigger-overflow-mul)
  (ok (* u{} u2))
)" , u128::MAX),
        function_name: "trigger-overflow-mul",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `add` arithmetic operation at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_add_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "overflow-add",
        contract_code: &format!("(define-constant overflow (+ u{} u1))", u128::MAX),
    );
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `add` arithmetic operation at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_add_ccall() {
    contract_call_consensus_test!(
        contract_name: "overflow-add",
        contract_code: &format!("
(define-public (trigger-overflow-add)
  (ok (+ u{} u1))
)", u128::MAX),
        function_name: "trigger-overflow-add",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `to-int` conversion at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_to_int_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "overflow-to-int",
        contract_code: &format!("(define-constant overflow (to-int u{}))", u128::MAX),
    );
}

/// Error: [`RuntimeError::ArithmeticOverflow`]
/// Caused by: overflow when doing `to-int` conversion at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_overflow_to_int_ccall() {
    contract_call_consensus_test!(
        contract_name: "overflow-to-int",
        contract_code: &format!("
(define-public (overflow-to-int-large)
  (ok (to-int u{}))
)", u128::MAX),
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
        contract_code: &format!("
(define-fungible-token token)

(define-public (trigger-ft-mint-overflow)
  (begin
    (try! (ft-mint? token u{} tx-sender))
    (ft-mint? token u1 tx-sender)
  )
)", u128::MAX),
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
        contract_code: "
(define-fungible-token token u1000000)
(define-public (trigger-ft-supply-overflow)
  (begin
    (try! (ft-mint? token u500000 tx-sender))
    (ft-mint? token u600000 tx-sender)
  )
)
    ",
        function_name: "trigger-ft-supply-overflow",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: `native_to_uint` conversion of a negative number at deploy time.
/// Outcome: block accepted.
#[test]
fn to_uint_underflow_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "to-uint-negative",
        contract_code: "(define-constant overflow (to-uint -10))",
    );
}

/// Error: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: `native_to_uint` conversion of a negative number at call time.
/// Outcome: block accepted.
#[test]
fn to_uint_underflow_ccall() {
    contract_call_consensus_test!(
        contract_name: "to-uint-negative",
        contract_code: "
(define-read-only (trigger-underflow)
  (to-uint -10)
)",
        function_name: "trigger-underflow",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: subtraction at deploy time.
/// Outcome: block accepted.
#[test]
fn sub_underflow_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "sub-underflow-deploy",
        contract_code: "(define-constant overflow (- u10 u11))",
    );
}

/// Error: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: subtraction at call time.
/// Outcome: block accepted.
#[test]
fn sub_underflow_ccall() {
    contract_call_consensus_test!(
        contract_name: "sub-underflow",
        contract_code: "
(define-read-only (trigger-underflow)
  (- u10 u11)
)",
        function_name: "trigger-underflow",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: single-argument subtraction attempts to negate an unsigned integer at deploy time.
/// Outcome: block accepted.
#[test]
fn sub_arg_len_underflow_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "arg-len-underflow",
        contract_code: "(define-constant overflow (- u5))",
    );
}

/// Error: [`RuntimeError::ArithmeticUnderflow`]
/// Caused by: single-argument subtraction attempts to negate an unsigned integer at call time.
/// Outcome: block accepted.
#[test]
fn sub_arg_len_underflow_ccall() {
    contract_call_consensus_test!(
        contract_name: "arg-len-underflow",
        contract_code: "
(define-read-only (trigger) 
  (- u5))
",
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::DivisionByZero`]
/// Caused by: modulo at deploy time.
/// Outcome: block accepted.
#[test]
fn division_by_zero_mod_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "division-by-zero-mod",
        contract_code: "(define-constant overflow (mod 10 0))",
    );
}

/// Error: [`RuntimeError::DivisionByZero`]
/// Caused by: modulo at call time.
/// Outcome: block accepted.
#[test]
fn division_by_zero_mod_ccall() {
    contract_call_consensus_test!(
        contract_name: "division-by-zero-mod",
        contract_code: "
(define-read-only (trigger)
  (mod 10 0)
)",
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::DivisionByZero`]
/// Caused by: division at deploy time.
/// Outcome: block accepted.
#[test]
fn division_by_zero_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "division-by-zero",
        contract_code: "(define-constant overflow (/ 10 0))",
    );
}

/// Error: [`RuntimeError::DivisionByZero`]
/// Caused by: division at call time.
/// Outcome: block accepted.
#[test]
fn division_by_zero_ccall() {
    contract_call_consensus_test!(
        contract_name: "division-by-zero",
        contract_code: "
(define-read-only (trigger)
  (/ 10 0)
)",
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: sqrt of a negative integer at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_sqrti_neg_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "sqrti-neg-deploy",
        contract_code: "(define-constant overflow (sqrti -1))",
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: sqrt of a negative integer at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_sqrti_neg_ccall() {
    contract_call_consensus_test!(
        contract_name: "sqrti-neg",
        contract_code: "
(define-read-only (trigger)
  (sqrti -1)
)",
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: log2 of a negative integer at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_log2_neg_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "log2-neg-deploy",
        contract_code: "(define-constant overflow (log2 -8))",
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: log2 of a negative integer at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_log2_neg_ccall() {
    contract_call_consensus_test!(
        contract_name: "log2-neg",
        contract_code: "
(define-read-only (trigger)
  (log2 -8)
)",
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: pow of too large a number at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_pow_large_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "pow-large-deploy",
        contract_code: &format!(
            "(define-constant overflow (pow 2 {}))",
            u64::from(u32::MAX) + 1
        ),
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: pow of too large a number at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_pow_large_ccall() {
    contract_call_consensus_test!(
        contract_name: "pow-large",
        contract_code: &format!("
(define-read-only (trigger)
  (pow 2 {})
)", u64::from(u32::MAX) + 1),
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: pow of negative number at deploy time.
/// Outcome: block accepted.
#[test]
fn arithmetic_pow_neg_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "pow-neg-deploy",
        contract_code: "(define-constant overflow (pow 2 (- 1)))",
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: pow of negative number at call time.
/// Outcome: block accepted.
#[test]
fn arithmetic_pow_neg_ccall() {
    contract_call_consensus_test!(
        contract_name: "pow-neg",
        contract_code: "
(define-read-only (trigger)
  (pow 2 (- 1))
)",
        function_name: "trigger",
        function_args: &[],
    );
}
/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: calling nlogn with n = 0
/// Outcome: block accepted at deploy time.
/// Note: Returns a [`clarity::vm::analysis::CheckErrorKind::CostComputationFailed`] which wrapps the underlying [`RuntimeError::Arithmetic`] error.
#[test]
fn arithmetic_zero_n_log_n_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "zero-n-log-n-deploy",
        contract_code: "(define-constant overflow (from-consensus-buff? int 0x))",
        deploy_epochs: &StacksEpochId::since(StacksEpochId::Epoch21),
        exclude_clarity_versions: &[ClarityVersion::Clarity1],
    );
}

/// Error: [`RuntimeError::Arithmetic`]
/// Caused by: calling nlogn with n = 0
/// Outcome: block accepted at call time.
/// Note: Returns a [`clarity::vm::analysis::CheckErrorKind::CostComputationFailed`] which wrapps the underlying [`RuntimeError::Arithmetic`] error.
#[test]
fn arithmetic_zero_n_log_n_ccall() {
    contract_call_consensus_test!(
        contract_name: "zero-n-log-n",
        contract_code: "
(define-read-only (trigger)
  (from-consensus-buff? int 0x)
)",
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: &StacksEpochId::since(StacksEpochId::Epoch21),
        exclude_clarity_versions: &[ClarityVersion::Clarity1],
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
        contract_code: "
;; This literal decodes via c32 but has the wrong byte length
(define-constant my-principal 'S162RK3CHJPCSSK6BM757FW)",
    );
}

/// Error: [RuntimeError::MaxStackDepthReached]
/// Caused by: private function call chain exceeding runtime stack depth at deploy time.
/// Outcome: block accepted
#[test]
fn stack_depth_too_deep_call_chain_cdeploy() {
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
/// Caused by: private function call chain exceeding runtime stack depth at function call time.
/// Outcome: block accepted, execution rejected when function is called
#[test]
fn stack_depth_too_deep_call_chain_ccall() {
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
        contract_code: "
(define-public (trigger)
  (ok
    (at-block 
      0x0202020202020202020202020202020202020202020202020202020202020202
      (+ 1 2)
    )
  )
)",
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
        contract_code: "
(define-public (trigger)
  (ok
    (at-block 
      0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e
      (+ 1 2)
    )
  )
)",
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
        contract_code: "
(define-public (trigger (input (response uint uint))) 
    (ok (unwrap-err-panic input))
)",
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
        contract_code: "
(define-public (trigger (input (response uint uint)))
  (ok (unwrap-panic input))
)",
        function_name: "trigger",
        function_args: &[
            ClarityValue::Response(ResponseData {
                committed: false,
                data: Box::new(ClarityValue::UInt(3)),
            })
        ],
    );
}

/// Error: [`RuntimeError::DefunctPoxContract`]
/// Caused by: calling stack-stx on outdated pox contracts in the latest epoch
/// Outcome: block accepted
#[test]
fn defunct_pox_contracts() {
    let sender_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let address = to_addr(&sender_sk);
    let principal: PrincipalData = address.clone().into();
    let signer_key = StacksPublicKey::from_private(&sender_sk);

    let nonce = 0;
    let hash_mode = AddressHashMode::SerializeP2PKH;
    let addr_bytes = address.bytes();
    let lock_period = 1;
    let auth_id = 1;
    let height = 48;
    let pox_address = PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, addr_bytes.clone());

    let lock_amount = TestStacker::DEFAULT_STACKER_AMOUNT;
    let addr_bytes = address.bytes();
    let lock_period = 1;
    let auth_id = 1;

    let initial_balances = vec![(principal.clone(), u64::try_from(lock_amount).unwrap() * 2)];

    let signature = make_signer_key_signature(
        &pox_address,
        &sender_sk,
        6,
        &Pox4SignatureTopic::StackStx,
        1,
        u128::MAX,
        auth_id,
    );

    let mut blocks = vec![];
    // Attempt to mine each transaction in a diff block
    for tx in [
        // These pox lockups should fail
        make_pox_lockup(
            &sender_sk,
            nonce,
            lock_amount,
            hash_mode,
            addr_bytes,
            lock_period,
            height,
        ),
        make_pox_2_lockup(
            &sender_sk,
            nonce + 1,
            lock_amount,
            pox_address.clone(),
            lock_period,
            height,
        ),
        make_pox_3_lockup(
            &sender_sk,
            nonce + 2,
            lock_amount,
            pox_address.clone(),
            lock_period,
            height,
        ),
        // This final lockup should succeed until we upgrade our pox contract
        make_pox_4_lockup(
            &sender_sk,
            nonce + 3,
            lock_amount,
            &pox_address,
            1,
            &signer_key,
            48,
            Some(signature.clone()),
            u128::MAX,
            auth_id,
        ),
    ] {
        blocks.push(TestBlock {
            transactions: vec![tx],
        })
    }

    let epoch_blocks = HashMap::from([(StacksEpochId::latest(), blocks)]);

    let results = ConsensusTest::new(function_name!(), initial_balances, epoch_blocks).run();

    insta::assert_ron_snapshot!(results);
}

/// Error: [`RuntimeError::BlockTimeNotAvailable`]
/// Caused by: attempting to retrieve the stacks-block-time from a pre-3.3 height
/// Outcome: block accepted
#[test]
fn block_time_not_available() {
    contract_call_consensus_test!(
        contract_name: "no-block-time",
        contract_code: "
        (define-read-only (trigger (height uint))
          (ok (at-block (unwrap! (get-stacks-block-info? id-header-hash height) (err u100))
            stacks-block-time
           ))
        )",
        function_name: "trigger",
        function_args: &[ClarityValue::UInt(1)],
        deploy_epochs: &StacksEpochId::since(StacksEpochId::Epoch33),
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    )
}
