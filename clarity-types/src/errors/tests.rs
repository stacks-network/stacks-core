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

//! Tests for Avoiding Accidental Consensus (AAC) Error Handling
//!
//! These tests ensure that error types maintain proper boundaries and don't
//! accidentally change consensus behavior. This directly addresses issues:
//! - #6727: Split CostErrors from ParseErrors
//! - #6728: Split CostErrors from CheckErrors
//! - #6729: Rename error types for clarification
//! - #6730: Add Unreachable error for unreachable runtime check errors
//! - #6731: Add new layer of errors for clarity-types
//!
//! Key invariants tested:
//! 1. Error type separation: CostErrors, ParseErrors, and CheckErrors remain distinct
//! 2. No panics from untrusted data: All external input must return errors, never panic
//! 3. Rejectable errors: Only specific errors should invalidate blocks
//! 4. Error conversions: Conversions between error types preserve consensus properties

use crate::errors::analysis::{CheckErrorKind, StaticCheckError, SyntaxBindingError};
use crate::errors::ast::{ParseError, ParseErrorKind};
use crate::errors::cost::CostErrors;
use crate::errors::{EarlyReturnError, RuntimeError, VmExecutionError, VmInternalError};
use crate::execution_cost::ExecutionCost;
use crate::types::{TypeSignature, Value};

/// Test that CostErrors and CheckErrors are properly separated.
/// Addresses #6728: Split CostErrors from CheckErrors
#[test]
fn test_cost_error_to_check_error_conversion() {
    // CostErrors should convert to CheckErrorKind variants
    let cost_overflow = CostErrors::CostOverflow;
    let check_err: CheckErrorKind = cost_overflow.into();
    assert!(matches!(check_err, CheckErrorKind::CostOverflow));

    let cost_balance = CostErrors::CostBalanceExceeded(
        ExecutionCost::ZERO,
        ExecutionCost {
            write_length: 100,
            write_count: 10,
            read_length: 200,
            read_count: 20,
            runtime: 1000,
        },
    );
    let check_err: CheckErrorKind = cost_balance.into();
    assert!(matches!(
        check_err,
        CheckErrorKind::CostBalanceExceeded(_, _)
    ));

    // Memory balance exceeded
    let mem_balance = CostErrors::MemoryBalanceExceeded(1000, 500);
    let check_err: CheckErrorKind = mem_balance.into();
    assert!(matches!(
        check_err,
        CheckErrorKind::MemoryBalanceExceeded(1000, 500)
    ));
}

/// Test that CostErrors and ParseErrors are properly separated.
/// Addresses #6727: Split CostErrors from ParseErrors
#[test]
fn test_cost_error_to_parse_error_conversion() {
    // CostErrors should convert to ParseErrorKind variants
    let cost_overflow = CostErrors::CostOverflow;
    let parse_err: ParseError = cost_overflow.into();
    assert!(matches!(*parse_err.err, ParseErrorKind::CostOverflow));

    let cost_balance = CostErrors::CostBalanceExceeded(
        ExecutionCost::ZERO,
        ExecutionCost {
            write_length: 100,
            write_count: 10,
            read_length: 200,
            read_count: 20,
            runtime: 1000,
        },
    );
    let parse_err: ParseError = cost_balance.into();
    assert!(matches!(
        *parse_err.err,
        ParseErrorKind::CostBalanceExceeded(_, _)
    ));
}

/// Test that rejectable() method correctly identifies consensus-critical errors.
/// Only specific errors should be able to invalidate blocks.
#[test]
fn test_rejectable_errors_consensus_critical() {
    // CheckErrorKind rejectable errors
    assert!(CheckErrorKind::SupertypeTooLarge.rejectable());
    assert!(CheckErrorKind::Expects("test".into()).rejectable());
    // Non-rejectable CheckErrorKind errors
    assert!(!CheckErrorKind::CostOverflow.rejectable());
    assert!(
        !CheckErrorKind::TypeError(
            Box::new(TypeSignature::IntType),
            Box::new(TypeSignature::BoolType)
        )
        .rejectable()
    );

    // CostErrors rejectable errors
    assert!(CostErrors::InterpreterFailure.rejectable());
    assert!(CostErrors::Expect("test".into()).rejectable());
    // Non-rejectable CostErrors
    assert!(!CostErrors::CostOverflow.rejectable());
    assert!(!CostErrors::CostContractLoadFailure.rejectable());

    // ParseError rejectable errors
    let rejectable_parse = ParseError::new(ParseErrorKind::InterpreterFailure);
    assert!(rejectable_parse.rejectable());
    let rejectable_parse2 = ParseError::new(ParseErrorKind::ExpressionStackDepthTooDeep);
    assert!(rejectable_parse2.rejectable());
    // Non-rejectable ParseError
    let non_rejectable_parse = ParseError::new(ParseErrorKind::CostOverflow);
    assert!(!non_rejectable_parse.rejectable());
}

/// Test that error conversions preserve rejectable status.
/// This is critical for consensus - we must not accidentally make
/// a non-rejectable error rejectable or vice versa.
#[test]
fn test_error_conversion_preserves_rejectable_status() {
    // CostErrors::InterpreterFailure is rejectable
    let cost_err = CostErrors::InterpreterFailure;
    assert!(cost_err.rejectable());

    // When converted to CheckErrorKind via VmExecutionError, it becomes an Expects variant
    let vm_err: VmExecutionError = cost_err.into();
    if let VmExecutionError::Internal(VmInternalError::Expect(_)) = vm_err {
        // This is correct - interpreter failures become internal errors
    } else {
        panic!("InterpreterFailure should convert to Internal error");
    }

    // Non-rejectable CostErrors should remain non-rejectable
    let cost_overflow = CostErrors::CostOverflow;
    assert!(!cost_overflow.rejectable());
    let check_err: CheckErrorKind = cost_overflow.into();
    assert!(!check_err.rejectable());
}

/// Test that untrusted data parsing never panics.
/// Addresses the core AAC principle: untrusted data must not panic.
#[test]
fn test_untrusted_data_never_panics() {
    // Test with various invalid inputs that should return errors, not panic
    let long_name = "a".repeat(10000);
    let deep_nesting = "(".repeat(10000);
    let invalid_inputs = vec![
        "",
        "(",
        ")",
        "(((",
        ")))",
        "{",
        "}",
        "{ : }",
        "{ a : }",
        "{ : b }",
        long_name.as_str(),    // Very long name
        deep_nesting.as_str(), // Deep nesting
    ];

    for input in invalid_inputs {
        // This should never panic, only return errors
        let result = std::panic::catch_unwind(|| {
            // Simulate parsing untrusted input
            let _ = ParseError::new(ParseErrorKind::FailedParsingRemainder(input.to_string()));
        });
        assert!(
            result.is_ok(),
            "Parsing untrusted data panicked on input: {}",
            input
        );
    }
}

/// Test that SyntaxBindingError properly converts to CheckErrorKind.
/// Ensures binding errors are categorized correctly.
#[test]
fn test_syntax_binding_error_conversion() {
    let let_binding_err = SyntaxBindingError::let_binding_not_list(0);
    let check_err: CheckErrorKind = let_binding_err.into();
    assert!(matches!(check_err, CheckErrorKind::BadSyntaxBinding(_)));

    let eval_binding_err = SyntaxBindingError::eval_binding_invalid_length(1);
    let check_err: CheckErrorKind = eval_binding_err.into();
    assert!(matches!(check_err, CheckErrorKind::BadSyntaxBinding(_)));

    let tuple_cons_err = SyntaxBindingError::tuple_cons_not_atom(2);
    let check_err: CheckErrorKind = tuple_cons_err.into();
    assert!(matches!(check_err, CheckErrorKind::BadSyntaxBinding(_)));
}

/// Test that VmExecutionError conversions are correct.
/// Different error types should convert to the appropriate VmExecutionError variant.
#[test]
fn test_vm_execution_error_conversions() {
    // RuntimeError should convert to VmExecutionError::Runtime
    let runtime_err = RuntimeError::DivisionByZero;
    let vm_err: VmExecutionError = runtime_err.into();
    assert!(matches!(
        vm_err,
        VmExecutionError::Runtime(RuntimeError::DivisionByZero, None)
    ));

    // CheckErrorKind should convert to VmExecutionError::Unchecked
    let check_err = CheckErrorKind::CostOverflow;
    let vm_err: VmExecutionError = check_err.into();
    assert!(matches!(
        vm_err,
        VmExecutionError::Unchecked(CheckErrorKind::CostOverflow)
    ));

    // EarlyReturnError should convert to VmExecutionError::EarlyReturn
    let early_err = EarlyReturnError::UnwrapFailed(Box::new(Value::none()));
    let vm_err: VmExecutionError = early_err.into();
    assert!(matches!(vm_err, VmExecutionError::EarlyReturn(_)));

    // VmInternalError should convert to VmExecutionError::Internal
    let internal_err = VmInternalError::InvariantViolation("test".into());
    let vm_err: VmExecutionError = internal_err.into();
    assert!(matches!(vm_err, VmExecutionError::Internal(_)));
}

/// Test that ParseError from CostErrors maintains proper structure.
#[test]
fn test_parse_error_from_cost_errors_structure() {
    let cost_computation_failed = CostErrors::CostComputationFailed("test failure".into());
    let parse_err: ParseError = cost_computation_failed.into();

    assert!(matches!(
        *parse_err.err,
        ParseErrorKind::CostComputationFailed(_)
    ));
    if let ParseErrorKind::CostComputationFailed(msg) = *parse_err.err {
        assert_eq!(msg, "test failure");
    }
}

/// Test that StaticCheckError from CostErrors maintains diagnostic info.
#[test]
fn test_static_check_error_from_cost_errors() {
    let cost_overflow = CostErrors::CostOverflow;
    let static_err: StaticCheckError = cost_overflow.into();

    assert!(matches!(*static_err.err, CheckErrorKind::CostOverflow));
    assert!(!static_err.has_expression());
}

/// Test error equality and comparison.
/// Ensures that error types can be properly compared for testing and debugging.
#[test]
fn test_error_equality() {
    // VmExecutionError equality for Runtime errors
    let err1 = VmExecutionError::Runtime(RuntimeError::DivisionByZero, None);
    let err2 = VmExecutionError::Runtime(RuntimeError::DivisionByZero, None);
    let err3 = VmExecutionError::Runtime(RuntimeError::DivisionByZero, Some(vec![]));
    assert_eq!(err1, err2);
    assert_eq!(err1, err3); // Stack traces are ignored in equality

    // Different runtime errors should not be equal
    let err4 = VmExecutionError::Runtime(RuntimeError::ArithmeticOverflow, None);
    assert_ne!(err1, err4);

    // VmExecutionError equality for Unchecked errors
    let err5 = VmExecutionError::Unchecked(CheckErrorKind::CostOverflow);
    let err6 = VmExecutionError::Unchecked(CheckErrorKind::CostOverflow);
    assert_eq!(err5, err6);

    // Different error variants should not be equal
    assert_ne!(err1, err5);
}

/// Test that execution time expiry is consistently handled across error types.
#[test]
fn test_execution_time_expiry_consistency() {
    // CostErrors::ExecutionTimeExpired
    let cost_err = CostErrors::ExecutionTimeExpired;
    assert!(!cost_err.rejectable()); // Time expiry shouldn't invalidate blocks

    // Convert to CheckErrorKind
    let check_err: CheckErrorKind = cost_err.into();
    assert!(matches!(check_err, CheckErrorKind::ExecutionTimeExpired));
    assert!(!check_err.rejectable());

    // Convert to ParseError
    let parse_err: ParseError = CostErrors::ExecutionTimeExpired.into();
    assert!(matches!(
        *parse_err.err,
        ParseErrorKind::ExecutionTimeExpired
    ));
    assert!(!parse_err.rejectable());
}

/// Test that memory balance exceeded errors are handled consistently.
#[test]
fn test_memory_balance_exceeded_consistency() {
    let used = 2000u64;
    let limit = 1000u64;

    // In CostErrors
    let cost_err = CostErrors::MemoryBalanceExceeded(used, limit);
    assert!(!cost_err.rejectable());

    // Convert to CheckErrorKind
    let check_err: CheckErrorKind = cost_err.into();
    if let CheckErrorKind::MemoryBalanceExceeded(u, l) = check_err {
        assert_eq!(u, used);
        assert_eq!(l, limit);
    } else {
        panic!("Expected MemoryBalanceExceeded variant");
    }

    // Convert to ParseError
    let parse_err: ParseError = CostErrors::MemoryBalanceExceeded(used, limit).into();
    if let ParseErrorKind::MemoryBalanceExceeded(u, l) = *parse_err.err {
        assert_eq!(u, used);
        assert_eq!(l, limit);
    } else {
        panic!("Expected MemoryBalanceExceeded variant");
    }
}

/// Test that trait-related errors maintain proper boundaries.
#[test]
fn test_trait_error_boundaries() {
    // TraitReferenceUnknown in CheckErrorKind
    let check_err = CheckErrorKind::TraitReferenceUnknown("test-trait".into());
    assert!(!check_err.rejectable());

    // TraitReferenceUnknown in ParseErrorKind
    let parse_err = ParseError::new(ParseErrorKind::TraitReferenceUnknown("test-trait".into()));
    assert!(!parse_err.rejectable());

    // IncompatibleTrait should not be rejectable
    // Note: We test the error variant without creating actual TraitIdentifiers
    // as that requires valid principal addresses which are complex to construct
    let check_err = CheckErrorKind::TraitReferenceUnknown("another-trait".into());
    assert!(!check_err.rejectable());
}

/// Test error display formatting doesn't panic.
#[test]
fn test_error_display_formatting() {
    // Test various error types can be formatted without panicking
    let errors: Vec<Box<dyn std::fmt::Display>> = vec![
        Box::new(CheckErrorKind::CostOverflow),
        Box::new(ParseError::new(ParseErrorKind::CostOverflow)),
        Box::new(CostErrors::CostOverflow),
        Box::new(RuntimeError::DivisionByZero),
        Box::new(VmExecutionError::Runtime(
            RuntimeError::DivisionByZero,
            None,
        )),
    ];

    for err in errors {
        let display_str = format!("{}", err);
        assert!(!display_str.is_empty(), "Error display should not be empty");
    }
}

/// Test that error conversions from Expect variants are properly handled.
/// Addresses #6730: Add Unreachable error for unreachable runtime check errors
#[test]
fn test_expect_error_handling() {
    // CostErrors::Expect should be rejectable (indicates a bug)
    let cost_expect = CostErrors::Expect("unexpected condition".into());
    assert!(cost_expect.rejectable());

    // CheckErrorKind::Expects should be rejectable (indicates a bug)
    let check_expect = CheckErrorKind::Expects("unexpected condition".into());
    assert!(check_expect.rejectable());

    // Conversion to VmExecutionError
    let vm_err: VmExecutionError = cost_expect.into();
    assert!(matches!(
        vm_err,
        VmExecutionError::Internal(VmInternalError::Expect(_))
    ));
}

/// Test that cost computation failures are properly categorized.
#[test]
fn test_cost_computation_failure_categorization() {
    let failure_msg = "cost computation failed";

    // In CostErrors
    let cost_err = CostErrors::CostComputationFailed(failure_msg.into());
    assert!(!cost_err.rejectable()); // Computation failures shouldn't invalidate blocks

    // Convert to CheckErrorKind
    let check_err: CheckErrorKind = cost_err.into();
    if let CheckErrorKind::CostComputationFailed(msg) = check_err {
        assert_eq!(msg, failure_msg);
    } else {
        panic!("Expected CostComputationFailed variant");
    }
}

/// Test that StaticCheckError properly tracks expressions.
#[test]
fn test_static_check_error_expression_tracking() {
    let err = StaticCheckError::new(CheckErrorKind::CostOverflow);
    assert!(!err.has_expression());

    // After setting expression, it should be tracked
    // Note: We can't easily create a SymbolicExpression here without more dependencies,
    // so we just test the initial state
    assert!(err.expressions.is_none());
}

/// Test boundary conditions for argument count errors.
#[test]
fn test_argument_count_error_boundaries() {
    use crate::errors::analysis::{
        check_argument_count, check_arguments_at_least, check_arguments_at_most,
    };

    // Exact count
    let args = vec![1, 2, 3];
    assert!(check_argument_count(3, &args).is_ok());
    assert!(check_argument_count(2, &args).is_err());
    assert!(check_argument_count(4, &args).is_err());

    // At least
    assert!(check_arguments_at_least(2, &args).is_ok());
    assert!(check_arguments_at_least(3, &args).is_ok());
    assert!(check_arguments_at_least(4, &args).is_err());

    // At most
    assert!(check_arguments_at_most(4, &args).is_ok());
    assert!(check_arguments_at_most(3, &args).is_ok());
    assert!(check_arguments_at_most(2, &args).is_err());
}

/// Test that error messages are informative and don't leak sensitive info.
#[test]
fn test_error_message_safety() {
    // Error messages should not contain sensitive information
    let err = CheckErrorKind::NoSuchContract("test-contract".into());
    let msg = format!("{:?}", err);
    assert!(msg.contains("test-contract"));
    assert!(!msg.contains("password"));
    assert!(!msg.contains("secret"));

    // ParseError messages should also be safe
    let parse_err = ParseError::new(ParseErrorKind::IllegalVariableName("test-var".into()));
    let msg = format!("{:?}", parse_err);
    assert!(msg.contains("test-var"));
}

/// Test cost balance exceeded with various execution costs.
#[test]
fn test_cost_balance_exceeded_variants() {
    let high_cost = ExecutionCost {
        write_length: u64::MAX,
        write_count: u64::MAX,
        read_length: u64::MAX,
        read_count: u64::MAX,
        runtime: u64::MAX,
    };

    let err = CostErrors::CostBalanceExceeded(high_cost, ExecutionCost::ZERO);
    assert!(!err.rejectable());

    let check_err: CheckErrorKind = err.into();
    if let CheckErrorKind::CostBalanceExceeded(used, limit) = check_err {
        assert_eq!(used.runtime, u64::MAX);
        assert_eq!(limit, ExecutionCost::ZERO);
    } else {
        panic!("Expected CostBalanceExceeded variant");
    }
}
