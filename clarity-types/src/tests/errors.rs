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

use crate::errors::analysis::{CheckErrorKind, StaticCheckError, SyntaxBindingError};
use crate::errors::ast::{ParseError, ParseErrorKind};
use crate::errors::cost::CostErrors;
use crate::errors::{EarlyReturnError, RuntimeError, VmExecutionError, VmInternalError};
use crate::execution_cost::ExecutionCost;
use crate::types::{TypeSignature, Value};

/// Test that CostErrors and CheckErrors are properly separated.
/// Tests all CostErrors variants convert correctly to CheckErrorKind.
#[test]
fn test_cost_error_to_check_error_conversion() {
    // CostOverflow
    let cost_overflow = CostErrors::CostOverflow;
    let check_err: CheckErrorKind = cost_overflow.into();
    assert!(matches!(check_err, CheckErrorKind::CostOverflow));

    // CostBalanceExceeded
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
        CheckErrorKind::CostBalanceExceeded(
            ExecutionCost::ZERO,
            ExecutionCost {
                write_length: 100,
                write_count: 10,
                read_length: 200,
                read_count: 20,
                runtime: 1000,
            }
        )
    ));

    // MemoryBalanceExceeded
    let mem_balance = CostErrors::MemoryBalanceExceeded(1000, 500);
    let check_err: CheckErrorKind = mem_balance.into();
    assert!(matches!(
        check_err,
        CheckErrorKind::MemoryBalanceExceeded(1000, 500)
    ));

    // CostContractLoadFailure
    let cost_contract_load = CostErrors::CostContractLoadFailure;
    let check_err: CheckErrorKind = cost_contract_load.into();
    assert!(matches!(
        check_err,
        CheckErrorKind::CostComputationFailed(ref msg) if msg == "Failed to load cost contract"
    ));

    // CostComputationFailed
    let cost_computation = CostErrors::CostComputationFailed("test failure".into());
    let check_err: CheckErrorKind = cost_computation.into();
    assert!(matches!(
        check_err,
        CheckErrorKind::CostComputationFailed(ref msg) if msg == "test failure"
    ));

    // ExecutionTimeExpired
    let time_expired = CostErrors::ExecutionTimeExpired;
    let check_err: CheckErrorKind = time_expired.into();
    assert!(matches!(check_err, CheckErrorKind::ExecutionTimeExpired));

    // InterpreterFailure
    let interpreter_failure = CostErrors::InterpreterFailure;
    let check_err: CheckErrorKind = interpreter_failure.into();
    assert!(matches!(
        check_err,
        CheckErrorKind::Expects(ref msg) if msg == "Unexpected interpreter failure in cost computation"
    ));

    // Expect
    let expect_err = CostErrors::Expect("unexpected condition".into());
    let check_err: CheckErrorKind = expect_err.into();
    assert!(matches!(
        check_err,
        CheckErrorKind::Expects(ref msg) if msg == "unexpected condition"
    ));
}

/// Test that CostErrors and ParseErrors are properly separated.
/// Tests all CostErrors variants convert correctly to ParseErrorKind.
#[test]
fn test_cost_error_to_parse_error_conversion() {
    // CostOverflow
    let cost_overflow = CostErrors::CostOverflow;
    let parse_err: ParseError = cost_overflow.into();
    assert!(matches!(*parse_err.err, ParseErrorKind::CostOverflow));

    // CostBalanceExceeded
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
        ParseErrorKind::CostBalanceExceeded(
            ExecutionCost::ZERO,
            ExecutionCost {
                write_length: 100,
                write_count: 10,
                read_length: 200,
                read_count: 20,
                runtime: 1000,
            }
        )
    ));

    // MemoryBalanceExceeded
    let mem_balance = CostErrors::MemoryBalanceExceeded(2000, 1000);
    let parse_err: ParseError = mem_balance.into();
    assert!(matches!(
        *parse_err.err,
        ParseErrorKind::MemoryBalanceExceeded(2000, 1000)
    ));

    // CostContractLoadFailure
    let cost_contract_load = CostErrors::CostContractLoadFailure;
    let parse_err: ParseError = cost_contract_load.into();
    assert!(matches!(
        *parse_err.err,
        ParseErrorKind::CostComputationFailed(ref msg) if msg == "Failed to load cost contract"
    ));

    // CostComputationFailed
    let cost_computation = CostErrors::CostComputationFailed("parse test failure".into());
    let parse_err: ParseError = cost_computation.into();
    assert!(matches!(
        *parse_err.err,
        ParseErrorKind::CostComputationFailed(ref msg) if msg == "parse test failure"
    ));

    // ExecutionTimeExpired
    let time_expired = CostErrors::ExecutionTimeExpired;
    let parse_err: ParseError = time_expired.into();
    assert!(matches!(
        *parse_err.err,
        ParseErrorKind::ExecutionTimeExpired
    ));

    // InterpreterFailure
    let interpreter_failure = CostErrors::InterpreterFailure;
    let parse_err: ParseError = interpreter_failure.into();
    assert!(matches!(*parse_err.err, ParseErrorKind::InterpreterFailure));

    // Expect
    let expect_err = CostErrors::Expect("parse unexpected condition".into());
    let parse_err: ParseError = expect_err.into();
    assert!(matches!(*parse_err.err, ParseErrorKind::InterpreterFailure));
}

/// Test that rejectable() method correctly identifies consensus-critical errors.
/// Only specific errors should be able to invalidate blocks.
/// This test comprehensively covers all rejectable and non-rejectable variants.
#[test]
fn test_rejectable_errors_consensus_critical() {
    // CheckErrorKind - ALL rejectable variants
    assert!(CheckErrorKind::SupertypeTooLarge.rejectable());
    assert!(CheckErrorKind::Expects("test".into()).rejectable());

    // CheckErrorKind - Representative non-rejectable variants
    assert!(!CheckErrorKind::CostOverflow.rejectable());
    assert!(
        !CheckErrorKind::CostBalanceExceeded(ExecutionCost::ZERO, ExecutionCost::ZERO).rejectable()
    );
    assert!(!CheckErrorKind::MemoryBalanceExceeded(100, 50).rejectable());
    assert!(!CheckErrorKind::CostComputationFailed("test".into()).rejectable());
    assert!(!CheckErrorKind::ExecutionTimeExpired.rejectable());
    assert!(
        !CheckErrorKind::TypeError(
            Box::new(TypeSignature::IntType),
            Box::new(TypeSignature::BoolType)
        )
        .rejectable()
    );
    assert!(!CheckErrorKind::ValueTooLarge.rejectable());
    assert!(!CheckErrorKind::TypeSignatureTooDeep.rejectable());

    // CostErrors - ALL rejectable variants
    assert!(CostErrors::InterpreterFailure.rejectable());
    assert!(CostErrors::Expect("test".into()).rejectable());

    // CostErrors - ALL non-rejectable variants
    assert!(!CostErrors::CostOverflow.rejectable());
    assert!(
        !CostErrors::CostBalanceExceeded(ExecutionCost::ZERO, ExecutionCost::ZERO).rejectable()
    );
    assert!(!CostErrors::MemoryBalanceExceeded(100, 50).rejectable());
    assert!(!CostErrors::CostContractLoadFailure.rejectable());
    assert!(!CostErrors::CostComputationFailed("test".into()).rejectable());
    assert!(!CostErrors::ExecutionTimeExpired.rejectable());

    // ParseError - ALL rejectable variants
    assert!(ParseError::new(ParseErrorKind::InterpreterFailure).rejectable());
    assert!(ParseError::new(ParseErrorKind::ExpressionStackDepthTooDeep).rejectable());
    assert!(ParseError::new(ParseErrorKind::VaryExpressionStackDepthTooDeep).rejectable());

    // ParseError - Representative non-rejectable variants
    assert!(!ParseError::new(ParseErrorKind::CostOverflow).rejectable());
    assert!(
        !ParseError::new(ParseErrorKind::CostBalanceExceeded(
            ExecutionCost::ZERO,
            ExecutionCost::ZERO
        ))
        .rejectable()
    );
    assert!(!ParseError::new(ParseErrorKind::MemoryBalanceExceeded(100, 50)).rejectable());
    assert!(!ParseError::new(ParseErrorKind::ExecutionTimeExpired).rejectable());
    assert!(!ParseError::new(ParseErrorKind::TooManyExpressions).rejectable());
    assert!(!ParseError::new(ParseErrorKind::ProgramTooLarge).rejectable());

    // StaticCheckError - Inherits rejectable status from CheckErrorKind
    let rejectable_static = StaticCheckError::new(CheckErrorKind::SupertypeTooLarge);
    assert!(rejectable_static.err.rejectable());
    let non_rejectable_static = StaticCheckError::new(CheckErrorKind::CostOverflow);
    assert!(!non_rejectable_static.err.rejectable());
}

/// Test that CostErrors to CheckError conversions preserve rejectable status.
/// This is critical for consensus - we must not accidentally make
/// a non-rejectable error rejectable or vice versa.
#[test]
fn test_cost_error_conversion_check_error_preserves_rejectable_status() {
    // Rejectable CostErrors should remain rejectable after conversion to CheckError
    let cost_expect = CostErrors::Expect("test".into());
    assert!(cost_expect.rejectable());
    let check_err: CheckErrorKind = cost_expect.into();
    assert!(check_err.rejectable());

    let cost_interpreter = CostErrors::InterpreterFailure;
    assert!(cost_interpreter.rejectable());
    // InterpreterFailure converts to Expects variant in CheckErrorKind
    let check_err: CheckErrorKind = cost_interpreter.into();
    assert!(check_err.rejectable());

    // Non-rejectable CostErrors should remain non-rejectable
    let cost_overflow = CostErrors::CostOverflow;
    assert!(!cost_overflow.rejectable());
    let check_err: CheckErrorKind = cost_overflow.into();
    assert!(!check_err.rejectable());
}

/// Test that CostErrors to ParseError conversions preserve rejectable status.
#[test]
fn test_cost_error_conversion_parse_error_preserves_rejectable_status() {
    // Rejectable CostErrors should remain rejectable after conversion to ParseError
    let cost_expect = CostErrors::Expect("test".into());
    assert!(cost_expect.rejectable());
    let parse_err: ParseError = cost_expect.into();
    assert!(parse_err.rejectable());

    let cost_interpreter = CostErrors::InterpreterFailure;
    assert!(cost_interpreter.rejectable());
    let parse_err: ParseError = cost_interpreter.into();
    assert!(parse_err.rejectable());

    // Non-rejectable CostErrors should remain non-rejectable
    let cost_overflow = CostErrors::CostOverflow;
    assert!(!cost_overflow.rejectable());
    let parse_err: ParseError = cost_overflow.into();
    assert!(!parse_err.rejectable());
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

    assert!(
        matches!(*parse_err.err, ParseErrorKind::CostComputationFailed(ref msg) if msg == "test failure"),
        "Expected CostComputationFailed with correct message"
    );
}

/// Test that StaticCheckError from CostErrors maintains diagnostic info.
#[test]
fn test_static_check_error_from_cost_errors() {
    let cost_overflow = CostErrors::CostOverflow;
    let static_err: StaticCheckError = cost_overflow.into();

    assert!(matches!(*static_err.err, CheckErrorKind::CostOverflow));
    assert!(!static_err.has_expression());
}

/// Test that VmExecutionError equality ignores stack traces.
#[test]
fn vm_execution_error_equality_ignores_stack_traces() {
    // Runtime ignores stack traces
    assert_eq!(
        VmExecutionError::Runtime(RuntimeError::DivisionByZero, None),
        VmExecutionError::Runtime(RuntimeError::DivisionByZero, Some(vec![])),
    );

    // But the underlying runtime error still matters
    assert_ne!(
        VmExecutionError::Runtime(RuntimeError::DivisionByZero, None),
        VmExecutionError::Runtime(RuntimeError::ArithmeticOverflow, None),
    );

    // And variants still matter
    assert_ne!(
        VmExecutionError::Runtime(RuntimeError::DivisionByZero, None),
        VmExecutionError::Unchecked(CheckErrorKind::CostOverflow),
    );
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
    assert!(
        matches!(check_err, CheckErrorKind::MemoryBalanceExceeded(u, l) if u == used && l == limit),
        "Expected MemoryBalanceExceeded variant with correct values"
    );

    // Convert to ParseError
    let parse_err: ParseError = CostErrors::MemoryBalanceExceeded(used, limit).into();
    assert!(
        matches!(*parse_err.err, ParseErrorKind::MemoryBalanceExceeded(u, l) if u == used && l == limit),
        "Expected MemoryBalanceExceeded variant with correct values"
    );
}

/// Test that error conversions from Expect variants are properly handled.
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
    assert!(
        matches!(
            vm_err,
            VmExecutionError::Internal(VmInternalError::Expect(_))
        ),
        "Expect errors should convert to Internal VmExecutionError"
    );
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
    assert!(
        matches!(check_err, CheckErrorKind::CostComputationFailed(ref msg) if msg == failure_msg),
        "Expected CostComputationFailed variant with correct message"
    );
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

/// Test cost balance exceeded with various execution costs.
/// Tests that all cost fields are preserved correctly, not just runtime.
#[test]
fn test_cost_balance_exceeded_variants() {
    // Test where only runtime exceeds (other fields are low)
    let runtime_exceeded = ExecutionCost {
        write_length: 10,
        write_count: 5,
        read_length: 20,
        read_count: 8,
        runtime: 1000,
    };
    let runtime_limit = ExecutionCost {
        write_length: 100,
        write_count: 50,
        read_length: 200,
        read_count: 80,
        runtime: 500,
    };
    let err = CostErrors::CostBalanceExceeded(runtime_exceeded, runtime_limit);
    assert!(!err.rejectable());
    let check_err: CheckErrorKind = err.into();
    assert!(
        matches!(
            check_err,
            CheckErrorKind::CostBalanceExceeded(ref used, ref limit)
            if used.write_length == 10 && used.write_count == 5
                && used.read_length == 20 && used.read_count == 8
                && used.runtime == 1000
                && limit.write_length == 100 && limit.write_count == 50
                && limit.read_length == 200 && limit.read_count == 80
                && limit.runtime == 500
        ),
        "Expected CostBalanceExceeded with all cost fields preserved"
    );

    // Test where only write_length exceeds (other fields are low)
    let write_exceeded = ExecutionCost {
        write_length: 5000,
        write_count: 2,
        read_length: 10,
        read_count: 3,
        runtime: 100,
    };
    let write_limit = ExecutionCost {
        write_length: 1000,
        write_count: 50,
        read_length: 1000,
        read_count: 50,
        runtime: 10000,
    };
    let err = CostErrors::CostBalanceExceeded(write_exceeded, write_limit);
    let check_err: CheckErrorKind = err.into();
    assert!(
        matches!(
            check_err,
            CheckErrorKind::CostBalanceExceeded(ref used, ref limit)
            if used.write_length == 5000 && used.write_count == 2
                && used.read_length == 10 && used.read_count == 3
                && used.runtime == 100
                && limit.write_length == 1000 && limit.write_count == 50
                && limit.read_length == 1000 && limit.read_count == 50
                && limit.runtime == 10000
        ),
        "Expected CostBalanceExceeded with all cost fields preserved"
    );
}
