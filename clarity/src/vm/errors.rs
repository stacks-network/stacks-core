// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::{error, fmt};

#[cfg(feature = "rusqlite")]
use rusqlite::Error as SqliteError;
use serde_json::Error as SerdeJSONErr;
use stacks_common::types::chainstate::BlockHeaderHash;

use super::ast::errors::ParseErrors;
pub use crate::vm::analysis::errors::{
    check_argument_count, check_arguments_at_least, check_arguments_at_most, CheckErrorKind,
    SyntaxBindingError, SyntaxBindingErrorType,
};
use crate::vm::ast::errors::ParseError;
use crate::vm::contexts::StackTrace;
use crate::vm::costs::CostErrors;
use crate::vm::types::Value;
use crate::vm::SymbolicExpression;

#[derive(Debug)]
pub struct IncomparableError<T> {
    pub err: T,
}

/// Represents any error that can occur during the execution phase of the Clarity VM.
///
/// This enum categorizes all possible failure modes **after** a program has been successfully
/// parsed and statically analyzed. It serves as the comprehensive error type for the
/// evaluation loop.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum VmExecutionError {
    /// A semantically valid error that is part of the Clarity language specification.
    ///
    /// These are errors that user-written smart contracts are expected to be able to
    /// trigger, such as arithmetic overflows or failed assertions. The VM is behaving
    /// correctly when it produces a `Runtime` error.
    ///
    /// # Example
    /// A user's code executes `(/ 1 0)`, resulting in `RuntimeError::DivisionByZero`.
    Runtime(RuntimeError, Option<StackTrace>),

    /// A critical, unrecoverable bug within the VM's internal logic.
    ///
    /// The presence of this error indicates a violation of one of the VM's invariants
    /// or a corrupted state. This is **not** an error in the user's Clarity code, but
    /// rather a bug in the VM's Rust implementation that requires a developer's attention.
    ///
    /// # Example
    /// The VM's evaluation loop attempts to `pop` from an empty internal call stack,
    /// indicating a mismatch in function entry/exit logic.
    Internal(VmInternalError),

    /// A failure of a language rule discovered during execution.
    /// The Clarity VM performs static analysis before execution to catch errors like
    /// incorrect argument counts or type mismatches. However, some checks can only
    /// be fully resolved during execution.
    /// If one of these checks fails, it produces a `IntegrityCheck` error.
    ///
    /// # Example
    /// TODO: I still have to dive into the exact cases!
    IntegrityCheck(CheckErrorKind),

    /// A control-flow mechanism for implementing an early return from a function.
    ///
    /// This is **not** a true error. It is used by native Clarity functions like
    /// `asserts!`, `unwrap!`, and `try!` to immediately halt execution and return a
    /// value from the current function.
    EarlyReturn(EarlyReturnValue),
}

/// VmInternalError are errors that *should never* occur.
/// Test executions may trigger these errors.
#[derive(Debug, PartialEq)]
pub enum VmInternalError {
    BadSender(Value),
    BadSymbolicRepresentation(String),
    InterpreterError(String),
    UninitializedPersistedVariable,
    FailedToConstructAssetTable,
    FailedToConstructEventBatch,
    #[cfg(feature = "rusqlite")]
    SqliteError(IncomparableError<SqliteError>),
    BadFileName,
    FailedToCreateDataDirectory,
    MarfFailure(String),
    FailureConstructingTupleWithType,
    FailureConstructingListWithType,
    InsufficientBalance,
    CostContractLoadFailure,
    DBError(String),
    Expect(String),
}

/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq)]
pub enum RuntimeError {
    Arithmetic(String),
    ArithmeticOverflow,
    ArithmeticUnderflow,
    SupplyOverflow(u128, u128),
    SupplyUnderflow(u128, u128),
    DivisionByZero,
    // error in parsing types
    ParseError(String),
    // error in parsing the AST
    ASTError(ParseError),
    MaxStackDepthReached,
    MaxContextDepthReached,
    ListDimensionTooHigh,
    BadTypeConstruction,
    ValueTooLarge,
    BadBlockHeight(String),
    TransferNonPositiveAmount,
    NoSuchToken,
    NotImplemented,
    NoCallerInContext,
    NoSenderInContext,
    NonPositiveTokenSupply,
    JSONParseError(IncomparableError<SerdeJSONErr>),
    AttemptToFetchInTransientContext,
    BadNameValue(&'static str, String),
    UnknownBlockHeaderHash(BlockHeaderHash),
    BadBlockHash(Vec<u8>),
    UnwrapFailure,
    DefunctPoxContract,
    PoxAlreadyLocked,
    MetadataAlreadySet,
}

/// The value to be returned by an `EarlyReturn` control-flow event.
#[derive(Debug, PartialEq)]
pub enum EarlyReturnValue {
    /// The value returned by an `unwrap!`-style function when the unwrap fails.
    FromUnwrap(Value),
    /// The value returned by an `asserts!` expression when the assertion fails.
    FromAssert(Value),
}

pub type ExecutionResult<R> = Result<R, VmExecutionError>;

impl<T> PartialEq<IncomparableError<T>> for IncomparableError<T> {
    fn eq(&self, _other: &IncomparableError<T>) -> bool {
        false
    }
}

impl PartialEq<VmExecutionError> for VmExecutionError {
    fn eq(&self, other: &VmExecutionError) -> bool {
        match (self, other) {
            (VmExecutionError::Runtime(x, _), VmExecutionError::Runtime(y, _)) => x == y,
            (VmExecutionError::IntegrityCheck(x), VmExecutionError::IntegrityCheck(y)) => x == y,
            (VmExecutionError::EarlyReturn(x), VmExecutionError::EarlyReturn(y)) => x == y,
            (VmExecutionError::Internal(x), VmExecutionError::Internal(y)) => x == y,
            _ => false,
        }
    }
}

impl fmt::Display for VmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VmExecutionError::Runtime(ref err, ref stack) => {
                write!(f, "{err}")?;
                if let Some(ref stack_trace) = stack {
                    writeln!(f, "\n Stack Trace: ")?;
                    for item in stack_trace.iter() {
                        writeln!(f, "{item}")?;
                    }
                }
                Ok(())
            }
            _ => write!(f, "{self:?}"),
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl error::Error for VmExecutionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<ParseError> for VmExecutionError {
    fn from(err: ParseError) -> Self {
        match &err.err {
            ParseErrors::InterpreterFailure => VmExecutionError::from(VmInternalError::Expect(
                "Unexpected interpreter failure during parsing".into(),
            )),
            _ => VmExecutionError::from(RuntimeError::ASTError(err)),
        }
    }
}

impl From<CostErrors> for VmExecutionError {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::InterpreterFailure => VmExecutionError::from(VmInternalError::Expect(
                "Interpreter failure during cost calculation".into(),
            )),
            CostErrors::Expect(s) => VmExecutionError::from(VmInternalError::Expect(format!(
                "Interpreter failure during cost calculation: {s}"
            ))),
            other_err => VmExecutionError::from(CheckErrorKind::from(other_err)),
        }
    }
}

impl From<RuntimeError> for VmExecutionError {
    fn from(err: RuntimeError) -> Self {
        VmExecutionError::Runtime(err, None)
    }
}

impl From<CheckErrorKind> for VmExecutionError {
    fn from(err: CheckErrorKind) -> Self {
        VmExecutionError::IntegrityCheck(err)
    }
}

impl From<(CheckErrorKind, &SymbolicExpression)> for VmExecutionError {
    fn from(err: (CheckErrorKind, &SymbolicExpression)) -> Self {
        VmExecutionError::IntegrityCheck(err.0)
    }
}

impl From<EarlyReturnValue> for VmExecutionError {
    fn from(err: EarlyReturnValue) -> Self {
        VmExecutionError::EarlyReturn(err)
    }
}

impl From<VmInternalError> for VmExecutionError {
    fn from(err: VmInternalError) -> Self {
        VmExecutionError::Internal(err)
    }
}

#[cfg(test)]
impl From<VmExecutionError> for () {
    fn from(err: VmExecutionError) -> Self {}
}

impl From<EarlyReturnValue> for Value {
    fn from(val: EarlyReturnValue) -> Self {
        match val {
            EarlyReturnValue::FromUnwrap(v) => v,
            EarlyReturnValue::FromAssert(v) => v,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "developer-mode")]
    fn error_formats() {
        let t = "(/ 10 0)";
        let expected = "DivisionByZero
 Stack Trace:
_native_:native_div
";

        assert_eq!(format!("{}", crate::vm::execute(t).unwrap_err()), expected);
    }

    #[test]
    fn equality() {
        assert_eq!(
            VmExecutionError::EarlyReturn(EarlyReturnValue::FromUnwrap(Value::Bool(true))),
            VmExecutionError::EarlyReturn(EarlyReturnValue::FromUnwrap(Value::Bool(true)))
        );
        assert_eq!(
            VmExecutionError::Internal(VmInternalError::InterpreterError("".to_string())),
            VmExecutionError::Internal(VmInternalError::InterpreterError("".to_string()))
        );
        assert!(
            VmExecutionError::EarlyReturn(EarlyReturnValue::FromUnwrap(Value::Bool(true)))
                != VmExecutionError::Internal(VmInternalError::InterpreterError("".to_string()))
        );
    }
}
