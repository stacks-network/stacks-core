// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use clarity_types::Value;
pub use clarity_types::errors::{ClarityTypeError, IncomparableError};
use clarity_types::errors::{CostErrors, ParseError};
use clarity_types::representations::SymbolicExpression;
use clarity_types::types::FunctionIdentifier;
#[cfg(feature = "rusqlite")]
use rusqlite::Error as SqliteError;
use stacks_common::types::chainstate::BlockHeaderHash;

pub use crate::vm::analysis::errors::{
    CommonCheckErrorKind, RuntimeCheckErrorKind, StaticCheckError, StaticCheckErrorKind,
    SyntaxBindingError, SyntaxBindingErrorType, check_argument_count, check_arguments_at_least,
    check_arguments_at_most,
};

pub type StackTrace = Vec<FunctionIdentifier>;

/// Errors that can occur during the runtime execution of Clarity contracts in the virtual machine.
/// These encompass type-checking failures, interpreter issues, runtime errors, and premature returns.
/// Unlike static analysis errors in `ClarityError::StaticCheck(StaticCheckError)` or `ClarityError::Parse(ParseError)`,
/// which are caught before execution during type-checking or parsing, these errors occur during dynamic
/// evaluation and may involve conditions not detectable statically, such as dynamically constructed expressions
/// (e.g., based on VRF seeds or runtime data).
#[derive(Debug)]
pub enum VmExecutionError {
    /// Type-checking errors caught during runtime analysis, which should typically be detected by
    /// static type-checking passes before execution. These may occur in test executions or when
    /// dynamic expression construction (e.g., using runtime data like VRF seeds) creates structures
    /// violating type or resource constraints (e.g., excessive stack depth).
    /// The `RuntimeCheckErrorKind` wraps the specific type-checking error encountered at runtime.
    RuntimeCheck(RuntimeCheckErrorKind),
    /// A critical, unrecoverable bug within the VM's internal logic.
    ///
    /// The presence of this error indicates a violation of one of the VM's
    /// invariants or a corrupted state. This is **not** an error in the user's
    /// Clarity code, but a bug in the VM's Rust implementation.
    ///
    /// # Example
    /// The VM's evaluation loop attempts to `pop` from an empty internal call stack,
    /// indicating a mismatch in function entry/exit logic.
    Internal(VmInternalError),
    /// Errors that occur during runtime execution of Clarity code, such as arithmetic errors or
    /// invalid operations, expected as part of contract evaluation.
    /// The `RuntimeError` wraps the specific runtime error, and the `Option<StackTrace>` provides
    /// an optional stack trace for debugging, if available.
    Runtime(RuntimeError, Option<StackTrace>),
    /// Errors triggered during Clarity contract evaluation that cause early termination with
    /// insufficient results (e.g., unwrapping an empty `Option`).
    /// The `EarlyReturnError` wraps the specific early return condition, detailing the premature
    /// termination cause.
    EarlyReturn(EarlyReturnError),
}

/// Represents an internal, unrecoverable error within the Clarity VM.
///
/// These errors signify a bug in the VM's logic or a violation of its internal
/// invariants. They are not meant to be caught or handled by Clarity contracts.
#[derive(Debug, PartialEq)]
pub enum VmInternalError {
    /// Raised when the VM encounters an invalid or malformed `SymbolicExpression`
    /// e.g., bad variable name or missing argument.
    /// The `String` provides a message describing the specific issue.
    BadSymbolicRepresentation(String),
    /// A generic, unexpected internal error, indicating a logic failure within
    /// the VM.
    /// The `String` provides a message describing the specific failure.
    InvariantViolation(String), // TODO: merge with VmInternalError::Expect
    /// The VM failed to produce the final `AssetMap` when finalizing the
    /// execution environment for a transaction.
    FailedToConstructAssetTable,
    /// The VM failed to produce the final `EventBatch` when finalizing the
    /// execution environment for a transaction.
    FailedToConstructEventBatch,
    /// An error occurred during an interaction with the database.
    /// The parameter contains the corresponding SQLite error.
    #[cfg(feature = "rusqlite")]
    SqliteError(IncomparableError<SqliteError>),
    /// The file path provided for the MARF database is invalid because it
    /// contains non-UTF-8 characters.
    BadFileName,
    /// The VM failed to create the necessary directory for the MARF persistent
    /// storage. Likely due to a file system permissions error or an invalid path
    FailedToCreateDataDirectory,
    /// A failure occurred within the MARF implementation.
    /// The `String` provides a message describing the specific failure.
    MarfFailure(String),
    /// An STX transfer failed due to insufficient balance.
    InsufficientBalance,
    /// A generic error occurred during a database operation.
    /// The `String` represents a descriptive message detailing the specific issue.
    DBError(String),
    /// An internal expectation or assertion failed. This is used for conditions
    /// that are believed to be unreachable but are handled gracefully to prevent
    /// a panic.
    /// The `String` provides a message describing the failed expectation.
    Expect(String),
}

/// Runtime errors that Clarity smart contracts are expected to trigger during execution in the virtual
/// machine, such as arithmetic errors, invalid operations, or blockchain-specific issues. These errors
/// are distinct from static analysis errors and occur during dynamic evaluation of contract code.
#[derive(Debug, PartialEq)]
pub enum RuntimeError {
    /// A generic arithmetic error encountered during contract execution.
    /// The `String` represents a descriptive message detailing the specific arithmetic issue.
    Arithmetic(String),
    /// An arithmetic operation exceeded the maximum value for the data type (e.g., `u128`).
    ArithmeticOverflow,
    /// An arithmetic operation resulted in a value below zero for an unsigned type.
    ArithmeticUnderflow,
    /// Attempt to increase token supply beyond the maximum limit.
    /// The first u128 represents the attempted new supply (current supply plus increase),
    /// and the second represents the maximum allowed supply.
    SupplyOverflow(u128, u128),
    /// Attempt to decrease token supply below zero.
    /// The first `u128` represents the current token supply, and the second represents the attempted decrease amount.
    SupplyUnderflow(u128, u128),
    /// Attempt to divide or compute modulo by zero.
    DivisionByZero,
    /// The call stack exceeded the virtual machine's maximum depth.
    MaxStackDepthReached,
    /// The execution context depth exceeded the virtual machine's limit.
    MaxContextDepthReached,
    /// Reference to an invalid or out-of-bounds block height.
    /// The `String` represents the string representation of the queried block height that was invalid.
    BadBlockHeight(String),
    /// Attempt to interact with a non-existent token (e.g., in NFT or fungible token operations).
    NoSuchToken,
    /// Feature or function not yet implemented in the virtual machine.
    NotImplemented,
    /// No caller principal available in the current execution context.
    NoCallerInContext,
    /// No sender principal available in the current execution context.
    NoSenderInContext,
    /// Reference to a non-existent block header hash.
    /// The `BlockHeaderHash` represents the unknown block header hash.
    UnknownBlockHeaderHash(BlockHeaderHash),
    /// Invalid block hash provided (e.g., incorrect format or length).
    /// The `Vec<u8>` represents the invalid block hash data.
    BadBlockHash(Vec<u8>),
    /// Failed to unwrap an `Optional` (`none`) or `Response` (`err` or `ok`) Clarity value.
    UnwrapFailure,
    /// Interaction with a deprecated or inactive Proof of Transfer (PoX) contract.
    DefunctPoxContract,
    /// Attempt to lock STX for stacking when already locked in an active PoX cycle.
    PoxAlreadyLocked,
    /// Block time unavailable during execution.
    BlockTimeNotAvailable,
    /// A Clarity string used as a token name for a post-condition is not a valid Clarity name.
    BadTokenName(String),
}

#[derive(Debug, PartialEq)]
/// Errors triggered during Clarity contract evaluation that cause early termination.
/// These errors halt evaluation and fail the transaction.
pub enum EarlyReturnError {
    /// Failed to unwrap an `Optional` (`none`) or `Response` (`err` or `ok`) Clarity value.
    /// The `Box<Value>` holds the original or thrown value. Triggered by `try!`, `unwrap-or`, or
    /// `unwrap-err-or`.
    UnwrapFailed(Box<Value>),
    /// An 'asserts!' expression evaluated to false.
    /// The `Box<Value>` holds the value provided as the second argument to `asserts!`.
    AssertionFailed(Box<Value>),
}

impl PartialEq<VmExecutionError> for VmExecutionError {
    fn eq(&self, other: &VmExecutionError) -> bool {
        match (self, other) {
            (VmExecutionError::Runtime(x, _), VmExecutionError::Runtime(y, _)) => x == y,
            (VmExecutionError::RuntimeCheck(x), VmExecutionError::RuntimeCheck(y)) => x == y,
            (VmExecutionError::EarlyReturn(x), VmExecutionError::EarlyReturn(y)) => x == y,
            (VmExecutionError::Internal(x), VmExecutionError::Internal(y)) => x == y,
            _ => false,
        }
    }
}

impl fmt::Display for VmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VmExecutionError::Runtime(err, stack) => {
                write!(f, "{err}")?;
                if let Some(stack_trace) = stack
                    && !stack_trace.is_empty()
                {
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

impl From<ClarityTypeError> for VmExecutionError {
    fn from(err: ClarityTypeError) -> Self {
        match err {
            ClarityTypeError::InvariantViolation(s) => {
                VmExecutionError::Internal(VmInternalError::Expect(s))
            }
            ClarityTypeError::InvalidPrincipalVersion(_) => VmExecutionError::Internal(
                VmInternalError::Expect("Unexpected principal data".into()),
            ),
            other_err => VmExecutionError::from(RuntimeCheckErrorKind::from(other_err)),
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
            other_err => VmExecutionError::from(RuntimeCheckErrorKind::from(other_err)),
        }
    }
}

impl From<RuntimeError> for VmExecutionError {
    fn from(err: RuntimeError) -> Self {
        VmExecutionError::Runtime(err, None)
    }
}

impl From<CommonCheckErrorKind> for VmExecutionError {
    fn from(err: CommonCheckErrorKind) -> Self {
        VmExecutionError::RuntimeCheck(err.into())
    }
}

impl From<RuntimeCheckErrorKind> for VmExecutionError {
    fn from(err: RuntimeCheckErrorKind) -> Self {
        VmExecutionError::RuntimeCheck(err)
    }
}

impl From<(CommonCheckErrorKind, &SymbolicExpression)> for VmExecutionError {
    fn from(err: (CommonCheckErrorKind, &SymbolicExpression)) -> Self {
        VmExecutionError::RuntimeCheck(err.0.into())
    }
}

impl From<EarlyReturnError> for VmExecutionError {
    fn from(err: EarlyReturnError) -> Self {
        VmExecutionError::EarlyReturn(err)
    }
}

impl From<VmInternalError> for VmExecutionError {
    fn from(err: VmInternalError) -> Self {
        VmExecutionError::Internal(err)
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<VmExecutionError> for () {
    fn from(_err: VmExecutionError) -> Self {}
}

impl From<EarlyReturnError> for Value {
    fn from(val: EarlyReturnError) -> Self {
        match val {
            EarlyReturnError::UnwrapFailed(v) => *v,
            EarlyReturnError::AssertionFailed(v) => *v,
        }
    }
}

/// An error that occurs during Clarity evaluation, either a VM execution error or a parse error.
#[derive(Debug, PartialEq)]
pub enum ClarityEvalError {
    Vm(VmExecutionError),
    Parse(ParseError),
}

impl From<VmExecutionError> for ClarityEvalError {
    fn from(err: VmExecutionError) -> Self {
        Self::Vm(err)
    }
}

impl From<ParseError> for ClarityEvalError {
    fn from(err: ParseError) -> Self {
        Self::Parse(err)
    }
}

impl From<RuntimeCheckErrorKind> for ClarityEvalError {
    fn from(err: RuntimeCheckErrorKind) -> Self {
        Self::Vm(err.into())
    }
}

impl From<RuntimeError> for ClarityEvalError {
    fn from(err: RuntimeError) -> Self {
        Self::Vm(err.into())
    }
}

impl fmt::Display for ClarityEvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClarityEvalError::Vm(err) => write!(f, "{err}"),
            ClarityEvalError::Parse(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(test)]
mod test {
    use clarity_types::Value;

    use crate::vm::errors::{EarlyReturnError, VmExecutionError, VmInternalError};

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
            VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(Box::new(Value::Bool(
                true
            )))),
            VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(Box::new(Value::Bool(
                true
            ))))
        );
        assert_eq!(
            VmExecutionError::Internal(VmInternalError::InvariantViolation("".to_string())),
            VmExecutionError::Internal(VmInternalError::InvariantViolation("".to_string()))
        );
        assert!(
            VmExecutionError::EarlyReturn(EarlyReturnError::UnwrapFailed(Box::new(Value::Bool(
                true
            )))) != VmExecutionError::Internal(VmInternalError::InvariantViolation("".to_string()))
        );
    }
}
