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

pub mod analysis;
pub mod ast;
pub mod cost;
pub mod lexer;

use std::{error, fmt};

pub use analysis::{CheckErrorKind, StaticCheckError};
pub use ast::{ParseError, ParseErrors, ParseResult};
pub use cost::CostErrors;
pub use lexer::LexerError;
#[cfg(feature = "rusqlite")]
use rusqlite::Error as SqliteError;
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::representations::SymbolicExpression;
use crate::types::{FunctionIdentifier, Value};

pub type StackTrace = Vec<FunctionIdentifier>;

#[derive(Debug)]
pub struct IncomparableError<T> {
    pub err: T,
}

#[derive(Debug)]
pub enum Error {
    /// UncheckedErrors are errors that *should* be caught by the
    ///   TypeChecker and other check passes. Test executions may
    ///   trigger these errors.
    Unchecked(CheckErrorKind),
    Interpreter(InterpreterError),
    Runtime(RuntimeError, Option<StackTrace>),
    EarlyReturn(EarlyReturnError),
}

/// InterpreterErrors are errors that *should never* occur.
/// Test executions may trigger these errors.
#[derive(Debug, PartialEq)]
pub enum InterpreterError {
    BadSymbolicRepresentation(String),
    InterpreterError(String),
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
    DBError(String),
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
    /// Failure to parse types dynamically during contract execution.
    /// The `String` represents the specific parsing issue, such as invalid data formats.
    TypeParseFailure(String),
    /// Failure to parse the abstract syntax tree (AST) during dynamic evaluation.
    /// The `Box<ParseError>` wraps the specific parsing error encountered, detailing code interpretation issues.
    ASTError(Box<ParseError>),
    /// The call stack exceeded the virtual machine's maximum depth.
    MaxStackDepthReached,
    /// The execution context depth exceeded the virtual machine's limit.
    MaxContextDepthReached,
    /// Attempt to construct an invalid or unsupported type at runtime (e.g., malformed data structure).
    BadTypeConstruction,
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
    /// Invalid name-value pair in contract data (e.g., map keys).
    /// The `&'static str` represents the name of the invalid pair, and the `String` represents the offending value.
    BadNameValue(&'static str, String),
    /// Reference to a non-existent block header hash.
    /// The `BlockHeaderHash` represents the unknown block header hash.
    UnknownBlockHeaderHash(BlockHeaderHash),
    /// Invalid block hash provided (e.g., incorrect format or length).
    /// The `Vec<u8>` represents the invalid block hash data.
    BadBlockHash(Vec<u8>),
    /// Failed to unwrap an `Optional` (`none`) or `Response` (`err` or `ok`) Clarity value.
    UnwrapFailure,
    /// Attempt to set metadata (e.g., for NFTs or tokens) that was already initialized.
    MetadataAlreadySet,
    /// Interaction with a deprecated or inactive Proof of Transfer (PoX) contract.
    DefunctPoxContract,
    /// Attempt to lock STX for stacking when already locked in an active PoX cycle.
    PoxAlreadyLocked,
    /// Block time unavailable during execution.
    BlockTimeNotAvailable,
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

pub type InterpreterResult<R> = Result<R, Error>;

impl<T> PartialEq<IncomparableError<T>> for IncomparableError<T> {
    fn eq(&self, _other: &IncomparableError<T>) -> bool {
        false
    }
}

impl PartialEq<Error> for Error {
    fn eq(&self, other: &Error) -> bool {
        match (self, other) {
            (Error::Runtime(x, _), Error::Runtime(y, _)) => x == y,
            (Error::Unchecked(x), Error::Unchecked(y)) => x == y,
            (Error::EarlyReturn(x), Error::EarlyReturn(y)) => x == y,
            (Error::Interpreter(x), Error::Interpreter(y)) => x == y,
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Runtime(err, stack) => {
                write!(f, "{err}")?;
                if let Some(stack_trace) = stack {
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

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        match *err.err {
            ParseErrors::InterpreterFailure => Error::from(InterpreterError::Expect(
                "Unexpected interpreter failure during parsing".into(),
            )),
            _ => Error::from(RuntimeError::ASTError(Box::new(err))),
        }
    }
}

impl From<CostErrors> for Error {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::InterpreterFailure => Error::from(InterpreterError::Expect(
                "Interpreter failure during cost calculation".into(),
            )),
            CostErrors::Expect(s) => Error::from(InterpreterError::Expect(format!(
                "Interpreter failure during cost calculation: {s}"
            ))),
            other_err => Error::from(CheckErrorKind::from(other_err)),
        }
    }
}

impl From<RuntimeError> for Error {
    fn from(err: RuntimeError) -> Self {
        Error::Runtime(err, None)
    }
}

impl From<CheckErrorKind> for Error {
    fn from(err: CheckErrorKind) -> Self {
        Error::Unchecked(err)
    }
}

impl From<(CheckErrorKind, &SymbolicExpression)> for Error {
    fn from(err: (CheckErrorKind, &SymbolicExpression)) -> Self {
        Error::Unchecked(err.0)
    }
}

impl From<EarlyReturnError> for Error {
    fn from(err: EarlyReturnError) -> Self {
        Error::EarlyReturn(err)
    }
}

impl From<InterpreterError> for Error {
    fn from(err: InterpreterError) -> Self {
        Error::Interpreter(err)
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<Error> for () {
    fn from(_err: Error) -> Self {}
}

impl From<EarlyReturnError> for Value {
    fn from(val: EarlyReturnError) -> Self {
        match val {
            EarlyReturnError::UnwrapFailed(v) => *v,
            EarlyReturnError::AssertionFailed(v) => *v,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn equality() {
        assert_eq!(
            Error::EarlyReturn(EarlyReturnError::UnwrapFailed(Box::new(Value::Bool(true)))),
            Error::EarlyReturn(EarlyReturnError::UnwrapFailed(Box::new(Value::Bool(true))))
        );
        assert_eq!(
            Error::Interpreter(InterpreterError::InterpreterError("".to_string())),
            Error::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
        assert!(
            Error::EarlyReturn(EarlyReturnError::UnwrapFailed(Box::new(Value::Bool(true))))
                != Error::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
    }
}
