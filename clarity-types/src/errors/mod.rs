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

pub use analysis::{CheckError, CheckErrors};
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
    Unchecked(CheckErrors),
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
    Runtime(RuntimeErrorType, Option<StackTrace>),
    ShortReturn(ShortReturnType),
}

/// Represents an internal, unrecoverable error within the Clarity VM.
///
/// These errors signify a bug in the VM's logic or a violation of its internal
/// invariants. They are not meant to be caught or handled by Clarity contracts.
#[derive(Debug, PartialEq)]
pub enum VmInternalError {
    BadSymbolicRepresentation(String),
    /// A generic, unexpected internal error, indicating a logic failure within
    /// the VM.
    /// TODO: merge with VmInternalError::Expect
    AssertionFailed(String),
    /// The VM failed to produce the final `AssetMap` when finalizing the
    /// execution environment for a transaction.
    FailedToConstructAssetTable,
    /// The VM failed to produce the final `EventBatch` when finalizing the
    /// execution environment for a transaction.
    FailedToConstructEventBatch,
    /// An error occurred during an interaction with the database.
    #[cfg(feature = "rusqlite")]
    SqliteError(IncomparableError<SqliteError>),
    /// The file path provided for the MARF database is invalid because it
    /// contains non-UTF-8 characters.
    BadFileName,
    /// The VM failed to create the necessary directory for the MARF persistent
    /// storage. Likely due to a file system permissions error or an invalid path
    FailedToCreateDataDirectory,
    /// A failure occurred within the MARF implementation.
    MarfFailure(String),
    /// Failed to construct a tuple value from provided data because it did not
    ///  match the expected type signature.
    FailureConstructingTupleWithType,
    /// Failed to construct a list value from provided data because it
    /// did not match the expected type signature.
    FailureConstructingListWithType,
    /// An STX transfer failed due to insufficient balance.
    InsufficientBalance,
    /// A generic error occurred during a database operation.
    DBError(String),
    /// An internal expectation or assertion failed. This is used for conditions
    /// that are believed to be unreachable but are handled gracefully to prevent
    /// a panic.
    Expect(String),
}

/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq)]
pub enum RuntimeErrorType {
    Arithmetic(String),
    ArithmeticOverflow,
    ArithmeticUnderflow,
    SupplyOverflow(u128, u128),
    SupplyUnderflow(u128, u128),
    DivisionByZero,
    // error in parsing types
    ParseError(String),
    // error in parsing the AST
    ASTError(Box<ParseError>),
    MaxStackDepthReached,
    MaxContextDepthReached,
    BadTypeConstruction,
    BadBlockHeight(String),
    NoSuchToken,
    NotImplemented,
    NoCallerInContext,
    NoSenderInContext,
    BadNameValue(&'static str, String),
    UnknownBlockHeaderHash(BlockHeaderHash),
    BadBlockHash(Vec<u8>),
    UnwrapFailure,
    MetadataAlreadySet,
    // pox-locking errors
    DefunctPoxContract,
    PoxAlreadyLocked,

    BlockTimeNotAvailable,
}

#[derive(Debug, PartialEq)]
pub enum ShortReturnType {
    ExpectedValue(Box<Value>),
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
            (Error::ShortReturn(x), Error::ShortReturn(y)) => x == y,
            (Error::Internal(x), Error::Internal(y)) => x == y,
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

impl fmt::Display for RuntimeErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for RuntimeErrorType {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        match *err.err {
            ParseErrors::InterpreterFailure => Error::from(VmInternalError::Expect(
                "Unexpected interpreter failure during parsing".into(),
            )),
            _ => Error::from(RuntimeErrorType::ASTError(Box::new(err))),
        }
    }
}

impl From<CostErrors> for Error {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::InterpreterFailure => Error::from(VmInternalError::Expect(
                "Interpreter failure during cost calculation".into(),
            )),
            CostErrors::Expect(s) => Error::from(VmInternalError::Expect(format!(
                "Interpreter failure during cost calculation: {s}"
            ))),
            other_err => Error::from(CheckErrors::from(other_err)),
        }
    }
}

impl From<RuntimeErrorType> for Error {
    fn from(err: RuntimeErrorType) -> Self {
        Error::Runtime(err, None)
    }
}

impl From<CheckErrors> for Error {
    fn from(err: CheckErrors) -> Self {
        Error::Unchecked(err)
    }
}

impl From<(CheckErrors, &SymbolicExpression)> for Error {
    fn from(err: (CheckErrors, &SymbolicExpression)) -> Self {
        Error::Unchecked(err.0)
    }
}

impl From<ShortReturnType> for Error {
    fn from(err: ShortReturnType) -> Self {
        Error::ShortReturn(err)
    }
}

impl From<VmInternalError> for Error {
    fn from(err: VmInternalError) -> Self {
        Error::Internal(err)
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<Error> for () {
    fn from(_err: Error) -> Self {}
}

impl From<ShortReturnType> for Value {
    fn from(val: ShortReturnType) -> Self {
        match val {
            ShortReturnType::ExpectedValue(v) => *v,
            ShortReturnType::AssertionFailed(v) => *v,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn equality() {
        assert_eq!(
            Error::ShortReturn(ShortReturnType::ExpectedValue(Box::new(Value::Bool(true)))),
            Error::ShortReturn(ShortReturnType::ExpectedValue(Box::new(Value::Bool(true))))
        );
        assert_eq!(
            Error::Internal(VmInternalError::AssertionFailed("".to_string())),
            Error::Internal(VmInternalError::AssertionFailed("".to_string()))
        );
        assert!(
            Error::ShortReturn(ShortReturnType::ExpectedValue(Box::new(Value::Bool(true))))
                != Error::Internal(VmInternalError::AssertionFailed("".to_string()))
        );
    }
}
