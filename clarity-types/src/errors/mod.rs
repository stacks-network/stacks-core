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
    Interpreter(InterpreterError),
    Runtime(RuntimeError, Option<StackTrace>),
    ShortReturn(ShortReturnType),
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

/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq)]
pub enum RuntimeError {
    /// A generic arithmetic error with a descriptive message.
    Arithmetic(String),
    /// An arithmetic operation exceeded the maximum value for the data type (e.g., u128).
    ArithmeticOverflow,
    /// An arithmetic operation resulted in a value below zero for an unsigned type.
    ArithmeticUnderflow,
    /// Attempt to increase token supply beyond the maximum limit.
    /// The parameters represent the current supply and the attempted increase.
    SupplyOverflow(u128, u128),
    /// Attempt to decrease token supply below zero.
    /// The parameters represent the current supply and the attempted decrease.
    SupplyUnderflow(u128, u128),
    /// Attempt to divide or compute modulo by zero.
    DivisionByZero,
    /// Failure to parse types dynamically during execution.
    /// The string describes the specific parsing issue, such as invalid data formats.
    TypeParseFailure(String),
    /// Failure to parse the abstract syntax tree (AST) during dynamic evaluation.
    /// Wraps a detailed `ParseError` for issues in code interpretation.
    ASTError(Box<ParseError>),
    /// The call stack exceeded the virtual machine's maximum depth.
    MaxStackDepthReached,
    /// The execution context depth exceeded the virtual machine's limit.
    MaxContextDepthReached,
    /// Attempt to construct an invalid or unsupported type at runtime.
    BadTypeConstruction,
    /// Reference to an invalid or out-of-bounds block height.
    /// The string details the issue, such as querying a future block.
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
    /// The static string specifies the name, and the dynamic string provides the offending value.
    BadNameValue(&'static str, String),
    /// Reference to a non-existent block header hash.
    UnknownBlockHeaderHash(BlockHeaderHash),
    /// Invalid block hash provided (e.g., incorrect format or length).
    /// The byte vector contains the invalid hash data.
    BadBlockHash(Vec<u8>),
    /// Failed to unwrap an `Optional` (`none`) or `Response` (`err` or `ok`) Clarity value.
    UnwrapFailure,
    /// Attempt to set metadata already initialized (e.g., for NFTs or tokens).
    MetadataAlreadySet,
    /// Interaction with a deprecated or inactive Proof of Transfer (PoX) contract.
    DefunctPoxContract,
    /// Attempt to lock STX for stacking when already locked in an active PoX cycle.
    PoxAlreadyLocked,
    /// Block time unavailable during execution.
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
            other_err => Error::from(CheckErrors::from(other_err)),
        }
    }
}

impl From<RuntimeError> for Error {
    fn from(err: RuntimeError) -> Self {
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

impl From<InterpreterError> for Error {
    fn from(err: InterpreterError) -> Self {
        Error::Interpreter(err)
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
            Error::Interpreter(InterpreterError::InterpreterError("".to_string())),
            Error::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
        assert!(
            Error::ShortReturn(ShortReturnType::ExpectedValue(Box::new(Value::Bool(true))))
                != Error::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
    }
}
