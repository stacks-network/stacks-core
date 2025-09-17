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
pub enum VmExecutionError {
    /// UncheckedErrors are errors that *should* be caught by the
    ///   TypeChecker and other check passes. Test executions may
    ///   trigger these errors.
    Unchecked(CheckErrors),
    Interpreter(InterpreterError),
    Runtime(RuntimeErrorType, Option<StackTrace>),
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

pub type InterpreterResult<R> = Result<R, VmExecutionError>;

impl<T> PartialEq<IncomparableError<T>> for IncomparableError<T> {
    fn eq(&self, _other: &IncomparableError<T>) -> bool {
        false
    }
}

impl PartialEq<VmExecutionError> for VmExecutionError {
    fn eq(&self, other: &VmExecutionError) -> bool {
        match (self, other) {
            (VmExecutionError::Runtime(x, _), VmExecutionError::Runtime(y, _)) => x == y,
            (VmExecutionError::Unchecked(x), VmExecutionError::Unchecked(y)) => x == y,
            (VmExecutionError::ShortReturn(x), VmExecutionError::ShortReturn(y)) => x == y,
            (VmExecutionError::Interpreter(x), VmExecutionError::Interpreter(y)) => x == y,
            _ => false,
        }
    }
}

impl fmt::Display for VmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VmExecutionError::Runtime(err, stack) => {
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

impl error::Error for VmExecutionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for RuntimeErrorType {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<ParseError> for VmExecutionError {
    fn from(err: ParseError) -> Self {
        match *err.err {
            ParseErrors::InterpreterFailure => VmExecutionError::from(InterpreterError::Expect(
                "Unexpected interpreter failure during parsing".into(),
            )),
            _ => VmExecutionError::from(RuntimeErrorType::ASTError(Box::new(err))),
        }
    }
}

impl From<CostErrors> for VmExecutionError {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::InterpreterFailure => VmExecutionError::from(InterpreterError::Expect(
                "Interpreter failure during cost calculation".into(),
            )),
            CostErrors::Expect(s) => VmExecutionError::from(InterpreterError::Expect(format!(
                "Interpreter failure during cost calculation: {s}"
            ))),
            other_err => VmExecutionError::from(CheckErrors::from(other_err)),
        }
    }
}

impl From<RuntimeErrorType> for VmExecutionError {
    fn from(err: RuntimeErrorType) -> Self {
        VmExecutionError::Runtime(err, None)
    }
}

impl From<CheckErrors> for VmExecutionError {
    fn from(err: CheckErrors) -> Self {
        VmExecutionError::Unchecked(err)
    }
}

impl From<(CheckErrors, &SymbolicExpression)> for VmExecutionError {
    fn from(err: (CheckErrors, &SymbolicExpression)) -> Self {
        VmExecutionError::Unchecked(err.0)
    }
}

impl From<ShortReturnType> for VmExecutionError {
    fn from(err: ShortReturnType) -> Self {
        VmExecutionError::ShortReturn(err)
    }
}

impl From<InterpreterError> for VmExecutionError {
    fn from(err: InterpreterError) -> Self {
        VmExecutionError::Interpreter(err)
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<VmExecutionError> for () {
    fn from(_err: VmExecutionError) -> Self {}
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
            VmExecutionError::ShortReturn(ShortReturnType::ExpectedValue(Box::new(Value::Bool(
                true
            )))),
            VmExecutionError::ShortReturn(ShortReturnType::ExpectedValue(Box::new(Value::Bool(
                true
            ))))
        );
        assert_eq!(
            VmExecutionError::Interpreter(InterpreterError::InterpreterError("".to_string())),
            VmExecutionError::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
        assert!(
            VmExecutionError::ShortReturn(ShortReturnType::ExpectedValue(Box::new(Value::Bool(
                true
            )))) != VmExecutionError::Interpreter(InterpreterError::InterpreterError(
                "".to_string()
            ))
        );
    }
}
