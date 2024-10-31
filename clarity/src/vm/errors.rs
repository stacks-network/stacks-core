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

use std::error::Error as ErrorTrait;
use std::{error, fmt};

#[cfg(feature = "canonical")]
use rusqlite::Error as SqliteError;
use serde_json::Error as SerdeJSONErr;
use stacks_common::types::chainstate::BlockHeaderHash;

use super::ast::errors::ParseErrors;
pub use crate::vm::analysis::errors::{
    check_argument_count, check_arguments_at_least, check_arguments_at_most, CheckErrors,
};
use crate::vm::ast::errors::ParseError;
use crate::vm::contexts::StackTrace;
use crate::vm::costs::CostErrors;
use crate::vm::types::{TypeSignature, Value};

#[derive(Debug)]
pub struct IncomparableError<T> {
    pub err: T,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// UncheckedErrors are errors that *should* be caught by the
    ///   TypeChecker and other check passes. Test executions may
    ///   trigger these errors.
    #[error("{0:?}")]
    Unchecked(#[from] CheckErrors),
    #[error("{0:?}")]
    Interpreter(#[from] InterpreterError),
    #[error("{0}{}", .1.as_deref().map(|stack_trace| 
        {
            let result = "\n StackTrace: \n".into();
            stack_trace.iter().fold(result, |acc, item| {
                format!("{}{}\n", acc, item)
            })
        }).unwrap_or("".into()))]
    Runtime(RuntimeErrorType, Option<StackTrace>),
    #[error("{0:?}")]
    ShortReturn(ShortReturnType),
}

/// InterpreterErrors are errors that *should never* occur.
/// Test executions may trigger these errors.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum InterpreterError {
    #[error("Bad sender: {0}")]
    BadSender(Value),
    #[error("Bad symbolic representation: {0}")]
    BadSymbolicRepresentation(String),
    #[error("Interpreter error: {0}")]
    InterpreterError(String),
    #[error("Uninitialized persisted variable")]
    UninitializedPersistedVariable,
    #[error("Failed to construct asset table")]
    FailedToConstructAssetTable,
    #[error("Failed to construct event batch")]
    FailedToConstructEventBatch,
    #[cfg(feature = "canonical")]
    #[error("Sqlite error: {0:?}")]
    SqliteError(IncomparableError<SqliteError>),
    #[error("Bad file name")]
    BadFileName,
    #[error("Failed to create data directory")]
    FailedToCreateDataDirectory,
    #[error("MARF failure: {0}")]
    MarfFailure(String),
    #[error("Failure constructing tuple with type")]
    FailureConstructingTupleWithType,
    #[error("Failure constructing list with type")]
    FailureConstructingListWithType,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Cost contract load failure")]
    CostContractLoadFailure,
    #[error("DB error: {0}")]
    DBError(String),
    #[error("Expect: {0}")]
    Expect(String),
}

/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum RuntimeErrorType {
    #[error("Arithmetic: {0}")]
    Arithmetic(String),
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
    #[error("Arithmetic underflow")]
    ArithmeticUnderflow,
    #[error("Supply overflow: {0} + {1}")]
    SupplyOverflow(u128, u128),
    #[error("Supply underflow: {0} - {1}")]
    SupplyUnderflow(u128, u128),
    #[error("Division by zero")]
    DivisionByZero,
    // error in parsing types
    #[error("Parse type error: {0}")]
    ParseError(String),
    // error in parsing the AST
    #[error("AST parsing error: {0}")]
    ASTError(ParseError),
    #[error("Max stack depth reached")]
    MaxStackDepthReached,
    #[error("Max context depth reached")]
    MaxContextDepthReached,
    #[error("List dimension too high")]
    ListDimensionTooHigh,
    #[error("Bad type construciton")]
    BadTypeConstruction,
    #[error("Value too large")]
    ValueTooLarge,
    #[error("Bad block height: {0}")]
    BadBlockHeight(String),
    #[error("Transfer non positive amount")]
    TransferNonPositiveAmount,
    #[error("No such token")]
    NoSuchToken,
    #[error("Not implemented")]
    NotImplemented,
    #[error("No caller in context")]
    NoCallerInContext,
    #[error("No sender in context")]
    NoSenderInContext,
    #[error("Non positive token supply")]
    NonPositiveTokenSupply,
    #[error("JSON parse error: {0:?}")]
    JSONParseError(IncomparableError<SerdeJSONErr>),
    #[error("Attempt to fetch in transient context")]
    AttemptToFetchInTransientContext,
    #[error("Bad name value: {0}, {1}")]
    BadNameValue(&'static str, String),
    #[error("Unknown block header hash: {0}")]
    UnknownBlockHeaderHash(BlockHeaderHash),
    #[error("Bad block hash: {0:?}")]
    BadBlockHash(Vec<u8>),
    #[error("Unwrap failure")]
    UnwrapFailure,
    #[error("Defunct pox contract")]
    DefunctPoxContract,
    #[error("Pox already locked")]
    PoxAlreadyLocked,
    #[error("Metadata already set")]
    MetadataAlreadySet,
}

#[derive(Debug, PartialEq)]
pub enum ShortReturnType {
    ExpectedValue(Value),
    AssertionFailed(Value),
}

pub type InterpreterResult<R> = Result<R, Error>;

impl<T> PartialEq<IncomparableError<T>> for IncomparableError<T> {
    fn eq(&self, _other: &IncomparableError<T>) -> bool {
        return false;
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

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        match &err.err {
            ParseErrors::InterpreterFailure => Error::from(InterpreterError::Expect(
                "Unexpected interpreter failure during parsing".into(),
            )),
            _ => Error::from(RuntimeErrorType::ASTError(err)),
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

impl From<RuntimeErrorType> for Error {
    fn from(err: RuntimeErrorType) -> Self {
        Error::Runtime(err, None)
    }
}
impl From<ShortReturnType> for Error {
    fn from(err: ShortReturnType) -> Self {
        Error::ShortReturn(err)
    }
}

#[cfg(test)]
impl From<Error> for () {
    fn from(err: Error) -> Self {}
}

impl Into<Value> for ShortReturnType {
    fn into(self) -> Value {
        match self {
            ShortReturnType::ExpectedValue(v) => v,
            ShortReturnType::AssertionFailed(v) => v,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vm::execute;

    #[test]
    #[cfg(feature = "developer-mode")]
    fn error_formats() {
        let t = "(/ 10 0)";
        let expected = "DivisionByZero
 Stack Trace: 
_native_:native_div
";

        assert_eq!(format!("{}", execute(t).unwrap_err()), expected);
    }

    #[test]
    fn equality() {
        assert_eq!(
            Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Bool(true))),
            Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Bool(true)))
        );
        assert_eq!(
            Error::Interpreter(InterpreterError::InterpreterError("".to_string())),
            Error::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
        assert!(
            Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Bool(true)))
                != Error::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
    }
}
