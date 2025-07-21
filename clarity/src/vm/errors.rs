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

pub use clarity_serialization::errors::CodecError;
#[cfg(feature = "rusqlite")]
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
use crate::vm::types::Value;

#[derive(Debug)]
pub struct IncomparableError<T> {
    pub err: T,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// UncheckedErrors are errors that *should* be caught by the
    ///   TypeChecker and other check passes. Test executions may
    ///   trigger these errors.
    Unchecked(CheckErrors),
    Interpreter(InterpreterError),
    Runtime(RuntimeErrorType, Option<StackTrace>),
    ShortReturn(ShortReturnType),
}
impl From<CodecError> for Error {
    fn from(err: CodecError) -> Self {
        match err {
            CodecError::ParseError(msg) => Error::from(RuntimeErrorType::ParseError(msg)),
            CodecError::BadTypeConstruction => Error::from(RuntimeErrorType::BadTypeConstruction),
            CodecError::ValueTooLarge => Error::from(CheckErrors::ValueTooLarge),
            CodecError::ValueOutOfBounds => Error::from(CheckErrors::ValueOutOfBounds),
            CodecError::TypeSignatureTooDeep => Error::from(CheckErrors::TypeSignatureTooDeep),
            CodecError::SupertypeTooLarge => Error::from(CheckErrors::SupertypeTooLarge),
            CodecError::EmptyTuplesNotAllowed => Error::from(CheckErrors::EmptyTuplesNotAllowed),
            CodecError::FailureConstructingTupleWithType => {
                Error::from(InterpreterError::FailureConstructingTupleWithType)
            }
            CodecError::FailureConstructingListWithType => {
                Error::from(InterpreterError::FailureConstructingListWithType)
            }
            CodecError::ListTypesMustMatch => Error::from(CheckErrors::ListTypesMustMatch),
            CodecError::TypeError { expected, found } => {
                Error::from(CheckErrors::TypeError(*expected, *found))
            }
            CodecError::TypeValueError { expected, found } => {
                Error::from(CheckErrors::TypeValueError(*expected, *found))
            }
            CodecError::CouldNotDetermineSerializationType => {
                Error::from(CheckErrors::CouldNotDetermineSerializationType)
            }
            CodecError::CouldNotDetermineType => Error::from(CheckErrors::CouldNotDetermineType),
            CodecError::NameAlreadyUsedInTuple(name) => {
                Error::from(CheckErrors::NameAlreadyUsed(name))
            }
            CodecError::NoSuchTupleField(name, tuple_type_signature) => {
                Error::from(CheckErrors::NoSuchTupleField(name, tuple_type_signature))
            }
            CodecError::InvalidClarityName(name, msg) => {
                Error::from(RuntimeErrorType::BadNameValue(name, msg))
            }
            CodecError::InvalidContractName(name, msg) => {
                Error::from(RuntimeErrorType::BadNameValue(name, msg))
            }
            CodecError::InvalidStringCharacters => {
                Error::from(CheckErrors::InvalidCharactersDetected)
            }
            CodecError::InvalidUtf8Encoding => Error::from(CheckErrors::InvalidUTF8Encoding),
            CodecError::Expect(msg) => Error::from(CheckErrors::Expects(msg)),
            // These errors don't have a match in CheckErrors, so we convert
            // them to a descriptive string inside the `Expects` variant.
            // Based on the current code, this should never happen.
            CodecError::Io(_)
            | CodecError::Serialization(_)
            | CodecError::Deserialization(_)
            | CodecError::DeserializeExpected(_)
            | CodecError::UnexpectedSerialization
            | CodecError::LeftoverBytesInDeserialization => Error::from(CheckErrors::from(err)),
        }
    }
}

/// InterpreterErrors are errors that *should never* occur.
/// Test executions may trigger these errors.
#[derive(Debug, PartialEq)]
pub enum InterpreterError {
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

#[derive(Debug, PartialEq)]
pub enum ShortReturnType {
    ExpectedValue(Value),
    AssertionFailed(Value),
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
            Error::Runtime(ref err, ref stack) => {
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

impl From<CheckErrors> for Error {
    fn from(err: CheckErrors) -> Self {
        Error::Unchecked(err)
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

#[cfg(test)]
impl From<Error> for () {
    fn from(err: Error) -> Self {}
}

impl From<ShortReturnType> for Value {
    fn from(val: ShortReturnType) -> Self {
        match val {
            ShortReturnType::ExpectedValue(v) => v,
            ShortReturnType::AssertionFailed(v) => v,
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
