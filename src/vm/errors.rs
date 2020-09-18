use std::fmt;
use std::error;
use vm::ast::errors::ParseError;
pub use vm::analysis::errors::{CheckErrors};
pub use vm::analysis::errors::{check_argument_count, check_arguments_at_least};
use vm::types::{Value, TypeSignature};
use vm::contexts::StackTrace;
use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::index::{Error as MarfError};
use vm::costs::CostErrors;
use serde_json::Error as SerdeJSONErr;
use rusqlite::Error as SqliteError;

#[derive(Debug)]
pub struct IncomparableError<T> {
    pub err: T
}

#[derive(Debug)]
pub enum Error {
/// UncheckedErrors are errors that *should* be caught by the
///   TypeChecker and other check passes. Test executions may
///   trigger these errors.
    Unchecked(CheckErrors),
    Interpreter(InterpreterError),
    Runtime(RuntimeErrorType, Option<StackTrace>),
    ShortReturn(ShortReturnType)
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
    SqliteError(IncomparableError<SqliteError>),
    BadFileName,
    FailedToCreateDataDirectory,
    MarfFailure(IncomparableError<MarfError>),
    FailureConstructingTupleWithType,
    FailureConstructingListWithType,
    InsufficientBalance
}


/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq)]
pub enum RuntimeErrorType {
    Arithmetic(String),
    ArithmeticOverflow,
    ArithmeticUnderflow,
    SupplyOverflow(u128, u128),
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
    NoSenderInContext,
    NonPositiveTokenSupply,
    JSONParseError(IncomparableError<SerdeJSONErr>),
    AttemptToFetchInTransientContext,
    BadNameValue(&'static str, String),
    UnknownBlockHeaderHash(BlockHeaderHash),
    BadBlockHash(Vec<u8>),
    UnwrapFailure,
}

#[derive(Debug, PartialEq)]
pub enum ShortReturnType {
    ExpectedValue(Value),
    AssertionFailed(Value),
}

pub type InterpreterResult <R> = Result<R, Error>;

impl <T> PartialEq<IncomparableError<T>> for IncomparableError<T> {
    fn eq(&self, _other: &IncomparableError<T>) -> bool {
        return false
    }
}

impl PartialEq<Error> for Error {
    fn eq(&self, other: &Error) -> bool {
        match (self, other) {
            (Error::Runtime(x, _), Error::Runtime(y, _)) => x == y,
            (Error::Unchecked(x), Error::Unchecked(y)) => x == y,
            (Error::ShortReturn(x), Error::ShortReturn(y)) => x == y,
            (Error::Interpreter(x), Error::Interpreter(y)) => x == y,
            _ => false
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Runtime(ref err, ref stack) => {
                match err {
                    _ =>  write!(f, "{}", err)
                }?;

                if let Some(ref stack_trace) = stack {
                    write!(f, "\n Stack Trace: \n")?;
                    for item in stack_trace.iter() {
                        write!(f, "{}\n", item)?;
                    }
                }
                Ok(())
            },
            _ =>  write!(f, "{:?}", self)
        }
    }
}

impl fmt::Display for RuntimeErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
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

impl From<CostErrors> for Error {
    fn from(err: CostErrors) -> Self {
        Error::from(CheckErrors::from(err))
    }
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Error::from(RuntimeErrorType::ASTError(err))
    }
}

impl From<SerdeJSONErr> for Error {
    fn from(err: SerdeJSONErr) -> Self {
        Error::from(RuntimeErrorType::JSONParseError(IncomparableError { err }))
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

impl Into<Value> for ShortReturnType {
    fn into(self) -> Value {
        match self {
            ShortReturnType::ExpectedValue(v) => v,
            ShortReturnType::AssertionFailed(v) => v
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use vm::{execute};

    #[test]
    fn error_formats() {
        let t = "(/ 10 0)";
        let expected = "DivisionByZero
 Stack Trace: 
_native_:native_div
";

        assert_eq!(
            format!("{}", execute(t).unwrap_err()),
            expected);
    }

    #[test]
    fn equality() {
        assert_eq!(Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Bool(true))),
                   Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Bool(true))));
        assert_eq!(Error::Interpreter(InterpreterError::InterpreterError("".to_string())),
                   Error::Interpreter(InterpreterError::InterpreterError("".to_string())));
        assert!(Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Bool(true))) !=
                Error::Interpreter(InterpreterError::InterpreterError("".to_string())));

    }

}
