use std::fmt;
use std::error;
use vm::types::Value;
use vm::contexts::StackTrace;

use serde_json::Error as SerdeJSONErr;
use rusqlite::Error as SqliteError;

#[derive(Debug)]
pub struct IncomparableError<T> {
    pub err: T
}

#[derive(Debug)]
pub enum Error {
    Unchecked(UncheckedError),
    Interpreter(InterpreterError),
    Runtime(RuntimeErrorType, Option<StackTrace>),
    ShortReturn(ShortReturnType)
}

/// UncheckedErrors are errors that *should* be caught by the
///   typechecker and other check passes. Test executions may
///   trigger these errors.
#[derive(Debug, PartialEq)]
pub enum UncheckedError {
    NonPublicFunction(String),
    TypeError(String, Value),
    InvalidArguments(String),
    UndefinedVariable(String),
    UndefinedFunction(String),
    UndefinedContract(String),
    UndefinedMap(String),
    TryEvalToFunction,
    RecursionDetected,
    ExpectedListPairs,
    ReservedName(String),
    ContractAlreadyExists(String),
    VariableDefinedMultipleTimes(String),
    ContractMustReturnBoolean,
    WriteFromReadOnlyContext,
}

/// InterpreterErrors are errors that *should never* occur.
/// Test executions may trigger these errors.
#[derive(Debug, PartialEq)]
pub enum InterpreterError {
    BadSender(Value),
    BadSymbolicRepresentation(String),
    InterpreterError(String),
    UninitializedPersistedVariable,
    SqliteError(IncomparableError<SqliteError>),
}


/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq)]
pub enum RuntimeErrorType {
    Arithmetic(String),
    ParseError(String),
    MaxStackDepthReached,
    MaxContextDepthReached,
    ListDimensionTooHigh,
    ListTooLarge,
    BadTypeConstruction,
    BufferTooLarge,
    ValueTooLarge,
    InvalidTypeDescription,
    BadBlockHeight(String),
    NotImplemented,
}

#[derive(Debug, PartialEq)]
pub enum ShortReturnType {
    ExpectedValue(Value),
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
                    _ =>  write!(f, "{:?}", err)
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

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<RuntimeErrorType> for Error {
    fn from(err: RuntimeErrorType) -> Self {
        Error::Runtime(err, None)
    }
}

impl From<UncheckedError> for Error {
    fn from(err: UncheckedError) -> Self {
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
            ShortReturnType::ExpectedValue(v) => v
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
        let expected = "Arithmetic(\"Divide by 0\")
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
