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

/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq)]
pub struct RuntimeError {
    pub err_type: RuntimeErrorType,
    pub stack_trace: Option<StackTrace>,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    Unchecked(UncheckedError),
    Interpreter(InterpreterError),
    Runtime(RuntimeError),
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
}

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
    SqliteError(IncomparableError<SqliteError>),
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

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.err_type {
            _ =>  write!(f, "{:?}", self.err_type)
        }?;

        if let Some(ref stack_trace) = self.stack_trace {
            write!(f, "\n Stack Trace: \n")?;
            for item in stack_trace.iter() {
                write!(f, "{}\n", item)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Runtime(ref err) => write!(f, "{}", err),
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
        Error::Runtime(RuntimeError::new(err))
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

impl RuntimeError {
    pub fn new(err_type: RuntimeErrorType) -> RuntimeError {
        RuntimeError { err_type: err_type,
                       stack_trace: None }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_formats() {
        assert_eq!(format!("{}", Error::new(ErrType::RecursionDetected)),
                   "Illegal operation: attempted recursion detected.");
        assert_eq!(format!("{}", Error::new(ErrType::TryEvalToFunction)),
                   "Illegal operation: attempt to evaluate to function.");
        assert_eq!(format!("{}", Error::new(ErrType::NotImplemented)),
                   "NotImplemented");
    }
}
