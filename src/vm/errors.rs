use std::fmt;
use std::error;
use vm::types::Value;

#[derive(Debug,PartialEq)]
pub enum Error {
    Generic(String),
    NotImplemented,
    TypeError(String, Value),
    InvalidArguments(String),
    Undefined(String),
    TryEvalToFunction,
    Arithmetic(String),
    ParseError(String),
    RecursionDetected,
    MaxStackDepthReached,
    MaxContextDepthReached,
    ListDimensionTooHigh,
    ListTooLarge,
    BadTypeConstruction,
    BufferTooLarge,
    ValueTooLarge,
    ExpectedListPairs,
    InvalidTypeDescription,
    BadSender(Value),
    BadSymbolicRepresentation(String),
    ReservedName(String),
    InterpreterError(String),
    MultiplyDefined(String)
}

pub type InterpreterResult <R> = Result<R, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::RecursionDetected => write!(f, "Illegal operation: attempted recursion detected."),
            Error::TryEvalToFunction => write!(f, "Illegal operation: attempt to evaluate to function."),
            Error::TypeError(ref expected, ref found) => write!(f, "TypeError: Expected {}, found {}.", expected, found),
            _ =>  write!(f, "{:?}", self)
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[test]
fn error_formats() {
    assert_eq!(format!("{}", Error::RecursionDetected),
               "Illegal operation: attempted recursion detected.");
    assert_eq!(format!("{}", Error::TryEvalToFunction),
               "Illegal operation: attempt to evaluate to function.");
    assert_eq!(format!("{}", Error::TypeError("Test".to_string(), Value::Void)),
               "TypeError: Expected Test, found null.");
    assert_eq!(format!("{}", Error::NotImplemented),
               "NotImplemented");
}
