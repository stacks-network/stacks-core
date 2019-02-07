use std::fmt;
use std::error;
use super::types::Value;

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
    ExpectedListPairs
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::RecursionDetected => write!(f, "Illegal operation: attempted recursion detected."),
            Error::TryEvalToFunction => write!(f, "Illegal operation: attempt to evaluate to function."),
            Error::TypeError(ref expected, ref found) => write!(f, "TypeError: Expected {}, found {:?}.", expected, found),
            _ =>  write!(f, "{:?}", self)
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None
        }
    }
}
