use std::fmt;
use std::error;
use vm::types::Value;
use vm::contexts::StackTrace;

#[derive(Clone, Debug, PartialEq)]
pub struct Error {
    err_type: ErrType,
    stack_trace: Option<StackTrace>
}

#[derive(Clone, Debug, PartialEq)]
pub enum ErrType {
    NotImplemented,
    NonPublicFunction(String, StackTrace),
    TypeError(String, Value, StackTrace),
    InvalidArguments(String),
    UndefinedVariable(String, StackTrace),
    UndefinedFunction(String, StackTrace),
    UndefinedContract(String),
    TryEvalToFunction,
    Arithmetic(String),
    ParseError(String),
    RecursionDetected,
    ContractAlreadyInvoked,
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
    ContractAlreadyExists(String),
    VariableDefinedMultipleTimes(String)
}

pub type InterpreterResult <R> = Result<R, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.err_type {
            Error::RecursionDetected => write!(f, "Illegal operation: attempted recursion detected."),
            Error::TryEvalToFunction => write!(f, "Illegal operation: attempt to evaluate to function."),
            Error::TypeError(ref expected, ref found) =>
                write!(f, "TypeError: Expected {}, found {}.", expected, found),
            _ =>  write!(f, "{:?}", self)
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl Error {
    pub fn new(err_type: ErrType) -> Error {
        Error { err_type: err_type,
                stack_trace: None }
    }

    pub fn has_stack_trace(&self) -> bool {
        false
    }

    pub fn extend_with(&self, _extension: StackTrace) -> Error {
        self.clone()
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
