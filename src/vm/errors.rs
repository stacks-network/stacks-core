use std::fmt;
use std::error;
use vm::types::Value;
use vm::contexts::StackTrace;

#[derive(Clone, Debug, PartialEq)]
pub struct Error {
    pub err_type: ErrType,
    pub stack_trace: Option<StackTrace>
}

#[derive(Clone, Debug, PartialEq)]
pub enum ErrType {
    NotImplemented,
    NonPublicFunction(String),
    TypeError(String, Value),
    InvalidArguments(String),
    UndefinedVariable(String),
    UndefinedFunction(String),
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
            ErrType::RecursionDetected => write!(f, "Illegal operation: attempted recursion detected."),
            ErrType::TryEvalToFunction => write!(f, "Illegal operation: attempt to evaluate to function."),
            ErrType::TypeError(ref expected, ref found) =>
                write!(f, "TypeError: Expected {}, found {}.", expected, found),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_formats() {
        assert_eq!(format!("{}", Error::new(ErrType::RecursionDetected)),
                   "Illegal operation: attempted recursion detected.");
        assert_eq!(format!("{}", Error::new(ErrType::TryEvalToFunction)),
                   "Illegal operation: attempt to evaluate to function.");
        assert_eq!(format!("{}", Error::new(ErrType::TypeError("Test".to_string(), Value::Void))),
                   "TypeError: Expected Test, found null.");
        assert_eq!(format!("{}", Error::new(ErrType::NotImplemented)),
                   "NotImplemented");
    }
}
