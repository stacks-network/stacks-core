use vm::types::TypeSignature;
use std::error;
use std::fmt;

pub type CheckResult <T> = Result<T, CheckError>;

#[derive(Debug, PartialEq)]
pub enum CheckErrors {
    VariadicNeedsOneArgument,
    TypeAlreadyAnnotatedFailure,
    TypeNotAnnotatedFailure,
    UnboundVariable(String),
    IncorrectArgumentCount(usize, usize),
    TypeError(TypeSignature, TypeSignature),
    IfArmsMustMatch(TypeSignature, TypeSignature),
    NotImplemented,
    TooManyExpressions,
    NonFunctionApplication,
    UnknownFunction(String),
    Generic(String)
}

#[derive(Debug, PartialEq)]
pub struct CheckError {
    pub err: CheckErrors
}

impl CheckError {
    pub fn new(err: CheckErrors) -> CheckError {
        CheckError {
            err: err
        }
    }
}


impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.err {
            _ =>  write!(f, "{:?}", self.err)
        }?;

        Ok(())
    }
}

impl error::Error for CheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.err {
            _ => None
        }
    }
}
