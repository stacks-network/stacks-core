use std::fmt;
use std::error;

#[derive(Debug,PartialEq)]
pub enum Error {
    Generic(String),
    NotImplemented,
    TypeError(String, String),
    InvalidArguments(String),
    RecursionDetected
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None
        }
    }
}
