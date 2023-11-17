use std::fmt;

use crate::deps_common::ctrlc::platform;

/// Ctrl-C error.
#[derive(Debug)]
pub enum Error {
    /// Ctrl-C signal handler already registered.
    MultipleHandlers,
    /// Unexpected system error.
    System(std::io::Error),
}

impl Error {
    fn describe(&self) -> &str {
        match *self {
            Error::MultipleHandlers => "Ctrl-C signal handler already registered",
            Error::System(_) => "Unexpected system error",
        }
    }
}

impl From<platform::Error> for Error {
    fn from(e: platform::Error) -> Error {
        let system_error = std::io::Error::new(std::io::ErrorKind::Other, e);
        Error::System(system_error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ctrl-C error: {}", self.describe())
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        self.describe()
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::System(ref e) => Some(e),
            _ => None,
        }
    }
}
