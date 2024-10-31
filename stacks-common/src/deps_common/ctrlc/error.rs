use std::fmt;

use crate::deps_common::ctrlc::platform;

/// Ctrl-C error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ctrl-C signal handler already registered.
    #[error("Ctrl-C error: Ctrl-C signal handler already registered")]
    MultipleHandlers,
    /// Unexpected system error.
    #[error("Ctrl-C error: Unexpected system error")]
    System(std::io::Error),
}

impl From<platform::Error> for Error {
    fn from(e: platform::Error) -> Error {
        let system_error = std::io::Error::new(std::io::ErrorKind::Other, e);
        Error::System(system_error)
    }
}
