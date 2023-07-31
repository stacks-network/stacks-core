use thiserror::Error;

pub mod encoding;
pub mod hash;
pub mod uint;

#[derive(Error, Debug, Clone)]
pub enum StacksError {
    #[error("Invalid arguments: {0}")]
    InvalidArguments(&'static str),
    // #[error("Could not crackford32 encode or decode: {0}")]
    // C32Error(#[from] c32::C32Error),
    #[error("Address version is invalid: {0}")]
    InvalidAddressVersion(u8),
}

pub type StacksResult<T> = Result<T, StacksError>;
