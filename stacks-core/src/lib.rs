use std::array::TryFromSliceError;

use thiserror::Error;

pub mod encoding;
pub mod hash;
pub mod uint;

#[derive(Error, Debug, Clone)]
pub enum StacksError {
    #[error("Invalid arguments: {0}")]
    InvalidArguments(&'static str),
    #[error("Address version is invalid: {0}")]
    InvalidAddressVersion(u8),
    #[error("Could not build array from slice: {0}")]
    InvalidSliceLength(#[from] TryFromSliceError),
    #[error("Could not encode or decode hex: {0}")]
    BadHex(#[from] hex::FromHexError),
}

pub type StacksResult<T> = Result<T, StacksError>;
