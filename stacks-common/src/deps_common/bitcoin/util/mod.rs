// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Utility functions
//!
//! Functions needed by all parts of the Bitcoin library

pub mod hash;

use std::{error, fmt};

use secp256k1;

use crate::deps_common::bitcoin::network;
use crate::deps_common::bitcoin::network::serialize;

/// A trait which allows numbers to act as fixed-size bit arrays
pub trait BitArray {
    /// Is bit set?
    fn bit(&self, idx: usize) -> bool;

    /// Returns an array which is just the bits from start to end
    fn bit_slice(&self, start: usize, end: usize) -> Self;

    /// Bitwise and with `n` ones
    fn mask(&self, n: usize) -> Self;

    /// Trailing zeros
    fn trailing_zeros(&self) -> usize;

    /// Create all-zeros value
    fn zero() -> Self;

    /// Create value represeting one
    fn one() -> Self;
}

/// A general error code, other errors should implement conversions to/from this
/// if appropriate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// secp-related error
    #[error("{0}")]
    Secp256k1(#[from] secp256k1::Error),
    /// Serialization error
    #[error("{0}")]
    Serialize(#[from] serialize::Error),
    /// Network error
    #[error("{0}")]
    Network(#[from] network::Error),
    /// The header hash is not below the target
    #[error("target correct but not attained")]
    SpvBadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty
    #[error("target incorrect")]
    SpvBadTarget,
}
