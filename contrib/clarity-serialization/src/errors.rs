// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::io;

use thiserror::Error;

use crate::types::{TupleTypeSignature, TypeSignature, Value};

/// The primary error type for the `clarity-codec` crate.
///
/// It represents all possible failures that can occur when encoding, decoding,
/// or validating the structure and types of a Clarity value.
#[derive(Error, Debug)]
pub enum CodecError {
    #[error("I/O error during (de)serialization: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error caused by IO: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("Deserialization expected the type of the input to be: {0}")]
    DeserializeExpected(Box<TypeSignature>),

    #[error("The serializer handled an input in an unexpected way")]
    UnexpectedSerialization,

    #[error("Deserialization finished but there were leftover bytes in the buffer")]
    LeftoverBytesInDeserialization,

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Bad type construction.")]
    BadTypeConstruction,

    // --- Structural and Size Errors ---
    #[error("A value being constructed is larger than the 1MB Clarity limit")]
    ValueTooLarge,

    #[error("A value is out of its prescribed bounds")]
    ValueOutOfBounds,

    #[error("A type signature is deeper than the 32-level Clarity limit")]
    TypeSignatureTooDeep,

    #[error("The supertype of two types is too large to be represented")]
    SupertypeTooLarge,

    #[error("Empty tuples are not allowed")]
    EmptyTuplesNotAllowed,

    #[error("Failed to construct a tuple with the given type")]
    FailureConstructingTupleWithType,

    #[error("Failed to construct a list with the given type")]
    FailureConstructingListWithType,

    #[error("All elements in a list must have a compatible supertype")]
    ListTypesMustMatch,

    // --- Type Mismatch and Semantic Errors ---
    #[error("Expected a value of type '{expected}', but found a value of type '{found}'")]
    TypeError {
        expected: Box<TypeSignature>,
        found: Box<TypeSignature>,
    },

    #[error("Expected a value of type '{expected}', but found the value '{found}'")]
    TypeValueError {
        expected: Box<TypeSignature>,
        found: Box<Value>,
    },

    #[error("could not determine the input type for the serialization function")]
    CouldNotDetermineSerializationType,

    #[error("type of expression cannot be determined")]
    CouldNotDetermineType,

    // --- Naming and Identifier Errors ---
    #[error("Name '{0}' is already used in this tuple")]
    NameAlreadyUsedInTuple(String),

    #[error("Could not find field '{0}' in tuple '{1}'")]
    NoSuchTupleField(String, TupleTypeSignature),

    #[error("Failed to parse {0}: {1}")]
    InvalidClarityName(&'static str, String),

    #[error("Failed to parse {0}: {1}")]
    InvalidContractName(&'static str, String),

    // --- String/Buffer Content Errors ---
    #[error("Invalid characters detected in string")]
    InvalidStringCharacters,

    #[error("Invalid UTF-8 encoding in string")]
    InvalidUtf8Encoding,

    // --- Catch-all for internal logic errors ---
    #[error("An unexpected internal error occurred: {0}")]
    Expect(String),
}

// Implement PartialEq for testing and simple equality checks by comparing the
// string representations of each error. This avoids requiring all wrapped
// fields (like `std::io::Error`) to implement PartialEq.
#[cfg(any(test, feature = "testing"))]
impl PartialEq for CodecError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}
