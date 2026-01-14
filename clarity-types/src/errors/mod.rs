// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

pub mod analysis;
pub mod ast;
pub mod cost;
pub mod lexer;

use std::{error, fmt};

pub use analysis::{CheckErrorKind, CommonCheckErrorKind, StaticCheckError, StaticCheckErrorKind};
pub use ast::{AstError, ParseError, ParseErrorKind, ParseResult};
pub use cost::CostErrors;
pub use lexer::LexerError;
use stacks_common::types::StacksEpochId;

use crate::types::{TupleTypeSignature, TypeSignature, Value};

/// Wraps error types that do not implement [`PartialEq`], enabling their
/// use in enums that implement the trait. Any two `IncomparableError` values
/// are always considered unequal.
#[derive(Debug)]
pub struct IncomparableError<T> {
    /// The wrapped error value.
    pub err: T,
}

impl<T> PartialEq<IncomparableError<T>> for IncomparableError<T> {
    fn eq(&self, _other: &IncomparableError<T>) -> bool {
        false
    }
}

/// Errors originating purely from the Clarity type system layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClarityTypeError {
    // Size & Depth Invariants
    /// The constructed value exceeds the maximum allowed Clarity value size.
    ValueTooLarge,
    /// The constructed value exceeds the maximum allowed nesting depth.
    TypeSignatureTooDeep,

    // String & Encoding Errors
    /// A non-ASCII byte was found in an ASCII string.
    InvalidAsciiCharacter(u8),
    /// The provided bytes did not form valid UTF-8.
    InvalidUtf8Encoding,

    // List, Tuple, & Structural Type Errors
    /// A list operation failed because element types do not match.
    ListTypeMismatch,
    /// An index was out of bounds for a sequence.
    ValueOutOfBounds,
    /// A tuple was constructed with duplicate field names.
    DuplicateTupleField(String),
    /// Referenced tuple field does not exist in the tuple type.
    /// The `String` wraps the requested field name, and the `TupleTypeSignature` wraps the tuple’s type.
    NoSuchTupleField(String, TupleTypeSignature),
    /// Value does not match the expected type.
    /// The `Box<TypeSignature>` wraps the expected type, and the `Box<Value>` wraps the invalid value.
    TypeMismatchValue(Box<TypeSignature>, Box<Value>),
    /// Expected type does not match the actual type during analysis.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    TypeMismatch(Box<TypeSignature>, Box<TypeSignature>),
    /// Expected a different response type
    ResponseTypeMismatch {
        /// Whether the response type should be an `Ok` response
        expected_ok: bool,
    },
    /// Invalid contract name.
    /// The `String` represents the offending value.
    InvalidContractName(String),
    /// Invalid Clarity name.
    /// The `String` represents the offending value.
    InvalidClarityName(String),
    /// Invalid URL.
    /// The `String` represents the offending value.
    InvalidUrlString(String),
    /// Empty tuple is not allowed in Clarity.
    EmptyTuplesNotAllowed,
    /// Supertype (e.g., trait or union) exceeds the maximum allowed size or complexity.
    SupertypeTooLarge,
    /// Type description is invalid or malformed, preventing proper type-checking.
    InvalidTypeDescription,
    /// Sequence element length mismatch
    SequenceElementArityMismatch { expected: usize, found: usize },
    /// Expected a sequence value
    ExpectedSequenceValue,

    // Principal & Identifier Errors
    /// An invalid version byte was used for a principal.
    InvalidPrincipalVersion(u8),
    /// An invalid principal byte length was supplied.
    InvalidPrincipalLength(usize),
    /// C32 decode failed
    InvalidPrincipalEncoding(String),
    /// An invalid qualified identifier was supplied with a missing '.' separator.
    QualifiedContractMissingDot,
    /// An invalid qualified identifier was supplied with a missing issuer.
    QualifiedContractEmptyIssuer,

    // Type Resolution & Abstract Type Failures
    /// The value has a valid abstract type, but it cannot be serialized
    /// into a concrete consensus representation.
    CouldNotDetermineSerializationType,
    /// The type signature could not be determined.
    CouldNotDetermineType,

    /// Type is unsupported in the given epoch
    UnsupportedTypeInEpoch(Box<TypeSignature>, StacksEpochId),
    /// Unsupported epoch
    UnsupportedEpoch(StacksEpochId),
    /// Something unexpected happened that should not be possible
    InvariantViolation(String),
}

impl fmt::Display for ClarityTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl error::Error for ClarityTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
