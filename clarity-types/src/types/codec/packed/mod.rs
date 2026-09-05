// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Canonical packed representation for Clarity values.
//!
//! This is not Clarity's consensus serialization. Packed value records and their optional
//! reconstruction metadata are separate, independently versioned streams. Encoding selects each
//! version explicitly; decoding dispatches from the leading version byte and rejects unknown
//! versions without probing another grammar.
//!
//! The version registry and byte-level specifications are linked from the
//! [packed-codec overview][format-spec].
//!
//! [format-spec]: https://github.com/stacks-network/stacks-core/blob/main/clarity-types/src/types/codec/packed/README.md
//!
//! Two invariants establish canonical byte identity:
//!
//! - Packed bytes depend only on the active [`Value`], never declared bounds or epoch;
//! - [`ValueShape`] records only information omitted from packed bytes that is needed to reconstruct
//!   the exact consensus serialization without a declared [`crate::types::TypeSignature`].

use crate::types::{TypeSignature, Value};

mod error;
mod shape;
mod v1;

pub use error::{
    PackedCodecInvariant, PackedRecordError, PackedSchemaError, PackedValueError,
    ReconstructionError, ValueShapeError,
};

/// Supported packed value-record wire versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum PackedValueVersion {
    /// Packed Grammar V1.
    V1 = 1,
}

impl PackedValueVersion {
    /// Return this version's wire discriminator.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Return this version's record-header length.
    pub const fn header_len(self) -> usize {
        match self {
            Self::V1 => v1::PACKED_VALUE_HEADER_LEN,
        }
    }

    /// Return this version's maximum packed-body length.
    pub const fn maximum_body_len(self) -> usize {
        match self {
            Self::V1 => v1::BOUND_PACKED_VALUE_BODY_BYTES,
        }
    }

    /// Parse a packed value-record version byte.
    fn from_u8(byte: u8) -> Result<Self, PackedValueError> {
        match byte {
            value if value == Self::V1.as_u8() => Ok(Self::V1),
            version => Err(PackedValueError::UnsupportedPackedValueVersion { version }),
        }
    }
}

/// Supported value-shape descriptor wire versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ValueShapeVersion {
    /// Value-shape descriptor V1.
    V1 = 1,
}

impl ValueShapeVersion {
    /// Return this version's wire discriminator.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Return this version's maximum complete descriptor length.
    pub const fn maximum_descriptor_len(self) -> usize {
        match self {
            Self::V1 => v1::BOUND_VALUE_SHAPE_BYTES,
        }
    }

    /// Parse a value-shape descriptor version byte.
    fn from_u8(byte: u8) -> Result<Self, PackedValueError> {
        match byte {
            value if value == Self::V1.as_u8() => Ok(Self::V1),
            version => Err(PackedValueError::UnsupportedValueShapeVersion { version }),
        }
    }
}

/// The encoded bytes and logical length produced by the packed codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedValue {
    /// Complete versioned packed record.
    bytes: Vec<u8>,
    /// Parsed record version.
    version: PackedValueVersion,
    /// Equivalent consensus-serialization length cached from the record header.
    consensus_byte_len: u32,
}

impl PackedValue {
    /// Encode one runtime value into its canonical packed representation.
    ///
    /// This operation is independent of declared types and execution epochs. Callers that require
    /// typed admission must perform it before encoding.
    pub fn encode(version: PackedValueVersion, value: &Value) -> Result<Self, PackedValueError> {
        match version {
            PackedValueVersion::V1 => v1::encode(value),
        }
    }

    /// Encode one runtime value after an opaque caller-owned prefix in one allocation.
    ///
    /// The returned buffer contains `prefix` followed by one complete packed record. The prefix is
    /// not interpreted by this codec. `consensus_byte_len` must come from the exact consensus
    /// serialization of `value`, and callers must keep the value and its derived length coupled so
    /// they cannot be mispaired. Trusting that already-proven length avoids repeating a full
    /// consensus-serialization traversal in storage hot paths.
    pub fn encode_with_prefix(
        version: PackedValueVersion,
        value: &Value,
        prefix: &[u8],
        consensus_byte_len: u32,
    ) -> Result<Vec<u8>, PackedValueError> {
        match version {
            PackedValueVersion::V1 => v1::encode_with_prefix(value, prefix, consensus_byte_len),
        }
    }

    /// Transcode one exact self-describing consensus value into canonical packed bytes.
    ///
    /// Historical unsanitized values can contain active data omitted by a cached read schema. The
    /// resulting record preserves that data, but typed decoding under the narrower schema is not
    /// guaranteed. Call [`Self::transcode_consensus_with_shape`] when the caller needs the
    /// descriptor required for compatibility reconstruction without a caller-supplied type.
    pub fn transcode_consensus(
        version: PackedValueVersion,
        consensus: &[u8],
    ) -> Result<Self, PackedValueError> {
        match version {
            PackedValueVersion::V1 => v1::transcode_consensus(consensus),
        }
    }

    /// Transcode consensus bytes and derive their descriptor-guided reconstruction metadata.
    ///
    /// The returned descriptor allows exact reconstruction when a historical unsanitized value
    /// cannot be decoded directly under its cached read schema.
    pub fn transcode_consensus_with_shape(
        packed_version: PackedValueVersion,
        shape_version: ValueShapeVersion,
        consensus: &[u8],
    ) -> Result<(Self, ValueShape), PackedValueError> {
        match (packed_version, shape_version) {
            (PackedValueVersion::V1, ValueShapeVersion::V1) => {
                v1::transcode_consensus_with_shape(consensus)
            }
        }
    }

    /// Return the complete packed record bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume this record and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Return the equivalent consensus-serialization length.
    pub fn consensus_byte_len(&self) -> u32 {
        self.consensus_byte_len
    }

    /// Return this record's packed wire version.
    pub const fn version(&self) -> PackedValueVersion {
        self.version
    }

    /// Borrow this owned record through the packed record read API.
    pub fn as_packed_ref(&self) -> PackedValueRef<'_> {
        PackedValueRef {
            bytes: &self.bytes,
            version: self.version,
            consensus_byte_len: self.consensus_byte_len,
        }
    }
}

/// A borrowed view over one packed value record with a validated envelope.
///
/// Parsing validates its version, header, and physical body bound. Typed decoding or audited
/// reconstruction validates the body grammar and canonical encoding.
#[derive(Clone, Copy, Debug)]
pub struct PackedValueRef<'a> {
    /// Complete packed record bytes.
    bytes: &'a [u8],
    /// Parsed record version.
    version: PackedValueVersion,
    /// Equivalent consensus-serialization length read from the record header.
    consensus_byte_len: u32,
}

impl<'a> PackedValueRef<'a> {
    /// Dispatch to the declared version and parse its envelope without decoding the value body.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PackedValueError> {
        let version =
            PackedValueVersion::from_u8(bytes.first().copied().ok_or(PackedRecordError::Empty)?)?;
        let consensus_byte_len = match version {
            PackedValueVersion::V1 => v1::parse_record(bytes)?,
        };
        Ok(Self {
            bytes,
            version,
            consensus_byte_len,
        })
    }

    /// Return the complete borrowed record bytes.
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Return the equivalent consensus-serialization length from the record header.
    pub const fn consensus_byte_len(self) -> u32 {
        self.consensus_byte_len
    }

    /// Return this record's packed wire version.
    pub const fn version(self) -> PackedValueVersion {
        self.version
    }

    /// Decode and validate this record under a declared read schema.
    pub fn decode(self, expected: &TypeSignature) -> Result<DecodedPackedValue, PackedValueError> {
        match self.version {
            PackedValueVersion::V1 => v1::decode(self, expected),
        }
    }

    /// Reconstruct exact consensus bytes using a value-shape descriptor.
    ///
    /// This checks framing and the declared logical length, but does not prove that the output is a
    /// valid bounded Clarity value. Use [`Self::audit_reconstruction`] for untrusted records.
    pub fn reconstruct_consensus(self, descriptor: &[u8]) -> Result<Vec<u8>, PackedValueError> {
        self.reconstruct_consensus_with_shape(ValueShapeRef::parse(descriptor)?)
    }

    /// Reconstruct exact consensus bytes using an already parsed value-shape descriptor.
    pub fn reconstruct_consensus_with_shape(
        self,
        shape: ValueShapeRef<'_>,
    ) -> Result<Vec<u8>, PackedValueError> {
        match (self.version, shape.version) {
            (PackedValueVersion::V1, ValueShapeVersion::V1) => {
                v1::reconstruct_consensus(self, shape)
            }
        }
    }

    /// Reconstruct consensus bytes and prove this record and shape are canonical.
    pub fn audit_reconstruction(self, descriptor: &[u8]) -> Result<Vec<u8>, PackedValueError> {
        self.audit_reconstruction_with_shape(ValueShapeRef::parse(descriptor)?)
    }

    /// Audit reconstruction using an already parsed value-shape descriptor.
    pub fn audit_reconstruction_with_shape(
        self,
        shape: ValueShapeRef<'_>,
    ) -> Result<Vec<u8>, PackedValueError> {
        match (self.version, shape.version) {
            (PackedValueVersion::V1, ValueShapeVersion::V1) => {
                v1::audit_reconstruction(self, shape)
            }
        }
    }

    /// Return the packed body after its version-specific envelope.
    fn body(self) -> &'a [u8] {
        &self.bytes[self.version.header_len()..]
    }
}

/// An owned, versioned value-shape descriptor.
///
/// The descriptor contains only information omitted from [`PackedValue`] that is required to
/// reconstruct consensus bytes without a caller-supplied [`TypeSignature`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ValueShape {
    /// Complete versioned descriptor bytes.
    bytes: Vec<u8>,
    /// Parsed descriptor version.
    version: ValueShapeVersion,
}

impl ValueShape {
    /// Derive canonical reconstruction metadata solely from an active value.
    pub fn from_value(version: ValueShapeVersion, value: &Value) -> Result<Self, PackedValueError> {
        match version {
            ValueShapeVersion::V1 => v1::encode_shape(value),
        }
    }

    /// Borrow the complete versioned descriptor.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume this descriptor and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Return this descriptor's wire version.
    pub const fn version(&self) -> ValueShapeVersion {
        self.version
    }

    /// Borrow this owned descriptor through the shape read API.
    pub fn as_shape_ref(&self) -> ValueShapeRef<'_> {
        ValueShapeRef {
            bytes: &self.bytes,
            version: self.version,
        }
    }

    /// Parse and validate one complete versioned descriptor.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PackedValueError> {
        let shape = ValueShapeRef::parse(bytes)?;
        shape.validate()?;
        Ok(Self {
            bytes: bytes.to_vec(),
            version: shape.version,
        })
    }
}

/// A borrowed view over one versioned value-shape descriptor.
#[derive(Clone, Copy, Debug)]
pub struct ValueShapeRef<'a> {
    /// Complete descriptor bytes.
    bytes: &'a [u8],
    /// Parsed descriptor version.
    version: ValueShapeVersion,
}

impl<'a> ValueShapeRef<'a> {
    /// Parse the versioned descriptor envelope without materializing its recursive shape.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PackedValueError> {
        let version =
            ValueShapeVersion::from_u8(bytes.first().copied().ok_or(ValueShapeError::Empty)?)?;
        if bytes.len() > version.maximum_descriptor_len() {
            return Err(ValueShapeError::TooLarge {
                actual: bytes.len(),
                maximum: version.maximum_descriptor_len(),
            }
            .into());
        }
        Ok(Self { bytes, version })
    }

    /// Return the complete borrowed descriptor bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Return this descriptor's wire version.
    pub const fn version(self) -> ValueShapeVersion {
        self.version
    }

    /// Fully validate the recursive descriptor grammar.
    pub fn validate(self) -> Result<(), PackedValueError> {
        match self.version {
            ValueShapeVersion::V1 => v1::validate_shape(self),
        }
    }
}

/// An owned decoded value paired with its logical serialized length.
#[derive(Debug, PartialEq)]
pub struct DecodedPackedValue {
    /// The materialized Clarity value.
    pub value: Value,
    /// The length of its equivalent consensus serialization.
    pub consensus_byte_len: u32,
}
