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

//! Packed Grammar V1 implementation.
//!
//! V1 records use a four-byte envelope containing the version and equivalent consensus byte
//! length. Their bodies use minimal-width scalars, offset directories for variable-width children,
//! fixed concatenation where possible, and dense integer and Boolean list lanes. The complete wire
//! grammar is specified in the adjacent `README.md`.

use std::mem;

use super::{
    DecodedPackedValue, PackedCodecInvariant, PackedRecordError, PackedSchemaError, PackedValue,
    PackedValueError, PackedValueRef, PackedValueVersion, ReconstructionError, ValueShape,
    ValueShapeError, ValueShapeRef, ValueShapeVersion,
};
use crate::types::{BOUND_VALUE_SERIALIZATION_BYTES, MAX_VALUE_SIZE, TypeSignature, Value};

mod decode;
mod directory;
mod encode;
mod layout;
mod primitive;
mod reconstruct;
mod shape;

/// Number of bytes in a V1 packed record's consensus-length field.
const PACKED_VALUE_LENGTH_LEN: usize = 3;

/// V1 packed record discriminator.
const PACKED_VALUE_VERSION: u8 = PackedValueVersion::V1.as_u8();

/// V1 value-shape descriptor discriminator.
const VALUE_SHAPE_VERSION: u8 = ValueShapeVersion::V1.as_u8();

/// Number of bytes before a packed V1 value body.
pub const PACKED_VALUE_HEADER_LEN: usize = 4;

/// Largest consensus byte length representable by the packed V1 header.
const MAX_PACKED_CONSENSUS_BYTE_LEN: u32 = 0x00ff_ffff;

const _: () = assert!(BOUND_VALUE_SERIALIZATION_BYTES <= MAX_PACKED_CONSENSUS_BYTE_LEN);

/// Widest offset emitted by the packed V1 directory grammar.
const MAX_PACKED_OFFSET_BYTES: usize = mem::size_of::<u32>();

/// Width tag and terminal offset contributed once by each packed V1 directory.
const MAX_PACKED_DIRECTORY_FIXED_BYTES: usize = 1 + MAX_PACKED_OFFSET_BYTES;

/// Maximum directory overhead beyond the bounded consensus representation.
///
/// A legal value has at most `MAX_VALUE_SIZE` child edges. Each can require one widest offset and
/// can root at most one directory. The root can contribute one additional directory.
const MAX_PACKED_DIRECTORY_OVERHEAD: usize = MAX_VALUE_SIZE as usize
    * (MAX_PACKED_OFFSET_BYTES + MAX_PACKED_DIRECTORY_FIXED_BYTES)
    + MAX_PACKED_DIRECTORY_FIXED_BYTES;

/// Conservative upper bound for one V1 packed value body, excluding its header.
pub const BOUND_PACKED_VALUE_BODY_BYTES: usize =
    BOUND_VALUE_SERIALIZATION_BYTES as usize + MAX_PACKED_DIRECTORY_OVERHEAD;

/// Maximum length of one versioned V1 value-shape descriptor.
///
/// For a canonical descriptor derived from a legal value, every descriptor node is covered by at
/// least as many bytes in the corresponding consensus value. Tuple names occur in both streams,
/// while merged optional, response, and list shapes are shared by the multiple active values whose
/// consensus bytes cover their children. The descriptor version is the only byte without a
/// consensus counterpart. Parsers use the same limit as a conservative pre-audit resource ceiling.
pub const BOUND_VALUE_SHAPE_BYTES: usize = BOUND_VALUE_SERIALIZATION_BYTES as usize + 1;

/// Encode one value as a complete V1 packed record.
pub fn encode(value: &Value) -> Result<PackedValue, PackedValueError> {
    encode::value(value)
}

/// Encode one complete V1 packed record after an opaque caller-owned prefix.
pub fn encode_with_prefix(
    value: &Value,
    prefix: &[u8],
    consensus_byte_len: u32,
) -> Result<Vec<u8>, PackedValueError> {
    encode::prefixed_value(value, prefix, consensus_byte_len)
}

/// Transcode one exact consensus value to a V1 packed record.
pub fn transcode_consensus(consensus: &[u8]) -> Result<PackedValue, PackedValueError> {
    encode::transcode(consensus)
}

/// Transcode one exact consensus value to V1 packed and shape streams.
pub fn transcode_consensus_with_shape(
    consensus: &[u8],
) -> Result<(PackedValue, ValueShape), PackedValueError> {
    encode::transcode_with_shape(consensus)
}

/// Parse the V1 record envelope and return its normalized metadata.
pub fn parse_record(bytes: &[u8]) -> Result<u32, PackedValueError> {
    validate_packed_body_len(bytes.len().saturating_sub(PACKED_VALUE_HEADER_LEN))?;
    let header =
        bytes
            .get(..PACKED_VALUE_HEADER_LEN)
            .ok_or(PackedRecordError::TruncatedV1Header {
                actual: bytes.len(),
                required: PACKED_VALUE_HEADER_LEN,
            })?;
    let (&version, length) = header
        .split_first()
        .ok_or(PackedRecordError::TruncatedV1Header {
            actual: bytes.len(),
            required: PACKED_VALUE_HEADER_LEN,
        })?;
    if version != PackedValueVersion::V1.as_u8() {
        return Err(PackedCodecInvariant::IncorrectV1RecordVersion {
            expected: PackedValueVersion::V1.as_u8(),
            actual: version,
        }
        .into());
    }
    if length.len() != PACKED_VALUE_LENGTH_LEN {
        return Err(PackedCodecInvariant::InvalidV1LengthHeader {
            expected: PACKED_VALUE_LENGTH_LEN,
            actual: length.len(),
        }
        .into());
    }
    primitive::read_u24_le(length)
}

/// Decode one parsed V1 record under a caller-supplied schema.
pub fn decode(
    packed: PackedValueRef<'_>,
    expected: &TypeSignature,
) -> Result<DecodedPackedValue, PackedValueError> {
    decode::value(packed, expected)
}

/// Reconstruct exact consensus bytes from V1 record and shape streams.
pub fn reconstruct_consensus(
    packed: PackedValueRef<'_>,
    shape: ValueShapeRef<'_>,
) -> Result<Vec<u8>, PackedValueError> {
    reconstruct::reconstruct_consensus(packed, shape.as_bytes())
}

/// Reconstruct and prove that V1 record and shape streams are canonical.
pub fn audit_reconstruction(
    packed: PackedValueRef<'_>,
    shape: ValueShapeRef<'_>,
) -> Result<Vec<u8>, PackedValueError> {
    reconstruct::audit_reconstruction(packed, shape.as_bytes())
}

/// Encode one active value as a complete V1 shape descriptor.
pub fn encode_shape(value: &Value) -> Result<ValueShape, PackedValueError> {
    shape::encode_value_shape(value)
}

/// Validate one complete V1 shape descriptor.
pub fn validate_shape(shape: ValueShapeRef<'_>) -> Result<(), PackedValueError> {
    shape::parse_value_shape(shape.as_bytes()).map(|_| ())
}

/// Reject a V1 packed body that exceeds its worst-case expansion bound.
fn validate_packed_body_len(body_len: usize) -> Result<(), PackedValueError> {
    if body_len > BOUND_PACKED_VALUE_BODY_BYTES {
        Err(PackedRecordError::BodyTooLarge {
            actual: body_len,
            maximum: BOUND_PACKED_VALUE_BODY_BYTES,
        }
        .into())
    } else {
        Ok(())
    }
}
