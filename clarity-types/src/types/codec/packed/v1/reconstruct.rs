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

//! Version 1 reconstruction of exact consensus bytes from packed values and active shapes.

use std::str;

use super::shape::{self, ActiveShape};
use super::{
    PackedCodecInvariant, PackedRecordError, PackedValueError, PackedValueRef, ReconstructionError,
    directory, encode, layout, primitive,
};
use crate::representations::ClarityName;
use crate::types::serialization::TypePrefix;

/// Structurally reconstruct exact consensus bytes without a declared schema.
///
/// This bounded pass validates record framing, shape grammar, scalar encodings, and the declared
/// logical length. It does not prove that the output deserializes as a valid bounded Clarity value.
/// Call [`PackedValueRef::audit_reconstruction`] to establish that property and additionally prove
/// that the payload and shape are their canonical representations of the reconstructed value.
pub fn reconstruct_consensus(
    packed: PackedValueRef<'_>,
    descriptor: &[u8],
) -> Result<Vec<u8>, PackedValueError> {
    let expected_len = packed.consensus_byte_len();
    if expected_len > crate::types::BOUND_VALUE_SERIALIZATION_BYTES {
        return Err(PackedRecordError::DeclaredConsensusLengthTooLarge {
            declared: expected_len,
            maximum: crate::types::BOUND_VALUE_SERIALIZATION_BYTES,
        }
        .into());
    }
    let shape = shape::parse_value_shape(descriptor)?;
    let expected_capacity =
        usize::try_from(expected_len).map_err(|_| PackedValueError::SizeOverflow)?;
    let mut reconstructor = ConsensusReconstructor::with_capacity(expected_capacity);
    reconstructor.reconstruct_body(packed.body(), &shape)?;
    reconstructor.finish()
}

/// Reconstruct consensus bytes and prove the packed payload and shape are canonical.
pub fn audit_reconstruction(
    packed: PackedValueRef<'_>,
    descriptor: &[u8],
) -> Result<Vec<u8>, PackedValueError> {
    let consensus = reconstruct_consensus(packed, descriptor)?;
    let (canonical_packed, canonical_shape) = encode::transcode_with_shape(&consensus)?;
    if canonical_packed.as_bytes() != packed.as_bytes() {
        return Err(ReconstructionError::NonCanonicalPackedValue {
            first_mismatch: first_mismatch(canonical_packed.as_bytes(), packed.as_bytes()),
            stored_length: packed.as_bytes().len(),
            canonical_length: canonical_packed.as_bytes().len(),
        }
        .into());
    }
    if canonical_shape.as_bytes() != descriptor {
        return Err(ReconstructionError::NonCanonicalValueShape {
            first_mismatch: first_mismatch(canonical_shape.as_bytes(), descriptor),
            stored_length: descriptor.len(),
            canonical_length: canonical_shape.as_bytes().len(),
        }
        .into());
    }
    Ok(consensus)
}

/// Return the first differing byte offset, or the shorter length when one stream is a prefix.
fn first_mismatch(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| left.len().min(right.len()))
}

/// Stateful writer for exact consensus reconstruction.
struct ConsensusReconstructor {
    /// Reconstructed consensus bytes accumulated in wire order.
    output: Vec<u8>,
    /// Exact output length declared by the packed record.
    expected_len: usize,
}

impl ConsensusReconstructor {
    /// Allocate a reconstructor for the logical length declared by the packed record.
    fn with_capacity(capacity: usize) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
            expected_len: capacity,
        }
    }

    /// Consume the reconstructor after verifying the exact declared output length.
    fn finish(self) -> Result<Vec<u8>, PackedValueError> {
        if self.output.len() != self.expected_len {
            return Err(ReconstructionError::ConsensusLengthMismatch {
                declared: self.expected_len,
                actual: self.output.len(),
            }
            .into());
        }
        Ok(self.output)
    }

    /// Reject an append that would exceed the record's declared logical length.
    fn ensure_remaining(&self, additional: usize) -> Result<(), PackedValueError> {
        let end = self
            .output
            .len()
            .checked_add(additional)
            .ok_or(PackedValueError::SizeOverflow)?;
        if end > self.expected_len {
            return Err(ReconstructionError::ConsensusExceedsDeclaredLength {
                declared: self.expected_len,
                attempted: end,
            }
            .into());
        }
        Ok(())
    }

    /// Append one byte without exceeding the declared logical length.
    fn push(&mut self, byte: u8) -> Result<(), PackedValueError> {
        self.ensure_remaining(1)?;
        self.output.push(byte);
        Ok(())
    }

    /// Append a byte slice without exceeding the declared logical length.
    fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), PackedValueError> {
        self.ensure_remaining(bytes.len())?;
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    /// Append `count` copies of one byte without exceeding the declared logical length.
    fn extend_repeated(&mut self, count: usize, byte: u8) -> Result<(), PackedValueError> {
        self.ensure_remaining(count)?;
        let end = self.output.len() + count;
        self.output.resize(end, byte);
        Ok(())
    }

    /// Append exact consensus bytes for one packed body and its active shape.
    fn reconstruct_body(
        &mut self,
        bytes: &[u8],
        shape: &ActiveShape,
    ) -> Result<(), PackedValueError> {
        match shape {
            ActiveShape::Int => {
                primitive::validate_canonical_signed_scalar(bytes)?;
                self.push(TypePrefix::Int.to_u8())?;
                let fill = if bytes[0] & 0x80 == 0 { 0 } else { 0xff };
                self.append_integer_padding(bytes.len(), fill)?;
                self.extend_from_slice(bytes)?;
            }
            ActiveShape::UInt => {
                primitive::validate_canonical_unsigned_scalar(bytes)?;
                self.push(TypePrefix::UInt.to_u8())?;
                self.append_integer_padding(bytes.len(), 0)?;
                self.extend_from_slice(bytes)?;
            }
            ActiveShape::Bool => match bytes {
                [0] => self.push(TypePrefix::BoolFalse.to_u8())?,
                [1] => self.push(TypePrefix::BoolTrue.to_u8())?,
                _ => {
                    return Err(PackedRecordError::InvalidBoolean {
                        length: bytes.len(),
                        first_byte: bytes.first().copied(),
                    }
                    .into());
                }
            },
            ActiveShape::Buffer => self.reconstruct_sequence(TypePrefix::Buffer.to_u8(), bytes)?,
            ActiveShape::Ascii => {
                if let Some((offset, &byte)) = bytes
                    .iter()
                    .enumerate()
                    .find(|(_, byte)| !primitive::valid_ascii_byte(byte))
                {
                    return Err(PackedRecordError::InvalidAsciiString { offset, byte }.into());
                }
                self.reconstruct_sequence(TypePrefix::StringASCII.to_u8(), bytes)?;
            }
            ActiveShape::Utf8 => {
                str::from_utf8(bytes).map_err(|error| PackedRecordError::InvalidUtf8String {
                    valid_up_to: error.valid_up_to(),
                    error_len: error.error_len(),
                })?;
                self.reconstruct_sequence(TypePrefix::StringUTF8.to_u8(), bytes)?;
            }
            ActiveShape::Principal => self.reconstruct_principal(bytes)?,
            ActiveShape::Optional(child_shape) => {
                let (tag, child) = primitive::split_tag(bytes)?;
                match (tag, child_shape) {
                    (0, _) if child.is_empty() => self.push(TypePrefix::OptionalNone.to_u8())?,
                    (0, _) => {
                        return Err(PackedRecordError::InvalidOptional {
                            discriminant: tag,
                            child_length: child.len(),
                        }
                        .into());
                    }
                    (1, Some(shape)) => {
                        self.push(TypePrefix::OptionalSome.to_u8())?;
                        self.reconstruct_body(child, shape)?;
                    }
                    (1, None) => {
                        return Err(ReconstructionError::OptionalShapeMismatch.into());
                    }
                    _ => {
                        return Err(PackedRecordError::InvalidOptional {
                            discriminant: tag,
                            child_length: child.len(),
                        }
                        .into());
                    }
                }
            }
            ActiveShape::Response { ok, err } => {
                let (tag, child) = primitive::split_tag(bytes)?;
                let (prefix, shape) = match tag {
                    0 => (TypePrefix::ResponseErr.to_u8(), err.as_deref()),
                    1 => (TypePrefix::ResponseOk.to_u8(), ok.as_deref()),
                    _ => {
                        return Err(PackedRecordError::InvalidResponse { discriminant: tag }.into());
                    }
                };
                let shape = shape
                    .ok_or(ReconstructionError::MissingResponseBranch { discriminant: tag })?;
                self.push(prefix)?;
                self.reconstruct_body(child, shape)?;
            }
            ActiveShape::Tuple(fields) => self.reconstruct_tuple(bytes, fields)?,
            ActiveShape::List(element_shape) => {
                self.reconstruct_list(bytes, element_shape.as_deref().map(ListShapes::Shared))?
            }
            ActiveShape::ListElements(element_shapes) => {
                self.reconstruct_list(bytes, Some(ListShapes::PerElement(element_shapes)))?
            }
        }
        Ok(())
    }

    /// Append a consensus sequence prefix, byte length, and payload.
    fn reconstruct_sequence(&mut self, prefix: u8, bytes: &[u8]) -> Result<(), PackedValueError> {
        self.push(prefix)?;
        self.extend_from_slice(
            &u32::try_from(bytes.len())
                .map_err(|_| PackedValueError::SizeOverflow)?
                .to_be_bytes(),
        )?;
        self.extend_from_slice(bytes)
    }

    /// Reconstruct a standard or contract principal consensus value.
    fn reconstruct_principal(&mut self, bytes: &[u8]) -> Result<(), PackedValueError> {
        match primitive::PackedPrincipal::parse(bytes)? {
            primitive::PackedPrincipal::Standard(principal) => {
                self.push(TypePrefix::PrincipalStandard.to_u8())?;
                self.extend_from_slice(principal)?;
            }
            primitive::PackedPrincipal::Contract { issuer, name } => {
                self.push(TypePrefix::PrincipalContract.to_u8())?;
                self.extend_from_slice(issuer)?;
                self.push(u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?)?;
                self.extend_from_slice(name.as_bytes())?;
            }
        }
        Ok(())
    }

    /// Reconstruct tuple fields from fixed concatenation or directory framing.
    fn reconstruct_tuple(
        &mut self,
        bytes: &[u8],
        fields: &[(ClarityName, ActiveShape)],
    ) -> Result<(), PackedValueError> {
        self.push(TypePrefix::Tuple.to_u8())?;
        self.extend_from_slice(
            &u32::try_from(fields.len())
                .map_err(|_| PackedValueError::SizeOverflow)?
                .to_be_bytes(),
        )?;
        if fields
            .iter()
            .all(|(_, shape)| layout::fixed_shape_width(shape).is_some())
        {
            let mut cursor = 0usize;
            for (name, shape) in fields {
                let width = layout::fixed_shape_width(shape)
                    .ok_or(PackedCodecInvariant::FixedValueShapeClassificationChanged)?;
                let end = cursor
                    .checked_add(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
                let child =
                    bytes
                        .get(cursor..end)
                        .ok_or(ReconstructionError::TruncatedFixedTuple {
                            required_end: end,
                            actual: bytes.len(),
                        })?;
                self.reconstruct_tuple_field(name, child, shape)?;
                cursor = end;
            }
            if cursor != bytes.len() {
                return Err(ReconstructionError::FixedTupleTrailingBytes {
                    consumed: cursor,
                    actual: bytes.len(),
                }
                .into());
            }
        } else {
            let directory = directory::Directory::parse(bytes, fields.len())?;
            for ((name, shape), child) in fields.iter().zip(directory.children()) {
                self.reconstruct_tuple_field(name, child?, shape)?;
            }
        }
        Ok(())
    }

    /// Append one named tuple field in consensus order.
    fn reconstruct_tuple_field(
        &mut self,
        name: &ClarityName,
        bytes: &[u8],
        shape: &ActiveShape,
    ) -> Result<(), PackedValueError> {
        let name = name.as_str().as_bytes();
        self.push(u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?)?;
        self.extend_from_slice(name)?;
        self.reconstruct_body(bytes, shape)
    }
}

/// Shape access strategy for homogeneous and historical heterogeneous lists.
#[derive(Clone, Copy)]
enum ListShapes<'a> {
    /// One merged shape applies to every list element.
    Shared(&'a ActiveShape),
    /// Each historical unsanitized element requires its own shape.
    PerElement(&'a [ActiveShape]),
}

impl<'a> ListShapes<'a> {
    /// Return the shape applying to one list element.
    fn get(self, index: usize) -> Result<&'a ActiveShape, PackedValueError> {
        match self {
            Self::Shared(shape) => Ok(shape),
            Self::PerElement(shapes) => shapes.get(index).ok_or_else(|| {
                PackedCodecInvariant::ListShapeIndexOutOfBounds {
                    index,
                    count: shapes.len(),
                }
                .into()
            }),
        }
    }

    /// Return the total directory-free element-region length, when all shapes are fixed-width.
    fn fixed_data_len(self, count: usize) -> Result<Option<usize>, PackedValueError> {
        match self {
            Self::Shared(shape) => layout::fixed_shape_width(shape)
                .map(|width| {
                    width
                        .checked_mul(count)
                        .ok_or(PackedValueError::SizeOverflow)
                })
                .transpose(),
            Self::PerElement(shapes) => shapes.iter().try_fold(Some(0usize), |total, shape| {
                let (Some(total), Some(width)) = (total, layout::fixed_shape_width(shape)) else {
                    return Ok(None);
                };
                total
                    .checked_add(width)
                    .map(Some)
                    .ok_or(PackedValueError::SizeOverflow)
            }),
        }
    }
}

/// List and scalar-lane reconstruction operations.
impl ConsensusReconstructor {
    /// Reconstruct a list using shared or per-element active shapes.
    fn reconstruct_list(
        &mut self,
        bytes: &[u8],
        element_shapes: Option<ListShapes<'_>>,
    ) -> Result<(), PackedValueError> {
        let (count, elements) = primitive::split_list(bytes)?;
        self.push(TypePrefix::List.to_u8())?;
        self.extend_from_slice(
            &u32::try_from(count)
                .map_err(|_| PackedValueError::SizeOverflow)?
                .to_be_bytes(),
        )?;
        if count == 0 {
            if !elements.is_empty() {
                return Err(PackedRecordError::EmptyListHasElementRegion {
                    actual: elements.len(),
                }
                .into());
            }
            if let Some(ListShapes::PerElement(shapes)) = element_shapes {
                return Err(ReconstructionError::EmptyListShapeMismatch {
                    shape_count: shapes.len(),
                }
                .into());
            }
            return Ok(());
        }
        let shapes = element_shapes.ok_or(ReconstructionError::MissingListElementShape {
            record_count: count,
        })?;
        if let ListShapes::PerElement(element_shapes) = shapes
            && element_shapes.len() != count
        {
            return Err(ReconstructionError::ListShapeCountMismatch {
                record_count: count,
                shape_count: element_shapes.len(),
            }
            .into());
        }
        match shapes {
            ListShapes::Shared(ActiveShape::UInt) => {
                return self.reconstruct_unsigned_lane(elements, count);
            }
            ListShapes::Shared(ActiveShape::Int) => {
                return self.reconstruct_signed_lane(elements, count);
            }
            ListShapes::Shared(ActiveShape::Bool) => {
                return self.reconstruct_bool_lane(elements, count);
            }
            ListShapes::Shared(_) | ListShapes::PerElement(_) => {}
        }
        if let Some(expected_len) = shapes.fixed_data_len(count)? {
            if elements.len() != expected_len {
                return Err(ReconstructionError::FixedListLengthMismatch {
                    actual: elements.len(),
                    expected: expected_len,
                }
                .into());
            }
            let mut cursor = 0usize;
            for index in 0..count {
                let shape = shapes.get(index)?;
                let width = layout::fixed_shape_width(shape)
                    .ok_or(PackedCodecInvariant::FixedListShapeClassificationChanged)?;
                let end = cursor
                    .checked_add(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
                let child = elements.get(cursor..end).ok_or(
                    PackedCodecInvariant::FixedListChildRangeOutOfBounds {
                        start: cursor,
                        end,
                        length: elements.len(),
                    },
                )?;
                self.reconstruct_body(child, shape)?;
                cursor = end;
            }
        } else {
            let directory = directory::Directory::parse(elements, count)?;
            for (index, child) in directory.children().enumerate() {
                self.reconstruct_body(child?, shapes.get(index)?)?;
            }
        }
        Ok(())
    }

    /// Expand a packed unsigned-integer lane into consensus scalar encodings.
    fn reconstruct_unsigned_lane(
        &mut self,
        elements: &[u8],
        count: usize,
    ) -> Result<(), PackedValueError> {
        let lane = primitive::IntegerLane::parse_unsigned(elements, count)?;
        let width = lane.width();
        for element in lane.iter() {
            self.push(TypePrefix::UInt.to_u8())?;
            self.append_integer_padding(width, 0)?;
            self.extend_from_slice(element)?;
        }
        Ok(())
    }

    /// Expand a packed signed-integer lane into consensus scalar encodings.
    fn reconstruct_signed_lane(
        &mut self,
        elements: &[u8],
        count: usize,
    ) -> Result<(), PackedValueError> {
        let lane = primitive::IntegerLane::parse_signed(elements, count)?;
        let width = lane.width();
        for element in lane.iter() {
            self.push(TypePrefix::Int.to_u8())?;
            let fill = if element[0] & 0x80 == 0 { 0 } else { 0xff };
            self.append_integer_padding(width, fill)?;
            self.extend_from_slice(element)?;
        }
        Ok(())
    }

    /// Restore a packed integer to the fixed 16-byte consensus representation.
    fn append_integer_padding(
        &mut self,
        packed_width: usize,
        fill: u8,
    ) -> Result<(), PackedValueError> {
        let padding = 16usize.checked_sub(packed_width).ok_or(
            PackedCodecInvariant::IntegerWidthTooLarge {
                actual: packed_width,
                maximum: 16,
            },
        )?;
        self.extend_repeated(padding, fill)
    }

    /// Expand a bit-packed Boolean lane into consensus Boolean prefixes.
    fn reconstruct_bool_lane(
        &mut self,
        elements: &[u8],
        count: usize,
    ) -> Result<(), PackedValueError> {
        primitive::validate_bool_lane(elements, count)?;
        for index in 0..count {
            let byte = elements.get(index / 8).ok_or(
                PackedCodecInvariant::BooleanLaneIndexOutOfBounds {
                    index,
                    bit_count: elements.len().saturating_mul(8),
                },
            )?;
            self.push(if byte & (1 << (index % 8)) == 0 {
                TypePrefix::BoolFalse.to_u8()
            } else {
                TypePrefix::BoolTrue.to_u8()
            })?;
        }
        Ok(())
    }
}
