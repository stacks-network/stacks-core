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

//! Version 1 value descriptor encoding and decoding.
//!
//! A descriptor records structural metadata, such as tuple field names and active
//! optional/response/list shapes, plus its own framing. Counts delimit child shapes independently
//! of the packed record. It is derived from the value itself; declared bounds and the current epoch
//! must never influence these bytes.

pub use super::super::shape::ActiveShape;
use super::super::shape::merge_list_elements;
use super::{
    BOUND_VALUE_DESCRIPTOR_BYTES, PackedCodecInvariant, PackedValueError, VALUE_DESCRIPTOR_VERSION,
    ValueDescriptor, ValueDescriptorError, ValueDescriptorVersion,
};
use crate::representations::ClarityName;
use crate::types::Value;

/// Width of the descriptor version prefix omitted from [`DescriptorParser::bytes`].
const VALUE_DESCRIPTOR_VERSION_LEN: usize = 1;

/// Opcode identifying one node in a Version 1 value descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ShapeOpcode {
    Int = 0x00,
    UInt = 0x01,
    Bool = 0x02,
    Buffer = 0x03,
    Ascii = 0x04,
    Utf8 = 0x05,
    Principal = 0x06,
    /// No child shape was observed; only absent optional values can be described.
    OptionalNone = 0x07,
    /// An observed child shape shared by absent and present optional values.
    Optional = 0x08,
    /// Only the `ok` child shape is supplied; describes only `ok` values.
    ResponseOk = 0x09,
    /// Only the `err` child shape is supplied; describes only `err` values.
    ResponseErr = 0x0a,
    /// Observed shapes for both branches; each packed response tag selects one.
    Response = 0x0b,
    Tuple = 0x0c,
    /// No element shape was observed; only empty lists can be described.
    EmptyList = 0x0d,
    /// An observed element shape shared by empty and non-empty lists.
    List = 0x0e,
    ListElements = 0x0f,
}

impl ShapeOpcode {
    /// Parse one descriptor opcode byte.
    fn from_byte(byte: u8) -> Result<Self, PackedValueError> {
        match byte {
            0x00 => Ok(Self::Int),
            0x01 => Ok(Self::UInt),
            0x02 => Ok(Self::Bool),
            0x03 => Ok(Self::Buffer),
            0x04 => Ok(Self::Ascii),
            0x05 => Ok(Self::Utf8),
            0x06 => Ok(Self::Principal),
            0x07 => Ok(Self::OptionalNone),
            0x08 => Ok(Self::Optional),
            0x09 => Ok(Self::ResponseOk),
            0x0a => Ok(Self::ResponseErr),
            0x0b => Ok(Self::Response),
            0x0c => Ok(Self::Tuple),
            0x0d => Ok(Self::EmptyList),
            0x0e => Ok(Self::List),
            0x0f => Ok(Self::ListElements),
            _ => Err(ValueDescriptorError::UnknownOpcode { opcode: byte }.into()),
        }
    }

    /// Return this opcode's stable Version 1 wire value.
    const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Encode the canonical value descriptor for a runtime value.
pub fn encode_value_descriptor(value: &Value) -> Result<ValueDescriptor, PackedValueError> {
    let shape = ActiveShape::from_value(value);
    let mut bytes = Vec::new();
    bytes.push(VALUE_DESCRIPTOR_VERSION);
    encode_shape_node(&shape, &mut bytes)?;
    if bytes.len() > BOUND_VALUE_DESCRIPTOR_BYTES {
        return Err(PackedValueError::SizeOverflow);
    }
    Ok(ValueDescriptor {
        bytes,
        version: ValueDescriptorVersion::V1,
    })
}

/// Parse and validate one complete Version 1 value descriptor.
pub fn parse_value_descriptor(bytes: &[u8]) -> Result<ActiveShape, PackedValueError> {
    if bytes.len() > BOUND_VALUE_DESCRIPTOR_BYTES {
        return Err(ValueDescriptorError::TooLarge {
            actual: bytes.len(),
            maximum: BOUND_VALUE_DESCRIPTOR_BYTES,
        }
        .into());
    }
    let (&version, body) = bytes.split_first().ok_or(ValueDescriptorError::Empty)?;
    if version != VALUE_DESCRIPTOR_VERSION {
        return Err(PackedCodecInvariant::IncorrectV1DescriptorVersion {
            expected: VALUE_DESCRIPTOR_VERSION,
            actual: version,
        }
        .into());
    }
    DescriptorParser::new(body).parse()
}

/// Stateful reader for one recursive value descriptor body.
struct DescriptorParser<'a> {
    /// Descriptor body, excluding its version byte.
    bytes: &'a [u8],
    /// Next unread byte within `bytes`.
    cursor: usize,
}

impl<'a> DescriptorParser<'a> {
    /// Begin parsing one descriptor body.
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    /// Parse one complete descriptor body with no trailing bytes.
    fn parse(mut self) -> Result<ActiveShape, PackedValueError> {
        let shape = self.parse_shape(0)?;
        if self.cursor != self.bytes.len() {
            return Err(ValueDescriptorError::TrailingBytes {
                trailing: self.bytes.len() - self.cursor,
            }
            .into());
        }
        Ok(shape)
    }

    /// Parse one recursive shape node while enforcing depth and canonicality limits.
    fn parse_shape(&mut self, depth: u8) -> Result<ActiveShape, PackedValueError> {
        if depth >= crate::types::MAX_TYPE_DEPTH {
            return Err(ValueDescriptorError::MaximumDepthExceeded {
                actual: depth,
                maximum: crate::types::MAX_TYPE_DEPTH,
            }
            .into());
        }
        let opcode = ShapeOpcode::from_byte(self.take_byte()?)?;
        let child_depth = depth.checked_add(1).ok_or(PackedValueError::SizeOverflow)?;
        match opcode {
            ShapeOpcode::Int => Ok(ActiveShape::Int),
            ShapeOpcode::UInt => Ok(ActiveShape::UInt),
            ShapeOpcode::Bool => Ok(ActiveShape::Bool),
            ShapeOpcode::Buffer => Ok(ActiveShape::Buffer),
            ShapeOpcode::Ascii => Ok(ActiveShape::Ascii),
            ShapeOpcode::Utf8 => Ok(ActiveShape::Utf8),
            ShapeOpcode::Principal => Ok(ActiveShape::Principal),
            ShapeOpcode::OptionalNone => Ok(ActiveShape::Optional(None)),
            ShapeOpcode::Optional => Ok(ActiveShape::Optional(Some(Box::new(
                self.parse_shape(child_depth)?,
            )))),
            ShapeOpcode::ResponseOk => Ok(ActiveShape::Response {
                ok: Some(Box::new(self.parse_shape(child_depth)?)),
                err: None,
            }),
            ShapeOpcode::ResponseErr => Ok(ActiveShape::Response {
                ok: None,
                err: Some(Box::new(self.parse_shape(child_depth)?)),
            }),
            ShapeOpcode::Response => Ok(ActiveShape::Response {
                ok: Some(Box::new(self.parse_shape(child_depth)?)),
                err: Some(Box::new(self.parse_shape(child_depth)?)),
            }),
            ShapeOpcode::Tuple => self.parse_tuple(child_depth),
            ShapeOpcode::EmptyList => Ok(ActiveShape::List(None)),
            ShapeOpcode::List => Ok(ActiveShape::List(Some(Box::new(
                self.parse_shape(child_depth)?,
            )))),
            ShapeOpcode::ListElements => self.parse_list_elements(child_depth),
        }
    }

    /// Parse a non-empty, canonically ordered tuple descriptor.
    fn parse_tuple(&mut self, child_depth: u8) -> Result<ActiveShape, PackedValueError> {
        let count =
            usize::try_from(self.take_varuint()?).map_err(|_| PackedValueError::SizeOverflow)?;
        if count == 0 {
            return Err(ValueDescriptorError::EmptyTuple.into());
        }
        let remaining_bytes = self.bytes.len().saturating_sub(self.cursor);
        if count > remaining_bytes / 2 {
            return Err(ValueDescriptorError::TupleFieldCountExceedsDescriptor {
                declared: count,
                remaining_bytes,
            }
            .into());
        }
        let mut fields: Vec<(ClarityName, ActiveShape)> = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = usize::from(self.take_byte()?);
            let end = self
                .cursor
                .checked_add(name_len)
                .ok_or(PackedValueError::SizeOverflow)?;
            let name_bytes = self.bytes.get(self.cursor..end).ok_or(
                ValueDescriptorError::TruncatedTupleName {
                    declared: name_len,
                    remaining: self.bytes.len().saturating_sub(self.cursor),
                },
            )?;
            let name = str::from_utf8(name_bytes).map_err(|error| {
                ValueDescriptorError::InvalidTupleNameUtf8 {
                    valid_up_to: error.valid_up_to(),
                    error_len: error.error_len(),
                }
            })?;
            let name = ClarityName::try_from(name.to_owned())
                .map_err(|_| ValueDescriptorError::InvalidTupleName { length: name_len })?;
            if let Some((previous, _)) = fields.last()
                && previous >= &name
            {
                return Err(ValueDescriptorError::NonCanonicalTupleFields {
                    previous: previous.as_str().into(),
                    current: name.as_str().into(),
                }
                .into());
            }
            self.cursor = end;
            fields.push((name, self.parse_shape(child_depth)?));
        }
        Ok(ActiveShape::Tuple(fields))
    }

    /// Parse non-mergeable per-element list descriptors.
    fn parse_list_elements(&mut self, child_depth: u8) -> Result<ActiveShape, PackedValueError> {
        let count =
            usize::try_from(self.take_varuint()?).map_err(|_| PackedValueError::SizeOverflow)?;
        let remaining_bytes = self.bytes.len().saturating_sub(self.cursor);
        if count == 0 || count > remaining_bytes {
            return Err(ValueDescriptorError::InvalidPerElementListCount {
                declared: count,
                remaining_bytes,
            }
            .into());
        }
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(self.parse_shape(child_depth)?);
        }
        if merge_list_elements(&elements).is_some() {
            return Err(ValueDescriptorError::MergeableListUsesPerElementShapes {
                element_count: elements.len(),
            }
            .into());
        }
        Ok(ActiveShape::ListElements(elements))
    }

    /// Decode one minimal unsigned LEB128 count bounded by the wire format to `u32`.
    fn take_varuint(&mut self) -> Result<u32, PackedValueError> {
        let start = self.cursor;
        let mut value = 0u32;
        let mut shift = 0u32;
        loop {
            let byte = self.take_byte()?;
            let group = u32::from(byte & 0x7f);
            if group > (u32::MAX >> shift) {
                return Err(self.varuint_overflow(start).into());
            }
            let part = group << shift;
            value = value
                .checked_add(part)
                .ok_or_else(|| self.varuint_overflow(start))?;
            if byte & 0x80 == 0 {
                if self.cursor - start > 1 && byte & 0x7f == 0 {
                    return Err(ValueDescriptorError::NonCanonicalVarUint {
                        encoded_groups: self.cursor - start,
                        value,
                    }
                    .into());
                }
                return Ok(value);
            }
            shift = shift
                .checked_add(7)
                .ok_or_else(|| self.varuint_overflow(start))?;
            if shift >= u32::BITS {
                return Err(self.varuint_overflow(start).into());
            }
        }
    }

    /// Describe an overflowing descriptor varuint using complete-descriptor coordinates.
    fn varuint_overflow(&self, start: usize) -> ValueDescriptorError {
        ValueDescriptorError::VarUintOverflow {
            offset: start.saturating_add(VALUE_DESCRIPTOR_VERSION_LEN),
            encoded_groups: self.cursor.saturating_sub(start),
        }
    }

    /// Read one descriptor byte and advance the parser.
    fn take_byte(&mut self) -> Result<u8, PackedValueError> {
        let byte = self
            .bytes
            .get(self.cursor)
            .copied()
            .ok_or(ValueDescriptorError::Truncated {
                offset: self.cursor.saturating_add(VALUE_DESCRIPTOR_VERSION_LEN),
            })?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(PackedValueError::SizeOverflow)?;
        Ok(byte)
    }
}

/// Append one shape node using the canonical Version 1 descriptor grammar.
fn encode_shape_node(shape: &ActiveShape, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    match shape {
        ActiveShape::Int => output.push(ShapeOpcode::Int.to_byte()),
        ActiveShape::UInt => output.push(ShapeOpcode::UInt.to_byte()),
        ActiveShape::Bool => output.push(ShapeOpcode::Bool.to_byte()),
        ActiveShape::Buffer => output.push(ShapeOpcode::Buffer.to_byte()),
        ActiveShape::Ascii => output.push(ShapeOpcode::Ascii.to_byte()),
        ActiveShape::Utf8 => output.push(ShapeOpcode::Utf8.to_byte()),
        ActiveShape::Principal => output.push(ShapeOpcode::Principal.to_byte()),
        ActiveShape::Optional(None) => output.push(ShapeOpcode::OptionalNone.to_byte()),
        ActiveShape::Optional(Some(child)) => {
            output.push(ShapeOpcode::Optional.to_byte());
            encode_shape_node(child, output)?;
        }
        ActiveShape::Response {
            ok: Some(ok),
            err: None,
        } => {
            output.push(ShapeOpcode::ResponseOk.to_byte());
            encode_shape_node(ok, output)?;
        }
        ActiveShape::Response {
            ok: None,
            err: Some(err),
        } => {
            output.push(ShapeOpcode::ResponseErr.to_byte());
            encode_shape_node(err, output)?;
        }
        ActiveShape::Response {
            ok: Some(ok),
            err: Some(err),
        } => {
            output.push(ShapeOpcode::Response.to_byte());
            encode_shape_node(ok, output)?;
            encode_shape_node(err, output)?;
        }
        ActiveShape::Response {
            ok: None,
            err: None,
        } => {
            return Err(PackedCodecInvariant::ResponseShapeHasNoActiveBranch.into());
        }
        ActiveShape::Tuple(fields) => {
            output.push(ShapeOpcode::Tuple.to_byte());
            encode_varuint(fields.len(), output)?;
            for (name, shape) in fields {
                let name = name.as_str().as_bytes();
                output.push(u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?);
                output.extend_from_slice(name);
                encode_shape_node(shape, output)?;
            }
        }
        ActiveShape::List(None) => output.push(ShapeOpcode::EmptyList.to_byte()),
        ActiveShape::List(Some(child)) => {
            output.push(ShapeOpcode::List.to_byte());
            encode_shape_node(child, output)?;
        }
        ActiveShape::ListElements(elements) => {
            if elements.is_empty() {
                return Err(PackedCodecInvariant::EmptyPerElementListShape.into());
            }
            output.push(ShapeOpcode::ListElements.to_byte());
            encode_varuint(elements.len(), output)?;
            for element in elements {
                encode_shape_node(element, output)?;
            }
        }
    }
    Ok(())
}

/// Check a host-sized count against the `u32` wire limit and append its minimal unsigned LEB128.
fn encode_varuint(value: usize, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    let mut value = u32::try_from(value).map_err(|_| PackedValueError::SizeOverflow)?;
    loop {
        let mut byte = u8::try_from(value & 0x7f).map_err(|_| PackedValueError::SizeOverflow)?;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::types::BOUND_VALUE_SERIALIZATION_BYTES;
    use crate::types::codec::packed::{PackedValue, PackedValueVersion};

    /// Independent vectors cover every unsigned LEB128 width transition through `u32::MAX`.
    #[test]
    fn varuint_u32_boundary_vectors() {
        let vectors: &[(u32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (16_383, &[0xff, 0x7f]),
            (16_384, &[0x80, 0x80, 0x01]),
            (2_097_151, &[0xff, 0xff, 0x7f]),
            (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
            (268_435_455, &[0xff, 0xff, 0xff, 0x7f]),
            (268_435_456, &[0x80, 0x80, 0x80, 0x80, 0x01]),
            (u32::MAX, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
        ];
        for &(value, bytes) in vectors {
            let mut parser = DescriptorParser::new(bytes);
            assert_eq!(parser.take_varuint().unwrap(), value);
            assert_eq!(parser.cursor, bytes.len());
            let mut encoded = Vec::new();
            encode_varuint(usize::try_from(value).unwrap(), &mut encoded).unwrap();
            assert_eq!(encoded, bytes);
        }
    }

    /// Neither excessive fifth-byte payload bits nor continuation past five groups can fit `u32`.
    #[test]
    fn varuint_overflow_uses_complete_descriptor_coordinates() {
        for bytes in [
            [0x80, 0x80, 0x80, 0x80, 0x10],
            [0xff, 0xff, 0xff, 0xff, 0x7f],
            [0x80, 0x80, 0x80, 0x80, 0x80],
            [0xff, 0xff, 0xff, 0xff, 0x8f],
        ] {
            let mut body = vec![0x0c];
            body.extend_from_slice(&bytes);
            let mut parser = DescriptorParser::new(&body);
            parser.take_byte().unwrap();
            assert_matches!(
                parser.take_varuint(),
                Err(PackedValueError::Descriptor(
                    ValueDescriptorError::VarUintOverflow {
                        offset: 2,
                        encoded_groups: 5,
                    }
                ))
            );
        }
    }

    /// The numeric limit does not replace minimality or truncation checks.
    #[test]
    fn varuint_rejects_redundant_and_truncated_groups() {
        for (bytes, value) in [
            (&[0x80, 0x00][..], 0),
            (&[0xff, 0x00][..], 127),
            (&[0x80, 0x80, 0x80, 0x80, 0x00][..], 0),
        ] {
            assert_matches!(
                DescriptorParser::new(bytes).take_varuint(),
                Err(PackedValueError::Descriptor(ValueDescriptorError::NonCanonicalVarUint {
                    encoded_groups,
                    value: actual,
                })) if encoded_groups == bytes.len() && actual == value
            );
        }
        for length in 0..5 {
            let bytes = vec![0x80; length];
            assert_matches!(
                DescriptorParser::new(&bytes).take_varuint(),
                Err(PackedValueError::Descriptor(ValueDescriptorError::Truncated {
                    offset,
                })) if offset == length + VALUE_DESCRIPTOR_VERSION_LEN
            );
        }
    }

    /// Host-sized counts above the wire limit must fail before appending any bytes.
    #[test]
    fn varuint_writer_rejects_counts_above_u32() {
        let Ok(oversized) = usize::try_from(u64::from(u32::MAX) + 1) else {
            // This count cannot exist on a host with a narrower usize.
            return;
        };
        let mut output = vec![0xa5];
        assert_matches!(
            encode_varuint(oversized, &mut output),
            Err(PackedValueError::SizeOverflow)
        );
        assert_eq!(output, [0xa5]);
    }

    /// A valid numeric count must still fit the remaining descriptor before allocating children.
    #[test]
    fn u32_counts_retain_descriptor_allocation_bounds() {
        let count = [0xff, 0xff, 0xff, 0xff, 0x0f];
        let mut tuple = vec![VALUE_DESCRIPTOR_VERSION, 0x0c];
        tuple.extend_from_slice(&count);
        assert_matches!(
            parse_value_descriptor(&tuple),
            Err(PackedValueError::Descriptor(ValueDescriptorError::TupleFieldCountExceedsDescriptor {
                declared,
                remaining_bytes: 0,
            })) if declared == usize::try_from(u32::MAX).unwrap()
        );
        let mut list = vec![VALUE_DESCRIPTOR_VERSION, 0x0f];
        list.extend_from_slice(&count);
        assert_matches!(
            parse_value_descriptor(&list),
            Err(PackedValueError::Descriptor(ValueDescriptorError::InvalidPerElementListCount {
                declared,
                remaining_bytes: 0,
            })) if declared == usize::try_from(u32::MAX).unwrap()
        );
    }

    /// Preserve the complete historical payload when its descriptor exceeds the runtime size bound.
    #[test]
    fn structurally_valid_shape_uses_its_own_descriptor_bound() {
        const LIST_ELEMENTS: u8 = 0x0f;
        const TUPLE: u8 = 0x0c;
        const BOOL: u8 = 0x02;
        const ELEMENT_COUNT: usize = 131_070;
        const NARROW_CONSENSUS: [u8; 8] = [0x0c, 0, 0, 0, 1, 1, b'a', 0x03];
        const WIDE_CONSENSUS: [u8; 14] = [
            0x0c, 0, 0, 0, 3, 1, b'a', 0x03, 1, b'b', 0x03, 1, b'c', 0x03,
        ];
        const ELEMENT_COUNT_VARUINT: [u8; 3] = [0xfe, 0xff, 0x07];
        const NARROW_SHAPE: [u8; 5] = [TUPLE, 1, 1, b'a', BOOL];
        const WIDE_SHAPE: [u8; 11] = [TUPLE, 3, 1, b'a', BOOL, 1, b'b', BOOL, 1, b'c', BOOL];

        // The historical left-to-right type fold retains the first tuple's narrow field set.
        // Its full active data and descriptor still need the larger storage-format bounds.
        let consensus_len = 5 + NARROW_CONSENSUS.len() + (ELEMENT_COUNT - 1) * WIDE_CONSENSUS.len();
        assert_eq!(consensus_len, 1_834_979);
        assert!(consensus_len <= BOUND_VALUE_SERIALIZATION_BYTES as usize);
        let mut consensus = Vec::with_capacity(consensus_len);
        consensus.push(0x0b);
        consensus.extend(u32::try_from(ELEMENT_COUNT).unwrap().to_be_bytes());
        consensus.extend(NARROW_CONSENSUS);
        for _ in 1..ELEMENT_COUNT {
            consensus.extend(WIDE_CONSENSUS);
        }
        assert_eq!(consensus.len(), consensus_len);

        let mut descriptor = Vec::with_capacity(
            2 + ELEMENT_COUNT_VARUINT.len()
                + NARROW_SHAPE.len()
                + (ELEMENT_COUNT - 1) * WIDE_SHAPE.len(),
        );
        descriptor.extend([VALUE_DESCRIPTOR_VERSION, LIST_ELEMENTS]);
        descriptor.extend(ELEMENT_COUNT_VARUINT);
        descriptor.extend(NARROW_SHAPE);
        for _ in 1..ELEMENT_COUNT {
            descriptor.extend(WIDE_SHAPE);
        }
        assert!(descriptor.len() > crate::types::MAX_VALUE_SIZE as usize);
        assert!(descriptor.len() <= BOUND_VALUE_DESCRIPTOR_BYTES);

        let shape = parse_value_descriptor(&descriptor).unwrap();
        let mut reencoded = vec![VALUE_DESCRIPTOR_VERSION];
        encode_shape_node(&shape, &mut reencoded).unwrap();
        assert_eq!(reencoded, descriptor);
        assert_eq!(
            ValueDescriptor::from_bytes(&descriptor).unwrap().as_bytes(),
            descriptor
        );

        let (packed, transcoded_descriptor) = PackedValue::transcode_consensus_with_descriptor(
            PackedValueVersion::V1,
            ValueDescriptorVersion::V1,
            &consensus,
        )
        .unwrap();
        assert_eq!(packed.consensus_byte_len() as usize, consensus_len);
        assert_eq!(transcoded_descriptor.as_bytes(), descriptor);
        assert_eq!(
            packed
                .as_packed_ref()
                .audit_reconstruction(transcoded_descriptor.as_bytes())
                .unwrap(),
            consensus
        );
    }
}
