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

//! Version 1 value-shape descriptor encoding and decoding.
//!
//! A descriptor records only information omitted from packed bytes, such as tuple field names and
//! active optional/response/list shapes. It is derived from the value itself; declared bounds and
//! the current epoch must never influence these bytes.

pub use super::super::shape::ActiveShape;
use super::super::shape::merge_list_elements;
use super::{
    BOUND_VALUE_SHAPE_BYTES, PackedCodecInvariant, PackedValueError, VALUE_SHAPE_VERSION,
    ValueShape, ValueShapeError, ValueShapeVersion,
};
use crate::representations::ClarityName;
use crate::types::Value;

/// Width of the value-shape version prefix omitted from [`ShapeParser::bytes`].
const VALUE_SHAPE_VERSION_LEN: usize = 1;

/// Opcode identifying one node in a Version 1 value-shape descriptor.
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
    OptionalNone = 0x07,
    OptionalSome = 0x08,
    ResponseOk = 0x09,
    ResponseErr = 0x0a,
    ResponseBoth = 0x0b,
    Tuple = 0x0c,
    EmptyList = 0x0d,
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
            0x08 => Ok(Self::OptionalSome),
            0x09 => Ok(Self::ResponseOk),
            0x0a => Ok(Self::ResponseErr),
            0x0b => Ok(Self::ResponseBoth),
            0x0c => Ok(Self::Tuple),
            0x0d => Ok(Self::EmptyList),
            0x0e => Ok(Self::List),
            0x0f => Ok(Self::ListElements),
            _ => Err(ValueShapeError::UnknownOpcode { opcode: byte }.into()),
        }
    }

    /// Return this opcode's stable Version 1 wire value.
    const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Encode the canonical value-shape descriptor for a runtime value.
pub fn encode_value_shape(value: &Value) -> Result<ValueShape, PackedValueError> {
    let shape = ActiveShape::from_value(value);
    let mut bytes = Vec::new();
    bytes.push(VALUE_SHAPE_VERSION);
    encode_shape_node(&shape, &mut bytes)?;
    if bytes.len() > BOUND_VALUE_SHAPE_BYTES {
        return Err(PackedValueError::SizeOverflow);
    }
    Ok(ValueShape {
        bytes,
        version: ValueShapeVersion::V1,
    })
}

/// Parse and validate one complete Version 1 value-shape descriptor.
pub fn parse_value_shape(bytes: &[u8]) -> Result<ActiveShape, PackedValueError> {
    if bytes.len() > BOUND_VALUE_SHAPE_BYTES {
        return Err(ValueShapeError::TooLarge {
            actual: bytes.len(),
            maximum: BOUND_VALUE_SHAPE_BYTES,
        }
        .into());
    }
    let (&version, body) = bytes.split_first().ok_or(ValueShapeError::Empty)?;
    if version != VALUE_SHAPE_VERSION {
        return Err(PackedCodecInvariant::IncorrectV1ShapeVersion {
            expected: VALUE_SHAPE_VERSION,
            actual: version,
        }
        .into());
    }
    ShapeParser::new(body).parse()
}

/// Stateful reader for one recursive value-shape descriptor body.
struct ShapeParser<'a> {
    /// Descriptor body, excluding its version byte.
    bytes: &'a [u8],
    /// Next unread byte within `bytes`.
    cursor: usize,
}

impl<'a> ShapeParser<'a> {
    /// Begin parsing one descriptor body.
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    /// Parse one complete descriptor body with no trailing bytes.
    fn parse(mut self) -> Result<ActiveShape, PackedValueError> {
        let shape = self.parse_shape(0)?;
        if self.cursor != self.bytes.len() {
            return Err(ValueShapeError::TrailingBytes {
                trailing: self.bytes.len() - self.cursor,
            }
            .into());
        }
        Ok(shape)
    }

    /// Parse one recursive shape node while enforcing depth and canonicality limits.
    fn parse_shape(&mut self, depth: u8) -> Result<ActiveShape, PackedValueError> {
        if depth >= crate::types::MAX_TYPE_DEPTH {
            return Err(ValueShapeError::MaximumDepthExceeded {
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
            ShapeOpcode::OptionalSome => Ok(ActiveShape::Optional(Some(Box::new(
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
            ShapeOpcode::ResponseBoth => Ok(ActiveShape::Response {
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
        let count = self.take_varuint()?;
        if count == 0 {
            return Err(ValueShapeError::EmptyTuple.into());
        }
        let remaining_bytes = self.bytes.len().saturating_sub(self.cursor);
        if count > remaining_bytes / 2 {
            return Err(ValueShapeError::TupleFieldCountExceedsDescriptor {
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
            let name_bytes =
                self.bytes
                    .get(self.cursor..end)
                    .ok_or(ValueShapeError::TruncatedTupleName {
                        declared: name_len,
                        remaining: self.bytes.len().saturating_sub(self.cursor),
                    })?;
            let name = str::from_utf8(name_bytes).map_err(|error| {
                ValueShapeError::InvalidTupleNameUtf8 {
                    valid_up_to: error.valid_up_to(),
                    error_len: error.error_len(),
                }
            })?;
            let name = ClarityName::try_from(name.to_owned())
                .map_err(|_| ValueShapeError::InvalidTupleName { length: name_len })?;
            if let Some((previous, _)) = fields.last()
                && previous >= &name
            {
                return Err(ValueShapeError::NonCanonicalTupleFields {
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
        let count = self.take_varuint()?;
        let remaining_bytes = self.bytes.len().saturating_sub(self.cursor);
        if count == 0 || count > remaining_bytes {
            return Err(ValueShapeError::InvalidPerElementListCount {
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
            return Err(ValueShapeError::MergeableListUsesPerElementShapes {
                element_count: elements.len(),
            }
            .into());
        }
        Ok(ActiveShape::ListElements(elements))
    }

    /// Decode one minimal unsigned LEB128 descriptor integer.
    fn take_varuint(&mut self) -> Result<usize, PackedValueError> {
        let start = self.cursor;
        let mut value = 0usize;
        let mut shift = 0u32;
        loop {
            let byte = self.take_byte()?;
            let group = usize::from(byte & 0x7f);
            if group > (usize::MAX >> shift) {
                return Err(self.varuint_overflow(start).into());
            }
            let part = group << shift;
            value = value
                .checked_add(part)
                .ok_or_else(|| self.varuint_overflow(start))?;
            if byte & 0x80 == 0 {
                if self.cursor - start > 1 && byte & 0x7f == 0 {
                    return Err(ValueShapeError::NonCanonicalVarUint {
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
            if shift >= usize::BITS {
                return Err(self.varuint_overflow(start).into());
            }
        }
    }

    /// Describe an overflowing shape varuint using complete-descriptor coordinates.
    fn varuint_overflow(&self, start: usize) -> ValueShapeError {
        ValueShapeError::VarUintOverflow {
            offset: start.saturating_add(VALUE_SHAPE_VERSION_LEN),
            encoded_groups: self.cursor.saturating_sub(start),
        }
    }

    /// Read one descriptor byte and advance the parser.
    fn take_byte(&mut self) -> Result<u8, PackedValueError> {
        let byte = self
            .bytes
            .get(self.cursor)
            .copied()
            .ok_or(ValueShapeError::Truncated {
                offset: self.cursor.saturating_add(VALUE_SHAPE_VERSION_LEN),
            })?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(PackedValueError::SizeOverflow)?;
        Ok(byte)
    }
}

/// Append one value-shape node using the canonical Version 1 descriptor grammar.
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
            output.push(ShapeOpcode::OptionalSome.to_byte());
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
            output.push(ShapeOpcode::ResponseBoth.to_byte());
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

/// Append a minimal unsigned LEB128 descriptor integer.
fn encode_varuint(mut value: usize, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
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
    use super::*;
    use crate::types::BOUND_VALUE_SERIALIZATION_BYTES;
    use crate::types::codec::packed::{PackedValue, PackedValueVersion};

    /// Preserve the complete historical payload when its descriptor exceeds the runtime size bound.
    #[test]
    fn structurally_valid_shape_uses_its_own_stream_bound() {
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
        descriptor.extend([VALUE_SHAPE_VERSION, LIST_ELEMENTS]);
        descriptor.extend(ELEMENT_COUNT_VARUINT);
        descriptor.extend(NARROW_SHAPE);
        for _ in 1..ELEMENT_COUNT {
            descriptor.extend(WIDE_SHAPE);
        }
        assert!(descriptor.len() > crate::types::MAX_VALUE_SIZE as usize);
        assert!(descriptor.len() <= BOUND_VALUE_SHAPE_BYTES);

        let shape = parse_value_shape(&descriptor).unwrap();
        let mut reencoded = vec![VALUE_SHAPE_VERSION];
        encode_shape_node(&shape, &mut reencoded).unwrap();
        assert_eq!(reencoded, descriptor);
        assert_eq!(
            ValueShape::from_bytes(&descriptor).unwrap().as_bytes(),
            descriptor
        );

        let (packed, transcoded_shape) = PackedValue::transcode_consensus_with_shape(
            PackedValueVersion::V1,
            ValueShapeVersion::V1,
            &consensus,
        )
        .unwrap();
        assert_eq!(packed.consensus_byte_len() as usize, consensus_len);
        assert_eq!(transcoded_shape.as_bytes(), descriptor);
        assert_eq!(
            packed
                .as_packed_ref()
                .audit_reconstruction(transcoded_shape.as_bytes())
                .unwrap(),
            consensus
        );
    }
}
