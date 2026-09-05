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

//! Version 1 sizing and canonical packed encoding.

use super::{
    PACKED_VALUE_HEADER_LEN, PACKED_VALUE_VERSION, PackedCodecInvariant, PackedValue,
    PackedValueError, PackedValueVersion, ValueShape, directory, layout, primitive, shape,
    validate_packed_body_len,
};
use crate::types::serialization::SerializationError;
use crate::types::{
    CharType, ListData, QualifiedContractIdentifier, SequenceData, TupleData, Value,
};

/// Final body length and maximum output length reached while encoding that body.
#[derive(Debug, Eq, PartialEq)]
struct BodySize {
    /// Encoded body length after directory compaction.
    compact_len: usize,
    /// Largest body length while temporary wide directories are present.
    peak_len: usize,
}

impl BodySize {
    /// Account for bytes preceding this body that remain present throughout encoding.
    fn with_prefix(self, prefix_len: usize) -> Result<Self, PackedValueError> {
        Ok(Self {
            compact_len: prefix_len
                .checked_add(self.compact_len)
                .ok_or(PackedValueError::SizeOverflow)?,
            peak_len: prefix_len
                .checked_add(self.peak_len)
                .ok_or(PackedValueError::SizeOverflow)?,
        })
    }
}

/// Encode one runtime value independently of any declared type or execution epoch.
pub fn value(value: &Value) -> Result<PackedValue, PackedValueError> {
    let consensus_byte_len = value.serialized_size()?;
    value_with_consensus_len(value, consensus_byte_len)
}

/// Encode with a consensus length already proven from the same value's exact serialization.
fn value_with_consensus_len(
    value: &Value,
    consensus_byte_len: u32,
) -> Result<PackedValue, PackedValueError> {
    let bytes = prefixed_value(value, &[], consensus_byte_len)?;
    Ok(PackedValue {
        bytes,
        version: PackedValueVersion::V1,
        consensus_byte_len,
    })
}

/// Encode one exact packed record after an opaque prefix in one allocation.
pub fn prefixed_value(
    value: &Value,
    prefix: &[u8],
    consensus_byte_len: u32,
) -> Result<Vec<u8>, PackedValueError> {
    let size = body_size(value)?;
    let compact_body_len = size.compact_len;
    // The format bound governs compact wire bytes; the transient peak only sizes the allocation.
    // The bound already budgets widest offsets for every directory.
    validate_packed_body_len(compact_body_len)?;
    let prefix_len = prefix
        .len()
        .checked_add(PACKED_VALUE_HEADER_LEN)
        .ok_or(PackedValueError::SizeOverflow)?;
    let output_size = size.with_prefix(prefix_len)?;
    let expected_output_len = output_size.compact_len;
    let reserve_len = output_size.peak_len;
    let mut output = Vec::with_capacity(reserve_len);
    let initial_capacity = output.capacity();
    output.extend_from_slice(prefix);
    output.push(PACKED_VALUE_VERSION);
    primitive::write_u24_le(consensus_byte_len, &mut output)?;
    // This trusted path avoids a release-build traversal when the exact length is already known.
    debug_assert_eq!(
        value
            .serialized_size()
            .expect("trusted packed value must have a consensus size"),
        consensus_byte_len,
        "trusted consensus length must match the encoded value"
    );
    body(value, &mut output)?;
    debug_assert_eq!(
        output.capacity(),
        initial_capacity,
        "packed encoding must not grow its output buffer"
    );
    if output.len() != expected_output_len {
        let actual = output
            .len()
            .saturating_sub(prefix.len())
            .saturating_sub(PACKED_VALUE_HEADER_LEN);
        return Err(PackedCodecInvariant::EncoderBodyLengthMismatch {
            expected: compact_body_len,
            actual,
        }
        .into());
    }
    Ok(output)
}

/// Transcode one exact self-describing consensus value into canonical packed.
///
/// This correctness-first implementation materializes one bounded Clarity value. The migration API
/// remains streaming at row granularity; a direct cursor implementation can replace this without
/// changing the format. Historical unsanitized values may require descriptor-based reconstruction
/// instead of direct typed decoding under their cached schema.
pub fn transcode(consensus: &[u8]) -> Result<PackedValue, PackedValueError> {
    let value = deserialize_canonical_consensus(consensus)?;
    let consensus_byte_len =
        u32::try_from(consensus.len()).map_err(|_| PackedValueError::SizeOverflow)?;
    value_with_consensus_len(&value, consensus_byte_len)
}

/// Measure final and peak body lengths so encoding needs one output allocation.
///
/// This mirrors [`body`], including the lifetime of each temporary wide directory.
fn body_size(value: &Value) -> Result<BodySize, PackedValueError> {
    let len = match value {
        Value::Int(value) => primitive::packed_int_width(*value),
        Value::UInt(value) => primitive::packed_uint_width(*value),
        Value::Bool(_) => 1,
        Value::Sequence(SequenceData::Buffer(buffer)) => buffer.data.len(),
        Value::Sequence(SequenceData::String(CharType::ASCII(string))) => string.data.len(),
        Value::Sequence(SequenceData::String(CharType::UTF8(string))) => {
            string.data.iter().try_fold(0usize, |total, scalar| {
                total
                    .checked_add(scalar.len())
                    .ok_or(PackedValueError::SizeOverflow)
            })?
        }
        Value::Principal(principal) => primitive::principal_body_len(principal)?,
        Value::CallableContract(callable) => contract_body_len(&callable.contract_identifier)?,
        Value::Optional(optional) => match &optional.data {
            None => 1,
            Some(child) => return body_size(child)?.with_prefix(1),
        },
        Value::Response(response) => return body_size(&response.data)?.with_prefix(1),
        Value::Tuple(tuple) => return tuple_body_size(tuple),
        Value::Sequence(SequenceData::List(list)) => return list_body_size(list),
    };
    Ok(BodySize {
        compact_len: len,
        peak_len: len,
    })
}

/// Return the packed byte length of a callable contract's canonical principal identity.
fn contract_body_len(contract: &QualifiedContractIdentifier) -> Result<usize, PackedValueError> {
    22usize
        .checked_add(contract.name.as_str().len())
        .ok_or(PackedValueError::SizeOverflow)
}

/// Measure sequential children, compacting each before the next child begins.
fn children_size<'a>(
    children: impl Iterator<Item = &'a Value>,
) -> Result<BodySize, PackedValueError> {
    let mut compact_len = 0usize;
    let mut peak_len = 0usize;
    for child in children {
        let child_size = body_size(child)?;
        peak_len = peak_len.max(
            compact_len
                .checked_add(child_size.peak_len)
                .ok_or(PackedValueError::SizeOverflow)?,
        );
        compact_len = compact_len
            .checked_add(child_size.compact_len)
            .ok_or(PackedValueError::SizeOverflow)?;
    }
    Ok(BodySize {
        compact_len,
        peak_len,
    })
}

/// Add canonical framing and the wide header kept live while children are encoded.
fn directory_size(count: usize, children: BodySize) -> Result<BodySize, PackedValueError> {
    Ok(BodySize {
        compact_len: directory::directory_total_len(count, children.compact_len)?,
        peak_len: directory::wide_directory_header_len(count)?
            .checked_add(children.peak_len)
            .ok_or(PackedValueError::SizeOverflow)?,
    })
}

/// Measure a tuple body, including an offset directory when any child is variable-width.
fn tuple_body_size(tuple: &TupleData) -> Result<BodySize, PackedValueError> {
    let children = children_size(tuple.data_map.values())?;
    if tuple
        .data_map
        .values()
        .all(|value| layout::fixed_value_width(value).is_some())
    {
        Ok(children)
    } else {
        directory_size(tuple.data_map.len(), children)
    }
}

/// Measure a list body using the same lane or framing choice as the encoder.
fn list_body_size(list: &ListData) -> Result<BodySize, PackedValueError> {
    let count = list.data.len();
    let elements_len = match layout::list_layout(list) {
        layout::ListLayout::Empty => 0,
        layout::ListLayout::UnsignedLane => primitive::unsigned_lane_width(&list.data)?
            .checked_mul(count)
            .ok_or(PackedValueError::SizeOverflow)?,
        layout::ListLayout::SignedLane => primitive::signed_lane_width(&list.data)?
            .checked_mul(count)
            .ok_or(PackedValueError::SizeOverflow)?,
        layout::ListLayout::BooleanLane => {
            count.checked_add(7).ok_or(PackedValueError::SizeOverflow)? / 8
        }
        layout::ListLayout::Fixed => return children_size(list.data.iter())?.with_prefix(4),
        layout::ListLayout::Variable => {
            let children = children_size(list.data.iter())?;
            return directory_size(count, children)?.with_prefix(4);
        }
    };
    BodySize {
        compact_len: elements_len,
        peak_len: elements_len,
    }
    .with_prefix(4)
}

/// Append the schema-independent packed body for one active value.
fn body(value: &Value, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    match value {
        Value::Int(value) => {
            let width = primitive::packed_int_width(*value);
            output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
        }
        Value::UInt(value) => {
            let width = primitive::packed_uint_width(*value);
            output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
        }
        Value::Bool(value) => output.push(u8::from(*value)),
        Value::Sequence(SequenceData::Buffer(buffer)) => output.extend_from_slice(&buffer.data),
        Value::Sequence(SequenceData::String(CharType::ASCII(string))) => {
            output.extend_from_slice(&string.data);
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(string))) => {
            for scalar in &string.data {
                output.extend_from_slice(scalar);
            }
        }
        Value::Principal(principal) => primitive::encode_principal(principal, output),
        Value::CallableContract(callable) => {
            primitive::encode_contract_principal(&callable.contract_identifier, output);
        }
        Value::Optional(optional) => match &optional.data {
            None => output.push(0),
            Some(child) => {
                output.push(1);
                body(child, output)?;
            }
        },
        Value::Response(response) => {
            output.push(u8::from(response.committed));
            body(&response.data, output)?;
        }
        Value::Tuple(tuple_value) => tuple(tuple_value, output)?,
        Value::Sequence(SequenceData::List(list_value)) => list(list_value, output)?,
    }
    Ok(())
}

/// Append tuple children in consensus field order, framing variable-width children by offset.
fn tuple(tuple: &TupleData, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    // Fixed tuples are self-framing under either the active value or a matching schema. Any
    // variable child requires a directory so readers can find child boundaries without scanning.
    if tuple
        .data_map
        .values()
        .all(|value| layout::fixed_value_width(value).is_some())
    {
        for value in tuple.data_map.values() {
            body(value, output)?;
        }
        return Ok(());
    }
    let mut directory = directory::reserve_wide_directory(tuple.data_map.len(), output)?;
    for value in tuple.data_map.values() {
        body(value, output)?;
        directory.write_next_offset(output)?;
    }
    directory.compact(output)
}

/// Append a list count and its canonically selected lane or child framing.
fn list(list: &ListData, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    let count = u32::try_from(list.data.len()).map_err(|_| PackedValueError::SizeOverflow)?;
    output.extend_from_slice(&count.to_le_bytes());
    match layout::list_layout(list) {
        layout::ListLayout::Empty => {}
        // Homogeneous scalar lanes amortize width metadata across the entire list. The active values
        // select the lane width; declared integer bounds never affect physical bytes.
        layout::ListLayout::UnsignedLane => {
            let width = primitive::unsigned_lane_width(&list.data)?;
            for value in &list.data {
                let Value::UInt(value) = value else {
                    return Err(PackedCodecInvariant::ListLaneClassificationChanged.into());
                };
                output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
            }
        }
        layout::ListLayout::SignedLane => {
            let width = primitive::signed_lane_width(&list.data)?;
            for value in &list.data {
                let Value::Int(value) = value else {
                    return Err(PackedCodecInvariant::ListLaneClassificationChanged.into());
                };
                output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
            }
        }
        layout::ListLayout::BooleanLane => {
            let byte_count = list
                .data
                .len()
                .checked_add(7)
                .ok_or(PackedValueError::SizeOverflow)?
                / 8;
            let start = output.len();
            let end = start
                .checked_add(byte_count)
                .ok_or(PackedValueError::SizeOverflow)?;
            output.resize(end, 0);
            for (index, value) in list.data.iter().enumerate() {
                let Value::Bool(value) = value else {
                    return Err(PackedCodecInvariant::ListLaneClassificationChanged.into());
                };
                if *value {
                    let byte_index = start
                        .checked_add(index / 8)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let byte = output
                        .get_mut(byte_index)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    *byte |= 1 << (index % 8);
                }
            }
        }
        layout::ListLayout::Fixed => {
            for value in &list.data {
                body(value, output)?;
            }
        }
        layout::ListLayout::Variable => {
            let mut directory = directory::reserve_wide_directory(list.data.len(), output)?;
            for value in &list.data {
                body(value, output)?;
                directory.write_next_offset(output)?;
            }
            directory.compact(output)?;
        }
    }
    Ok(())
}

/// Transcode one exact consensus value into canonical packed bytes and its descriptor.
///
/// The descriptor preserves active data omitted by historical cached schemas and enables exact
/// compatibility reconstruction without a caller-supplied type.
pub fn transcode_with_shape(
    consensus: &[u8],
) -> Result<(PackedValue, ValueShape), PackedValueError> {
    let value = deserialize_canonical_consensus(consensus)?;
    let consensus_byte_len =
        u32::try_from(consensus.len()).map_err(|_| PackedValueError::SizeOverflow)?;
    let packed = value_with_consensus_len(&value, consensus_byte_len)?;
    let shape = shape::encode_value_shape(&value)?;
    Ok((packed, shape))
}

/// Deserialize one exact consensus value and reject accepted-but-non-canonical encodings.
fn deserialize_canonical_consensus(consensus: &[u8]) -> Result<Value, PackedValueError> {
    let value =
        Value::try_deserialize_slice_exact_untyped(consensus).map_err(|error| match error {
            SerializationError::LeftoverBytesInDeserialization => {
                PackedValueError::NonCanonicalConsensusValue
            }
            error => PackedValueError::from(error),
        })?;
    if value.serialize_to_vec()? != consensus {
        return Err(PackedValueError::NonCanonicalConsensusValue);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{BodySize, body_size};
    use crate::representations::ClarityName;
    use crate::types::codec::packed::{PackedValue, PackedValueRef, PackedValueVersion};
    use crate::types::{TupleData, TypeSignature, Value};

    /// Construct a tuple with canonically ordered field names.
    fn tuple(fields: Vec<(&str, Value)>) -> Value {
        Value::Tuple(
            TupleData::from_data(
                fields
                    .into_iter()
                    .map(|(name, value)| (ClarityName::try_from(name.to_owned()).unwrap(), value))
                    .collect(),
            )
            .unwrap(),
        )
    }

    /// Check independent body-size expectations and prefixed public encoding round trips.
    fn assert_sizes(value: &Value, compact_len: usize, peak_len: usize) -> Vec<u8> {
        assert_eq!(
            body_size(value).unwrap(),
            BodySize {
                compact_len,
                peak_len,
            }
        );
        let consensus = value.serialize_to_vec().unwrap();
        let expected_type = TypeSignature::type_of(value).unwrap();
        let packed = PackedValue::encode(PackedValueVersion::V1, value).unwrap();
        let header_len = PackedValueVersion::V1.header_len();
        for prefix in [&[][..], &[0xa5, 0x5a][..]] {
            let output = PackedValue::encode_with_prefix(
                PackedValueVersion::V1,
                value,
                prefix,
                u32::try_from(consensus.len()).unwrap(),
            )
            .unwrap();
            assert_eq!(output.len(), prefix.len() + header_len + compact_len);
            assert_eq!(&output[..prefix.len()], prefix);
            assert_eq!(&output[prefix.len()..], packed.as_bytes());
            let decoded = PackedValueRef::parse(&output[prefix.len()..])
                .unwrap()
                .decode(&expected_type)
                .unwrap();
            assert_eq!(decoded.value.serialize_to_vec().unwrap(), consensus);
        }
        packed.into_bytes()[header_len..].to_vec()
    }

    #[rstest]
    #[case(0, &[0, 0, 0], 3, 9)]
    #[case(1, &[0, 0, 1], 4, 10)]
    #[case(255, &[0, 0, 255], 258, 264)]
    #[case(256, &[1, 0, 0, 0, 1], 261, 265)]
    #[case(65_535, &[1, 0, 0, 255, 255], 65_540, 65_544)]
    #[case(65_536, &[2, 0, 0, 0, 0, 0, 0, 1, 0], 65_545, 65_545)]
    /// Pin compact bytes and wide-header peaks on both sides of each offset-width boundary.
    fn tuple_directory_sizes_at_offset_boundaries(
        #[case] payload_len: usize,
        #[case] expected_directory: &[u8],
        #[case] compact_len: usize,
        #[case] peak_len: usize,
    ) {
        let payload = vec![0x42; payload_len];
        let value = tuple(vec![(
            "payload",
            Value::buff_from(payload.clone()).unwrap(),
        )]);
        let body = assert_sizes(&value, compact_len, peak_len);
        let mut expected_body = expected_directory.to_vec();
        expected_body.extend_from_slice(&payload);
        assert_eq!(body, expected_body);
    }

    #[test]
    /// Sibling wide directories do not coexist; wrapper tags and list counts remain live.
    fn nested_siblings_compact_before_the_next_child() {
        let first = tuple(vec![("a", Value::UInt(1))]);
        let second = tuple(vec![("a", Value::UInt(2))]);
        let value = tuple(vec![("a", first.clone()), ("b", second.clone())]);
        // Each child is four compact bytes and peaks at ten. The parent retains its
        // 13-byte wide directory: 13 + max(10, 4 + 10) = 27, rather than 33.
        let body = assert_sizes(&value, 12, 27);
        assert_eq!(body, [0, 0, 4, 8, 0, 0, 1, 1, 0, 0, 1, 2]);

        let list = Value::cons_list_unsanitized(vec![first, second]).unwrap();
        let body = assert_sizes(&list, 16, 31);
        assert_eq!(body, [2, 0, 0, 0, 0, 0, 4, 8, 0, 0, 1, 1, 0, 0, 1, 2]);
        let wrapped = Value::some(Value::okay(list).unwrap()).unwrap();
        let wrapped_body = assert_sizes(&wrapped, 18, 33);
        assert_eq!(&wrapped_body[..2], &[1, 1]);
        assert_eq!(&wrapped_body[2..], body);
    }

    #[test]
    /// Empty children leave only a count and directory, whose temporary width dominates the peak.
    fn empty_buffer_list_reserves_its_wide_directory() {
        let value =
            Value::cons_list_unsanitized(vec![Value::buff_from(vec![]).unwrap(); 4_096]).unwrap();
        let body = assert_sizes(&value, 4_102, 16_393);
        assert_eq!(&body[..5], &[0, 16, 0, 0, 0]);
        assert!(body[5..].iter().all(|byte| *byte == 0));
    }

    #[test]
    /// A later payload can absorb an earlier child's expansion; reversing them changes the peak.
    fn peak_tracks_child_order_instead_of_summing_expansions() {
        let list =
            Value::cons_list_unsanitized(vec![Value::buff_from(vec![]).unwrap(); 4_096]).unwrap();
        let buffer = Value::buff_from(vec![0x42; 20_000]).unwrap();
        // The two-byte compact parent directory is seven bytes; its wide form is 13.
        // List first: 13 + max(16_393, 4_102 + 20_000) = 24_115.
        let list_first = tuple(vec![("a", list.clone()), ("b", buffer.clone())]);
        assert_sizes(&list_first, 24_109, 24_115);
        // List last: 13 + max(20_000, 20_000 + 16_393) = 36_406.
        let list_last = tuple(vec![("a", buffer), ("b", list)]);
        assert_sizes(&list_last, 24_109, 36_406);
    }
}
