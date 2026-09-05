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

//! Version 1 schema-aware decoding and logical-length validation.

use std::str;

use super::{
    DecodedPackedValue, PackedCodecInvariant, PackedRecordError, PackedSchemaError,
    PackedValueError, PackedValueRef, directory, layout, primitive,
};
use crate::types::signatures::{CallableSubtype, SequenceSubtype, StringSubtype};
use crate::types::{
    ASCIIData, CallableData, CharType, ListData, ListTypeData, PrincipalData,
    QualifiedContractIdentifier, SequenceData, TraitIdentifier, TupleData, TypeSignature, UTF8Data,
    Value,
};

/// Decode and validate one canonical packed record under a declared read schema.
pub fn value(
    packed: PackedValueRef<'_>,
    expected: &TypeSignature,
) -> Result<DecodedPackedValue, PackedValueError> {
    let (value, actual_len) = body(packed.body(), expected)?;
    if actual_len != packed.consensus_byte_len() {
        return Err(PackedRecordError::ConsensusLengthMismatch {
            declared: packed.consensus_byte_len(),
            actual: actual_len,
        }
        .into());
    }
    Ok(DecodedPackedValue {
        value,
        consensus_byte_len: actual_len,
    })
}

/// Decode one complete packed body under its caller-supplied schema.
///
/// The returned length is the value's consensus-serialized length, used to validate the record
/// header and preserve consensus cost accounting.
fn body(bytes: &[u8], expected: &TypeSignature) -> Result<(Value, u32), PackedValueError> {
    use TypeSignature::*;

    match expected {
        IntType => Ok((Value::Int(primitive::decode_canonical_i128(bytes)?), 17)),
        UIntType => Ok((Value::UInt(primitive::decode_canonical_u128(bytes)?), 17)),
        BoolType => match bytes {
            [0] => Ok((Value::Bool(false), 1)),
            [1] => Ok((Value::Bool(true), 1)),
            _ => Err(PackedRecordError::InvalidBoolean {
                length: bytes.len(),
                first_byte: bytes.first().copied(),
            }
            .into()),
        },
        SequenceType(SequenceSubtype::BufferType(max_len)) => {
            let maximum = u32::from(max_len) as usize;
            if bytes.len() > maximum {
                return Err(PackedSchemaError::BufferExceedsBound {
                    actual: bytes.len(),
                    maximum,
                }
                .into());
            }
            Ok((
                Value::Sequence(SequenceData::Buffer(crate::types::BuffData {
                    data: bytes.to_vec(),
                })),
                primitive::logical_sequence_len(bytes.len())?,
            ))
        }
        SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(max_len))) => {
            if let Some((offset, &byte)) = bytes
                .iter()
                .enumerate()
                .find(|(_, byte)| !primitive::valid_ascii_byte(byte))
            {
                return Err(PackedRecordError::InvalidAsciiString { offset, byte }.into());
            }
            let maximum = u32::from(max_len) as usize;
            if bytes.len() > maximum {
                return Err(PackedSchemaError::AsciiStringExceedsBound {
                    actual: bytes.len(),
                    maximum,
                }
                .into());
            }
            Ok((
                Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                    data: bytes.to_vec(),
                }))),
                primitive::logical_sequence_len(bytes.len())?,
            ))
        }
        SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(max_len))) => {
            let string =
                str::from_utf8(bytes).map_err(|error| PackedRecordError::InvalidUtf8String {
                    valid_up_to: error.valid_up_to(),
                    error_len: error.error_len(),
                })?;
            let actual = string.chars().count();
            let maximum = u32::from(max_len) as usize;
            if actual > maximum {
                return Err(PackedSchemaError::Utf8StringExceedsBound { actual, maximum }.into());
            }
            let data = string
                .chars()
                .map(|character| {
                    let mut scalar = vec![0; character.len_utf8()];
                    character.encode_utf8(&mut scalar);
                    scalar
                })
                .collect();
            Ok((
                Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data }))),
                primitive::logical_sequence_len(bytes.len())?,
            ))
        }
        PrincipalType => {
            let principal = primitive::PackedPrincipal::parse(bytes)?;
            let logical_len = principal.consensus_byte_len()?;
            Ok((
                Value::Principal(principal.to_principal_data()?),
                logical_len,
            ))
        }
        CallableType(subtype) => callable(bytes, subtype),
        TraitReferenceType(trait_identifier) => trait_callable(bytes, trait_identifier.clone()),
        OptionalType(inner) => {
            let (tag, child) = primitive::split_tag(bytes)?;
            match tag {
                0 if child.is_empty() => Ok((Value::none(), 1)),
                1 => {
                    let (value, child_len) = body(child, inner)?;
                    Ok((
                        Value::some(value)?,
                        primitive::checked_logical_add(1, child_len)?,
                    ))
                }
                _ => Err(PackedRecordError::InvalidOptional {
                    discriminant: tag,
                    child_length: child.len(),
                }
                .into()),
            }
        }
        ResponseType(types) => {
            let (tag, child) = primitive::split_tag(bytes)?;
            match tag {
                0 => {
                    let (value, child_len) = body(child, &types.1)?;
                    Ok((
                        Value::error(value)?,
                        primitive::checked_logical_add(1, child_len)?,
                    ))
                }
                1 => {
                    let (value, child_len) = body(child, &types.0)?;
                    Ok((
                        Value::okay(value)?,
                        primitive::checked_logical_add(1, child_len)?,
                    ))
                }
                _ => Err(PackedRecordError::InvalidResponse { discriminant: tag }.into()),
            }
        }
        TupleType(tuple_type) => tuple(bytes, tuple_type),
        SequenceType(SequenceSubtype::ListType(list_type)) => list(bytes, list_type),
        NoType => Err(PackedSchemaError::NoType.into()),
        ListUnionType(_) => Err(PackedSchemaError::ListUnionType.into()),
    }
}

/// Decode a callable contract and restore the schema-provided callable identity.
fn callable(bytes: &[u8], expected: &CallableSubtype) -> Result<(Value, u32), PackedValueError> {
    let (contract_identifier, logical_len) = contract(bytes)?;
    let trait_identifier = match expected {
        CallableSubtype::Principal(expected_contract) => {
            if contract_identifier != *expected_contract {
                return Err(PackedSchemaError::CallableContractMismatch {
                    expected: Box::new(expected_contract.clone()),
                    actual: Box::new(contract_identifier),
                }
                .into());
            }
            None
        }
        CallableSubtype::Trait(trait_identifier) => Some(Box::new(trait_identifier.clone())),
    };
    Ok((
        Value::CallableContract(CallableData {
            contract_identifier,
            trait_identifier,
        }),
        logical_len,
    ))
}

/// Decode the canonical contract-principal body shared by callable schema variants.
fn contract(bytes: &[u8]) -> Result<(QualifiedContractIdentifier, u32), PackedValueError> {
    let principal = primitive::PackedPrincipal::parse(bytes)?;
    let logical_len = principal.consensus_byte_len()?;
    match principal.to_principal_data()? {
        PrincipalData::Contract(contract) => Ok((contract, logical_len)),
        PrincipalData::Standard(actual) => {
            Err(PackedSchemaError::CallableRequiresContractPrincipal { actual }.into())
        }
    }
}

/// Decode a trait callable while restoring its schema-provided trait identifier.
fn trait_callable(
    bytes: &[u8],
    trait_identifier: TraitIdentifier,
) -> Result<(Value, u32), PackedValueError> {
    let (contract_identifier, logical_len) = contract(bytes)?;
    Ok((
        Value::CallableContract(CallableData {
            contract_identifier,
            trait_identifier: Some(Box::new(trait_identifier)),
        }),
        logical_len,
    ))
}

/// Decode a tuple using fixed concatenation or an offset directory selected by its schema.
fn tuple(
    bytes: &[u8],
    expected: &crate::types::TupleTypeSignature,
) -> Result<(Value, u32), PackedValueError> {
    let all_fixed = expected
        .get_type_map()
        .values()
        .try_fold(true, |all_fixed, child| {
            Ok::<_, PackedValueError>(all_fixed && layout::fixed_type_width(child)?.is_some())
        })?;
    let mut fields = Vec::with_capacity(expected.get_type_map().len());
    let mut logical_len = 5u32;
    if all_fixed {
        let mut cursor = 0usize;
        for (name, field_type) in expected.get_type_map() {
            let width = layout::fixed_type_width(field_type)?
                .ok_or(PackedCodecInvariant::FixedTupleClassificationChanged)?;
            let end = cursor
                .checked_add(width)
                .ok_or(PackedValueError::SizeOverflow)?;
            let field = bytes
                .get(cursor..end)
                .ok_or(PackedRecordError::TruncatedFixedTuple {
                    required_end: end,
                    actual: bytes.len(),
                })?;
            let (value, child_len) = body(field, field_type)?;
            logical_len = primitive::tuple_logical_add(logical_len, name.as_str(), child_len)?;
            fields.push((name.clone(), value));
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(PackedRecordError::FixedTupleTrailingBytes {
                consumed: cursor,
                actual: bytes.len(),
            }
            .into());
        }
    } else {
        let directory = directory::Directory::parse(bytes, expected.get_type_map().len())?;
        for ((name, field_type), child) in expected.get_type_map().iter().zip(directory.children())
        {
            let (value, child_len) = body(child?, field_type)?;
            logical_len = primitive::tuple_logical_add(logical_len, name.as_str(), child_len)?;
            fields.push((name.clone(), value));
        }
    }
    let value = Value::Tuple(TupleData {
        type_signature: expected.clone(),
        data_map: fields.into_iter().collect(),
    });
    Ok((value, logical_len))
}

/// Decode a counted list using its scalar lane, fixed-width, or directory-framed layout.
fn list(bytes: &[u8], expected: &ListTypeData) -> Result<(Value, u32), PackedValueError> {
    let (count, elements) = primitive::split_list(bytes)?;
    let maximum = expected.get_max_len() as usize;
    if count > maximum {
        return Err(PackedSchemaError::ListExceedsBound {
            actual: count,
            maximum,
        }
        .into());
    }
    if count == 0 {
        if !elements.is_empty() {
            return Err(PackedRecordError::EmptyListHasElementRegion {
                actual: elements.len(),
            }
            .into());
        }
        return Ok((decoded_list(vec![], expected), 5));
    }
    let element_type = expected.get_list_item_type();
    let (values, children_len) = match element_type {
        TypeSignature::UIntType => {
            let lane = primitive::IntegerLane::parse_unsigned(elements, count)?;
            let logical_len = lane.consensus_byte_len()?;
            (lane.decode_unsigned_values(), logical_len)
        }
        TypeSignature::IntType => {
            let lane = primitive::IntegerLane::parse_signed(elements, count)?;
            let logical_len = lane.consensus_byte_len()?;
            (lane.decode_signed_values(), logical_len)
        }
        TypeSignature::BoolType => (
            primitive::decode_bool_lane(elements, count)?,
            u32::try_from(count).map_err(|_| PackedValueError::SizeOverflow)?,
        ),
        _ => match layout::fixed_type_width(element_type)? {
            Some(width) => {
                let expected_len = count
                    .checked_mul(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
                if elements.len() != expected_len {
                    return Err(PackedRecordError::FixedListLengthMismatch {
                        actual: elements.len(),
                        expected: expected_len,
                    }
                    .into());
                }
                let mut values = Vec::with_capacity(count);
                let mut children_len = 0u32;
                for index in 0..count {
                    let start = index
                        .checked_mul(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let end = start
                        .checked_add(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let child = elements.get(start..end).ok_or(
                        PackedCodecInvariant::FixedListChildRangeOutOfBounds {
                            start,
                            end,
                            length: elements.len(),
                        },
                    )?;
                    let (value, child_len) = body(child, element_type)?;
                    children_len = primitive::checked_logical_add(children_len, child_len)?;
                    values.push(value);
                }
                (values, children_len)
            }
            None => {
                let directory = directory::Directory::parse(elements, count)?;
                let mut values = Vec::with_capacity(count);
                let mut children_len = 0u32;
                for child in directory.children() {
                    let (value, child_len) = body(child?, element_type)?;
                    children_len = primitive::checked_logical_add(children_len, child_len)?;
                    values.push(value);
                }
                (values, children_len)
            }
        },
    };
    Ok((
        decoded_list(values, expected),
        primitive::checked_logical_add(5, children_len)?,
    ))
}

/// Construct a list after this module has validated its count and every child against `expected`.
fn decoded_list(values: Vec<Value>, expected: &ListTypeData) -> Value {
    Value::Sequence(SequenceData::List(ListData {
        data: values,
        type_signature: expected.clone(),
    }))
}
