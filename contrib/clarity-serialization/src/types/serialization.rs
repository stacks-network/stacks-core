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

use std::io::{Read, Write};
use std::{cmp, str};

use lazy_static::lazy_static;
use stacks_common::codec::{Error as codec_error, StacksMessageCodec};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{hex_bytes, to_hex};
use stacks_common::util::retry::BoundReader;

use super::{ListTypeData, TupleTypeSignature};
use crate::errors::CodecError;
use crate::representations::{ClarityName, ContractName, MAX_STRING_LEN};
use crate::types::{
    BOUND_VALUE_SERIALIZATION_BYTES, BufferLength, CallableData, CharType, MAX_TYPE_DEPTH,
    MAX_VALUE_SIZE, OptionalData, PrincipalData, QualifiedContractIdentifier, SequenceData,
    SequenceSubtype, StandardPrincipalData, StringSubtype, TupleData, TypeSignature, Value,
};

lazy_static! {
    pub static ref NONE_SERIALIZATION_LEN: u64 = {
        #[allow(clippy::unwrap_used)]
        u64::try_from(Value::none().serialize_to_vec().unwrap().len()).unwrap()
    };
}

/// Deserialization uses a specific epoch for passing to the type signature checks
/// The reason this is pinned to Epoch21 is so that values stored before epoch-2.4
///  can still be read from the database.
const DESERIALIZATION_TYPE_CHECK_EPOCH: StacksEpochId = StacksEpochId::Epoch21;

/// Pre-sanitization values could end up being larger than the deserializer originally
///  supported, so we increase the bound to a higher level limit imposed by the cost checker.
const SANITIZATION_READ_BOUND: u64 = 15_000_000;

/// Before epoch-2.4, this is the deserialization depth limit.
/// After epoch-2.4, with type sanitization support, the full
///  clarity depth limit is supported.
const UNSANITIZED_DEPTH_CHECK: usize = 16;

define_u8_enum!(TypePrefix {
    Int = 0,
    UInt = 1,
    Buffer = 2,
    BoolTrue = 3,
    BoolFalse = 4,
    PrincipalStandard = 5,
    PrincipalContract = 6,
    ResponseOk = 7,
    ResponseErr = 8,
    OptionalNone = 9,
    OptionalSome = 10,
    List = 11,
    Tuple = 12,
    StringASCII = 13,
    StringUTF8 = 14
});

impl From<&PrincipalData> for TypePrefix {
    fn from(v: &PrincipalData) -> TypePrefix {
        use super::PrincipalData::*;
        match v {
            Standard(_) => TypePrefix::PrincipalStandard,
            Contract(_) => TypePrefix::PrincipalContract,
        }
    }
}

impl From<&Value> for TypePrefix {
    fn from(v: &Value) -> TypePrefix {
        use super::CharType;
        use super::SequenceData::*;
        use super::Value::*;

        match v {
            Int(_) => TypePrefix::Int,
            UInt(_) => TypePrefix::UInt,
            Bool(value) => {
                if *value {
                    TypePrefix::BoolTrue
                } else {
                    TypePrefix::BoolFalse
                }
            }
            Principal(p) => TypePrefix::from(p),
            Response(response) => {
                if response.committed {
                    TypePrefix::ResponseOk
                } else {
                    TypePrefix::ResponseErr
                }
            }
            Optional(OptionalData { data: None }) => TypePrefix::OptionalNone,
            Optional(OptionalData { data: Some(_) }) => TypePrefix::OptionalSome,
            Tuple(_) => TypePrefix::Tuple,
            Sequence(Buffer(_)) => TypePrefix::Buffer,
            Sequence(List(_)) => TypePrefix::List,
            Sequence(String(CharType::ASCII(_))) => TypePrefix::StringASCII,
            Sequence(String(CharType::UTF8(_))) => TypePrefix::StringUTF8,
            &CallableContract(_) => TypePrefix::PrincipalContract,
        }
    }
}

/// Not a public trait,
///   this is just used to simplify serializing some types that
///   are repeatedly serialized or deserialized.
trait ClarityValueSerializable<T: std::marker::Sized> {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    fn deserialize_read<R: Read>(r: &mut R) -> Result<T, CodecError>;
}

impl ClarityValueSerializable<StandardPrincipalData> for StandardPrincipalData {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[self.version()])?;
        w.write_all(&self.1)
    }

    fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let mut version = [0; 1];
        let mut data = [0; 20];
        r.read_exact(&mut version)?;
        r.read_exact(&mut data)?;
        StandardPrincipalData::new(version[0], data)
            .map_err(|_| CodecError::UnexpectedSerialization)
    }
}

macro_rules! serialize_guarded_string {
    ($Name:ident) => {
        impl ClarityValueSerializable<$Name> for $Name {
            fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
                w.write_all(&self.len().to_be_bytes())?;
                // self.as_bytes() is always len bytes, because this is only used for GuardedStrings
                //   which are a subset of ASCII
                w.write_all(self.as_str().as_bytes())
            }

            fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, CodecError> {
                let mut len = [0; 1];
                r.read_exact(&mut len)?;
                let len = u8::from_be_bytes(len);
                if len > MAX_STRING_LEN {
                    return Err(CodecError::Deserialization("String too long".to_string()));
                }

                let mut data = vec![0; len as usize];
                r.read_exact(&mut data)?;

                String::from_utf8(data)
                    .map_err(|_| CodecError::Deserialization("Non-UTF8 string data".into()))
                    .and_then(|x| {
                        $Name::try_from(x).map_err(|_| {
                            CodecError::Deserialization("Illegal Clarity string".into())
                        })
                    })
            }
        }
    };
}

serialize_guarded_string!(ClarityName);
serialize_guarded_string!(ContractName);

impl PrincipalData {
    fn inner_consensus_serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[TypePrefix::from(self) as u8])?;
        match self {
            PrincipalData::Standard(p) => p.serialize_write(w),
            PrincipalData::Contract(contract_identifier) => {
                contract_identifier.issuer.serialize_write(w)?;
                contract_identifier.name.serialize_write(w)
            }
        }
    }

    fn inner_consensus_deserialize<R: Read>(r: &mut R) -> Result<PrincipalData, CodecError> {
        let mut header = [0];
        r.read_exact(&mut header)?;

        let prefix = TypePrefix::from_u8(header[0])
            .ok_or(CodecError::Deserialization("Bad principal prefix".into()))?;

        match prefix {
            TypePrefix::PrincipalStandard => {
                StandardPrincipalData::deserialize_read(r).map(PrincipalData::from)
            }
            TypePrefix::PrincipalContract => {
                let issuer = StandardPrincipalData::deserialize_read(r)?;
                let name = ContractName::deserialize_read(r)?;
                Ok(PrincipalData::from(QualifiedContractIdentifier {
                    issuer,
                    name,
                }))
            }
            _ => Err(CodecError::Deserialization("Bad principal prefix".into())),
        }
    }
}

impl StacksMessageCodec for PrincipalData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.inner_consensus_serialize(fd)
            .map_err(codec_error::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<PrincipalData, codec_error> {
        PrincipalData::inner_consensus_deserialize(fd)
            .map_err(|e| codec_error::DeserializeError(e.to_string()))
    }
}

macro_rules! check_match {
    ($item:expr, $Pattern:pat) => {
        match $item {
            None => Ok(()),
            Some($Pattern) => Ok(()),
            Some(x) => Err(CodecError::DeserializeExpected(Box::new(x))),
        }
    };
}

/// `DeserializeStackItem` objects are used by the deserializer to indicate
///  how the deserialization loop's current object is to be handled once it is
///  deserialized: i.e., is the object the top-level object for the serialization
///  or is it an entry in a composite type (e.g., a list or tuple)?
enum DeserializeStackItem {
    List {
        items: Vec<Value>,
        expected_len: u32,
        expected_type: Option<ListTypeData>,
    },
    Tuple {
        items: Vec<(ClarityName, Value)>,
        expected_len: u64,
        processed_entries: u64,
        expected_type: Option<TupleTypeSignature>,
        next_name: ClarityName,
        next_sanitize: bool,
    },
    OptionSome {
        inner_expected_type: Option<TypeSignature>,
    },
    ResponseOk {
        inner_expected_type: Option<TypeSignature>,
    },
    ResponseErr {
        inner_expected_type: Option<TypeSignature>,
    },
    TopLevel {
        expected_type: Option<TypeSignature>,
    },
}

impl DeserializeStackItem {
    /// What is the expected type for the child of this deserialization stack item?
    ///
    /// Returns `None` if this stack item either doesn't have an expected type, or the
    ///   next child is going to be sanitized/elided.
    fn next_expected_type(&self) -> Result<Option<TypeSignature>, CodecError> {
        match self {
            DeserializeStackItem::List { expected_type, .. } => Ok(expected_type
                .as_ref()
                .map(|lt| lt.get_list_item_type())
                .cloned()),
            DeserializeStackItem::Tuple {
                expected_type,
                next_name,
                next_sanitize,
                ..
            } => match expected_type {
                None => Ok(None),
                Some(some_tuple) => {
                    // if we're sanitizing this tuple, and the `next_name` field is to be
                    //  removed, don't return an expected type.
                    if *next_sanitize {
                        return Ok(None);
                    }
                    let field_type = some_tuple.field_type(next_name).ok_or_else(|| {
                        CodecError::DeserializeExpected(Box::new(TypeSignature::TupleType(
                            some_tuple.clone(),
                        )))
                    })?;
                    Ok(Some(field_type.clone()))
                }
            },
            DeserializeStackItem::OptionSome {
                inner_expected_type,
            } => Ok(inner_expected_type.clone()),
            DeserializeStackItem::ResponseOk {
                inner_expected_type,
            } => Ok(inner_expected_type.clone()),
            DeserializeStackItem::ResponseErr {
                inner_expected_type,
            } => Ok(inner_expected_type.clone()),
            DeserializeStackItem::TopLevel { expected_type } => Ok(expected_type.clone()),
        }
    }
}

impl TypeSignature {
    /// Return the maximum length of the consensus serialization of a
    /// Clarity value of this type. The returned length *may* not fit
    /// in a Clarity buffer! For example, the maximum serialized
    /// size of a `(buff 1024*1024)` is `1+1024*1024` because of the
    /// type prefix byte. However, that is 1 byte larger than the maximum
    /// buffer size in Clarity.
    pub fn max_serialized_size(&self) -> Result<u32, CodecError> {
        let type_prefix_size = 1;

        let max_output_size = match self {
            TypeSignature::NoType => {
                // A `NoType` should *never* actually be evaluated
                // (`NoType` corresponds to the Some branch of a
                // `none` that is never matched with a corresponding
                // `some` or similar with `result` types).  So, when
                // serializing an object with a `NoType`, the other
                // branch should always be used.
                return Err(CodecError::CouldNotDetermineSerializationType);
            }
            TypeSignature::IntType => 16,
            TypeSignature::UIntType => 16,
            TypeSignature::BoolType => 0,
            TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)) => {
                // u32 length as big-endian bytes
                let list_length_encode = 4;
                list_type
                    .get_max_len()
                    .checked_mul(list_type.get_list_item_type().max_serialized_size()?)
                    .and_then(|x| x.checked_add(list_length_encode))
                    .ok_or_else(|| CodecError::ValueTooLarge)?
            }
            TypeSignature::SequenceType(SequenceSubtype::BufferType(buff_length)) => {
                // u32 length as big-endian bytes
                let buff_length_encode = 4;
                u32::from(buff_length)
                    .checked_add(buff_length_encode)
                    .ok_or_else(|| CodecError::ValueTooLarge)?
            }
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                length,
            ))) => {
                // u32 length as big-endian bytes
                let str_length_encode = 4;
                // ascii is 1-byte per character
                u32::from(length)
                    .checked_add(str_length_encode)
                    .ok_or_else(|| CodecError::ValueTooLarge)?
            }
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
                length,
            ))) => {
                // u32 length as big-endian bytes
                let str_length_encode = 4;
                // utf-8 is maximum 4 bytes per codepoint (which is the length)
                u32::from(length)
                    .checked_mul(4)
                    .and_then(|x| x.checked_add(str_length_encode))
                    .ok_or_else(|| CodecError::ValueTooLarge)?
            }
            TypeSignature::PrincipalType
            | TypeSignature::CallableType(_)
            | TypeSignature::TraitReferenceType(_) => {
                // version byte + 20 byte hash160
                let maximum_issuer_size = 21;
                let contract_name_length_encode = 1;
                // contract name maximum length is `MAX_STRING_LEN` (128), and ASCII
                let maximum_contract_name = MAX_STRING_LEN as u32;
                maximum_contract_name + maximum_issuer_size + contract_name_length_encode
            }
            TypeSignature::TupleType(tuple_type) => {
                let type_map = tuple_type.get_type_map();
                // u32 length as big-endian bytes
                let tuple_length_encode: u32 = 4;
                let mut total_size = tuple_length_encode;
                for (key, value) in type_map.iter() {
                    let value_size = value.max_serialized_size()?;
                    total_size = total_size
                        .checked_add(1) // length of key-name
                        .and_then(|x| x.checked_add(key.len() as u32)) // ClarityName is ascii-only, so 1 byte per length
                        .and_then(|x| x.checked_add(value_size))
                        .ok_or_else(|| CodecError::ValueTooLarge)?;
                }
                total_size
            }
            TypeSignature::OptionalType(some_type) => {
                match some_type.max_serialized_size() {
                    Ok(size) => size,
                    // if NoType, then this is just serializing a none
                    // value, which is only the type prefix
                    Err(CodecError::CouldNotDetermineSerializationType) => 0,
                    Err(e) => return Err(e),
                }
            }
            TypeSignature::ResponseType(response_types) => {
                let (ok_type, err_type) = response_types.as_ref();
                let (ok_type_max_size, no_ok_type) = match ok_type.max_serialized_size() {
                    Ok(size) => (size, false),
                    Err(CodecError::CouldNotDetermineSerializationType) => (0, true),
                    Err(e) => return Err(e),
                };
                let err_type_max_size = match err_type.max_serialized_size() {
                    Ok(size) => size,
                    Err(CodecError::CouldNotDetermineSerializationType) => {
                        if no_ok_type {
                            // if both the ok type and the error type are NoType,
                            //  throw a CheckError. This should not be possible, but the check
                            //  is done out of caution.
                            return Err(CodecError::CouldNotDetermineSerializationType);
                        } else {
                            0
                        }
                    }
                    Err(e) => return Err(e),
                };
                cmp::max(ok_type_max_size, err_type_max_size)
            }
            TypeSignature::ListUnionType(_) => {
                return Err(CodecError::CouldNotDetermineSerializationType);
            }
        };

        max_output_size
            .checked_add(type_prefix_size)
            .ok_or_else(|| CodecError::ValueTooLarge)
    }
}

impl Value {
    pub fn deserialize_read<R: Read>(
        r: &mut R,
        expected_type: Option<&TypeSignature>,
        sanitize: bool,
    ) -> Result<Value, CodecError> {
        Self::deserialize_read_count(r, expected_type, sanitize).map(|(value, _)| value)
    }

    /// Deserialize just like `deserialize_read` but also
    ///  return the bytes read.
    /// If `sanitize` argument is set to true and `expected_type` is supplied,
    ///  this method will remove any extraneous tuple fields which may have been
    ///  allowed by `least_super_type`.
    pub fn deserialize_read_count<R: Read>(
        r: &mut R,
        expected_type: Option<&TypeSignature>,
        sanitize: bool,
    ) -> Result<(Value, u64), CodecError> {
        let bound_value_serialization_bytes = if sanitize && expected_type.is_some() {
            SANITIZATION_READ_BOUND
        } else {
            BOUND_VALUE_SERIALIZATION_BYTES as u64
        };
        let mut bound_reader = BoundReader::from_reader(r, bound_value_serialization_bytes);
        let value = Value::inner_deserialize_read(&mut bound_reader, expected_type, sanitize)?;
        let bytes_read = bound_reader.num_read();
        if let Some(expected_type) = expected_type {
            let expect_size = match expected_type.max_serialized_size() {
                Ok(x) => x,
                Err(e) => {
                    debug!(
                        "Failed to determine max serialized size when checking expected_type argument";
                        "err" => ?e
                    );
                    return Ok((value, bytes_read));
                }
            };

            if bytes_read > expect_size as u64 {
                // this can happen due to sanitization, so its no longer indicative of a *problem* with the node.
                debug!(
                    "Deserialized more bytes than expected size during deserialization. Expected size = {expect_size}, bytes read = {bytes_read}, type = {expected_type:?}"
                );
            }
        }

        Ok((value, bytes_read))
    }

    fn inner_deserialize_read<R: Read>(
        r: &mut R,
        top_expected_type: Option<&TypeSignature>,
        sanitize: bool,
    ) -> Result<Value, CodecError> {
        use super::Value::*;

        let mut stack = vec![DeserializeStackItem::TopLevel {
            expected_type: top_expected_type.cloned(),
        }];

        while !stack.is_empty() {
            let depth_check = if sanitize {
                MAX_TYPE_DEPTH as usize
            } else {
                UNSANITIZED_DEPTH_CHECK
            };
            if stack.len() > depth_check {
                return Err(CodecError::TypeSignatureTooDeep);
            }

            #[allow(clippy::expect_used)]
            let expected_type = stack
                .last()
                .expect("FATAL: stack.last() should always be some() because of loop condition")
                .next_expected_type()?;

            let mut header = [0];
            r.read_exact(&mut header)?;
            let prefix = TypePrefix::from_u8(header[0])
                .ok_or(CodecError::Deserialization("Bad type prefix".into()))?;

            let item = match prefix {
                TypePrefix::Int => {
                    check_match!(expected_type, TypeSignature::IntType)?;
                    let mut buffer = [0; 16];
                    r.read_exact(&mut buffer)?;
                    Ok(Int(i128::from_be_bytes(buffer)))
                }
                TypePrefix::UInt => {
                    check_match!(expected_type, TypeSignature::UIntType)?;
                    let mut buffer = [0; 16];
                    r.read_exact(&mut buffer)?;
                    Ok(UInt(u128::from_be_bytes(buffer)))
                }
                TypePrefix::Buffer => {
                    let mut buffer_len = [0; 4];
                    r.read_exact(&mut buffer_len)?;
                    let buffer_len = BufferLength::try_from(u32::from_be_bytes(buffer_len))?;

                    if let Some(x) = &expected_type {
                        let passed_test = match x {
                            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                                expected_len,
                            )) => u32::from(&buffer_len) <= u32::from(expected_len),
                            _ => false,
                        };
                        if !passed_test {
                            return Err(CodecError::DeserializeExpected(Box::new(x.clone())));
                        }
                    }

                    let mut data = vec![0; u32::from(buffer_len) as usize];

                    r.read_exact(&mut data[..])?;

                    Value::buff_from(data)
                        .map_err(|_| CodecError::Deserialization("Bad buffer".into()))
                }
                TypePrefix::BoolTrue => {
                    check_match!(expected_type, TypeSignature::BoolType)?;
                    Ok(Bool(true))
                }
                TypePrefix::BoolFalse => {
                    check_match!(expected_type, TypeSignature::BoolType)?;
                    Ok(Bool(false))
                }
                TypePrefix::PrincipalStandard => {
                    check_match!(expected_type, TypeSignature::PrincipalType)?;
                    StandardPrincipalData::deserialize_read(r).map(Value::from)
                }
                TypePrefix::PrincipalContract => {
                    check_match!(expected_type, TypeSignature::PrincipalType)?;
                    let issuer = StandardPrincipalData::deserialize_read(r)?;
                    let name = ContractName::deserialize_read(r)?;
                    Ok(Value::from(QualifiedContractIdentifier { issuer, name }))
                }
                TypePrefix::ResponseOk | TypePrefix::ResponseErr => {
                    let committed = prefix == TypePrefix::ResponseOk;

                    let expect_contained_type = match &expected_type {
                        None => None,
                        Some(x) => {
                            let contained_type = match (committed, x) {
                                (true, TypeSignature::ResponseType(types)) => Ok(&types.0),
                                (false, TypeSignature::ResponseType(types)) => Ok(&types.1),
                                _ => Err(CodecError::DeserializeExpected(Box::new(x.clone()))),
                            }?;
                            Some(contained_type)
                        }
                    };

                    let stack_item = if committed {
                        DeserializeStackItem::ResponseOk {
                            inner_expected_type: expect_contained_type.cloned(),
                        }
                    } else {
                        DeserializeStackItem::ResponseErr {
                            inner_expected_type: expect_contained_type.cloned(),
                        }
                    };

                    stack.push(stack_item);
                    continue;
                }
                TypePrefix::OptionalNone => {
                    check_match!(expected_type, TypeSignature::OptionalType(_))?;
                    Ok(Value::none())
                }
                TypePrefix::OptionalSome => {
                    let expect_contained_type = match &expected_type {
                        None => None,
                        Some(x) => {
                            let contained_type = match x {
                                TypeSignature::OptionalType(some_type) => Ok(some_type.as_ref()),
                                _ => Err(CodecError::DeserializeExpected(Box::new(x.clone()))),
                            }?;
                            Some(contained_type)
                        }
                    };

                    let stack_item = DeserializeStackItem::OptionSome {
                        inner_expected_type: expect_contained_type.cloned(),
                    };

                    stack.push(stack_item);
                    continue;
                }
                TypePrefix::List => {
                    let mut len = [0; 4];
                    r.read_exact(&mut len)?;
                    let len = u32::from_be_bytes(len);

                    if len > MAX_VALUE_SIZE {
                        return Err(CodecError::Deserialization("Illegal list type".into()));
                    }

                    let (list_type, _entry_type) = match expected_type.as_ref() {
                        None => (None, None),
                        Some(TypeSignature::SequenceType(SequenceSubtype::ListType(list_type))) => {
                            if len > list_type.get_max_len() {
                                // unwrap is safe because of the match condition
                                #[allow(clippy::unwrap_used)]
                                return Err(CodecError::DeserializeExpected(Box::new(
                                    expected_type.unwrap(),
                                )));
                            }
                            (Some(list_type), Some(list_type.get_list_item_type()))
                        }
                        Some(x) => {
                            return Err(CodecError::DeserializeExpected(Box::new(x.clone())));
                        }
                    };

                    if len > 0 {
                        let items = Vec::with_capacity(len as usize);
                        let stack_item = DeserializeStackItem::List {
                            items,
                            expected_len: len,
                            expected_type: list_type.cloned(),
                        };

                        stack.push(stack_item);
                        continue;
                    } else {
                        let finished_list = if let Some(list_type) = list_type {
                            Value::list_with_type(
                                &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                vec![],
                                list_type.clone(),
                            )
                            .map_err(|_| CodecError::Deserialization("Illegal list type".into()))?
                        } else {
                            Value::cons_list_unsanitized(vec![]).map_err(|_| {
                                CodecError::Deserialization("Illegal list type".into())
                            })?
                        };

                        Ok(finished_list)
                    }
                }
                TypePrefix::Tuple => {
                    let mut len = [0; 4];
                    r.read_exact(&mut len)?;
                    let len = u32::from_be_bytes(len);
                    let expected_len = u64::from(len);

                    if len > MAX_VALUE_SIZE {
                        return Err(CodecError::Deserialization(
                            "Illegal tuple type".to_string(),
                        ));
                    }

                    let tuple_type = match expected_type.as_ref() {
                        None => None,
                        Some(TypeSignature::TupleType(tuple_type)) => {
                            if sanitize {
                                if u64::from(len) < tuple_type.len() {
                                    // unwrap is safe because of the match condition
                                    #[allow(clippy::unwrap_used)]
                                    return Err(CodecError::DeserializeExpected(Box::new(
                                        expected_type.unwrap(),
                                    )));
                                }
                            } else if u64::from(len) != tuple_type.len() {
                                // unwrap is safe because of the match condition
                                #[allow(clippy::unwrap_used)]
                                return Err(CodecError::DeserializeExpected(Box::new(
                                    expected_type.unwrap(),
                                )));
                            }
                            Some(tuple_type)
                        }
                        Some(x) => {
                            return Err(CodecError::DeserializeExpected(Box::new(x.clone())));
                        }
                    };

                    if len > 0 {
                        let items = Vec::with_capacity(expected_len as usize);
                        let first_key = ClarityName::deserialize_read(r)?;
                        // figure out if the next (key, value) pair for this
                        //  tuple will be elided (or sanitized) from the tuple.
                        // the logic here is that the next pair should be elided if:
                        //    * `sanitize` parameter is true
                        //    * `tuple_type` is some (i.e., there is an expected type for the
                        //       tuple)
                        //    * `tuple_type` does not contain an entry for `key`
                        let next_sanitize = sanitize
                            && tuple_type
                                .map(|tt| tt.field_type(&first_key).is_none())
                                .unwrap_or(false);
                        let stack_item = DeserializeStackItem::Tuple {
                            items,
                            expected_len,
                            processed_entries: 0,
                            expected_type: tuple_type.cloned(),
                            next_name: first_key,
                            next_sanitize,
                        };

                        stack.push(stack_item);
                        continue;
                    } else {
                        let finished_tuple = if let Some(tuple_type) = tuple_type {
                            TupleData::from_data_typed(
                                &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                vec![],
                                tuple_type,
                            )
                            .map_err(|_| CodecError::Deserialization("Illegal tuple type".into()))
                            .map(Value::from)?
                        } else {
                            TupleData::from_data(vec![])
                                .map_err(|_| {
                                    CodecError::Deserialization("Illegal tuple type".into())
                                })
                                .map(Value::from)?
                        };
                        Ok(finished_tuple)
                    }
                }
                TypePrefix::StringASCII => {
                    let mut buffer_len = [0; 4];
                    r.read_exact(&mut buffer_len)?;
                    let buffer_len = BufferLength::try_from(u32::from_be_bytes(buffer_len))?;

                    if let Some(x) = &expected_type {
                        let passed_test = match x {
                            TypeSignature::SequenceType(SequenceSubtype::StringType(
                                StringSubtype::ASCII(expected_len),
                            )) => u32::from(&buffer_len) <= u32::from(expected_len),
                            _ => false,
                        };
                        if !passed_test {
                            return Err(CodecError::DeserializeExpected(Box::new(x.clone())));
                        }
                    }

                    let mut data = vec![0; u32::from(buffer_len) as usize];

                    r.read_exact(&mut data[..])?;

                    Value::string_ascii_from_bytes(data)
                        .map_err(|_| CodecError::Deserialization("Bad string".into()))
                }
                TypePrefix::StringUTF8 => {
                    let mut total_len = [0; 4];
                    r.read_exact(&mut total_len)?;
                    let total_len = BufferLength::try_from(u32::from_be_bytes(total_len))?;

                    let mut data: Vec<u8> = vec![0; u32::from(total_len) as usize];

                    r.read_exact(&mut data[..])?;

                    let value = Value::string_utf8_from_bytes(data).map_err(|_| {
                        CodecError::Deserialization("Illegal string_utf8 type".into())
                    });

                    if let Some(x) = &expected_type {
                        let passed_test = match (x, &value) {
                            (
                                TypeSignature::SequenceType(SequenceSubtype::StringType(
                                    StringSubtype::UTF8(expected_len),
                                )),
                                Ok(Value::Sequence(SequenceData::String(CharType::UTF8(utf8)))),
                            ) => utf8.data.len() as u32 <= u32::from(expected_len),
                            _ => false,
                        };
                        if !passed_test {
                            return Err(CodecError::DeserializeExpected(Box::new(x.clone())));
                        }
                    }

                    value
                }
            }?;

            let mut finished_item = Some(item);
            while let Some(item) = finished_item.take() {
                let stack_bottom = if let Some(stack_item) = stack.pop() {
                    stack_item
                } else {
                    // this should be unreachable!
                    warn!(
                        "Deserializer reached unexpected path: item processed, but deserializer stack does not expect another value";
                        "item" => %item,
                    );
                    return Err(CodecError::Deserialization(
                        "Deserializer processed item, but deserializer stack does not expect another value".into(),
                    ));
                };
                match stack_bottom {
                    DeserializeStackItem::TopLevel { .. } => return Ok(item),
                    DeserializeStackItem::List {
                        mut items,
                        expected_len,
                        expected_type,
                    } => {
                        items.push(item);
                        if expected_len as usize <= items.len() {
                            // list is finished!
                            let finished_list = if let Some(list_type) = expected_type {
                                Value::list_with_type(
                                    &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                    items,
                                    list_type.clone(),
                                )
                                .map_err(|_| {
                                    CodecError::Deserialization("Illegal list type".into())
                                })?
                            } else {
                                Value::cons_list_unsanitized(items).map_err(|_| {
                                    CodecError::Deserialization("Illegal list type".into())
                                })?
                            };

                            finished_item.replace(finished_list);
                        } else {
                            // list is not finished, reinsert on stack
                            stack.push(DeserializeStackItem::List {
                                items,
                                expected_len,
                                expected_type,
                            });
                        }
                    }
                    DeserializeStackItem::Tuple {
                        mut items,
                        expected_len,
                        expected_type,
                        next_name,
                        next_sanitize,
                        mut processed_entries,
                    } => {
                        let push_entry = if sanitize {
                            if expected_type.is_some() {
                                // if performing tuple sanitization, don't include a field
                                //  if it was sanitized
                                !next_sanitize
                            } else {
                                // always push the entry if there's no type expectation
                                true
                            }
                        } else {
                            true
                        };
                        let tuple_entry = (next_name, item);
                        if push_entry {
                            items.push(tuple_entry);
                        }
                        processed_entries += 1;
                        if expected_len <= processed_entries {
                            // tuple is finished!
                            let finished_tuple = if let Some(tuple_type) = expected_type {
                                if items.len() != tuple_type.len() as usize {
                                    return Err(CodecError::DeserializeExpected(Box::new(
                                        TypeSignature::TupleType(tuple_type),
                                    )));
                                }
                                TupleData::from_data_typed(
                                    &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                    items,
                                    &tuple_type,
                                )
                                .map_err(|_| {
                                    CodecError::Deserialization("Illegal tuple type".into())
                                })
                                .map(Value::from)?
                            } else {
                                TupleData::from_data(items)
                                    .map_err(|_| {
                                        CodecError::Deserialization("Illegal tuple type".into())
                                    })
                                    .map(Value::from)?
                            };

                            finished_item.replace(finished_tuple);
                        } else {
                            // tuple is not finished, read the next key name and reinsert on stack
                            let key = ClarityName::deserialize_read(r)?;
                            // figure out if the next (key, value) pair for this
                            //  tuple will be elided (or sanitized) from the tuple.
                            // the logic here is that the next pair should be elided if:
                            //    * `sanitize` parameter is true
                            //    * `tuple_type` is some (i.e., there is an expected type for the
                            //       tuple)
                            //    * `tuple_type` does not contain an entry for `key`
                            let next_sanitize = sanitize
                                && expected_type
                                    .as_ref()
                                    .map(|tt| tt.field_type(&key).is_none())
                                    .unwrap_or(false);
                            stack.push(DeserializeStackItem::Tuple {
                                items,
                                expected_type,
                                expected_len,
                                next_name: key,
                                next_sanitize,
                                processed_entries,
                            });
                        }
                    }
                    DeserializeStackItem::OptionSome { .. } => {
                        let finished_some = Value::some(item)
                            .map_err(|_x| CodecError::Deserialization("Value too large".into()))?;
                        finished_item.replace(finished_some);
                    }
                    DeserializeStackItem::ResponseOk { .. } => {
                        let finished_some = Value::okay(item)
                            .map_err(|_x| CodecError::Deserialization("Value too large".into()))?;
                        finished_item.replace(finished_some);
                    }
                    DeserializeStackItem::ResponseErr { .. } => {
                        let finished_some = Value::error(item)
                            .map_err(|_x| CodecError::Deserialization("Value too large".into()))?;
                        finished_item.replace(finished_some);
                    }
                };
            }
        }

        Err(CodecError::Deserialization(
            "Invalid data: stack ran out before finishing parsing".into(),
        ))
    }

    pub fn serialize_write<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        use super::CharType::*;
        use super::PrincipalData::*;
        use super::SequenceData::{self, *};
        use super::Value::*;

        w.write_all(&[TypePrefix::from(self) as u8])?;
        match self {
            Int(value) => w.write_all(&value.to_be_bytes())?,
            UInt(value) => w.write_all(&value.to_be_bytes())?,
            Principal(Standard(data)) => data.serialize_write(w)?,
            Principal(Contract(contract_identifier))
            | CallableContract(CallableData {
                contract_identifier,
                trait_identifier: _,
            }) => {
                contract_identifier.issuer.serialize_write(w)?;
                contract_identifier.name.serialize_write(w)?;
            }
            Response(response) => response.data.serialize_write(w)?,
            // Bool types don't need any more data.
            Bool(_) => {}
            // None types don't need any more data.
            Optional(OptionalData { data: None }) => {}
            Optional(OptionalData { data: Some(value) }) => {
                value.serialize_write(w)?;
            }
            Sequence(List(data)) => {
                let len_bytes = data
                    .len()
                    .map_err(|e| CodecError::Serialization(e.to_string()))?
                    .to_be_bytes();
                w.write_all(&len_bytes)?;
                for item in data.data.iter() {
                    item.serialize_write(w)?;
                }
            }
            Sequence(Buffer(value)) => {
                let len_bytes = u32::from(
                    value
                        .len()
                        .map_err(|e| CodecError::Serialization(e.to_string()))?,
                )
                .to_be_bytes();
                w.write_all(&len_bytes)?;
                w.write_all(&value.data)?
            }
            Sequence(SequenceData::String(UTF8(value))) => {
                let total_len: u32 = value.data.iter().fold(0u32, |len, c| len + c.len() as u32);
                w.write_all(&(total_len.to_be_bytes()))?;
                for bytes in value.data.iter() {
                    w.write_all(bytes)?
                }
            }
            Sequence(SequenceData::String(ASCII(value))) => {
                let len_bytes = u32::from(
                    value
                        .len()
                        .map_err(|e| CodecError::Serialization(e.to_string()))?,
                )
                .to_be_bytes();
                w.write_all(&len_bytes)?;
                w.write_all(&value.data)?
            }
            Tuple(data) => {
                let len_bytes = u32::try_from(data.data_map.len())
                    .map_err(|e| CodecError::Serialization(e.to_string()))?
                    .to_be_bytes();
                w.write_all(&len_bytes)?;
                for (key, value) in data.data_map.iter() {
                    key.serialize_write(w)?;
                    value.serialize_write(w)?;
                }
            }
        };

        Ok(())
    }

    /// This function attempts to deserialize a byte buffer into a Clarity Value.
    /// The `expected_type` parameter tells the deserializer to expect (and enforce)
    /// a particular type. `ClarityDB` uses this to ensure that lists, tuples, etc. loaded from the database
    /// have their max-length and other type information set by the type declarations in the contract.
    pub fn try_deserialize_bytes(
        bytes: &Vec<u8>,
        expected: &TypeSignature,
        sanitize: bool,
    ) -> Result<Value, CodecError> {
        Value::deserialize_read(&mut bytes.as_slice(), Some(expected), sanitize)
    }

    /// This function attempts to deserialize a hex string into a Clarity Value.
    /// The `expected_type` parameter tells the deserializer to expect (and enforce)
    /// a particular type. `ClarityDB` uses this to ensure that lists, tuples, etc. loaded from the database
    /// have their max-length and other type information set by the type declarations in the contract.
    pub fn try_deserialize_hex(
        hex: &str,
        expected: &TypeSignature,
        sanitize: bool,
    ) -> Result<Value, CodecError> {
        let data =
            hex_bytes(hex).map_err(|_| CodecError::Deserialization("Bad hex string".into()))?;
        Value::try_deserialize_bytes(&data, expected, sanitize)
    }

    /// This function attempts to deserialize a byte buffer into a
    /// Clarity Value, while ensuring that the whole byte buffer is
    /// consumed by the deserialization, erroring if it is not. The
    /// `expected_type` parameter tells the deserializer to expect
    /// (and enforce) a particular type. `ClarityDB` uses this to
    /// ensure that lists, tuples, etc. loaded from the database have
    /// their max-length and other type information set by the type
    /// declarations in the contract.
    pub fn try_deserialize_bytes_exact(
        bytes: &Vec<u8>,
        expected: &TypeSignature,
        sanitize: bool,
    ) -> Result<Value, CodecError> {
        let input_length = bytes.len();
        let (value, read_count) =
            Value::deserialize_read_count(&mut bytes.as_slice(), Some(expected), sanitize)?;
        if read_count != (input_length as u64) {
            Err(CodecError::LeftoverBytesInDeserialization)
        } else {
            Ok(value)
        }
    }

    /// Try to deserialize a value without type information. This *does not* perform sanitization
    ///  so it should not be used when decoding clarity database values.
    #[cfg(any(test, feature = "testing"))]
    pub fn try_deserialize_bytes_untyped(bytes: &Vec<u8>) -> Result<Value, CodecError> {
        Value::deserialize_read(&mut bytes.as_slice(), None, false)
    }

    /// Try to deserialize a value without type information. This *does not* perform sanitization
    ///  so it should not be used when decoding clarity database values.
    #[cfg(not(any(test, feature = "testing")))]
    fn try_deserialize_bytes_untyped(bytes: &Vec<u8>) -> Result<Value, CodecError> {
        Value::deserialize_read(&mut bytes.as_slice(), None, false)
    }

    /// Try to deserialize a value from a hex string without type information. This *does not*
    /// perform sanitization.
    pub fn try_deserialize_hex_untyped(hex: &str) -> Result<Value, CodecError> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let data =
            hex_bytes(hex).map_err(|_| CodecError::Deserialization("Bad hex string".into()))?;
        Value::try_deserialize_bytes_untyped(&data)
    }

    pub fn serialized_size(&self) -> Result<u32, CodecError> {
        let mut counter = WriteCounter { count: 0 };
        self.serialize_write(&mut counter).map_err(|_| {
            CodecError::Deserialization(
                "Error: Failed to count serialization length of Clarity value".into(),
            )
        })?;
        Ok(counter.count)
    }
}

/// A writer that just counts the bytes written
struct WriteCounter {
    count: u32,
}

impl Write for WriteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let input: u32 = buf
            .len()
            .try_into()
            .map_err(|_e| std::io::Error::other("Serialization size would overflow u32"))?;
        self.count = self
            .count
            .checked_add(input)
            .ok_or_else(|| std::io::Error::other("Serialization size would overflow u32"))?;
        Ok(input as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Value {
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut byte_serialization = Vec::new();
        self.serialize_write(&mut byte_serialization)
            .map_err(|_| CodecError::Expect("IOError filling byte buffer.".into()))?;
        Ok(byte_serialization)
    }

    /// This does *not* perform any data sanitization
    pub fn serialize_to_hex(&self) -> Result<String, CodecError> {
        let byte_serialization = self.serialize_to_vec()?;
        Ok(to_hex(byte_serialization.as_slice()))
    }

    /// Sanitize `value` against pre-2.4 serialization
    ///
    /// Returns Some if the sanitization is successful, or was not necessary.
    /// Returns None if the sanitization failed.
    ///
    /// Returns the sanitized value _and_ whether or not sanitization was required.
    pub fn sanitize_value(
        epoch: &StacksEpochId,
        expected: &TypeSignature,
        value: Value,
    ) -> Option<(Value, bool)> {
        // in epochs before 2.4, perform no sanitization
        if !epoch.value_sanitizing() {
            return Some((value, false));
        }
        let (output, did_sanitize) = match value {
            Value::Sequence(SequenceData::List(l)) => {
                let lt = match expected {
                    TypeSignature::SequenceType(SequenceSubtype::ListType(lt)) => lt,
                    _ => return None,
                };
                // if cannot compute l.len(), sanitization fails, so use ? operator can short return
                if l.len().ok()? > lt.get_max_len() {
                    return None;
                }
                let mut sanitized_items = Vec::with_capacity(l.data.len());
                let mut did_sanitize_children = false;
                for item in l.data.into_iter() {
                    let (sanitized_item, did_sanitize) =
                        Self::sanitize_value(epoch, lt.get_list_item_type(), item)?;
                    sanitized_items.push(sanitized_item);
                    did_sanitize_children = did_sanitize_children || did_sanitize;
                }
                // do not sanitize list before construction here, because we're already sanitizing
                let output_list = Value::cons_list_unsanitized(sanitized_items).ok()?;
                (output_list, did_sanitize_children)
            }
            Value::Tuple(tuple_data) => {
                let tt = match expected {
                    TypeSignature::TupleType(tt) => tt,
                    _ => return None,
                };
                let type_map = tt.get_type_map();
                let mut sanitized_tuple_entries = Vec::with_capacity(type_map.len());
                let original_tuple_len = tuple_data.len();
                let mut tuple_data_map = tuple_data.data_map;
                let mut did_sanitize_children = false;
                for (key, expect_key_type) in type_map.iter() {
                    let field_data = tuple_data_map.remove(key)?;
                    let (sanitized_field, did_sanitize) =
                        Self::sanitize_value(epoch, expect_key_type, field_data)?;
                    sanitized_tuple_entries.push((key.clone(), sanitized_field));
                    did_sanitize_children = did_sanitize_children || did_sanitize;
                }
                if sanitized_tuple_entries.len() as u64 != tt.len() {
                    // this code should be unreachable, because I think any case that
                    //    could trigger this would have returned None earlier
                    warn!(
                        "Sanitizer handled path that should have errored earlier, skipping sanitization"
                    );
                    return None;
                }
                let did_sanitize_tuple = did_sanitize_children || (tt.len() != original_tuple_len);
                (
                    Value::Tuple(TupleData::from_data(sanitized_tuple_entries).ok()?),
                    did_sanitize_tuple,
                )
            }
            Value::Optional(opt_data) => {
                let inner_type = match expected {
                    TypeSignature::OptionalType(inner_type) => inner_type,
                    _ => return None,
                };
                let some_data = match opt_data.data {
                    Some(data) => *data,
                    None => return Some((Value::none(), false)),
                };
                let (sanitized_data, did_sanitize_child) =
                    Self::sanitize_value(epoch, inner_type, some_data)?;
                (Value::some(sanitized_data).ok()?, did_sanitize_child)
            }
            Value::Response(response) => {
                let rt = match expected {
                    TypeSignature::ResponseType(rt) => rt,
                    _ => return None,
                };

                let response_ok = response.committed;
                let response_data = *response.data;
                let inner_type = if response_ok { &rt.0 } else { &rt.1 };
                let (sanitized_inner, did_sanitize_child) =
                    Self::sanitize_value(epoch, inner_type, response_data)?;
                let sanitized_resp = if response_ok {
                    Value::okay(sanitized_inner)
                } else {
                    Value::error(sanitized_inner)
                };
                (sanitized_resp.ok()?, did_sanitize_child)
            }
            value => {
                if expected.admits(epoch, &value).ok()? {
                    return Some((value, false));
                } else {
                    return None;
                }
            }
        };

        if expected.admits(epoch, &output).ok()? {
            Some((output, did_sanitize))
        } else {
            None
        }
    }
}

/// Note: the StacksMessageCodec implementation for Clarity values *does not*
///       sanitize its serialization or deserialization.
impl StacksMessageCodec for Value {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.serialize_write(fd).map_err(|e| match e {
            CodecError::Io(io_e) => codec_error::WriteError(io_e),
            other => codec_error::SerializeError(other.to_string()),
        })
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Value, codec_error> {
        Value::deserialize_read(fd, None, false).map_err(|e| match e {
            CodecError::Io(io_e) => codec_error::ReadError(io_e),
            _ => codec_error::DeserializeError(format!("Failed to decode clarity value: {e:?}")),
        })
    }
}
