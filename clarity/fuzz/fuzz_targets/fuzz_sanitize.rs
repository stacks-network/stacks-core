// Copyright (C) 2023 Stacks Open Internet Foundation
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

#![no_main]

use arbitrary::Arbitrary;
use clarity::vm::types::TypeSignature;
use clarity::vm::types::signatures::SequenceSubtype;
use clarity::vm::Value as ClarityValue;
use clarity::vm::types::SequenceData;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::StandardPrincipalData;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::types::TupleData;
use clarity::vm::types::CharType;
use clarity::vm::ClarityName;
use clarity::vm::representations::ContractName;
use clarity::vm::types::serialization::SerializationError;
use stacks_common::types::StacksEpochId;
use clarity::vm::analysis::CheckErrors;
use clarity::vm::types::StringSubtype;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct FuzzClarityValue(ClarityValue);

#[derive(Debug)]
struct FuzzStandardPrincipal(StandardPrincipalData);

#[derive(Debug)]
struct FuzzContractName(ContractName);

#[derive(Debug)]
struct FuzzClarityName(ClarityName);

impl arbitrary::Arbitrary<'_> for FuzzContractName {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let input_string = String::arbitrary(u)?;
        ContractName::try_from(input_string)
            .map(FuzzContractName)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

impl arbitrary::Arbitrary<'_> for FuzzClarityName {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let input_string = String::arbitrary(u)?;
        ClarityName::try_from(input_string)
            .map(FuzzClarityName)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

impl arbitrary::Arbitrary<'_> for FuzzStandardPrincipal {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let version = u8::arbitrary(u)?;
        if version >= 32 {
            return Err(arbitrary::Error::IncorrectFormat);
        }
        let data = Arbitrary::arbitrary(u)?;
        Ok(FuzzStandardPrincipal(StandardPrincipalData(version, data)))
    }
}

impl arbitrary::Arbitrary<'_> for FuzzClarityValue {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let clar_type = u8::arbitrary(u)?;
        let clar_value = match clar_type {
            0 => ClarityValue::Int(i128::arbitrary(u)?),
            1 => ClarityValue::UInt(u128::arbitrary(u)?),
            2 => ClarityValue::Bool(bool::arbitrary(u)?),
            3 => ClarityValue::some(FuzzClarityValue::arbitrary(u)?.0)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?,
            4 => ClarityValue::none(),
            5 => ClarityValue::okay(FuzzClarityValue::arbitrary(u)?.0)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?,
            6 => ClarityValue::error(FuzzClarityValue::arbitrary(u)?.0)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?,
            7 => ClarityValue::Principal(PrincipalData::Standard(FuzzStandardPrincipal::arbitrary(u)?.0)),
            8 => ClarityValue::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
                FuzzStandardPrincipal::arbitrary(u)?.0,
                FuzzContractName::arbitrary(u)?.0,
            ))),
            // utf8
            9 => ClarityValue::string_utf8_from_bytes(Arbitrary::arbitrary(u)?)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?,
            // ascii
            10 => ClarityValue::string_ascii_from_bytes(Arbitrary::arbitrary(u)?)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?,
            // buff
            11 => ClarityValue::buff_from(Arbitrary::arbitrary(u)?)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?,
            // list
            12 => {
                let value_vec: Vec<FuzzClarityValue> = Arbitrary::arbitrary(u)?;
                ClarityValue::cons_list_unsanitized(value_vec.into_iter().map(|x| x.0).collect())
                    .map_err(|_| arbitrary::Error::IncorrectFormat)?
            },
            // tuple
            13 => {
                let tuple_data: Vec<(FuzzClarityName, FuzzClarityValue)> = Arbitrary::arbitrary(u)?;
                TupleData::from_data(
                    tuple_data
                        .into_iter()
                        .map(|(key, value)| (key.0, value.0))
                        .collect()
                )                    
                    .map_err(|_| arbitrary::Error::IncorrectFormat)?
                    .into()
            },
            _ => return Err(arbitrary::Error::IncorrectFormat),
        };

        Ok(FuzzClarityValue(clar_value))
    }
}

pub fn strict_admits(me: &TypeSignature, x: &ClarityValue) -> Result<bool, CheckErrors> {
    match me {
        TypeSignature::NoType => Err(CheckErrors::CouldNotDetermineType),
        TypeSignature::IntType => match x {
            ClarityValue::Int(_) => Ok(true),
            _ => Ok(false),
        },
        TypeSignature::UIntType => match x {
            ClarityValue::UInt(_) => Ok(true),
            _ => Ok(false),
        },
        TypeSignature::BoolType => match x {
            ClarityValue::Bool(_) => Ok(true),
            _ => Ok(false),
        },
        TypeSignature::SequenceType(SequenceSubtype::ListType(ref my_list_type)) => {
            let list_data = match x {
                ClarityValue::Sequence(SequenceData::List(ref ld)) => ld,
                _ => return Ok(false),
            };
            if my_list_type.get_max_len() < list_data.len() {
                return Ok(false);
            }
            let my_entry_type = my_list_type.get_list_item_type();
            for entry in list_data.data.iter() {
                if !strict_admits(my_entry_type, entry)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        },
        TypeSignature::SequenceType(SequenceSubtype::BufferType(ref my_max_len)) => {
            let buff_data = match x {
                ClarityValue::Sequence(SequenceData::Buffer(ref buff_data)) => buff_data,
                _ => return Ok(false),
            };
            if &buff_data.len() > my_max_len {
                return Ok(false);
            }
            return Ok(true);
        },
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(ref my_max_len))) => {
            let ascii_data = match x {
                ClarityValue::Sequence(SequenceData::String(CharType::ASCII(ref ascii_data))) => ascii_data,
                _ => return Ok(false),
            };
            if &ascii_data.len() > my_max_len {
                return Ok(false);
            }
            return Ok(true);
        },
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(ref my_max_len))) => {
            let utf8_data = match x {
                ClarityValue::Sequence(SequenceData::String(CharType::UTF8(ref utf8_data))) => utf8_data,
                _ => return Ok(false),
            };
            if u32::from(utf8_data.len()) > u32::from(my_max_len) {
                return Ok(false);
            }
            return Ok(true);
        },
        TypeSignature::PrincipalType => match x {
            ClarityValue::Principal(_) => Ok(true),
            _ => Ok(false),
        },
        TypeSignature::OptionalType(ref ot) => match x {
            ClarityValue::Optional(inner_value) => {
                match &inner_value.data {
                    Some(some_value) => strict_admits(ot, some_value),
                    None => Ok(true),
                }
            },
            _ => Ok(false),
        },
        TypeSignature::ResponseType(ref rt) => {
            let response_data = match x {
                ClarityValue::Response(rd) => rd,
                _ => return Ok(false),
            };
            let inner_type = if response_data.committed {
                &rt.0
            } else {
                &rt.1
            };
            strict_admits(inner_type, &response_data.data)
        },
        TypeSignature::TupleType(ref tt) => {
            let tuple_data = match x {
                ClarityValue::Tuple(td) => td,
                _ => return Ok(false),
            };
            if tt.len() != tuple_data.len() {
                return Ok(false)
            }
            for (field, field_type) in tt.get_type_map().iter() {
                let field_value = match tuple_data.get(&field) {
                    Ok(x) => x,
                    Err(_) => return Ok(false)
                };
                if !strict_admits(field_type, field_value)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        },
        TypeSignature::CallableType(_) |
        TypeSignature::ListUnionType(_) |
        TypeSignature::TraitReferenceType(_) => Err(CheckErrors::TraitReferenceNotAllowed),
    }
}

fuzz_target!(|value: FuzzClarityValue| {
    fuzz_sanitize(value.0);
});



/// Same as fuzz_sanitize, but does not check any serialization routines
fn fuzz_value_sanitize(input: ClarityValue) {
    let computed_type = TypeSignature::type_of(&input);
    let did_strict_admit = strict_admits(&computed_type, &input).unwrap();

    let (sanitized_value, did_sanitize) = ClarityValue::sanitize_value(
        &StacksEpochId::Epoch24,
        &computed_type,
        input.clone()
    ).unwrap();

    if did_strict_admit {
        assert_eq!(sanitized_value, computed_type);
        assert!(!did_sanitize);
    } else {
        assert!(did_sanitize);
        assert!(strict_admits(&computed_type, &sanitized_value));
    }
}

fn fuzz_sanitize(input: ClarityValue) {
    let computed_type = TypeSignature::type_of(&input);
    let did_strict_admit = strict_admits(&computed_type, &input).unwrap();

    let (sanitized_value, did_sanitize) = ClarityValue::sanitize_value(
        &StacksEpochId::Epoch24,
        &computed_type,
        input.clone()
    ).unwrap();

    if did_strict_admit {
        assert_eq!(input, sanitized_value);
        assert!(!did_sanitize);
    } else {
        assert!(strict_admits(&computed_type, &sanitized_value).unwrap());
        assert!(did_sanitize);
    }

    let serialized = input.serialize_to_vec();
    let deserialize_unsanitized = ClarityValue::deserialize_read(
        &mut serialized.as_slice(),
        Some(&computed_type),
        false
    );
    if !did_strict_admit {
        deserialize_unsanitized.unwrap_err();
    } else {
        let deser_value = match deserialize_unsanitized {
            Err(SerializationError::BadTypeError(CheckErrors::TypeSignatureTooDeep)) => {
                // pre-2.4, deserializer could error on types deeper than a deserialization limit of 16.
                // with sanitization enabled (a 2.4-gated feature), these serializations are readable.
                ClarityValue::deserialize_read(
                    &mut serialized.as_slice(),
                    Some(&computed_type),
                    true
                ).unwrap()
            },
            deser_result => deser_result.unwrap(),
        };
        assert_eq!(deser_value, input);
    }

    let deserialize_sanitized = match ClarityValue::deserialize_read(
        &mut serialized.as_slice(),
        Some(&computed_type),
        true
    ) {
        Ok(x) => x,
        Err(SerializationError::BadTypeError(CheckErrors::TypeSignatureTooDeep)) => {
            assert!(!did_strict_admit, "Unsanitized inputs may fail to deserialize, but they must have needed sanitization");
            // check that the sanitized value *is* readable
            let serialized = sanitized_value.serialize_to_vec();
            let deserialize_unsanitized = match ClarityValue::deserialize_read(
                &mut serialized.as_slice(),
                Some(&computed_type),
                false
            ) {
                Err(SerializationError::BadTypeError(CheckErrors::TypeSignatureTooDeep)) => {
                    // pre-2.4, deserializer could error on legal types deeper than a deserialization limit of 16.
                    // with sanitization enabled (a 2.4-gated feature), these serializations are readable.
                    ClarityValue::deserialize_read(
                        &mut serialized.as_slice(),
                        Some(&computed_type),
                        true
                    ).unwrap()
                },
                deser_result => deser_result.unwrap(),
            };
            assert_eq!(deserialize_unsanitized, sanitized_value);
            assert!(strict_admits(&computed_type, &deserialize_unsanitized).unwrap());
            let deserialize_sanitized = ClarityValue::deserialize_read(
                &mut serialized.as_slice(),
                Some(&computed_type),
                true
            ).unwrap();
            assert_eq!(deserialize_sanitized, sanitized_value);
            assert!(strict_admits(&computed_type, &deserialize_sanitized).unwrap());
            return;
        }
        Err(e) => panic!("Unexpected error from deserialization: {}", e)
    };

    assert!(strict_admits(&computed_type, &deserialize_sanitized).unwrap());
    if did_strict_admit {
        assert_eq!(input, deserialize_sanitized)
    } else {
        assert_eq!(sanitized_value, deserialize_sanitized)
    }
}
