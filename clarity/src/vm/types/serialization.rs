// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::{error, str};

use clarity_serialization::errors::CodecError;
pub use clarity_serialization::types::serialization::{TypePrefix, NONE_SERIALIZATION_LEN};
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::vm::database::{ClarityDeserializable, ClaritySerializable};
use crate::vm::errors::{CheckErrors, Error as ClarityError, IncomparableError, InterpreterError};
use crate::vm::types::TypeSignature;

/// Errors that may occur in serialization or deserialization
/// If deserialization failed because the described type is a bad type and
///   a CheckError is thrown, it gets wrapped in BadTypeError.
/// Any IOErrrors from the supplied buffer will manifest as IOError variants,
///   except for EOF -- if the deserialization code experiences an EOF, it is caught
///   and rethrown as DeserializationError
#[derive(Debug, PartialEq)]
pub enum SerializationError {
    IOError(IncomparableError<std::io::Error>),
    BadTypeError(CheckErrors),
    DeserializationError(String),
    DeserializeExpected(TypeSignature),
    LeftoverBytesInDeserialization,
    SerializationError(String),
    UnexpectedSerialization,
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SerializationError::IOError(e) => {
                write!(f, "Serialization error caused by IO: {}", e.err)
            }
            SerializationError::BadTypeError(e) => {
                write!(f, "Deserialization error, bad type, caused by: {e}")
            }
            SerializationError::DeserializationError(e) => {
                write!(f, "Deserialization error: {e}")
            }
            SerializationError::SerializationError(e) => {
                write!(f, "Serialization error: {e}")
            }
            SerializationError::DeserializeExpected(e) => write!(
                f,
                "Deserialization expected the type of the input to be: {e}"
            ),
            SerializationError::UnexpectedSerialization => {
                write!(f, "The serializer handled an input in an unexpected way")
            }
            SerializationError::LeftoverBytesInDeserialization => {
                write!(f, "Deserialization error: bytes left over in buffer")
            }
        }
    }
}

impl error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            SerializationError::IOError(e) => Some(&e.err),
            SerializationError::BadTypeError(e) => Some(e),
            _ => None,
        }
    }
}

// Note: a byte stream that describes a longer type than
//   there are available bytes to read will result in an IOError(UnexpectedEOF)
impl From<std::io::Error> for SerializationError {
    fn from(err: std::io::Error) -> Self {
        SerializationError::IOError(IncomparableError { err })
    }
}

impl From<&str> for SerializationError {
    fn from(e: &str) -> Self {
        SerializationError::DeserializationError(e.into())
    }
}

impl From<CheckErrors> for SerializationError {
    fn from(e: CheckErrors) -> Self {
        SerializationError::BadTypeError(e)
    }
}

impl From<CodecError> for SerializationError {
    fn from(err: CodecError) -> Self {
        match err {
            CodecError::Io(e) => SerializationError::IOError(IncomparableError { err: e }),
            CodecError::Serialization(s) => SerializationError::SerializationError(s),
            CodecError::Deserialization(s) => SerializationError::DeserializationError(s),
            CodecError::DeserializeExpected(t) => SerializationError::DeserializeExpected(*t),
            CodecError::LeftoverBytesInDeserialization => {
                SerializationError::LeftoverBytesInDeserialization
            }
            CodecError::UnexpectedSerialization => SerializationError::UnexpectedSerialization,
            // For other errors, we must map them to a CheckError and then wrap in BadTypeError.
            // This follows the original pattern of SerializationError.
            other => SerializationError::BadTypeError(CheckErrors::from(other)),
        }
    }
}

impl ClaritySerializable for u32 {
    fn serialize(&self) -> String {
        to_hex(&self.to_be_bytes())
    }
}

impl ClarityDeserializable<u32> for u32 {
    fn deserialize(input: &str) -> Result<Self, ClarityError> {
        let bytes = hex_bytes(input).map_err(|_| {
            InterpreterError::Expect("u32 deserialization: failed decoding bytes.".into())
        })?;
        assert_eq!(bytes.len(), 4);
        Ok(u32::from_be_bytes(bytes[0..4].try_into().map_err(
            |_| InterpreterError::Expect("u32 deserialization: failed reading.".into()),
        )?))
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Write;

    use rstest::rstest;
    use rstest_reuse::{self, *};
    use stacks_common::types::StacksEpochId;

    use super::super::*;
    use super::SerializationError;
    use crate::vm::database::{ClarityDeserializable, ClaritySerializable, RollbackWrapper};
    use crate::vm::errors::{Error, InterpreterError};
    use crate::vm::tests::test_clarity_versions;
    use crate::vm::ClarityVersion;

    fn buff_type(size: u32) -> TypeSignature {
        TypeSignature::SequenceType(SequenceSubtype::BufferType(size.try_into().unwrap()))
    }

    fn test_deser_ser(v: Value) {
        assert_eq!(
            &v,
            &Value::try_deserialize_hex(
                &v.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&v).unwrap(),
                false
            )
            .unwrap()
        );
        assert_eq!(
            &v,
            &Value::try_deserialize_hex_untyped(&v.serialize_to_hex().unwrap()).unwrap()
        );
        // test the serialized_size implementation
        assert_eq!(
            v.serialized_size().unwrap(),
            v.serialize_to_hex().unwrap().len() as u32 / 2,
            "serialized_size() should return the byte length of the serialization (half the length of the hex encoding)",
        );
    }

    fn test_deser_u32_helper(num: u32) {
        assert_eq!(num, u32::deserialize(&num.serialize()).unwrap());
    }

    fn test_bad_expectation(v: Value, e: TypeSignature) {
        assert!(matches!(
            Value::try_deserialize_hex(&v.serialize_to_hex().unwrap(), &e, false)
                .unwrap_err()
                .into(),
            SerializationError::DeserializeExpected(_)
        ));
    }

    #[test]
    fn test_deser_u32() {
        test_deser_u32_helper(0);
        test_deser_u32_helper(10);
        test_deser_u32_helper(42);
        test_deser_u32_helper(10992);
        test_deser_u32_helper(10992);
        test_deser_u32_helper(262144);
        test_deser_u32_helper(134217728);
    }

    #[apply(test_clarity_versions)]
    fn test_lists(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        let list_list_int = Value::list_from(vec![Value::list_from(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3),
        ])
        .unwrap()])
        .unwrap();

        // Should be legal!
        Value::try_deserialize_hex(
            &Value::list_from(vec![])
                .unwrap()
                .serialize_to_hex()
                .unwrap(),
            &TypeSignature::from_string("(list 2 (list 3 int))", version, epoch),
            false,
        )
        .unwrap();
        Value::try_deserialize_hex(
            &list_list_int.serialize_to_hex().unwrap(),
            &TypeSignature::from_string("(list 2 (list 3 int))", version, epoch),
            false,
        )
        .unwrap();
        Value::try_deserialize_hex(
            &list_list_int.serialize_to_hex().unwrap(),
            &TypeSignature::from_string("(list 1 (list 4 int))", version, epoch),
            false,
        )
        .unwrap();

        test_deser_ser(list_list_int.clone());
        test_deser_ser(Value::list_from(vec![]).unwrap());
        test_bad_expectation(list_list_int.clone(), TypeSignature::BoolType);
        // inner type isn't expected
        test_bad_expectation(
            list_list_int.clone(),
            TypeSignature::from_string("(list 1 (list 4 uint))", version, epoch),
        );
        // child list longer than expected
        test_bad_expectation(
            list_list_int.clone(),
            TypeSignature::from_string("(list 1 (list 2 uint))", version, epoch),
        );
        // parent list longer than expected
        test_bad_expectation(
            list_list_int,
            TypeSignature::from_string("(list 0 (list 2 uint))", version, epoch),
        );

        // make a list too large for the type itself!
        //   this describes a list of size 1+MAX_VALUE_SIZE of Value::Bool(true)'s
        let mut too_big = vec![3u8; 6 + MAX_VALUE_SIZE as usize];
        // list prefix
        too_big[0] = 11;
        // list length
        Write::write_all(
            &mut too_big.get_mut(1..5).unwrap(),
            &(1 + MAX_VALUE_SIZE).to_be_bytes(),
        )
        .unwrap();

        assert_eq!(
            Value::deserialize_read(&mut too_big.as_slice(), None, false)
                .map_err(SerializationError::from)
                .unwrap_err(),
            "Illegal list type".into()
        );

        // make a list that says it is longer than it is!
        //   this describes a list of size MAX_VALUE_SIZE of Value::Bool(true)'s, but is actually only 59 bools.
        let mut eof = vec![3u8; 64_usize];
        // list prefix
        eof[0] = 11;
        // list length
        Write::write_all(
            &mut eof.get_mut(1..5).unwrap(),
            &(MAX_VALUE_SIZE).to_be_bytes(),
        )
        .unwrap();

        /*
         * jude -- this should return an IOError
        assert_eq!(
            Value::deserialize_read(&mut eof.as_slice(), None).unwrap_err(),
            "Unexpected end of byte stream".into());
        */

        match Value::deserialize_read(&mut eof.as_slice(), None, false)
            .map_err(SerializationError::from)
        {
            Ok(_) => panic!("Accidentally parsed truncated slice"),
            Err(eres) => match eres {
                SerializationError::IOError(ioe) => match ioe.err.kind() {
                    std::io::ErrorKind::UnexpectedEof => {}
                    _ => panic!("Invalid I/O error: {ioe:?}"),
                },
                _ => panic!("Invalid deserialize error: {eres:?}"),
            },
        }
    }

    #[test]
    fn test_bools() {
        test_deser_ser(Value::Bool(false));
        test_deser_ser(Value::Bool(true));

        test_bad_expectation(Value::Bool(false), TypeSignature::IntType);
        test_bad_expectation(Value::Bool(true), TypeSignature::IntType);
    }

    #[test]
    fn test_ints() {
        test_deser_ser(Value::Int(0));
        test_deser_ser(Value::Int(1));
        test_deser_ser(Value::Int(-1));
        test_deser_ser(Value::Int(i128::MAX));
        test_deser_ser(Value::Int(i128::MIN));

        test_bad_expectation(Value::Int(1), TypeSignature::UIntType);
    }

    #[test]
    fn test_uints() {
        test_deser_ser(Value::UInt(0));
        test_deser_ser(Value::UInt(1));
        test_deser_ser(Value::UInt(u128::MAX));
        test_deser_ser(Value::UInt(u128::MIN));

        test_bad_expectation(Value::UInt(1), TypeSignature::IntType);
    }

    #[apply(test_clarity_versions)]
    fn test_opts(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::none());
        test_deser_ser(Value::some(Value::Int(15)).unwrap());

        test_bad_expectation(Value::none(), TypeSignature::IntType);
        test_bad_expectation(Value::some(Value::Int(15)).unwrap(), TypeSignature::IntType);
        // bad expected _contained_ type
        test_bad_expectation(
            Value::some(Value::Int(15)).unwrap(),
            TypeSignature::from_string("(optional uint)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_resp(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::okay(Value::Int(15)).unwrap());
        test_deser_ser(Value::error(Value::Int(15)).unwrap());

        // Bad expected types.
        test_bad_expectation(Value::okay(Value::Int(15)).unwrap(), TypeSignature::IntType);
        test_bad_expectation(
            Value::okay(Value::Int(15)).unwrap(),
            TypeSignature::from_string("(response uint int)", version, epoch),
        );
        test_bad_expectation(
            Value::error(Value::Int(15)).unwrap(),
            TypeSignature::from_string("(response int uint)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_buffs(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::buff_from(vec![0, 0, 0, 0]).unwrap());
        test_deser_ser(Value::buff_from(vec![0xde, 0xad, 0xbe, 0xef]).unwrap());
        test_deser_ser(Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap());

        test_bad_expectation(
            Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap(),
            TypeSignature::BoolType,
        );

        // fail because we expect a shorter buffer
        test_bad_expectation(
            Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap(),
            TypeSignature::from_string("(buff 2)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_string_ascii(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::string_ascii_from_bytes(vec![61, 62, 63, 64]).unwrap());

        // fail because we expect a shorter string
        test_bad_expectation(
            Value::string_ascii_from_bytes(vec![61, 62, 63, 64]).unwrap(),
            TypeSignature::from_string("(string-ascii 3)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_string_utf8(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::string_utf8_from_bytes(vec![61, 62, 63, 64]).unwrap());
        test_deser_ser(
            Value::string_utf8_from_bytes(vec![61, 62, 63, 240, 159, 164, 151]).unwrap(),
        );

        // fail because we expect a shorter string
        test_bad_expectation(
            Value::string_utf8_from_bytes(vec![61, 62, 63, 64]).unwrap(),
            TypeSignature::from_string("(string-utf8 3)", version, epoch),
        );

        test_bad_expectation(
            Value::string_utf8_from_bytes(vec![61, 62, 63, 240, 159, 164, 151]).unwrap(),
            TypeSignature::from_string("(string-utf8 3)", version, epoch),
        );
    }

    #[test]
    fn test_tuples() {
        let t_1 = Value::from(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(1)),
            ])
            .unwrap(),
        );
        let t_0 = Value::from(
            TupleData::from_data(vec![
                ("b".into(), Value::Int(1)),
                ("a".into(), Value::Int(1)),
            ])
            .unwrap(),
        );
        let t_2 = Value::from(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Bool(true)),
            ])
            .unwrap(),
        );
        let t_3 = Value::from(TupleData::from_data(vec![("a".into(), Value::Int(1))]).unwrap());
        let t_4 = Value::from(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("c".into(), Value::Bool(true)),
            ])
            .unwrap(),
        );

        test_deser_ser(t_0.clone());
        test_deser_ser(t_1.clone());
        test_deser_ser(t_2.clone());
        test_deser_ser(t_3.clone());

        test_bad_expectation(t_0.clone(), TypeSignature::BoolType);

        // t_0 and t_1 are actually the same
        assert_eq!(
            Value::try_deserialize_hex(
                &t_1.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_0).unwrap(),
                false
            )
            .unwrap(),
            Value::try_deserialize_hex(
                &t_0.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_0).unwrap(),
                false
            )
            .unwrap()
        );

        // field number not equal to expectations
        assert!(matches!(
            Value::try_deserialize_hex(
                &t_3.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_1).unwrap(),
                false
            )
            .unwrap_err()
            .into(),
            SerializationError::DeserializeExpected(_)
        ));

        // field type mismatch
        assert!(matches!(
            Value::try_deserialize_hex(
                &t_2.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_1).unwrap(),
                false
            )
            .unwrap_err()
            .into(),
            SerializationError::DeserializeExpected(_)
        ));

        // field not-present in expected
        assert!(matches!(
            Value::try_deserialize_hex(
                &t_1.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_4).unwrap(),
                false
            )
            .unwrap_err()
            .into(),
            SerializationError::DeserializeExpected(_)
        ));
    }

    #[apply(test_clarity_versions)]
    fn test_sanitization(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        let v_1 = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::Int(2))])
                .unwrap()
                .into(),
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(4)),
                ("c".into(), Value::Int(3)),
            ])
            .unwrap()
            .into(),
        ])
        .unwrap();
        let v_1_good = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::Int(2))])
                .unwrap()
                .into(),
            TupleData::from_data(vec![("b".into(), Value::Int(4))])
                .unwrap()
                .into(),
        ])
        .unwrap();

        let t_1_good = TypeSignature::from_string("(list 5 (tuple (b int)))", version, epoch);
        let t_1_bad_0 =
            TypeSignature::from_string("(list 5 (tuple (b int) (a int)))", version, epoch);
        let t_1_bad_1 = TypeSignature::from_string("(list 5 (tuple (b uint)))", version, epoch);

        let v_2 = TupleData::from_data(vec![
            (
                "list-1".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("b".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![
                        ("a".into(), Value::Int(1)),
                        ("b".into(), Value::Int(4)),
                        ("c".into(), Value::Int(3)),
                    ])
                    .unwrap()
                    .into(),
                ])
                .unwrap(),
            ),
            (
                "list-2".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("c".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![
                        ("a".into(), Value::Int(1)),
                        ("b".into(), Value::Int(4)),
                        ("c".into(), Value::Int(3)),
                    ])
                    .unwrap()
                    .into(),
                ])
                .unwrap(),
            ),
        ])
        .unwrap()
        .into();

        let v_2_good = TupleData::from_data(vec![
            (
                "list-1".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("b".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![("b".into(), Value::Int(4))])
                        .unwrap()
                        .into(),
                ])
                .unwrap(),
            ),
            (
                "list-2".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("c".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![("c".into(), Value::Int(3))])
                        .unwrap()
                        .into(),
                ])
                .unwrap(),
            ),
        ])
        .unwrap()
        .into();

        let t_2_good = TypeSignature::from_string(
            "(tuple (list-2 (list 2 (tuple (c int)))) (list-1 (list 5 (tuple (b int)))))",
            version,
            epoch,
        );
        let t_2_bad_0 = TypeSignature::from_string(
            "(tuple (list-2 (list 2 (tuple (c int)))) (list-1 (list 5 (tuple (a int)))))",
            version,
            epoch,
        );
        let t_2_bad_1 = TypeSignature::from_string(
            "(tuple (list-2 (list 1 (tuple (c int)))) (list-1 (list 5 (tuple (b int)))))",
            version,
            epoch,
        );

        let v_3 = Value::some(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(4)),
                ("c".into(), Value::Int(3)),
            ])
            .unwrap()
            .into(),
        )
        .unwrap();

        let v_3_good = Value::some(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(4)),
            ])
            .unwrap()
            .into(),
        )
        .unwrap();

        let t_3_good =
            TypeSignature::from_string("(optional (tuple (a int) (b int)))", version, epoch);
        let t_3_bad_0 =
            TypeSignature::from_string("(optional (tuple (a uint) (b int)))", version, epoch);
        let t_3_bad_1 =
            TypeSignature::from_string("(optional (tuple (d int) (b int)))", version, epoch);

        let v_4 = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                .unwrap()
                .into(),
            TupleData::from_data(vec![
                ("a".into(), Value::some(Value::Int(1)).unwrap()),
                ("b".into(), Value::none()),
                ("c".into(), Value::some(Value::Int(3)).unwrap()),
            ])
            .unwrap()
            .into(),
        ])
        .unwrap();
        let v_4_good = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                .unwrap()
                .into(),
            TupleData::from_data(vec![("b".into(), Value::none())])
                .unwrap()
                .into(),
        ])
        .unwrap();

        let t_4_good =
            TypeSignature::from_string("(list 5 (tuple (b (optional int))))", version, epoch);
        let t_4_bad_0 = TypeSignature::from_string(
            "(list 5 (tuple (b (optional int)) (a (optional int))))",
            version,
            epoch,
        );
        let t_4_bad_1 =
            TypeSignature::from_string("(list 5 (tuple (b (optional uint))))", version, epoch);

        let v_5 = Value::okay(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![
                    ("a".into(), Value::some(Value::Int(1)).unwrap()),
                    ("b".into(), Value::none()),
                    ("c".into(), Value::some(Value::Int(3)).unwrap()),
                ])
                .unwrap()
                .into(),
            ])
            .unwrap(),
        )
        .unwrap();
        let v_5_good = Value::okay(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![("b".into(), Value::none())])
                    .unwrap()
                    .into(),
            ])
            .unwrap(),
        )
        .unwrap();

        let t_5_good_0 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional int)))) int)",
            version,
            epoch,
        );
        let t_5_good_1 = TypeSignature::from_string(
            "(response (list 2 (tuple (b (optional int)))) int)",
            version,
            epoch,
        );
        let t_5_good_2 = TypeSignature::from_string(
            "(response (list 2 (tuple (b (optional int)))) bool)",
            version,
            epoch,
        );
        let t_5_bad_0 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional int)) (a (optional int)))) uint)",
            version,
            epoch,
        );
        let t_5_bad_1 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional uint)))) int)",
            version,
            epoch,
        );
        let t_5_bad_2 = TypeSignature::from_string(
            "(response int (list 5 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_5_bad_3 = TypeSignature::from_string(
            "(list 5 (tuple (b (optional int)) (a (optional int))))",
            version,
            epoch,
        );

        let v_6 = Value::error(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![
                    ("a".into(), Value::some(Value::Int(1)).unwrap()),
                    ("b".into(), Value::none()),
                    ("c".into(), Value::some(Value::Int(3)).unwrap()),
                ])
                .unwrap()
                .into(),
            ])
            .unwrap(),
        )
        .unwrap();
        let v_6_good = Value::error(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![("b".into(), Value::none())])
                    .unwrap()
                    .into(),
            ])
            .unwrap(),
        )
        .unwrap();

        let t_6_good_0 = TypeSignature::from_string(
            "(response int (list 5 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_6_good_1 = TypeSignature::from_string(
            "(response int (list 2 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_6_good_2 = TypeSignature::from_string(
            "(response bool (list 2 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_6_bad_0 = TypeSignature::from_string(
            "(response uint (list 5 (tuple (b (optional int)) (a (optional int)))))",
            version,
            epoch,
        );
        let t_6_bad_1 = TypeSignature::from_string(
            "(response int (list 5 (tuple (b (optional uint)))))",
            version,
            epoch,
        );
        let t_6_bad_2 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional int)))) int)",
            version,
            epoch,
        );
        let t_6_bad_3 = TypeSignature::from_string(
            "(list 5 (tuple (b (optional int)) (a (optional int))))",
            version,
            epoch,
        );

        let test_cases = [
            (v_1, v_1_good, t_1_good, vec![t_1_bad_0, t_1_bad_1]),
            (v_2, v_2_good, t_2_good, vec![t_2_bad_0, t_2_bad_1]),
            (v_3, v_3_good, t_3_good, vec![t_3_bad_0, t_3_bad_1]),
            (v_4, v_4_good, t_4_good, vec![t_4_bad_0, t_4_bad_1]),
            (
                v_5.clone(),
                v_5_good.clone(),
                t_5_good_0,
                vec![t_5_bad_0, t_5_bad_1, t_5_bad_2, t_5_bad_3],
            ),
            (v_5.clone(), v_5_good.clone(), t_5_good_1, vec![]),
            (v_5, v_5_good, t_5_good_2, vec![]),
            (
                v_6.clone(),
                v_6_good.clone(),
                t_6_good_0,
                vec![t_6_bad_0, t_6_bad_1, t_6_bad_2, t_6_bad_3],
            ),
            (v_6.clone(), v_6_good.clone(), t_6_good_1, vec![]),
            (v_6, v_6_good, t_6_good_2, vec![]),
        ];

        for (input_val, expected_out, good_type, bad_types) in test_cases.iter() {
            eprintln!("Testing {input_val}. Expected sanitization = {expected_out}");
            let serialized = input_val.serialize_to_hex().unwrap();

            let result =
                RollbackWrapper::deserialize_value(&serialized, good_type, &epoch).map(|x| x.value);
            if epoch < StacksEpochId::Epoch24 {
                let error = result.unwrap_err();
                assert!(matches!(error, SerializationError::DeserializeExpected(_)));
            } else {
                let value = result.unwrap();
                assert_eq!(&value, expected_out);
            }

            for bad_type in bad_types.iter() {
                eprintln!("Testing bad type: {bad_type}");
                let result = RollbackWrapper::deserialize_value(&serialized, bad_type, &epoch);
                let error = result.unwrap_err();
                assert!(matches!(error, SerializationError::DeserializeExpected(_)));
            }

            // now test the value::sanitize routine
            let result = Value::sanitize_value(&epoch, good_type, input_val.clone());
            if epoch < StacksEpochId::Epoch24 {
                let (value, did_sanitize) = result.unwrap();
                assert_eq!(&value, input_val);
                assert!(!did_sanitize, "Should not sanitize before epoch-2.4");
            } else {
                let (value, did_sanitize) = result.unwrap();
                assert_eq!(&value, expected_out);
                assert!(did_sanitize, "Should have sanitized");
            }

            for bad_type in bad_types.iter() {
                eprintln!("Testing bad type: {bad_type}");
                let result = Value::sanitize_value(&epoch, bad_type, input_val.clone());
                if epoch < StacksEpochId::Epoch24 {
                    let (value, did_sanitize) = result.unwrap();
                    assert_eq!(&value, input_val);
                    assert!(!did_sanitize, "Should not sanitize before epoch-2.4");
                } else {
                    assert!(result.is_none());
                }
            }
        }
    }

    #[test]
    fn try_overflow_stack() {
        let input = "08080808080808080808070707080807080808080808080708080808080708080707080707080807080808080808080708080808080708080707080708070807080808080808080708080808080708080708080808080808080807070807080808080808070808070707080807070808070808080808070808070708070807080808080808080707080708070807080708080808080808070808080808070808070808080808080808080707080708080808080807080807070708080707080807080808080807080807070807080708080808080808070708070808080808080708080707070808070708080807080807070708";
        assert_eq!(
            CheckErrors::TypeSignatureTooDeep,
            Value::try_deserialize_hex_untyped(input)
                .unwrap_err()
                .into()
        );
    }

    #[test]
    fn test_principals() {
        let issuer =
            PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
                .unwrap();
        let standard_p = Value::from(issuer.clone());

        let contract_identifier = QualifiedContractIdentifier::new(issuer, "foo".into());
        let contract_p2 = Value::from(PrincipalData::Contract(contract_identifier));

        test_deser_ser(contract_p2.clone());
        test_deser_ser(standard_p.clone());

        test_bad_expectation(contract_p2, TypeSignature::BoolType);
        test_bad_expectation(standard_p, TypeSignature::BoolType);
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_serialize_to_vec_returns_interpreter_error_consensus_critical() {
        let value = Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
            data: vec![0; MAX_VALUE_SIZE as usize + 1],
        })));
        let err = value.serialize_to_vec().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "IOError filling byte buffer.".into()
            )),
            err.into()
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_serialize_to_hex_returns_interpreter_error_consensus_critical() {
        let value = Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
            data: vec![0; MAX_VALUE_SIZE as usize + 1],
        })));
        let err = value.serialize_to_hex().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "IOError filling byte buffer.".into()
            )),
            err.into()
        );
    }
}
