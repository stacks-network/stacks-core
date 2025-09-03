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

use std::str;

pub use clarity_serialization::types::serialization::{
    SerializationError, TypePrefix, NONE_SERIALIZATION_LEN,
};
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::vm::database::{ClarityDeserializable, ClaritySerializable};
use crate::vm::errors::{Error as ClarityError, InterpreterError};

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
            Value::try_deserialize_hex(&v.serialize_to_hex().unwrap(), &e, false).unwrap_err(),
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
            Value::deserialize_read(&mut too_big.as_slice(), None, false).unwrap_err(),
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

        match Value::deserialize_read(&mut eof.as_slice(), None, false) {
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
