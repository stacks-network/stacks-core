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
use std::io::Write;

use crate::Error;
use crate::errors::{CheckErrors, VmInternalError};
use crate::types::serialization::SerializationError;
use crate::types::{
    ASCIIData, CharType, MAX_VALUE_SIZE, PrincipalData, QualifiedContractIdentifier, SequenceData,
    StandardPrincipalData, TupleData, TypeSignature, Value,
};

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

fn test_bad_expectation(v: Value, e: TypeSignature) {
    assert!(matches!(
        Value::try_deserialize_hex(&v.serialize_to_hex().unwrap(), &e, false).unwrap_err(),
        SerializationError::DeserializeExpected(_)
    ));
}

#[test]
fn test_lists() {
    let list_list_int = Value::list_from(vec![
        Value::list_from(vec![Value::Int(1), Value::Int(2), Value::Int(3)]).unwrap(),
    ])
    .unwrap();
    test_deser_ser(list_list_int.clone());
    test_deser_ser(Value::list_from(vec![]).unwrap());
    test_bad_expectation(list_list_int.clone(), TypeSignature::BoolType);

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

#[test]
fn test_opts() {
    test_deser_ser(Value::none());
    test_deser_ser(Value::some(Value::Int(15)).unwrap());

    test_bad_expectation(Value::none(), TypeSignature::IntType);
    test_bad_expectation(Value::some(Value::Int(15)).unwrap(), TypeSignature::IntType);
}

#[test]
fn test_resp() {
    test_deser_ser(Value::okay(Value::Int(15)).unwrap());
    test_deser_ser(Value::error(Value::Int(15)).unwrap());

    // Bad expected types.
    test_bad_expectation(Value::okay(Value::Int(15)).unwrap(), TypeSignature::IntType);
}

#[test]
fn test_buffs() {
    test_deser_ser(Value::buff_from(vec![0, 0, 0, 0]).unwrap());
    test_deser_ser(Value::buff_from(vec![0xde, 0xad, 0xbe, 0xef]).unwrap());
    test_deser_ser(Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap());

    test_bad_expectation(
        Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap(),
        TypeSignature::BoolType,
    );
}

#[test]
fn test_string_ascii() {
    test_deser_ser(Value::string_ascii_from_bytes(vec![61, 62, 63, 64]).unwrap());
}

#[test]
fn test_string_utf8() {
    test_deser_ser(Value::string_utf8_from_bytes(vec![61, 62, 63, 64]).unwrap());
    test_deser_ser(Value::string_utf8_from_bytes(vec![61, 62, 63, 240, 159, 164, 151]).unwrap());
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
        .unwrap_err(),
        SerializationError::DeserializeExpected(_)
    ));

    // field type mismatch
    assert!(matches!(
        Value::try_deserialize_hex(
            &t_2.serialize_to_hex().unwrap(),
            &TypeSignature::type_of(&t_1).unwrap(),
            false
        )
        .unwrap_err(),
        SerializationError::DeserializeExpected(_)
    ));

    // field not-present in expected
    assert!(matches!(
        Value::try_deserialize_hex(
            &t_1.serialize_to_hex().unwrap(),
            &TypeSignature::type_of(&t_4).unwrap(),
            false
        )
        .unwrap_err(),
        SerializationError::DeserializeExpected(_)
    ));
}

#[test]
fn test_vectors() {
    let tests = [
        ("1010", Err("Bad type prefix".into())),
        ("0000000000000000000000000000000001", Ok(Value::Int(1))),
        ("00ffffffffffffffffffffffffffffffff", Ok(Value::Int(-1))),
        ("0100000000000000000000000000000001", Ok(Value::UInt(1))),
        (
            "0200000004deadbeef",
            Ok(Value::buff_from(vec![0xde, 0xad, 0xbe, 0xef]).unwrap()),
        ),
        ("03", Ok(Value::Bool(true))),
        ("04", Ok(Value::Bool(false))),
        (
            "050011deadbeef11ababffff11deadbeef11ababffff",
            Ok(StandardPrincipalData::new(
                0x00,
                [
                    0x11, 0xde, 0xad, 0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff, 0x11, 0xde, 0xad,
                    0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff,
                ],
            )
            .unwrap()
            .into()),
        ),
        (
            "060011deadbeef11ababffff11deadbeef11ababffff0461626364",
            Ok(QualifiedContractIdentifier::new(
                StandardPrincipalData::new(
                    0x00,
                    [
                        0x11, 0xde, 0xad, 0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff, 0x11, 0xde,
                        0xad, 0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff,
                    ],
                )
                .unwrap(),
                "abcd".into(),
            )
            .into()),
        ),
        (
            "0700ffffffffffffffffffffffffffffffff",
            Ok(Value::okay(Value::Int(-1)).unwrap()),
        ),
        (
            "0800ffffffffffffffffffffffffffffffff",
            Ok(Value::error(Value::Int(-1)).unwrap()),
        ),
        ("09", Ok(Value::none())),
        (
            "0a00ffffffffffffffffffffffffffffffff",
            Ok(Value::some(Value::Int(-1)).unwrap()),
        ),
        (
            "0b0000000400000000000000000000000000000000010000000000000000000000000000000002000000000000000000000000000000000300fffffffffffffffffffffffffffffffc",
            Ok(Value::list_from(vec![
                Value::Int(1),
                Value::Int(2),
                Value::Int(3),
                Value::Int(-4),
            ])
            .unwrap()),
        ),
        (
            "0c000000020362617a0906666f6f62617203",
            Ok(Value::from(
                TupleData::from_data(vec![
                    ("baz".into(), Value::none()),
                    ("foobar".into(), Value::Bool(true)),
                ])
                .unwrap(),
            )),
        ),
    ];

    for (test, expected) in tests.iter() {
        if let Ok(x) = expected {
            assert_eq!(test, &x.serialize_to_hex().unwrap());
        }
        assert_eq!(expected, &Value::try_deserialize_hex_untyped(test));
        assert_eq!(
            expected,
            &Value::try_deserialize_hex_untyped(&format!("0x{test}"))
        );
    }

    // test the serialized_size implementation
    for (test, expected) in tests.iter() {
        if let Ok(value) = expected {
            assert_eq!(
                value.serialized_size().unwrap(),
                test.len() as u32 / 2,
                "serialized_size() should return the byte length of the serialization (half the length of the hex encoding)",
            );
        }
    }
}

#[test]
fn try_deser_large_list() {
    let buff = vec![
        11, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    assert_eq!(
        Value::try_deserialize_bytes_untyped(&buff).unwrap_err(),
        SerializationError::DeserializationError("Illegal list type".to_string())
    );
}

#[test]
fn try_deser_large_tuple() {
    let buff = vec![
        12, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    assert_eq!(
        Value::try_deserialize_bytes_untyped(&buff).unwrap_err(),
        SerializationError::DeserializationError("Illegal tuple type".to_string())
    );
}

#[test]
fn try_overflow_stack() {
    let input = "08080808080808080808070707080807080808080808080708080808080708080707080707080807080808080808080708080808080708080707080708070807080808080808080708080808080708080708080808080808080807070807080808080808070808070707080807070808070808080808070808070708070807080808080808080707080708070807080708080808080808070808080808070808070808080808080808080707080708080808080807080807070708080707080807080808080807080807070807080708080808080808070708070808080808080708080707070808070708080807080807070708";
    assert_eq!(
        Err(CheckErrors::TypeSignatureTooDeep.into()),
        Value::try_deserialize_hex_untyped(input)
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

/// The returned VmInternalError is consensus-critical.
#[test]
fn test_serialize_to_vec_returns_vm_internal_error_consensus_critical() {
    let value = Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
        data: vec![0; MAX_VALUE_SIZE as usize + 1],
    })));
    let err = value.serialize_to_vec().unwrap_err();
    assert_eq!(
        Error::from(VmInternalError::Expect(
            "IOError filling byte buffer.".into()
        )),
        err.into()
    );
}

/// The returned VmInternalError is consensus-critical.
#[test]
fn test_serialize_to_hex_returns_vm_internal_error_consensus_critical() {
    let value = Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
        data: vec![0; MAX_VALUE_SIZE as usize + 1],
    })));
    let err = value.serialize_to_hex().unwrap_err();
    assert_eq!(
        Error::from(VmInternalError::Expect(
            "IOError filling byte buffer.".into()
        )),
        err.into()
    );
}
