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

use stacks_common::types::StacksEpochId;

pub use crate::vm::analysis::errors::CheckErrors;
use crate::vm::tests::test_clarity_versions;
use crate::vm::types::signatures::MAX_TO_ASCII_BUFFER_LEN;
use crate::vm::types::SequenceSubtype::BufferType;
use crate::vm::types::TypeSignature::SequenceType;
use crate::vm::types::{
    ASCIIData, BuffData, BufferLength, CharType, SequenceData, TypeSignature, UTF8Data, Value,
};
use crate::vm::{execute_v2, execute_with_parameters, ClarityVersion};

#[test]
fn test_simple_buff_to_int_le() {
    // For little-endian, 0001 at the beginning should be interpreted as the least significant bits.
    let good1_test = "(buff-to-int-le 0x00010000000000000000000000000000)";
    let good1_expected = Value::Int(256);
    assert_eq!(good1_expected, execute_v2(good1_test).unwrap().unwrap());

    // For signed conversion, all ff's should be negative.
    let good2_test = "(buff-to-int-le 0xffffffffffffffffffffffffffffffff)";
    let good2_expected = Value::Int(-1);
    assert_eq!(good2_expected, execute_v2(good2_test).unwrap().unwrap());

    // For little-endian, a partially filled buffer should behave as though 00's are padded on the right.
    let good3_test = "(buff-to-int-le 0x0001)";
    let good3_expected = Value::Int(256);
    assert_eq!(good3_expected, execute_v2(good3_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-int-le \"not-needed\" 0xfffffffffffffffffffffffffffffffe)";
    assert_eq!(
        execute_v2(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-int-le \"wrong-type\")";
    assert_eq!(
        execute_v2(bad_wrong_type_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::String(CharType::ASCII(
                ASCIIData {
                    data: "wrong-type".as_bytes().to_vec()
                }
            ))))
        )
        .into()
    );

    // Right number of arguments but buffer is too large.
    let bad_too_large_test = "(buff-to-int-le 0x000102030405060708090a0b0c0d0e0f00)";
    assert_eq!(
        execute_v2(bad_too_large_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::Buffer(BuffData {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]
            })))
        )
        .into()
    );
}

#[test]
fn test_simple_buff_to_uint_le() {
    // For little endian, 0001 at the beginning should be interpreted as the least significant bit.
    let good1_test = "(buff-to-uint-le 0x00010000000000000000000000000000)";
    let good1_expected = Value::UInt(256);
    assert_eq!(good1_expected, execute_v2(good1_test).unwrap().unwrap());

    // For unsigned conversion, all ff's should be max positive.
    let good2_test = "(buff-to-uint-le 0xffffffffffffffffffffffffffffffff)";
    let good2_expected = Value::UInt(u128::MAX);
    assert_eq!(good2_expected, execute_v2(good2_test).unwrap().unwrap());

    // For little-endian, a partially filled buffer should behave as though 00's are padded on the right.
    let good3_test = "(buff-to-uint-le 0x0001)";
    let good3_expected = Value::UInt(256);
    assert_eq!(good3_expected, execute_v2(good3_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-uint-le \"not-needed\" 0xfffffffffffffffffffffffffffffffe)";
    assert_eq!(
        execute_v2(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-uint-le \"wrong-type\")";
    assert_eq!(
        execute_v2(bad_wrong_type_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::String(CharType::ASCII(
                ASCIIData {
                    data: "wrong-type".as_bytes().to_vec()
                }
            ))))
        )
        .into()
    );

    // Right number of arguments but buffer is too large.
    let bad_too_large_test = "(buff-to-uint-le 0x000102030405060708090a0b0c0d0e0f00)";
    assert_eq!(
        execute_v2(bad_too_large_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::Buffer(BuffData {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]
            })))
        )
        .into()
    );
}

#[test]
fn test_simple_buff_to_int_be() {
    // For big-endian, 0100 at the end should be interpreted as least significant bits.
    let good1_test = "(buff-to-uint-be 0x00000000000000000000000000000100)";
    let good1_expected = Value::UInt(256);
    assert_eq!(good1_expected, execute_v2(good1_test).unwrap().unwrap());

    // For signed conversion, all ff's should be negative.
    let good2_test = "(buff-to-int-be 0xffffffffffffffffffffffffffffffff)";
    let good2_expected = Value::Int(-1);
    assert_eq!(good2_expected, execute_v2(good2_test).unwrap().unwrap());

    // For big-endian, a partially filled buffer should behave as though 00's are padded on the left.
    let good3_test = "(buff-to-int-be 0x0100)";
    let good3_expected = Value::Int(256);
    assert_eq!(good3_expected, execute_v2(good3_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-int-be \"not-needed\" 0xfffffffffffffffffffffffffffffffe)";
    assert_eq!(
        execute_v2(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-int-be \"wrong-type\")";
    assert_eq!(
        execute_v2(bad_wrong_type_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::String(CharType::ASCII(
                ASCIIData {
                    data: "wrong-type".as_bytes().to_vec()
                }
            ))))
        )
        .into()
    );

    // Right number of arguments but buffer is too large.
    let bad_too_large_test = "(buff-to-int-be 0x000102030405060708090a0b0c0d0e0f00)";
    assert_eq!(
        execute_v2(bad_too_large_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::Buffer(BuffData {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]
            })))
        )
        .into()
    );
}

#[test]
fn test_simple_buff_to_uint_be() {
    // For big-endian, 0100 at the end should be interpreted as least significant bits.
    let good1_test = "(buff-to-uint-be 0x00000000000000000000000000000100)";
    let good1_expected = Value::UInt(256);
    assert_eq!(good1_expected, execute_v2(good1_test).unwrap().unwrap());

    // For unsigned conversion, all ff's should be max positive.
    let good2_test = "(buff-to-uint-be 0xffffffffffffffffffffffffffffffff)";
    let good2_expected = Value::UInt(u128::MAX);
    assert_eq!(good2_expected, execute_v2(good2_test).unwrap().unwrap());

    // For big-endian, a partially filled buffer should behave as though 00's are padded on the left.
    let good3_test = "(buff-to-uint-be 0x0100)";
    let good3_expected = Value::UInt(256);
    assert_eq!(good3_expected, execute_v2(good3_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-uint-be \"not-needed\" 0xfffffffffffffffffffffffffffffffe)";
    assert_eq!(
        execute_v2(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-uint-be \"wrong-type\")";
    assert_eq!(
        execute_v2(bad_wrong_type_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::String(CharType::ASCII(
                ASCIIData {
                    data: "wrong-type".as_bytes().to_vec()
                }
            ))))
        )
        .into()
    );

    // Right number of arguments but buffer is too large.
    let bad_too_large_test = "(buff-to-uint-be 0x000102030405060708090a0b0c0d0e0f00)";
    assert_eq!(
        execute_v2(bad_too_large_test).unwrap_err(),
        CheckErrors::TypeValueError(
            Box::new(SequenceType(BufferType(
                BufferLength::try_from(16_u32).unwrap()
            ))),
            Box::new(Value::Sequence(SequenceData::Buffer(BuffData {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]
            })))
        )
        .into()
    );
}

#[test]
fn test_simple_string_to_int() {
    let good1_test = r#"(string-to-int? "-1")"#;
    assert_eq!(
        Value::some(Value::Int(-1)).unwrap(),
        execute_v2(good1_test).unwrap().unwrap()
    );

    let good2_test = r#"(string-to-int? u"-1")"#;
    assert_eq!(
        Value::some(Value::Int(-1)).unwrap(),
        execute_v2(good2_test).unwrap().unwrap()
    );

    let bad_value_error_ascii_test = r#"(string-to-int? "")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_ascii_test).unwrap().unwrap(),
    );

    let bad_value_error_ascii_test = r#"(string-to-int? "a")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_ascii_test).unwrap().unwrap(),
    );

    let bad_value_error_utf8_test = r#"(string-to-int? u"a")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_utf8_test).unwrap().unwrap(),
    );

    let bad_value_error_utf8_test = r#"(string-to-int? u"\u{211D}\u{221E}")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_utf8_test).unwrap().unwrap(),
    );

    let bad_value_error_too_big_test =
        r#"(string-to-int? u"340282366920938463463374607431768211455000")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_too_big_test).unwrap().unwrap(),
    );

    let no_args_test = r#"(string-to-int?)"#;
    assert_eq!(
        execute_v2(no_args_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 0).into()
    );

    let wrong_type_error_test = r#"(string-to-int? 1)"#;
    assert_eq!(
        execute_v2(wrong_type_error_test).unwrap_err(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ],
            Box::new(Value::Int(1))
        )
        .into()
    );
}

#[test]
fn test_simple_string_to_uint() {
    let good1_test = r#"(string-to-uint? "1")"#;
    assert_eq!(
        Value::some(Value::UInt(1)).unwrap(),
        execute_v2(good1_test).unwrap().unwrap()
    );

    let good2_test = r#"(string-to-uint? u"1")"#;
    assert_eq!(
        Value::some(Value::UInt(1)).unwrap(),
        execute_v2(good2_test).unwrap().unwrap()
    );

    let bad_value_error_ascii_test = r#"(string-to-uint? "")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_ascii_test).unwrap().unwrap(),
    );

    let bad_value_error_ascii_test = r#"(string-to-uint? "a")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_ascii_test).unwrap().unwrap(),
    );

    let bad_value_error_utf8_test = r#"(string-to-uint? u"a")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_utf8_test).unwrap().unwrap(),
    );

    let bad_value_error_utf8_test = r#"(string-to-uint? u"\u{211D}\u{221E}")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_utf8_test).unwrap().unwrap(),
    );

    let bad_value_error_too_big_test =
        r#"(string-to-uint? u"340282366920938463463374607431768211455000")"#;
    assert_eq!(
        Value::none(),
        execute_v2(bad_value_error_too_big_test).unwrap().unwrap(),
    );

    let no_args_test = r#"(string-to-uint?)"#;
    assert_eq!(
        execute_v2(no_args_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 0).into()
    );

    let wrong_type_error_test = r#"(string-to-uint? 1)"#;
    assert_eq!(
        execute_v2(wrong_type_error_test).unwrap_err(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ],
            Box::new(Value::Int(1))
        )
        .into()
    );
}

#[test]
fn test_simple_int_to_ascii() {
    let good1_test = r#"(int-to-ascii -1)"#;
    let good1_expected = Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
        data: "-1".as_bytes().to_vec(),
    })));
    assert_eq!(good1_expected, execute_v2(good1_test).unwrap().unwrap());

    let good2_test = r#"(int-to-ascii u1)"#;
    let good2_expected = Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
        data: "1".as_bytes().to_vec(),
    })));
    assert_eq!(good2_expected, execute_v2(good2_test).unwrap().unwrap());

    let no_args_test = r#"(int-to-ascii)"#;
    assert_eq!(
        execute_v2(no_args_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 0).into()
    );

    let wrong_type_error_test = r#"(int-to-ascii "1")"#;
    assert_eq!(
        execute_v2(wrong_type_error_test).unwrap_err(),
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Box::new(Value::Sequence(SequenceData::String(CharType::ASCII(
                ASCIIData {
                    data: "1".as_bytes().to_vec()
                }
            ))))
        )
        .into()
    );
}

#[test]
fn test_simple_int_to_utf8() {
    let good1_test = r#"(int-to-utf8 1)"#;
    let good1_expected = Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data {
        data: vec!["1".as_bytes().to_vec()],
    })));
    assert_eq!(good1_expected, execute_v2(good1_test).unwrap().unwrap());

    let good2_test = r#"(int-to-utf8 u1)"#;
    let good2_expected = Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data {
        data: vec!["1".as_bytes().to_vec()],
    })));
    assert_eq!(good2_expected, execute_v2(good2_test).unwrap().unwrap());

    let no_args_test = r#"(int-to-utf8)"#;
    assert_eq!(
        execute_v2(no_args_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 0).into()
    );

    let wrong_type_error_test = r#"(int-to-utf8 "1")"#;
    assert_eq!(
        execute_v2(wrong_type_error_test).unwrap_err(),
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Box::new(Value::Sequence(SequenceData::String(CharType::ASCII(
                ASCIIData {
                    data: "1".as_bytes().to_vec()
                }
            ))))
        )
        .into()
    );
}

#[apply(test_clarity_versions)]
fn test_to_ascii(version: ClarityVersion, epoch: StacksEpochId) {
    // to-ascii? is available in Clarity 4
    if version < ClarityVersion::Clarity4 {
        return;
    }

    // Test successful conversions
    let int_to_ascii = "(to-ascii? 9876)";
    assert_eq!(
        execute_with_parameters(int_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(Value::string_ascii_from_bytes(b"9876".to_vec()).unwrap()).unwrap()
        ))
    );

    let uint_to_ascii = "(to-ascii? u12345678)";
    assert_eq!(
        execute_with_parameters(uint_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(Value::string_ascii_from_bytes(b"u12345678".to_vec()).unwrap()).unwrap()
        ))
    );

    let bool_true_to_ascii = "(to-ascii? true)";
    assert_eq!(
        execute_with_parameters(bool_true_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(Value::string_ascii_from_bytes(b"true".to_vec()).unwrap()).unwrap()
        ))
    );

    let bool_false_to_ascii = "(to-ascii? false)";
    assert_eq!(
        execute_with_parameters(bool_false_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(Value::string_ascii_from_bytes(b"false".to_vec()).unwrap()).unwrap()
        ))
    );

    let standard_principal_to_ascii = "(to-ascii? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)";
    assert_eq!(
        execute_with_parameters(standard_principal_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(
                Value::string_ascii_from_bytes(
                    b"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".to_vec()
                )
                .unwrap()
            )
            .unwrap()
        ))
    );

    let contract_principal_to_ascii = "(to-ascii? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.foo)";
    assert_eq!(
        execute_with_parameters(contract_principal_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(
                Value::string_ascii_from_bytes(
                    b"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.foo".to_vec()
                )
                .unwrap()
            )
            .unwrap()
        ))
    );

    let buffer_to_ascii = "(to-ascii? 0x1234)";
    assert_eq!(
        execute_with_parameters(buffer_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(Value::string_ascii_from_bytes(b"0x1234".to_vec()).unwrap()).unwrap()
        ))
    );

    let utf8_string_to_ascii = "(to-ascii? u\"I am serious, and don't call me Shirley.\")";
    assert_eq!(
        execute_with_parameters(utf8_string_to_ascii, version, epoch, false,),
        Ok(Some(
            Value::okay(
                Value::string_ascii_from_bytes(
                    b"I am serious, and don't call me Shirley.".to_vec()
                )
                .unwrap()
            )
            .unwrap()
        ))
    );

    // This should error since the UTF-8 string contains a non-ASCII character
    let utf8_string_with_non_ascii = "(to-ascii? u\"A smiley face emoji: \\u{1F600}\")";
    assert_eq!(
        execute_with_parameters(utf8_string_with_non_ascii, version, epoch, false,),
        Ok(Some(Value::err_uint(1))) // Should return error for non-ASCII UTF8
    );

    // Test error cases - these should fail at analysis time with type errors
    let ascii_string_to_ascii = "(to-ascii? \"60 percent of the time, it works every time\")";
    let result = execute_with_parameters(ascii_string_to_ascii, version, epoch, false);
    // This should fail at analysis time since ASCII strings are not allowed
    assert!(result.is_err());

    let list_to_ascii = "(to-ascii? (list 1 2 3))";
    let result = execute_with_parameters(list_to_ascii, version, epoch, false);
    // This should fail at analysis time since lists are not allowed
    assert!(result.is_err());

    let tuple_to_ascii = "(to-ascii? { a: 1, b: u2 })";
    let result = execute_with_parameters(tuple_to_ascii, version, epoch, false);
    // This should fail at analysis time since tuples are not allowed
    assert!(result.is_err());

    let optional_to_ascii = "(to-ascii? (some u789))";
    let result = execute_with_parameters(optional_to_ascii, version, epoch, false);
    // This should fail at analysis time since optionals are not allowed
    assert!(result.is_err());

    let response_to_ascii = "(to-ascii? (ok true))";
    let result = execute_with_parameters(response_to_ascii, version, epoch, false);
    // This should fail at analysis time since responses are not allowed
    assert!(result.is_err());

    let oversized_buffer_to_ascii = format!(
        "(to-ascii? 0x{})",
        "ff".repeat(MAX_TO_ASCII_BUFFER_LEN as usize + 1)
    );
    let result = execute_with_parameters(response_to_ascii, version, epoch, false);
    // This should fail at analysis time since the value is too big
    assert!(result.is_err());
}
