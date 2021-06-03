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

pub use vm::analysis::errors::{CheckError, CheckErrors};
use vm::execute;
use vm::types::BufferLength;
use vm::types::SequenceSubtype::StringType;
use vm::types::SequenceSubtype::BufferType;
use vm::types::StringSubtype::ASCII;
use vm::types::TypeSignature::SequenceType;
use vm::types::Value;

#[test]
fn test_simple_buff_to_int_le() {
    // All 1 bits should be -1 for an int.
    let good1_test = "(buff-to-int-le 0xffffffffffffffffffffffffffffffff)";
    let good1_expected = Value::Int(-1);
    assert_eq!(good1_expected, execute(good1_test).unwrap().unwrap());

    // For little endian, 1 at the end should be interpreted as most significant bit.
    let good2_test = "(buff-to-int-le 0x00000000000000000000000000000001)";
    let good2_expected = Value::Int(1329227995784915872903807060280344576);
    assert_eq!(good2_expected, execute(good2_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-int-le \"not-needed\" 0xffffffffffffffffffffffffffffffff)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-int-le \"wrong-type\")";
    assert_eq!(
        execute(bad_wrong_type_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(StringType(ASCII(BufferLength(10))))).into()
    );

    // Right number of arguments but wrong buffer size.
    let bad_wrong_number_test = "(buff-to-int-le 0x01)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(BufferType(BufferLength(1)))).into()
    );
}

#[test]
fn test_simple_buff_to_uint_le() {
    // All 1 bits should be max value for a uint.
    let good1_test = "(buff-to-uint-le 0xffffffffffffffffffffffffffffffff)";
    let good1_expected = Value::UInt(340282366920938463463374607431768211455);
    assert_eq!(good1_expected, execute(good1_test).unwrap().unwrap());

    // For little endian, 1 at the end should be interpreted as most significant bit.
    let good2_test = "(buff-to-uint-le 0x00000000000000000000000000000001)";
    let good2_expected = Value::UInt(1329227995784915872903807060280344576);
    assert_eq!(good2_expected, execute(good2_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-uint-le \"not-needed\" 0xffffffffffffffffffffffffffffffff)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-uint-le \"wrong-type\")";
    assert_eq!(
        execute(bad_wrong_type_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(StringType(ASCII(BufferLength(10))))).into()
    );

    // Right number of arguments but wrong buffer size.
    let bad_wrong_number_test = "(buff-to-int-le 0x01)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(BufferType(BufferLength(1)))).into()
    );
}

#[test]
fn test_simple_buff_to_int_be() {
    // All 1 bits should be -1 for an int.
    let good1_test = "(buff-to-int-be 0xffffffffffffffffffffffffffffffff)";
    let good1_expected = Value::Int(-1);
    assert_eq!(good1_expected, execute(good1_test).unwrap().unwrap());

    // For big endian, 1 at the end should be interpreted as least significant bit.
    let good2_test = "(buff-to-int-be 0x00000000000000000000000000000001)";
    let good2_expected = Value::Int(1);
    assert_eq!(good2_expected, execute(good2_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-int-be \"not-needed\" 0xffffffffffffffffffffffffffffffff)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-int-be \"wrong-type\")";
    assert_eq!(
        execute(bad_wrong_type_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(StringType(ASCII(BufferLength(10))))).into()
    );

    // Right number of arguments but wrong buffer size.
    let bad_wrong_number_test = "(buff-to-int-le 0x01)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(BufferType(BufferLength(1)))).into()
    );
}

#[test]
fn test_simple_buff_to_uint_be() {
    // All 1 bits should be max value for a uint.
    let good1_test = "(buff-to-uint-be 0xffffffffffffffffffffffffffffffff)";
    let good1_expected = Value::UInt(340282366920938463463374607431768211455);
    assert_eq!(good1_expected, execute(good1_test).unwrap().unwrap());

    // For big endian, 1 at the end should be interpreted as least significant bit.
    let good2_test = "(buff-to-uint-be 0x00000000000000000000000000000001)";
    let good2_expected = Value::UInt(1);
    assert_eq!(good2_expected, execute(good2_test).unwrap().unwrap());

    // Wrong number of arguments.
    let bad_wrong_number_test =
        "(buff-to-uint-be \"not-needed\" 0xffffffffffffffffffffffffffffffff)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(1, 2).into()
    );

    // Right number of arguments, but wrong type.
    let bad_wrong_type_test = "(buff-to-uint-be \"wrong-type\")";
    assert_eq!(
        execute(bad_wrong_type_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(StringType(ASCII(BufferLength(10))))).into()
    );

    // Right number of arguments but wrong buffer size.
    let bad_wrong_number_test = "(buff-to-int-le 0x01)";
    assert_eq!(
        execute(bad_wrong_number_test).unwrap_err(),
        CheckErrors::ExpectedBuffer16(SequenceType(BufferType(BufferLength(1)))).into()
    );
}
