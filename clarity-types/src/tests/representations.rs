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

use rstest::rstest;

use crate::errors::RuntimeError;
use crate::representations::{
    CONTRACT_MAX_NAME_LENGTH, CONTRACT_MIN_NAME_LENGTH, ClarityName, ContractName, MAX_STRING_LEN,
};
use crate::stacks_common::codec::StacksMessageCodec;

#[rstest]
#[case::valid_name("hello")]
#[case::dash("hello-dash")]
#[case::underscore("hello_underscore")]
#[case::numbers("test123")]
#[case::single_letter("a")]
#[case::exclamation_mark("set-token-uri!")]
#[case::question_mark("is-owner?")]
#[case::plus("math+")]
#[case::less_than("greater-than<")]
#[case::greater_than("less-than>")]
#[case::less_than_or_equal_to("<=")]
#[case::greater_than_or_equal_to(">=")]
#[case::asterisk("*")]
#[case::slash("/")]
#[case::dash_only("-")]
#[case::equals("=")]
fn test_clarity_name_valid(#[case] name: &str) {
    let clarity_name = ClarityName::try_from(name.to_string())
        .unwrap_or_else(|_| panic!("Should parse valid clarity name: {name}"));
    assert_eq!(clarity_name.as_str(), name);
}

#[rstest]
#[case::empty("")]
#[case::starts_with_number("123abc")]
#[case::contains_space("hello world")]
#[case::contains_at("hello@world")]
#[case::contains_hash("hello#world")]
#[case::contains_dollar("hello$world")]
#[case::contains_percent("hello%world")]
#[case::contains_ampersand("hello&world")]
#[case::contains_dot("hello.world")]
#[case::contains_comma("hello,world")]
#[case::contains_semicolon("hello;world")]
#[case::contains_colon("hello:world")]
#[case::contains_pipe("hello|world")]
#[case::contains_backslash("hello\\world")]
#[case::contains_quote("hello\"world")]
#[case::contains_apostrophe("hello'world")]
#[case::contains_bracket_open("hello[world")]
#[case::contains_bracket_close("hello]world")]
#[case::contains_curly_open("hello{world")]
#[case::contains_curly_close("hello}world")]
#[case::contains_parenthesis_open("hello(world")]
#[case::contains_parenthesis_close("hello)world")]
#[case::too_long(&"a".repeat(MAX_STRING_LEN as usize + 1))]
fn test_clarity_name_invalid(#[case] name: &str) {
    let result = ClarityName::try_from(name.to_string());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RuntimeError::BadNameValue(_, _)
    ));
}

#[rstest]
#[case("test-name")]
#[case::max_length(&"a".repeat(MAX_STRING_LEN as usize))]
fn test_clarity_name_serialization(#[case] name: &str) {
    let name = ClarityName::try_from(name.to_string()).unwrap();

    let mut buffer = Vec::new();
    name.consensus_serialize(&mut buffer)
        .unwrap_or_else(|_| panic!("Serialization should succeed for name: {name}"));

    // Should have length byte followed by the string bytes
    assert_eq!(buffer[0], name.len());
    assert_eq!(&buffer[1..], name.as_bytes());

    // Test deserialization
    let deserialized = ClarityName::consensus_deserialize(&mut buffer.as_slice()).unwrap();
    assert_eq!(deserialized, name);
}

// the first byte is the length of the buffer.
#[rstest]
#[case::invalid_utf8(vec![4, 0xFF, 0xFE, 0xFD, 0xFC], "Failed to parse Clarity name: could not contruct from utf8")]
#[case::invalid_name(vec![2, b'2', b'i'], "Failed to parse Clarity name: BadNameValue(\"ClarityName\", \"2i\")")] // starts with number
#[case::too_long(vec![MAX_STRING_LEN + 1], "Failed to deserialize clarity name: too long")]
#[case::wrong_length(vec![3, b'a'], "failed to fill whole buffer")]
fn test_clarity_name_deserialization_errors(#[case] buffer: Vec<u8>, #[case] error_message: &str) {
    let result = ClarityName::consensus_deserialize(&mut buffer.as_slice());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), error_message);
}

#[rstest]
#[case::valid_name("hello")]
#[case::dash("contract-name")]
#[case::underscore("hello_world")]
#[case::numbers("test123")]
#[case::transient("__transient")]
#[case::min_length("a")]
#[case::max_length(&"a".repeat(CONTRACT_MAX_NAME_LENGTH))]
#[case::max_string_len(&"a".repeat(MAX_STRING_LEN as usize))]
fn test_contract_name_valid(#[case] name: &str) {
    let contract_name = ContractName::try_from(name.to_string())
        .unwrap_or_else(|_| panic!("Should parse valid contract name: {name}"));
    assert_eq!(contract_name.as_str(), name);
}

#[rstest]
#[case::empty("")]
#[case::starts_with_number("123contract")]
#[case::contains_space("hello world")]
#[case::contains_at("hello@world")]
#[case::contains_dot("hello.world")]
#[case::contains_exclamation("hello!world")]
#[case::contains_question("hello?world")]
#[case::contains_plus("hello+world")]
#[case::contains_asterisk("hello*world")]
#[case::contains_equals("hello=world")]
#[case::contains_slash("hello/world")]
#[case::contains_less_than("hello<world")]
#[case::contains_greater_than("hello>world")]
#[case::contains_comma("hello,world")]
#[case::contains_semicolon("hello;world")]
#[case::contains_colon("hello:world")]
#[case::contains_pipe("hello|world")]
#[case::contains_backslash("hello\\world")]
#[case::contains_quote("hello\"world")]
#[case::contains_apostrophe("hello'world")]
#[case::contains_bracket_open("hello[world")]
#[case::contains_bracket_close("hello]world")]
#[case::contains_curly_open("hello{world")]
#[case::contains_curly_close("hello}world")]
#[case::contains_parenthesis_open("hello(world")]
#[case::contains_parenthesis_close("hello)world")]
#[case::too_short(&"a".repeat(CONTRACT_MIN_NAME_LENGTH - 1))]
#[case::too_long(&"a".repeat(MAX_STRING_LEN as usize + 1))]
fn test_contract_name_invalid(#[case] name: &str) {
    let result = ContractName::try_from(name.to_string());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RuntimeError::BadNameValue(_, _)
    ));
}

#[rstest]
#[case::valid_name("test-contract")]
#[case::dash("contract-name")]
#[case::underscore("hello_world")]
#[case::numbers("test123")]
#[case::transient("__transient")]
#[case::min_length("a")]
#[case::max_length(&"a".repeat(CONTRACT_MAX_NAME_LENGTH))]
fn test_contract_name_serialization(#[case] name: &str) {
    let name = ContractName::try_from(name.to_string()).unwrap();
    let mut buffer = Vec::with_capacity((name.len() + 1) as usize);
    name.consensus_serialize(&mut buffer)
        .unwrap_or_else(|_| panic!("Serialization should succeed for name: {name}"));
    assert_eq!(buffer[0], name.len());
    assert_eq!(&buffer[1..], name.as_bytes());

    // Test deserialization
    let deserialized = ContractName::consensus_deserialize(&mut buffer.as_slice()).unwrap();
    assert_eq!(deserialized, name);
}

#[test]
fn test_contract_name_serialization_too_long() {
    let name =
        ContractName::try_from("a".repeat(CONTRACT_MAX_NAME_LENGTH + 1)).expect("should parse");
    let mut buffer = Vec::with_capacity((name.len() + 1) as usize);
    let result = name.consensus_serialize(&mut buffer);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "Failed to serialize contract name: too short or too long: {}",
            name.len()
        )
    );
}

// the first byte is the length of the buffer.
#[rstest]
#[case::invalid_utf8(vec![4, 0xFF, 0xFE, 0xFD, 0xFC], "Failed to parse Contract name: could not construct from utf8")]
#[case::invalid_name(vec![2, b'2', b'i'], "Failed to parse Contract name: BadNameValue(\"ContractName\", \"2i\")")] // starts with number
#[case::too_long(vec![MAX_STRING_LEN + 1], &format!("Failed to deserialize contract name: too short or too long: {}", MAX_STRING_LEN + 1))]
#[case::wrong_length(vec![3, b'a'], "failed to fill whole buffer")]
fn test_contract_name_deserialization_errors(#[case] buffer: Vec<u8>, #[case] error_message: &str) {
    let result = ContractName::consensus_deserialize(&mut buffer.as_slice());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), error_message);
}
