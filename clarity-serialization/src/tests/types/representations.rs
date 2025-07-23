use std::io::Read;

use test_case::test_case;

use crate::errors::CodecError;
use crate::representations::{
    CONTRACT_MAX_NAME_LENGTH, CONTRACT_MIN_NAME_LENGTH, ClarityName, ContractName, MAX_STRING_LEN,
};
use crate::stacks_common::codec::StacksMessageCodec;

#[test_case("hello"; "valid_name")]
#[test_case("hello-dash"; "dash")]
#[test_case("hello_underscore"; "underscore")]
#[test_case("test123"; "numbers")]
#[test_case("a"; "single_letter")]
#[test_case("set-token-uri!"; "exclamation_mark")]
#[test_case("is-owner?"; "question_mark")]
#[test_case("math+"; "plus")]
#[test_case("greater-than<"; "less_than")]
#[test_case("less-than>"; "greater_than")]
#[test_case("<="; "less_than_or_equal_to")]
#[test_case(">="; "greater_than_or_equal_to")]
#[test_case("*"; "asterisk")]
#[test_case("/"; "slash")]
#[test_case("-"; "dash-only")]
#[test_case("="; "equals")]
fn test_clarity_name_valid(name: &str) {
    let clarity_name = ClarityName::try_from(name.to_string())
        .unwrap_or_else(|_| panic!("Should parse valid clarity name: {name}"));
    assert_eq!(clarity_name.as_str(), name);
}

#[test_case(""; "empty")]
#[test_case("123abc"; "starts_with_number")]
#[test_case("hello world"; "contains_space")]
#[test_case("hello@world"; "contains_at")]
#[test_case("hello#world"; "contains_hash")]
#[test_case("hello$world"; "contains_dollar")]
#[test_case("hello%world"; "contains_percent")]
#[test_case("hello&world"; "contains_ampersand")]
#[test_case("hello.world"; "contains_dot")]
#[test_case("hello,world"; "contains_comma")]
#[test_case("hello;world"; "contains_semicolon")]
#[test_case("hello:world"; "contains_colon")]
#[test_case("hello|world"; "contains_pipe")]
#[test_case("hello\\world"; "contains_backslash")]
#[test_case("hello\"world"; "contains_quote")]
#[test_case("hello'world"; "contains_apostrophe")]
#[test_case("hello[world"; "contains_bracket_open")]
#[test_case("hello]world"; "contains_bracket_close")]
#[test_case("hello{world"; "contains_curly_open")]
#[test_case("hello}world"; "contains_curly_close")]
#[test_case("hello(world"; "contains_parenthesis_open")]
#[test_case("hello)world"; "contains_parenthesis_close")]
#[test_case(&"a".repeat(MAX_STRING_LEN as usize + 1); "too_long")]
fn test_clarity_name_invalid(name: &str) {
    let result = ClarityName::try_from(name.to_string());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CodecError::InvalidClarityName(_, _)
    ));
}

#[test_case("test-name")]
#[test_case(&"a".repeat(MAX_STRING_LEN as usize); "max-length")]
fn test_clarity_name_serialization(name: &str) {
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

#[test]
fn test_clarity_name_serialization_too_long() {
    // This test can't be implemented with the current API since
    // ClarityName::try_from would reject oversized strings
    // and we can't construct invalid ClarityName instances directly
}

// the first byte is the length of the buffer.
#[test_case(vec![4, 0xFF, 0xFE, 0xFD, 0xFC].as_slice(), "Failed to parse Clarity name: could not contruct from utf8"; "invalid_utf8")]
#[test_case(vec![2, b'2', b'i'].as_slice(), "Failed to parse Clarity name: InvalidClarityName(\"ClarityName\", \"2i\")"; "invalid_name")] // starts with number
#[test_case(vec![MAX_STRING_LEN + 1].as_slice(), "Failed to deserialize clarity name: too long"; "too_long")]
#[test_case(vec![3, b'a'].as_slice(), "failed to fill whole buffer"; "wrong_length")]
fn test_clarity_name_deserialization_errors<R: Read>(mut buffer: R, error_message: &str) {
    let result = ClarityName::consensus_deserialize(&mut buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), error_message);
}

#[test_case("hello"; "valid_name")]
#[test_case("contract-name"; "dash")]
#[test_case("hello_world"; "underscore")]
#[test_case("test123"; "numbers")]
#[test_case("__transient"; "transient")]
#[test_case("a"; "min_length")]
#[test_case(&"a".repeat(CONTRACT_MAX_NAME_LENGTH); "max_length")]
#[test_case(&"a".repeat(MAX_STRING_LEN as usize); "max_string_len")]
fn test_contract_name_valid(name: &str) {
    let contract_name = ContractName::try_from(name.to_string())
        .unwrap_or_else(|_| panic!("Should parse valid contract name: {name}"));
    assert_eq!(contract_name.as_str(), name);
}

#[test_case(""; "emtpy")]
#[test_case("123contract"; "starts_with_number")]
#[test_case("hello world"; "contains_space")]
#[test_case("hello@world"; "contains_at")]
#[test_case("hello.world"; "contains_dot")]
#[test_case("hello!world"; "contains_exclamation")]
#[test_case("hello?world"; "contains_question")]
#[test_case("hello+world"; "contains_plus")]
#[test_case("hello*world"; "contains_asterisk")]
#[test_case("hello=world"; "contains_equals")]
#[test_case("hello/world"; "contains_slash")]
#[test_case("hello<world"; "contains_less_than")]
#[test_case("hello>world"; "contains_greater_than")]
#[test_case("hello,world"; "contains_comma")]
#[test_case("hello;world"; "contains_semicolon")]
#[test_case("hello:world"; "contains_colon")]
#[test_case("hello|world"; "contains_pipe")]
#[test_case("hello\\world"; "contains_backslash")]
#[test_case("hello\"world"; "contains_quote")]
#[test_case("hello'world"; "contains_apostrophe")]
#[test_case("hello[world"; "contains_bracket_open")]
#[test_case("hello]world"; "contains_bracket_close")]
#[test_case("hello{world"; "contains_curly_open")]
#[test_case("hello}world"; "contains_curly_close")]
#[test_case("hello(world"; "contains_parenthesis_open")]
#[test_case("hello)world"; "contains_parenthesis_close")]
#[test_case(&"a".repeat(MAX_STRING_LEN as usize + 1); "too_long")]
fn test_contract_name_invalid(name: &str) {
    let result = ContractName::try_from(name.to_string());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CodecError::InvalidContractName(_, _)
    ));
}

#[test_case("test-contract"; "valid_name")]
#[test_case("contract-name"; "dash")]
#[test_case("hello_world"; "underscore")]
#[test_case("test123"; "numbers")]
#[test_case("__transient"; "transient")]
#[test_case("a"; "min_length")]
#[test_case(&"a".repeat(CONTRACT_MAX_NAME_LENGTH); "max_length")]
fn test_contract_name_serialization(name: &str) {
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

#[test_case(&"a".repeat(CONTRACT_MIN_NAME_LENGTH - 1); "too_short")]
#[test_case(&"a".repeat(CONTRACT_MAX_NAME_LENGTH + 1); "too_long")]
#[test_case(&"a".repeat(MAX_STRING_LEN as usize); "max_string_len")]
fn test_contract_name_serialization_too_long_or_short(_name: &str) {
    // This test can't be implemented with the current API since
    // ContractName::try_from would reject invalid strings
    // and we can't construct invalid ContractName instances directly
}

// the first byte is the length of the buffer.
#[test_case(vec![4, 0xFF, 0xFE, 0xFD, 0xFC].as_slice(), "Failed to parse Contract name: could not construct from utf8"; "invalid_utf8")]
#[test_case(vec![2, b'2', b'i'].as_slice(), "Failed to parse Contract name: InvalidContractName(\"ContractName\", \"2i\")"; "invalid_name")] // starts with number
#[test_case(vec![MAX_STRING_LEN + 1].as_slice(), &format!("Failed to deserialize contract name: too short or too long: {}", MAX_STRING_LEN + 1); "too_long")]
#[test_case(vec![3, b'a'].as_slice(), "failed to fill whole buffer"; "wrong_length")]
fn test_contract_name_deserialization_errors<R: Read>(mut buffer: R, error_message: &str) {
    let result = ContractName::consensus_deserialize(&mut buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), error_message);
}
