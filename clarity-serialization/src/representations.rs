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

use std::borrow::Borrow;
use std::fmt;
use std::io::{Read, Write};
use std::ops::Deref;

use lazy_static::lazy_static;
use regex::Regex;
use stacks_common::codec::{Error as codec_error, StacksMessageCodec, read_next, write_next};

use crate::errors::CodecError;

pub const CONTRACT_MIN_NAME_LENGTH: usize = 1;
pub const CONTRACT_MAX_NAME_LENGTH: usize = 40;
pub const MAX_STRING_LEN: u8 = 128;

lazy_static! {
    pub static ref STANDARD_PRINCIPAL_REGEX_STRING: String =
        "[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{28,41}".into();
    pub static ref CONTRACT_NAME_REGEX_STRING: String = format!(
        r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
        CONTRACT_MIN_NAME_LENGTH - 1,
        // NOTE: this is deliberate.  Earlier versions of the node will accept contract principals whose names are up to
        // 128 bytes.  This behavior must be preserved for backwards-compatibility.
        MAX_STRING_LEN - 1
    );
    pub static ref CONTRACT_PRINCIPAL_REGEX_STRING: String = format!(
        r#"{}(\.){}"#,
        *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING
    );
    pub static ref PRINCIPAL_DATA_REGEX_STRING: String = format!(
        "({})|({})",
        *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_PRINCIPAL_REGEX_STRING
    );
    pub static ref CLARITY_NAME_REGEX_STRING: String =
        "^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$".into();
    pub static ref CLARITY_NAME_REGEX: Regex =
    {
        Regex::new(CLARITY_NAME_REGEX_STRING.as_str()).unwrap()
    };
    pub static ref CONTRACT_NAME_REGEX: Regex =
    {
        Regex::new(format!("^{}$|^__transient$", CONTRACT_NAME_REGEX_STRING.as_str()).as_str())
            .unwrap()
    };
}

guarded_string!(
    ClarityName,
    "ClarityName",
    CLARITY_NAME_REGEX,
    MAX_STRING_LEN,
    CodecError,
    CodecError::InvalidClarityName
);

guarded_string!(
    ContractName,
    "ContractName",
    CONTRACT_NAME_REGEX,
    MAX_STRING_LEN,
    CodecError,
    CodecError::InvalidContractName
);

impl StacksMessageCodec for ClarityName {
    #[allow(clippy::needless_as_bytes)] // as_bytes isn't necessary, but verbosity is preferable in the codec impls
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        // ClarityName can't be longer than vm::representations::MAX_STRING_LEN, which itself is
        // a u8, so we should be good here.
        if self.as_bytes().len() > MAX_STRING_LEN as usize {
            return Err(codec_error::SerializeError(
                "Failed to serialize clarity name: too long".to_string(),
            ));
        }
        write_next(fd, &(self.as_bytes().len() as u8))?;
        fd.write_all(self.as_bytes())
            .map_err(codec_error::WriteError)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ClarityName, codec_error> {
        let len_byte: u8 = read_next(fd)?;
        if len_byte > MAX_STRING_LEN {
            return Err(codec_error::DeserializeError(
                "Failed to deserialize clarity name: too long".to_string(),
            ));
        }
        let mut bytes = vec![0u8; len_byte as usize];
        fd.read_exact(&mut bytes).map_err(codec_error::ReadError)?;

        // must encode a valid string
        let s = String::from_utf8(bytes).map_err(|_e| {
            codec_error::DeserializeError(
                "Failed to parse Clarity name: could not contruct from utf8".to_string(),
            )
        })?;

        // must decode to a clarity name
        let name = ClarityName::try_from(s).map_err(|e| {
            codec_error::DeserializeError(format!("Failed to parse Clarity name: {e:?}"))
        })?;
        Ok(name)
    }
}

impl StacksMessageCodec for ContractName {
    #[allow(clippy::needless_as_bytes)] // as_bytes isn't necessary, but verbosity is preferable in the codec impls
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        if self.as_bytes().len() < CONTRACT_MIN_NAME_LENGTH
            || self.as_bytes().len() > CONTRACT_MAX_NAME_LENGTH
        {
            return Err(codec_error::SerializeError(format!(
                "Failed to serialize contract name: too short or too long: {}",
                self.as_bytes().len()
            )));
        }
        write_next(fd, &(self.as_bytes().len() as u8))?;
        fd.write_all(self.as_bytes())
            .map_err(codec_error::WriteError)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ContractName, codec_error> {
        let len_byte: u8 = read_next(fd)?;
        if (len_byte as usize) < CONTRACT_MIN_NAME_LENGTH
            || (len_byte as usize) > CONTRACT_MAX_NAME_LENGTH
        {
            return Err(codec_error::DeserializeError(format!(
                "Failed to deserialize contract name: too short or too long: {len_byte}"
            )));
        }
        let mut bytes = vec![0u8; len_byte as usize];
        fd.read_exact(&mut bytes).map_err(codec_error::ReadError)?;

        // must encode a valid string
        let s = String::from_utf8(bytes).map_err(|_e| {
            codec_error::DeserializeError(
                "Failed to parse Contract name: could not construct from utf8".to_string(),
            )
        })?;

        let name = ContractName::try_from(s).map_err(|e| {
            codec_error::DeserializeError(format!("Failed to parse Contract name: {e:?}"))
        })?;
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

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
        let name = ClarityName("a".repeat(MAX_STRING_LEN as usize + 1));
        let mut buffer = Vec::new();
        let result = name.consensus_serialize(&mut buffer);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to serialize clarity name: too long"
        );
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
    fn test_contract_name_serialization_too_long_or_short(name: &str) {
        let name = ContractName(name.to_string());
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
    #[test_case(vec![4, 0xFF, 0xFE, 0xFD, 0xFC].as_slice(), "Failed to parse Contract name: could not construct from utf8"; "invalid_utf8")]
    #[test_case(vec![2, b'2', b'i'].as_slice(), "Failed to parse Contract name: InvalidContractName(\"ContractName\", \"2i\")"; "invalid_name")] // starts with number
    #[test_case(vec![MAX_STRING_LEN + 1].as_slice(), &format!("Failed to deserialize contract name: too short or too long: {}", MAX_STRING_LEN + 1); "too_long")]
    #[test_case(vec![3, b'a'].as_slice(), "failed to fill whole buffer"; "wrong_length")]
    fn test_contract_name_deserialization_errors<R: Read>(mut buffer: R, error_message: &str) {
        let result = ContractName::consensus_deserialize(&mut buffer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), error_message);
    }
}
