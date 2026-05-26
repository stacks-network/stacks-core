// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::fmt;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

use clarity_types::representations::{ClarityName, ContractName};
use serde::{Deserialize, Serialize};
use stacks_common::codec::{
    read_next, write_next, Error as codec_error, StacksMessageCodec, MAX_MESSAGE_LEN,
};
use stacks_common::util::retry::BoundReader;

/// printable-ASCII-only string, but encodable.
/// Note that it cannot be longer than ARRAY_MAX_LEN (4.1 billion bytes)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksString(Vec<u8>);

impl fmt::Display for StacksString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(String::from_utf8_lossy(self).into_owned().as_str())
    }
}

impl fmt::Debug for StacksString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(String::from_utf8_lossy(self).into_owned().as_str())
    }
}

impl Deref for StacksString {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl DerefMut for StacksString {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl StacksMessageCodec for StacksString {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.0)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksString, codec_error> {
        let bytes: Vec<u8> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        // must encode a valid string
        let s = String::from_utf8(bytes.clone()).map_err(|_e| {
            codec_error::DeserializeError(
                "Invalid Stacks string: could not build from utf8".to_string(),
            )
        })?;

        if !StacksString::is_valid_string(&s) {
            // non-printable ASCII or not ASCII
            return Err(codec_error::DeserializeError(
                "Invalid Stacks string: non-printable or non-ASCII string".to_string(),
            ));
        }

        Ok(StacksString(bytes))
    }
}

impl From<ClarityName> for StacksString {
    fn from(clarity_name: ClarityName) -> StacksString {
        // .unwrap() is safe since StacksString is less strict
        StacksString::from_str(&clarity_name).unwrap()
    }
}

impl From<ContractName> for StacksString {
    fn from(contract_name: ContractName) -> StacksString {
        // .unwrap() is safe since StacksString is less strict
        StacksString::from_str(&contract_name).unwrap()
    }
}

impl StacksString {
    /// Is the given string a valid Clarity string?
    pub fn is_valid_string(s: &String) -> bool {
        s.is_ascii() && StacksString::is_printable(s)
    }

    pub fn is_printable(s: &String) -> bool {
        if !s.is_ascii() {
            return false;
        }
        // all characters must be ASCII "printable" characters, excluding "delete".
        // This is 0x20 through 0x7e, inclusive, as well as '\t' and '\n'
        // TODO: DRY up with vm::representations
        for c in s.as_bytes().iter() {
            if (*c < 0x20 && *c != b'\t' && *c != b'\n') || *c > 0x7e {
                return false;
            }
        }
        true
    }

    pub fn is_clarity_variable(&self) -> bool {
        ClarityName::try_from(self.to_string()).is_ok()
    }

    pub fn from_string(s: &String) -> Option<StacksString> {
        if !StacksString::is_valid_string(s) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    // Inherent `from_str` is intentional: `StacksString::from_str` returns an
    // `Option`, while `std::str::FromStr::from_str` would have to return a
    // `Result`. Renaming would churn many call sites.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<StacksString> {
        if !StacksString::is_valid_string(&String::from(s)) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    // The inherent `to_string` is kept (rather than relying on `Display`'s
    // blanket impl) because it skips the formatter machinery — the bytes are
    // already valid ASCII.
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        // guaranteed to always succeed because the string is ASCII
        String::from_utf8(self.0.clone()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::codec::testing::check_codec_and_corruption;

    use super::*;

    #[test]
    fn stacks_strings_codec() {
        let s = "hello-world";
        let stacks_str = StacksString::from_str(s).unwrap();
        let clarity_str = ClarityName::try_from(s).unwrap();
        let contract_str = ContractName::try_from(s).unwrap();

        assert_eq!(&stacks_str[..], s.as_bytes());
        assert_eq!(stacks_str.to_string(), s);

        // stacks strings have a 4-byte BE length prefix
        let mut bytes = vec![0x00, 0x00, 0x00, s.len() as u8];
        bytes.extend_from_slice(s.as_bytes());
        check_codec_and_corruption::<StacksString>(&stacks_str, &bytes);

        // clarity names and contract names have a 1-byte length prefix
        let mut clarity_bytes = vec![s.len() as u8];
        clarity_bytes.extend_from_slice(clarity_str.as_bytes());
        check_codec_and_corruption::<ClarityName>(&clarity_str, &clarity_bytes);

        let mut contract_bytes = vec![s.len() as u8];
        contract_bytes.extend_from_slice(contract_str.as_bytes());
        check_codec_and_corruption::<ContractName>(&contract_str, &contract_bytes);
    }

    #[test]
    fn stacks_string_rejects_non_printable() {
        assert!(StacksString::from_str("hello\rworld").is_none());
        assert!(StacksString::from_str("hello\x01world").is_none());
        assert!(StacksString::from_str("hello\x7fworld").is_none());
        assert!(StacksString::from_str("héllo").is_none()); // non-ASCII
    }

    #[test]
    fn stacks_string_accepts_tab_and_newline() {
        // \t and \n are explicit exceptions in `is_printable`.
        assert!(StacksString::from_str("line1\nline2").is_some());
        assert!(StacksString::from_str("col1\tcol2").is_some());
    }

    #[test]
    fn stacks_string_printable_ascii_boundaries() {
        // 0x20 (space) is the lowest printable; 0x7e (~) is the highest.
        assert!(StacksString::from_str(" ").is_some());
        assert!(StacksString::from_str("~").is_some());
        // 0x1f and 0x7f are out of range and aren't the special-cased \t/\n.
        let s = String::from_utf8(vec![0x1f]).unwrap();
        assert!(StacksString::from_string(&s).is_none());
        let s = String::from_utf8(vec![0x7f]).unwrap();
        assert!(StacksString::from_string(&s).is_none());
    }

    /// A `StacksString` containing valid bytes but non-printable content must
    /// be rejected on deserialize even though it parses as valid UTF-8.
    #[test]
    fn stacks_string_deserialize_rejects_non_printable_bytes() {
        // 4-byte BE length prefix (0x00000005) followed by 5 bytes whose
        // second byte (0x01) is non-printable.
        let mut bytes = vec![0x00, 0x00, 0x00, 0x05];
        bytes.extend_from_slice(b"a\x01bcd");
        let err = StacksString::consensus_deserialize(&mut &bytes[..]).unwrap_err();
        assert!(
            matches!(err, codec_error::DeserializeError(_)),
            "expected DeserializeError, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("non-printable") || msg.contains("non-ASCII"),
            "unexpected error: {msg}"
        );
    }

    /// `is_clarity_variable` returns true for strings that satisfy the
    /// `ClarityName` rules.
    #[test]
    fn stacks_string_is_clarity_variable_accepts_valid_names() {
        let s = StacksString::from_str("foo-bar").unwrap();
        assert!(s.is_clarity_variable());
        // Operator names like `+`, `-`, `<=` are valid ClarityName variables
        // via the regex's operator-specific alternation arms, not the
        // identifier arm exercised above.
        let s = StacksString::from_str("<=").unwrap();
        assert!(s.is_clarity_variable());
    }

    /// `is_clarity_variable` returns false for strings that pass `StacksString`
    /// printable-ASCII validation but fail the stricter `ClarityName` rules.
    #[test]
    fn stacks_string_is_clarity_variable_rejects_invalid_names() {
        // ClarityName forbids '.' and spaces.
        let s = StacksString::from_str("not a name").unwrap();
        assert!(!s.is_clarity_variable());
        let s = StacksString::from_str("a.b").unwrap();
        assert!(!s.is_clarity_variable());
        // StacksString accepts the empty string (no chars to reject), but
        // ClarityName requires at least one character.
        let s = StacksString::from_str("").unwrap();
        assert!(!s.is_clarity_variable());
        // ClarityName must start with a letter.
        let s = StacksString::from_str("1abc").unwrap();
        assert!(!s.is_clarity_variable());
    }

    #[test]
    fn stacks_string_from_clarity_name_conversion() {
        let clarity_name = ClarityName::try_from("hello-world").unwrap();
        let stacks_str: StacksString = clarity_name.clone().into();
        assert_eq!(stacks_str.to_string(), "hello-world");
    }

    #[test]
    fn stacks_string_from_contract_name_conversion() {
        let contract_name = ContractName::try_from("hello-world").unwrap();
        let stacks_str: StacksString = contract_name.into();
        assert_eq!(stacks_str.to_string(), "hello-world");
    }
}
