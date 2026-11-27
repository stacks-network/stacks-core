// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Names (ABI 2.1).
//!
//! | Kind                             | Grammar                                                                                      | Length      |
//! | -------------------------------- | -------------------------------------------------------------------------------------------- | ----------- |
//! | Function, token, and event names | ASCII letters, digits, and `- _ ! ? + < > = / * ^`, not starting like a number, `[+-]?u?[0-9]` | 1–128 bytes |
//! | Contract names                   | an ASCII letter, then letters, digits, `-`, `_`                                              | 1–40 bytes  |
//!
//! Every source language shares these rules, and the one contract-name limit
//! applies everywhere: in deploys, in principals, and on the wire.

use std::fmt;

use clarity_types::ContractName;

/// Longest function, token, or event name, in bytes.
pub const NAME_MAX_LEN: usize = 128;
/// Longest contract name, in bytes.
pub const CONTRACT_NAME_MAX_LEN: usize = 40;

/// Why a byte string is not a valid name.
///
/// The rules are checked in the order of the variants, so every invalid input
/// has exactly one reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameError {
    /// The name has no bytes.
    Empty,
    /// The name is longer than its kind allows.
    TooLong,
    /// A byte is outside the character set of the name's kind.
    BadByte,
    /// The name starts in a way no name may: like a number (`[+-]?u?[0-9]`),
    /// or for a contract name with anything but a letter.
    BadStart,
}

impl NameError {
    /// Every reason, in the order the rules are checked.
    pub const ALL: [NameError; 4] = [
        NameError::Empty,
        NameError::TooLong,
        NameError::BadByte,
        NameError::BadStart,
    ];

    /// A stable identifier for the reason, used by the vectors.
    pub const fn as_str(self) -> &'static str {
        match self {
            NameError::Empty => "empty",
            NameError::TooLong => "too-long",
            NameError::BadByte => "bad-byte",
            NameError::BadStart => "bad-start",
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for NameError {}

const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_' | b'!' | b'?' | b'+' | b'<' | b'>' | b'=' | b'/' | b'*' | b'^'
        )
}

const fn is_contract_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

fn check(
    bytes: &[u8],
    max_len: usize,
    is_valid_byte: fn(u8) -> bool,
    is_valid_start: fn(&[u8]) -> bool,
) -> Result<(), NameError> {
    if bytes.is_empty() {
        return Err(NameError::Empty);
    }
    if bytes.len() > max_len {
        return Err(NameError::TooLong);
    }
    if !bytes.iter().all(|b| is_valid_byte(*b)) {
        return Err(NameError::BadByte);
    }
    if !is_valid_start(bytes) {
        return Err(NameError::BadStart);
    }
    Ok(())
}

/// Whether `bytes` starts like a number, `[+-]?u?[0-9]`: `u1`, `-7`, `+u1`.
fn starts_like_number(bytes: &[u8]) -> bool {
    let rest = bytes
        .strip_prefix(b"-")
        .or_else(|| bytes.strip_prefix(b"+"))
        .unwrap_or(bytes);
    let rest = rest.strip_prefix(b"u").unwrap_or(rest);
    rest.first().is_some_and(u8::is_ascii_digit)
}

/// Checks that `bytes` is a valid function, token, or event name.
pub fn check_name(bytes: &[u8]) -> Result<(), NameError> {
    check(bytes, NAME_MAX_LEN, is_name_byte, |b| {
        !starts_like_number(b)
    })
}

/// Checks that `bytes` is a valid contract name.
pub fn check_contract_name(bytes: &[u8]) -> Result<(), NameError> {
    check(bytes, CONTRACT_NAME_MAX_LEN, is_contract_name_byte, |b| {
        b.first().is_some_and(u8::is_ascii_alphabetic)
    })
}

/// A valid function, token, or event name.
///
/// Names order by their bytes, which is the order the ABI sorts them in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    /// The name's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The name as text; a valid name is ASCII.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&[u8]> for Name {
    type Error = NameError;

    fn try_from(bytes: &[u8]) -> Result<Self, NameError> {
        check_name(bytes)?;
        // Every byte of a valid name is ASCII.
        Ok(Name(bytes.iter().map(|b| char::from(*b)).collect()))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parses a contract name, accepting exactly the names of ABI 2.1.
///
/// [`ContractName`] itself also admits the longer names that legacy values
/// may carry, so a `ContractName` obtained elsewhere is not necessarily valid
/// under the ABI; [`check_contract_name`] tells.
pub fn parse_contract_name(bytes: &[u8]) -> Result<ContractName, NameError> {
    check_contract_name(bytes)?;
    let name: String = bytes.iter().map(|b| char::from(*b)).collect();
    // Every name the ABI accepts is one legacy accepts.
    ContractName::try_from(name).map_err(|_| NameError::BadByte)
}
