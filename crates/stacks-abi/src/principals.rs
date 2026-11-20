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

//! Principals (ABI 2.2).
//!
//! | Prefix | Principal | Payload                                    |
//! | ------ | --------- | ------------------------------------------ |
//! | `0x05` | standard  | version (1 byte, < 32), hash160 (20 bytes) |
//! | `0x06` | contract  | version, hash160, u8 name length, name     |
//!
//! This is the SIP-005 encoding of a principal. Decoding accepts exactly this
//! form, so a principal has one valid byte string: the prefix is `0x05` or
//! `0x06`, the version is below 32, a contract name is valid (ABI 2.1), and
//! no bytes remain.
//!
//! # Relation to the consensus codec
//!
//! `clarity-types` already decodes principals, as part of the consensus
//! serialization of Clarity values. This module has its own decoder rather
//! than calling that one or adding an epoch gate to it, because the two
//! answer to different rules:
//!
//! - The consensus decoder accepts more. A contract name may be up to 128
//!   bytes (40 only where the epoch 4.1 limit applies) and may be the
//!   internal name `__transient`. It reads from a stream, so bytes after the
//!   principal are the caller's concern, and it reports every failure as the
//!   same error.
//! - The consensus decoder reads existing chain data. What it accepts can
//!   change only behind an epoch gate, and it must keep reading what earlier
//!   epochs stored. What this module accepts is fixed by the ABI version and
//!   must not move when an epoch changes the consensus decoder.
//! - Compilers and tools decode principals with this crate, and have no epoch
//!   to pass.
//!
//! The two share their types and produce the same bytes, and the tests pin
//! how they relate: this decoder accepts an input exactly when the consensus
//! decoder accepts it and consumes all of it, and the contract name, if any,
//! is at most [`CONTRACT_NAME_MAX_LEN`] bytes and is not `__transient`.

use std::fmt;

use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};

use crate::names::{CONTRACT_NAME_MAX_LEN, NameError, check_contract_name, parse_contract_name};

/// Prefix byte of a standard principal.
pub const PREFIX_STANDARD: u8 = 0x05;
/// Prefix byte of a contract principal.
pub const PREFIX_CONTRACT: u8 = 0x06;
/// Length of an encoded standard principal: prefix, version, hash160.
pub const STANDARD_PRINCIPAL_LEN: usize = 22;
/// Length of the longest encoded principal: a contract principal with a name
/// of [`CONTRACT_NAME_MAX_LEN`] bytes.
pub const PRINCIPAL_MAX_LEN: usize = STANDARD_PRINCIPAL_LEN + 1 + CONTRACT_NAME_MAX_LEN;

/// Why a byte string is not the encoding of a principal.
///
/// Decoding reads the bytes front to back and stops at the first field that
/// is missing or invalid, so every invalid input has exactly one reason. A
/// name length over the limit is rejected before the name's bytes are read,
/// and bytes that follow the encoding are judged last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrincipalError {
    /// The bytes end before the encoding does.
    Truncated,
    /// The first byte is neither `0x05` nor `0x06`.
    BadPrefix,
    /// The version byte is 32 or more.
    BadVersion,
    /// The contract name is not valid.
    BadName(NameError),
    /// Bytes follow the encoding.
    TrailingBytes,
}

impl PrincipalError {
    /// Every reason.
    pub const ALL: [PrincipalError; 8] = [
        PrincipalError::Truncated,
        PrincipalError::BadPrefix,
        PrincipalError::BadVersion,
        PrincipalError::BadName(NameError::Empty),
        PrincipalError::BadName(NameError::TooLong),
        PrincipalError::BadName(NameError::BadByte),
        PrincipalError::BadName(NameError::BadStart),
        PrincipalError::TrailingBytes,
    ];

    /// A stable identifier for the reason, used by the vectors.
    pub const fn as_str(self) -> &'static str {
        match self {
            PrincipalError::Truncated => "truncated",
            PrincipalError::BadPrefix => "bad-prefix",
            PrincipalError::BadVersion => "bad-version",
            PrincipalError::BadName(NameError::Empty) => "name-empty",
            PrincipalError::BadName(NameError::TooLong) => "name-too-long",
            PrincipalError::BadName(NameError::BadByte) => "name-bad-byte",
            PrincipalError::BadName(NameError::BadStart) => "name-bad-start",
            PrincipalError::TrailingBytes => "trailing-bytes",
        }
    }
}

impl fmt::Display for PrincipalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for PrincipalError {}

/// Decodes a principal, accepting exactly its canonical encoding.
pub fn decode_principal(bytes: &[u8]) -> Result<PrincipalData, PrincipalError> {
    let (prefix, rest) = bytes.split_first().ok_or(PrincipalError::Truncated)?;
    if !matches!(*prefix, PREFIX_STANDARD | PREFIX_CONTRACT) {
        return Err(PrincipalError::BadPrefix);
    }
    let (version, rest) = rest.split_first().ok_or(PrincipalError::Truncated)?;
    if *version >= 32 {
        return Err(PrincipalError::BadVersion);
    }
    let (hash, rest) = rest
        .split_first_chunk::<20>()
        .ok_or(PrincipalError::Truncated)?;
    let issuer =
        StandardPrincipalData::new(*version, *hash).map_err(|_| PrincipalError::BadVersion)?;
    if *prefix == PREFIX_STANDARD {
        if !rest.is_empty() {
            return Err(PrincipalError::TrailingBytes);
        }
        return Ok(PrincipalData::Standard(issuer));
    }

    let (name_len, rest) = rest.split_first().ok_or(PrincipalError::Truncated)?;
    let name_len = usize::from(*name_len);
    // The length byte alone decides this, whatever bytes follow it.
    if name_len > CONTRACT_NAME_MAX_LEN {
        return Err(PrincipalError::BadName(NameError::TooLong));
    }
    let (name, rest) = rest
        .split_at_checked(name_len)
        .ok_or(PrincipalError::Truncated)?;
    let name = parse_contract_name(name).map_err(PrincipalError::BadName)?;
    if !rest.is_empty() {
        return Err(PrincipalError::TrailingBytes);
    }
    Ok(PrincipalData::Contract(QualifiedContractIdentifier::new(
        issuer, name,
    )))
}

/// Encodes a principal.
///
/// Fails for a principal that has no encoding under the ABI: a contract
/// principal whose name legacy admits but ABI 2.1 does not, such as one
/// longer than [`CONTRACT_NAME_MAX_LEN`] bytes.
pub fn encode_principal(principal: &PrincipalData) -> Result<Vec<u8>, PrincipalError> {
    let (prefix, issuer, name) = match principal {
        PrincipalData::Standard(issuer) => (PREFIX_STANDARD, issuer, None),
        PrincipalData::Contract(id) => (PREFIX_CONTRACT, &id.issuer, Some(id.name.as_bytes())),
    };
    if issuer.version() >= 32 {
        return Err(PrincipalError::BadVersion);
    }
    let mut bytes = Vec::with_capacity(PRINCIPAL_MAX_LEN);
    bytes.push(prefix);
    bytes.push(issuer.version());
    bytes.extend_from_slice(&issuer.1);
    if let Some(name) = name {
        check_contract_name(name).map_err(PrincipalError::BadName)?;
        // A valid contract name is at most 40 bytes.
        bytes.push(name.len() as u8);
        bytes.extend_from_slice(name);
    }
    Ok(bytes)
}
