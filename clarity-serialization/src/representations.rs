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
