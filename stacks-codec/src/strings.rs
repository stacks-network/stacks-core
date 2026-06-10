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

    pub fn from_str(s: &str) -> Option<StacksString> {
        if !StacksString::is_valid_string(&String::from(s)) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    pub fn to_string(&self) -> String {
        // guaranteed to always succeed because the string is ASCII
        String::from_utf8(self.0.clone()).unwrap()
    }
}
