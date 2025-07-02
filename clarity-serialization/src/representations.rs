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

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use lazy_static::lazy_static;
// use regex::Regex;
// use stacks_common::codec::{read_next, write_next, Error as codec_error, StacksMessageCodec};

use crate::types::StandardPrincipalData;

pub const CONTRACT_MIN_NAME_LENGTH: usize = 1;
pub const CONTRACT_MAX_NAME_LENGTH: usize = 40;
pub const MAX_STRING_LEN: u8 = 128;

lazy_static! {
    pub static ref STANDARD_PRINCIPAL_REGEX_STRING: String =
        "[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{28,41}".into();
    pub static ref CONTRACT_NAME_REGEX_STRING: String = format!(
        r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
        CONTRACT_MIN_NAME_LENGTH - 1,
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
}

/// A Clarity name - used for variables, functions, etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ClarityName(String);

/// A contract name
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContractName(ClarityName);

/// A qualified contract identifier (address + contract name)
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QualifiedContractIdentifier {
    pub issuer: StandardPrincipalData,
    pub name: ContractName,
}

impl fmt::Display for ClarityName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ContractName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for QualifiedContractIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.issuer, self.name)
    }
}

impl fmt::Display for StandardPrincipalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        stacks_common::address::c32::c32_address(self.0, &self.1)
            .map_err(|_| fmt::Error)
            .and_then(|address_str| write!(f, "{}", address_str))
    }
}

impl Deref for ClarityName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for ClarityName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Deref for ContractName {
    type Target = ClarityName;
    fn deref(&self) -> &ClarityName {
        &self.0
    }
}

impl TryFrom<String> for ClarityName {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 0 || value.len() > MAX_STRING_LEN as usize {
            return Err("Invalid clarity name length".into());
        }
        Ok(ClarityName(value))
    }
}

impl TryFrom<String> for ContractName {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() < CONTRACT_MIN_NAME_LENGTH || value.len() > CONTRACT_MAX_NAME_LENGTH {
            return Err("Invalid contract name length".into());
        }
        
        let clarity_name = ClarityName::try_from(value)?;
        Ok(ContractName(clarity_name))
    }
}

impl QualifiedContractIdentifier {
    pub fn new(issuer: StandardPrincipalData, name: ContractName) -> Self {
        Self { issuer, name }
    }
    
    pub fn local(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::new(
            StandardPrincipalData::transient(),
            ContractName::try_from(name.to_string())?,
        ))
    }
}