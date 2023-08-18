// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::convert::TryFrom;
use std::error;
use std::fmt;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};

use serde::Deserialize;

use toml;

use clarity::vm::types::QualifiedContractIdentifier;

#[derive(Debug)]
pub enum ConfigError {
    NoSuchConfigFile(String),
    ParseError(String),
    BadField(String, String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::NoSuchConfigFile(ref s) => fmt::Display::fmt(s, f),
            ConfigError::ParseError(ref s) => fmt::Display::fmt(s, f),
            ConfigError::BadField(ref f1, ref f2) => {
                write!(f, "identifier={}, value={}", f1, f2)
            }
        }
    }
}

impl error::Error for ConfigError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            ConfigError::NoSuchConfigFile(..) => None,
            ConfigError::ParseError(..) => None,
            ConfigError::BadField(..) => None,
        }
    }
}

pub struct ConfigFile {
    /// endpoint to the stacks node
    pub node_host: SocketAddr,
    /// smart contract that controls the target stackerdb
    pub stackerdb_contract_id: QualifiedContractIdentifier,
}

/// Internal struct for loading up the config file
#[derive(Deserialize)]
struct RawConfigFile {
    /// endpoint to stacks node
    pub node_host: String,
    /// contract identifier
    pub stackerdb_contract_id: String,
}

impl RawConfigFile {
    /// load the config from a string
    pub fn load_from_str(data: &str) -> Result<RawConfigFile, ConfigError> {
        let config: RawConfigFile =
            toml::from_str(data).map_err(|e| ConfigError::ParseError(format!("{:?}", &e)))?;
        Ok(config)
    }

    /// load the config from a file
    pub fn load_from_file(path: &str) -> Result<RawConfigFile, ConfigError> {
        let data = fs::read_to_string(path)
            .map_err(|_| ConfigError::NoSuchConfigFile(path.to_string()))?;
        Self::load_from_str(&data)
    }
}

impl TryFrom<RawConfigFile> for ConfigFile {
    type Error = ConfigError;

    /// Attempt to decode the raw config file's primitive types into our types.
    /// NOTE: network access is required for this to work
    fn try_from(raw_data: RawConfigFile) -> Result<ConfigFile, Self::Error> {
        let node_host = raw_data
            .node_host
            .clone()
            .to_socket_addrs()
            .map_err(|_| {
                ConfigError::BadField("node_host".to_string(), raw_data.node_host.clone())
            })?
            .next()
            .ok_or(ConfigError::BadField(
                "node_host".to_string(),
                raw_data.node_host.clone(),
            ))?;

        let stackerdb_contract_id =
            QualifiedContractIdentifier::parse(&raw_data.stackerdb_contract_id).map_err(|_| {
                ConfigError::BadField(
                    "stackerdb_contract_id".to_string(),
                    raw_data.stackerdb_contract_id,
                )
            })?;

        Ok(ConfigFile {
            node_host,
            stackerdb_contract_id,
        })
    }
}

impl ConfigFile {
    /// load the config from a string and parse it
    pub fn load_from_str(data: &str) -> Result<ConfigFile, ConfigError> {
        RawConfigFile::load_from_str(data)?.try_into()
    }

    /// load the config from a file and parse it
    pub fn load_from_file(path: &str) -> Result<ConfigFile, ConfigError> {
        let data = fs::read_to_string(path)
            .map_err(|_| ConfigError::NoSuchConfigFile(path.to_string()))?;
        Self::load_from_str(&data)
    }
}
