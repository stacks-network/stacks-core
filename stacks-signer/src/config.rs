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

use clarity::vm::types::QualifiedContractIdentifier;
use serde::Deserialize;
use stacks_common::types::chainstate::StacksPrivateKey;
use std::{
    convert::TryFrom,
    fs,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

#[derive(thiserror::Error, Debug)]
/// An error occurred parsing the provided configuration
pub enum ConfigError {
    /// Error occurred reading config file
    #[error("{0}")]
    InvalidConfig(String),
    /// An error occurred parsing the TOML data
    #[error("{0}")]
    ParseError(String),
    /// A field was malformed
    #[error("identifier={0}, value={1}")]
    BadField(String, String),
}

/// The parsed configuration for the signer
pub struct Config {
    /// endpoint to the stacks node
    pub node_host: SocketAddr,
    /// smart contract that controls the target stackerdb
    pub stackerdb_contract_id: QualifiedContractIdentifier,
    /// the private key used to sign blocks, chunks, and transactions
    pub private_key: StacksPrivateKey,
}

/// Internal struct for loading up the config file
#[derive(Deserialize, Debug)]
struct RawConfigFile {
    /// endpoint to stacks node
    pub node_host: String,
    /// contract identifier
    pub stackerdb_contract_id: String,
    /// the private key used to sign blocks, chunks, and transactions in hexademical format
    pub private_key: String,
}

impl RawConfigFile {
    /// load the config from a string
    pub fn load_from_str(data: &str) -> Result<Self, ConfigError> {
        let config: RawConfigFile =
            toml::from_str(data).map_err(|e| ConfigError::ParseError(format!("{:?}", &e)))?;
        Ok(config)
    }
    /// load the config from a file and parse it
    pub fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        Self::try_from(&PathBuf::from(path))
    }
}

impl TryFrom<&PathBuf> for RawConfigFile {
    type Error = ConfigError;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        RawConfigFile::load_from_str(&fs::read_to_string(path).map_err(|e| {
            ConfigError::InvalidConfig(format!("failed to read config file: {:?}", &e))
        })?)
    }
}

impl TryFrom<RawConfigFile> for Config {
    type Error = ConfigError;

    /// Attempt to decode the raw config file's primitive types into our types.
    /// NOTE: network access is required for this to work
    fn try_from(raw_data: RawConfigFile) -> Result<Self, Self::Error> {
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

        let private_key = StacksPrivateKey::from_hex(&raw_data.private_key)
            .map_err(|_| ConfigError::BadField("private_key".to_string(), raw_data.private_key))?;

        Ok(Self {
            node_host,
            stackerdb_contract_id,
            private_key,
        })
    }
}

impl TryFrom<&PathBuf> for Config {
    type Error = ConfigError;
    fn try_from(path: &PathBuf) -> Result<Self, ConfigError> {
        let config_file = RawConfigFile::try_from(path)?;
        Self::try_from(config_file)
    }
}

impl Config {
    /// load the config from a string and parse it
    pub fn load_from_str(data: &str) -> Result<Self, ConfigError> {
        RawConfigFile::load_from_str(data)?.try_into()
    }

    /// load the config from a file and parse it
    pub fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        Self::try_from(&PathBuf::from(path))
    }
}
