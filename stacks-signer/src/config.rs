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
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use blockstack_lib::chainstate::stacks::TransactionVersion;
use hashbrown::HashMap;
use serde::Deserialize;
use stacks_common::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks_common::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::types::PrivateKey;
use wsts::curve::scalar::Scalar;

/// List of key_ids for each signer_id
pub type SignerKeyIds = HashMap<u32, Vec<u32>>;

const EVENT_TIMEOUT_MS: u64 = 5000;
//TODO: make this zero once special cased transactions are allowed in the stacks node
const TX_FEE_MS: u64 = 10_000;

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
    /// An unsupported address version
    #[error("Failed to convert private key to address: unsupported address version.")]
    UnsupportedAddressVersion,
}

#[derive(serde::Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
/// The Stacks network to use.
pub enum Network {
    /// The mainnet network
    Mainnet,
    /// The testnet network
    Testnet,
    /// The mocknet network
    Mocknet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Mocknet => write!(f, "mocknet"),
        }
    }
}

impl Network {
    /// Converts a Network enum variant to a corresponding chain id
    pub fn to_chain_id(&self) -> u32 {
        match self {
            Self::Mainnet => CHAIN_ID_MAINNET,
            Self::Testnet | Self::Mocknet => CHAIN_ID_TESTNET,
        }
    }

    /// Convert a Network enum variant to a corresponding address version
    pub fn to_address_version(&self) -> u8 {
        match self {
            Self::Mainnet => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            Self::Testnet | Self::Mocknet => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        }
    }

    /// Convert a Network enum variant to a Transaction Version
    pub fn to_transaction_version(&self) -> TransactionVersion {
        match self {
            Self::Mainnet => TransactionVersion::Mainnet,
            Self::Testnet | Self::Mocknet => TransactionVersion::Testnet,
        }
    }

    /// Check if the network is Mainnet or not
    pub fn is_mainnet(&self) -> bool {
        match self {
            Self::Mainnet => true,
            Self::Testnet | Self::Mocknet => false,
        }
    }
}

/// The parsed configuration for the signer
#[derive(Clone, Debug)]
pub struct Config {
    /// endpoint to the stacks node
    pub node_host: SocketAddr,
    /// endpoint to the event receiver
    pub endpoint: SocketAddr,
    /// The Scalar representation of the private key for signer communication
    pub ecdsa_private_key: Scalar,
    /// The signer's Stacks private key
    pub stacks_private_key: StacksPrivateKey,
    /// The signer's Stacks address
    pub stacks_address: StacksAddress,
    /// The network to use. One of "mainnet" or "testnet".
    pub network: Network,
    /// The time to wait for a response from the stacker-db instance
    pub event_timeout: Duration,
    /// timeout to gather DkgPublicShares messages
    pub dkg_public_timeout: Option<Duration>,
    /// timeout to gather DkgPrivateShares messages
    pub dkg_private_timeout: Option<Duration>,
    /// timeout to gather DkgEnd messages
    pub dkg_end_timeout: Option<Duration>,
    /// timeout to gather nonces
    pub nonce_timeout: Option<Duration>,
    /// timeout to gather signature shares
    pub sign_timeout: Option<Duration>,
    /// the STX tx fee to use in uSTX
    pub tx_fee: u64,
}

/// Internal struct for loading up the config file
#[derive(Deserialize, Debug)]
struct RawConfigFile {
    /// endpoint to stacks node
    pub node_host: String,
    /// endpoint to event receiver
    pub endpoint: String,
    /// The hex representation of the signer's Stacks private key used for communicating
    /// with the Stacks Node, including writing to the Stacker DB instance.
    pub stacks_private_key: String,
    /// The network to use. One of "mainnet" or "testnet".
    pub network: Network,
    /// The time to wait (in millisecs) for a response from the stacker-db instance
    pub event_timeout_ms: Option<u64>,
    /// timeout in (millisecs) to gather DkgPublicShares messages
    pub dkg_public_timeout_ms: Option<u64>,
    /// timeout in (millisecs) to gather DkgPrivateShares messages
    pub dkg_private_timeout_ms: Option<u64>,
    /// timeout in (millisecs) to gather DkgEnd messages
    pub dkg_end_timeout_ms: Option<u64>,
    /// timeout in (millisecs) to gather nonces
    pub nonce_timeout_ms: Option<u64>,
    /// timeout in (millisecs) to gather signature shares
    pub sign_timeout_ms: Option<u64>,
    /// the STX tx fee to use in uSTX
    pub tx_fee_ms: Option<u64>,
}

impl RawConfigFile {
    /// load the config from a string
    pub fn load_from_str(data: &str) -> Result<Self, ConfigError> {
        let config: RawConfigFile =
            toml::from_str(data).map_err(|e| ConfigError::ParseError(format!("{:?}", &e)))?;
        Ok(config)
    }
    /// load the config from a file and parse it
    #[allow(dead_code)]
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

        let endpoint = raw_data
            .endpoint
            .clone()
            .to_socket_addrs()
            .map_err(|_| ConfigError::BadField("endpoint".to_string(), raw_data.endpoint.clone()))?
            .next()
            .ok_or(ConfigError::BadField(
                "endpoint".to_string(),
                raw_data.endpoint.clone(),
            ))?;

        let stacks_private_key =
            StacksPrivateKey::from_hex(&raw_data.stacks_private_key).map_err(|_| {
                ConfigError::BadField(
                    "stacks_private_key".to_string(),
                    raw_data.stacks_private_key.clone(),
                )
            })?;

        let ecdsa_private_key =
            Scalar::try_from(&stacks_private_key.to_bytes()[..32]).map_err(|_| {
                ConfigError::BadField(
                    "stacks_private_key".to_string(),
                    raw_data.stacks_private_key.clone(),
                )
            })?;
        let stacks_public_key = StacksPublicKey::from_private(&stacks_private_key);
        let stacks_address = StacksAddress::from_public_keys(
            raw_data.network.to_address_version(),
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![stacks_public_key],
        )
        .ok_or(ConfigError::UnsupportedAddressVersion)?;
        let event_timeout =
            Duration::from_millis(raw_data.event_timeout_ms.unwrap_or(EVENT_TIMEOUT_MS));
        let dkg_end_timeout = raw_data.dkg_end_timeout_ms.map(Duration::from_millis);
        let dkg_public_timeout = raw_data.dkg_public_timeout_ms.map(Duration::from_millis);
        let dkg_private_timeout = raw_data.dkg_private_timeout_ms.map(Duration::from_millis);
        let nonce_timeout = raw_data.nonce_timeout_ms.map(Duration::from_millis);
        let sign_timeout = raw_data.sign_timeout_ms.map(Duration::from_millis);
        Ok(Self {
            node_host,
            endpoint,
            stacks_private_key,
            ecdsa_private_key,
            stacks_address,
            network: raw_data.network,
            event_timeout,
            dkg_end_timeout,
            dkg_public_timeout,
            dkg_private_timeout,
            nonce_timeout,
            sign_timeout,
            tx_fee: raw_data.tx_fee_ms.unwrap_or(TX_FEE_MS),
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

/// Helper function for building a signer config for each provided signer private key
pub fn build_signer_config_tomls(
    stacks_private_keys: &[StacksPrivateKey],
    node_host: &str,
    timeout: Option<Duration>,
    network: &Network,
) -> Vec<String> {
    let mut signer_config_tomls = vec![];

    let mut port = 30000;
    for stacks_private_key in stacks_private_keys {
        let endpoint = format!("localhost:{}", port);
        port += 1;
        let stacks_private_key = stacks_private_key.to_hex();
        let mut signer_config_toml = format!(
            r#"
stacks_private_key = "{stacks_private_key}"
node_host = "{node_host}"
endpoint = "{endpoint}"
network = "{network}"
"#
        );

        if let Some(timeout) = timeout {
            let event_timeout_ms = timeout.as_millis();
            signer_config_toml = format!(
                r#"
{signer_config_toml}
event_timeout = {event_timeout_ms}   
"#
            )
        }

        signer_config_tomls.push(signer_config_toml);
    }

    signer_config_tomls
}
