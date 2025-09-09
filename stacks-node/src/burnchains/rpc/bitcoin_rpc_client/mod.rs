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

//! Bitcoin RPC client module.
//!
//! This module provides a typed interface for interacting with a Bitcoin Core node via RPC.
//! It includes structures representing RPC request parameters and responses,
//! as well as a client implementation ([`BitcoinRpcClient`]) for common node operations
//! such as creating wallets, listing UTXOs, importing descriptors, generating blocks, and sending transactions.
//!
//! Designed for use with Bitcoin Core versions v0.25.0 and newer

use std::time::Duration;

use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::burnchains::Txid;
use stacks::config::Config;
use stacks::types::chainstate::BurnchainHeaderHash;
use stacks::types::Address;
use stacks::util::hash::hex_bytes;
use stacks_common::deps_common::bitcoin::blockdata::script::Script;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::{
    serialize_hex, Error as bitcoin_serialize_error,
};

use crate::burnchains::rpc::rpc_transport::{RpcAuth, RpcError, RpcTransport};

#[cfg(test)]
pub mod test_utils;

#[cfg(test)]
mod tests;

/// Response structure for the `gettransaction` RPC call.
///
/// Contains metadata about a wallet transaction, currently limited to the confirmation count.
///
/// # Notes
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Deserialize)]
pub struct GetTransactionResponse {
    pub confirmations: u32,
}

/// Response returned by the `getdescriptorinfo` RPC call.
///
/// Contains information about a parsed descriptor, including its checksum.
///
/// # Notes
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Deserialize)]
pub struct DescriptorInfoResponse {
    pub checksum: String,
}

/// Represents the `timestamp` parameter accepted by the `importdescriptors` RPC method.
///
/// This indicates when the imported descriptor starts being relevant for address tracking.
/// It affects wallet rescanning behavior.
#[derive(Debug, Clone)]
pub enum Timestamp {
    /// Tells the wallet to start tracking from the current blockchain time
    Now,
    /// A Unix timestamp (in seconds) specifying when the wallet should begin scanning.
    Time(u64),
}

/// Serializes [`Timestamp`] to either the string `"now"` or a numeric timestamp,
/// matching the format expected by Bitcoin Core.
impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match *self {
            Timestamp::Now => serializer.serialize_str("now"),
            Timestamp::Time(timestamp) => serializer.serialize_u64(timestamp),
        }
    }
}

/// Represents a single descriptor import request for use with the `importdescriptors` RPC method.
///
/// This struct defines a descriptor to import into the loaded wallet,
/// along with metadata that influences how the wallet handles it (e.g., scan time, internal/external).
///
/// # Notes
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Serialize)]
pub struct ImportDescriptorsRequest {
    /// A descriptor string (e.g., `addr(...)#checksum`) with a valid checksum suffix.
    #[serde(rename = "desc")]
    pub descriptor: String,
    /// Specifies when the wallet should begin tracking addresses from this descriptor.
    pub timestamp: Timestamp,
    /// Optional flag indicating whether the descriptor is used for change addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
}

/// Response returned by the `importdescriptors` RPC method for each imported descriptor.
///
/// # Notes
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportDescriptorsResponse {
    /// whether the descriptor was imported successfully
    pub success: bool,
    /// Optional list of warnings encountered during the import process
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Optional detailed error information if the import failed for this descriptor
    pub error: Option<ImportDescriptorsErrorMessage>,
}

/// Represents a single UTXO (unspent transaction output) returned by the `listunspent` RPC method.
///
/// # Notes
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Deserialize)]
pub struct ListUnspentResponse {
    /// The transaction ID of the UTXO.
    #[serde(deserialize_with = "deserialize_string_to_txid")]
    pub txid: Txid,
    /// The index of the output in the transaction.
    pub vout: u32,
    /// The Bitcoin destination address
    #[serde(deserialize_with = "deserialize_string_to_bitcoin_address")]
    pub address: BitcoinAddress,
    /// The script associated with the output.
    #[serde(
        rename = "scriptPubKey",
        deserialize_with = "deserialize_string_to_script"
    )]
    pub script_pub_key: Script,
    /// The amount in BTC, deserialized as a string to preserve full precision.
    #[serde(deserialize_with = "deserialize_btc_string_to_sat")]
    pub amount: u64,
    /// The number of confirmations for the transaction.
    pub confirmations: u32,
}

/// Deserializes a JSON string (hex-encoded in big-endian order) into [`Txid`].
fn deserialize_string_to_txid<'de, D>(deserializer: D) -> Result<Txid, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str: String = Deserialize::deserialize(deserializer)?;
    let txid = Txid::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
    Ok(txid)
}

/// Deserializes a JSON string into [`BitcoinAddress`]
fn deserialize_string_to_bitcoin_address<'de, D>(
    deserializer: D,
) -> Result<BitcoinAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let addr_str: String = Deserialize::deserialize(deserializer)?;
    BitcoinAddress::from_string(&addr_str).ok_or(serde::de::Error::custom(
        "BitcoinAddress failed to create from string",
    ))
}

/// Deserializes a JSON string into [`Script`]
fn deserialize_string_to_script<'de, D>(deserializer: D) -> Result<Script, D::Error>
where
    D: Deserializer<'de>,
{
    let string: String = Deserialize::deserialize(deserializer)?;
    let bytes = hex_bytes(&string)
        .map_err(|e| serde::de::Error::custom(format!("invalid hex string for script: {e}")))?;
    Ok(bytes.into())
}

/// Deserializes a raw JSON value containing a BTC amount string into satoshis (`u64`).
///
/// First captures the value as unprocessed JSON to preserve exact formatting (e.g., float precision),
/// then convert the BTC string to its integer value in satoshis using [`convert_btc_string_to_sat`].
fn deserialize_btc_string_to_sat<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Box<RawValue> = Deserialize::deserialize(deserializer)?;
    let raw_str = raw.get();
    let sat_amount = convert_btc_string_to_sat(raw_str).map_err(serde::de::Error::custom)?;
    Ok(sat_amount)
}

/// Converts a BTC amount string (e.g. "1.12345678") into satoshis (u64).
///
/// # Arguments
/// * `amount` - A string slice containing the BTC amount in decimal notation.
///              Expected format: `<integer>.<fractional>` with up to 8 decimal places.
///              Examples: "1.00000000", "0.00012345", "0.5", "1".
///
/// # Returns
/// On success return the equivalent amount in satoshis (as u64).
fn convert_btc_string_to_sat(amount: &str) -> Result<u64, String> {
    const BTC_TO_SAT: u64 = 100_000_000;
    const MAX_DECIMAL_COUNT: usize = 8;
    let comps: Vec<&str> = amount.split('.').collect();
    match comps[..] {
        [lhs, rhs] => {
            let rhs_len = rhs.len();
            if rhs_len > MAX_DECIMAL_COUNT {
                return Err(format!("Unexpected amount of decimals ({rhs_len}) in '{amount}'"));
            }

            match (lhs.parse::<u64>(), rhs.parse::<u64>()) {
                (Ok(integer), Ok(decimal)) => {
                    let mut sat_amount = integer * BTC_TO_SAT;
                    let base: u64 = 10;
                    let sat = decimal * base.pow((MAX_DECIMAL_COUNT - rhs.len()) as u32);
                    sat_amount += sat;
                    Ok(sat_amount)
                }
                (lhs, rhs) => {
                    return Err(format!("Cannot convert BTC '{amount}' to sat integer: {lhs:?} - fractional: {rhs:?}"));
                }
            }
        },
        [lhs] => match lhs.parse::<u64>() {
            Ok(btc) => Ok(btc * BTC_TO_SAT),
            Err(_) => Err(format!("Cannot convert BTC '{amount}' integer part to sat: '{lhs}'")),
        },

        _ => Err(format!("Invalid BTC amount format: '{amount}'. Expected '<integer>.<fractional>' with up to 8 decimals.")),
    }
}

/// Converts a satoshi amount (u64) into a BTC string with exactly 8 decimal places.
///
/// # Arguments
/// * `amount` - The amount in satoshis.
///
/// # Returns
/// * A `String` representing the BTC value in the format `<integer>.<fractional>`,
///   always padded to 8 decimal places (e.g. "1.00000000", "0.50000000").
fn convert_sat_to_btc_string(amount: u64) -> String {
    let base: u64 = 10;
    let int_part = amount / base.pow(8);
    let frac_part = amount % base.pow(8);
    let amount = format!("{int_part}.{frac_part:08}");
    amount
}

/// Represents an error message returned when importing descriptors fails.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ImportDescriptorsErrorMessage {
    /// Numeric error code identifying the type of error.
    pub code: i64,
    /// Human-readable description of the error.
    pub message: String,
}

/// Response for `generatetoaddress` rpc, mainly used as deserialization wrapper for `BurnchainHeaderHash`
struct GenerateToAddressResponse(pub Vec<BurnchainHeaderHash>);

/// Deserializes a JSON string array into a vec of [`BurnchainHeaderHash`] and wrap it into [`GenerateToAddressResponse`]
impl<'de> Deserialize<'de> for GenerateToAddressResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hash_strs: Vec<String> = Deserialize::deserialize(deserializer)?;
        let mut hashes = Vec::with_capacity(hash_strs.len());
        for (i, s) in hash_strs.into_iter().enumerate() {
            let hash = BurnchainHeaderHash::from_hex(&s).map_err(|e| {
                serde::de::Error::custom(format!(
                    "Invalid BurnchainHeaderHash at index {}: {}",
                    i, e
                ))
            })?;
            hashes.push(hash);
        }

        Ok(GenerateToAddressResponse(hashes))
    }
}

/// Response mainly used as deserialization wrapper for [`Txid`]
struct TxidWrapperResponse(pub Txid);

/// Deserializes a JSON string (hex-encoded in big-endian order) into [`Txid`] and wrap it into [`TxidWrapperResponse`]
impl<'de> Deserialize<'de> for TxidWrapperResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: String = Deserialize::deserialize(deserializer)?;
        let txid = Txid::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
        Ok(TxidWrapperResponse(txid))
    }
}

/// Response mainly used as deserialization wrapper for [`BurnchainHeaderHash`]
struct BurnchainHeaderHashWrapperResponse(pub BurnchainHeaderHash);

/// Deserializes a JSON string (hex-encoded, big-endian) into [`BurnchainHeaderHash`],
/// and wrap it into [`BurnchainHeaderHashWrapperResponse`]
impl<'de> Deserialize<'de> for BurnchainHeaderHashWrapperResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: String = Deserialize::deserialize(deserializer)?;
        let bhh = BurnchainHeaderHash::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
        Ok(BurnchainHeaderHashWrapperResponse(bhh))
    }
}

/// Client for interacting with a Bitcoin RPC service.
#[derive(Debug, Clone)]
pub struct BitcoinRpcClient {
    /// The client ID to identify the source of the requests.
    client_id: String,
    /// RPC endpoint used for api calls
    endpoint: RpcTransport,
}

/// Represents errors that can occur when using [`BitcoinRpcClient`].
#[derive(Debug, thiserror::Error)]
pub enum BitcoinRpcClientError {
    // Missing credential error
    #[error("Missing credential error")]
    MissingCredentials,
    // RPC Transport errors
    #[error("Rcp error: {0}")]
    Rpc(#[from] RpcError),
    // JSON serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    // Bitcoin serialization errors
    #[error("Bitcoin Serialization error: {0}")]
    BitcoinSerialization(#[from] bitcoin_serialize_error),
}

/// Alias for results returned from client operations.
pub type BitcoinRpcClientResult<T> = Result<T, BitcoinRpcClientError>;

impl BitcoinRpcClient {
    /// Create a [`BitcoinRpcClient`] from Stacks Configuration, mainly using [`stacks::config::BurnchainConfig`]
    pub fn from_stx_config(config: &Config) -> BitcoinRpcClientResult<Self> {
        let host = config.burnchain.peer_host.clone();
        let port = config.burnchain.rpc_port;
        let username_opt = &config.burnchain.username;
        let password_opt = &config.burnchain.password;
        let timeout = config.burnchain.timeout;
        let client_id = "stacks".to_string();

        let rpc_auth = match (username_opt, password_opt) {
            (Some(username), Some(password)) => RpcAuth::Basic {
                username: username.clone(),
                password: password.clone(),
            },
            _ => return Err(BitcoinRpcClientError::MissingCredentials),
        };

        Self::new(host, port, rpc_auth, timeout, client_id)
    }

    /// Creates a new instance of the Bitcoin RPC client with both global and wallet-specific endpoints.
    ///
    /// # Arguments
    ///
    /// * `host` - Hostname or IP address of the Bitcoin RPC server (e.g., `localhost`).
    /// * `port` - Port number the RPC server is listening on.
    /// * `auth` - RPC authentication credentials (`RpcAuth::None` or `RpcAuth::Basic`).
    /// * `timeout` - Timeout for RPC requests, in seconds.
    /// * `client_id` - Identifier used in the `id` field of JSON-RPC requests for traceability.
    ///
    /// # Returns
    ///
    /// A [`BitcoinRpcClient`] on success, or a [`BitcoinRpcClientError`] otherwise.
    pub fn new(
        host: String,
        port: u16,
        auth: RpcAuth,
        timeout: u64,
        client_id: String,
    ) -> BitcoinRpcClientResult<Self> {
        let rpc_url = format!("http://{host}:{port}");
        let rpc_auth = auth;

        let rpc_timeout = Duration::from_secs(timeout);

        let endpoint = RpcTransport::new(rpc_url, rpc_auth.clone(), Some(rpc_timeout.clone()))?;

        Ok(Self {
            client_id,
            endpoint,
        })
    }

    /// create a wallet rpc path based on the given wallet name.
    fn wallet_path(wallet: &str) -> String {
        format!("wallet/{wallet}")
    }

    /// Creates and loads a new wallet into the Bitcoin Core node.
    ///
    /// Wallet is stored in the `-walletdir` specified in the Bitcoin Core configuration (or the default data directory if not set).
    ///
    /// # Arguments
    /// * `wallet_name` - Name of the wallet to create.
    /// * `disable_private_keys` - If `Some(true)`, the wallet will not be able to hold private keys.
    ///   If `None`, this defaults to `false`, allowing private key import/use.
    ///
    /// # Returns
    /// Returns `Ok(())` if the wallet is created successfully.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.17.0**.
    ///
    /// # Notes
    /// This method supports a subset of available RPC arguments to match current usage.
    /// Additional parameters can be added in the future as needed.
    pub fn create_wallet(
        &self,
        wallet_name: &str,
        disable_private_keys: Option<bool>,
    ) -> BitcoinRpcClientResult<()> {
        let disable_private_keys = disable_private_keys.unwrap_or(false);

        self.endpoint.send::<Value>(
            &self.client_id,
            None,
            "createwallet",
            vec![wallet_name.into(), disable_private_keys.into()],
        )?;
        Ok(())
    }

    /// Returns a list of currently loaded wallets by the Bitcoin Core node.
    ///
    /// # Returns
    /// A vector of wallet names as strings.
    ///
    /// # Availability
    /// Available since Bitcoin Core **v0.15.0**.
    pub fn list_wallets(&self) -> BitcoinRpcClientResult<Vec<String>> {
        Ok(self
            .endpoint
            .send(&self.client_id, None, "listwallets", vec![])?)
    }

    /// Retrieve a list of unspent transaction outputs (UTXOs) that meet the specified criteria.
    ///
    /// # Arguments
    /// * `wallet` - The name of the wallet to query. This is used to construct the wallet-specific RPC endpoint.
    /// * `min_confirmations` - Minimum number of confirmations required for a UTXO to be included (Default: 0).
    /// * `max_confirmations` - Maximum number of confirmations allowed (Default: 9.999.999).
    /// * `addresses` - Optional list of addresses to filter UTXOs by (Default: no filtering).
    /// * `include_unsafe` - Whether to include UTXOs from unconfirmed unsafe transactions (Default: `true`).
    /// * `minimum_amount` - Minimum amount in satoshis (internally converted to BTC string to preserve full precision) a UTXO must have to be included (Default: 0).
    /// * `maximum_count` - Maximum number of UTXOs to return. Use `None` for effectively 'unlimited' (Default: 0).
    ///
    /// # Returns
    /// A Vec<[`ListUnspentResponse`]> containing the matching UTXOs.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.7.0**.
    ///
    /// # Notes
    /// This method supports a subset of available RPC arguments to match current usage.
    /// Additional parameters can be added in the future as needed.
    pub fn list_unspent(
        &self,
        wallet: &str,
        min_confirmations: Option<u64>,
        max_confirmations: Option<u64>,
        addresses: Option<&[&BitcoinAddress]>,
        include_unsafe: Option<bool>,
        minimum_amount: Option<u64>,
        maximum_count: Option<u64>,
    ) -> BitcoinRpcClientResult<Vec<ListUnspentResponse>> {
        let min_confirmations = min_confirmations.unwrap_or(0);
        let max_confirmations = max_confirmations.unwrap_or(9_999_999);
        let addresses = addresses.unwrap_or(&[]);
        let include_unsafe = include_unsafe.unwrap_or(true);
        let minimum_amount = minimum_amount.unwrap_or(0);
        let maximum_count = maximum_count.unwrap_or(0);

        let addr_as_strings: Vec<String> = addresses.iter().map(|addr| addr.to_string()).collect();
        let min_amount_btc_str = convert_sat_to_btc_string(minimum_amount);

        Ok(self.endpoint.send(
            &self.client_id,
            Some(&Self::wallet_path(wallet)),
            "listunspent",
            vec![
                min_confirmations.into(),
                max_confirmations.into(),
                addr_as_strings.into(),
                include_unsafe.into(),
                json!({
                    "minimumAmount": min_amount_btc_str,
                    "maximumCount": maximum_count
                }),
            ],
        )?)
    }

    /// Mines a specified number of blocks and sends the block rewards to a given address.
    ///
    /// # Arguments
    /// * `num_blocks` - The number of blocks to mine.
    /// * `address` - The [`BitcoinAddress`] to receive the block rewards.
    ///
    /// # Returns
    /// A vector of [`BurnchainHeaderHash`] corresponding to the newly generated blocks.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.17.0**.
    ///
    /// # Notes
    /// Typically used on `regtest` or test networks.
    pub fn generate_to_address(
        &self,
        num_blocks: u64,
        address: &BitcoinAddress,
    ) -> BitcoinRpcClientResult<Vec<BurnchainHeaderHash>> {
        let response = self.endpoint.send::<GenerateToAddressResponse>(
            &self.client_id,
            None,
            "generatetoaddress",
            vec![num_blocks.into(), address.to_string().into()],
        )?;
        Ok(response.0)
    }

    /// Retrieves detailed information about an in-wallet transaction.
    ///
    /// This method returns information such as amount, fee, confirmations, block hash,
    /// hex-encoded transaction, and other metadata for a transaction tracked by the wallet.
    ///
    /// # Arguments
    /// * `wallet` - The name of the wallet to query. This is used to construct the wallet-specific RPC endpoint.
    /// * `txid` - The transaction ID (as [`Txid`]) to query (in big-endian order).
    ///
    /// # Returns
    /// A [`GetTransactionResponse`] containing detailed metadata for the specified transaction.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.10.0**.
    pub fn get_transaction(
        &self,
        wallet: &str,
        txid: &Txid,
    ) -> BitcoinRpcClientResult<GetTransactionResponse> {
        Ok(self.endpoint.send(
            &self.client_id,
            Some(&Self::wallet_path(wallet)),
            "gettransaction",
            vec![txid.to_hex().into()],
        )?)
    }

    /// Broadcasts a raw transaction to the Bitcoin network.
    ///
    /// This method sends a hex-encoded raw Bitcoin transaction. It supports optional limits for the
    /// maximum fee rate and maximum burn amount to prevent accidental overspending.
    ///
    /// # Arguments
    ///
    /// * `tx` - A [`Transaction`], that will be hex-encoded, representing the raw transaction.
    /// * `max_fee_rate` - Optional maximum fee rate (in BTC/kvB). If `None`, defaults to `0.10` BTC/kvB.
    ///     - Bitcoin Core will reject transactions exceeding this rate unless explicitly overridden.
    ///     - Set to `0.0` to disable fee rate limiting entirely.
    /// * `max_burn_amount` - Optional maximum amount (in satoshis) that can be "burned" in the transaction.
    ///     - Introduced in Bitcoin Core v25 (https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-25.0.md#rpc-and-other-apis)
    ///     - If `None`, defaults to `0`, meaning burning is not allowed.
    ///
    /// # Returns
    /// A [`Txid`] as a transaction ID (in big-endian order)
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.7.0**.
    /// - `maxburnamount` parameter is available starting from **v25.0**.
    pub fn send_raw_transaction(
        &self,
        tx: &Transaction,
        max_fee_rate: Option<f64>,
        max_burn_amount: Option<u64>,
    ) -> BitcoinRpcClientResult<Txid> {
        const DEFAULT_FEE_RATE_BTC_KVB: f64 = 0.10;
        let tx_hex = serialize_hex(tx)?;
        let max_fee_rate = max_fee_rate.unwrap_or(DEFAULT_FEE_RATE_BTC_KVB);
        let max_burn_amount = max_burn_amount.unwrap_or(0);

        let response = self.endpoint.send::<TxidWrapperResponse>(
            &self.client_id,
            None,
            "sendrawtransaction",
            vec![tx_hex.into(), max_fee_rate.into(), max_burn_amount.into()],
        )?;
        Ok(response.0)
    }

    /// Returns information about a descriptor, including its checksum.
    ///
    /// # Arguments
    /// * `descriptor` - The descriptor string to analyze.
    ///
    /// # Returns
    /// A [`DescriptorInfoResponse`] containing parsed descriptor information such as the checksum.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.18.0**.
    pub fn get_descriptor_info(
        &self,
        descriptor: &str,
    ) -> BitcoinRpcClientResult<DescriptorInfoResponse> {
        Ok(self.endpoint.send(
            &self.client_id,
            None,
            "getdescriptorinfo",
            vec![descriptor.into()],
        )?)
    }

    /// Imports one or more descriptors into the currently loaded wallet.
    ///
    /// # Arguments
    /// * `wallet` - The name of the wallet to query. This is used to construct the wallet-specific RPC endpoint.
    /// * `descriptors` – A slice of [`ImportDescriptorsRequest`] items. Each item defines a single
    ///   descriptor and optional metadata for how it should be imported.
    ///
    /// # Returns
    /// A vector of [`ImportDescriptorsResponse`] results, one for each descriptor import attempt.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.21.0**.
    pub fn import_descriptors(
        &self,
        wallet: &str,
        descriptors: &[&ImportDescriptorsRequest],
    ) -> BitcoinRpcClientResult<Vec<ImportDescriptorsResponse>> {
        let descriptor_values = descriptors
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(self.endpoint.send(
            &self.client_id,
            Some(&Self::wallet_path(wallet)),
            "importdescriptors",
            vec![descriptor_values.into()],
        )?)
    }

    /// Returns the hash of the block at the given height.
    ///
    /// # Arguments
    /// * `height` - The height (block number) of the block whose hash is requested.
    ///
    /// # Returns
    /// A [`BurnchainHeaderHash`] representing the block hash.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.9.0**.
    pub fn get_block_hash(&self, height: u64) -> BitcoinRpcClientResult<BurnchainHeaderHash> {
        let response = self.endpoint.send::<BurnchainHeaderHashWrapperResponse>(
            &self.client_id,
            None,
            "getblockhash",
            vec![height.into()],
        )?;
        Ok(response.0)
    }
}
