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
use stacks::config::Config;

use crate::burnchains::rpc::rpc_transport::{RpcAuth, RpcError, RpcTransport};

#[cfg(test)]
mod test_utils;

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
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResponse {
    /// The transaction ID of the UTXO.
    pub txid: String,
    /// The index of the output in the transaction.
    pub vout: u32,
    /// The script associated with the output.
    pub script_pub_key: String,
    /// The amount in BTC, deserialized as a string to preserve full precision.
    #[serde(deserialize_with = "serde_raw_to_string")]
    pub amount: String,
    /// The number of confirmations for the transaction.
    pub confirmations: u32,
}

/// Deserializes any raw JSON value into its unprocessed string representation.
///
/// Useful when you need to defer parsing, preserve exact formatting (e.g., precision),
/// or handle heterogeneous value types dynamically.
fn serde_raw_to_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Box<RawValue> = Deserialize::deserialize(deserializer)?;
    Ok(raw.get().to_string())
}

/// Represents an error message returned when importing descriptors fails.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportDescriptorsErrorMessage {
    /// Numeric error code identifying the type of error.
    pub code: i64,
    /// Human-readable description of the error.
    pub message: String,
}

/// Client for interacting with a Bitcoin RPC service.
#[derive(Debug)]
pub struct BitcoinRpcClient {
    /// The client ID to identify the source of the requests.
    client_id: String,
    /// RPC endpoint used for global calls
    global_ep: RpcTransport,
    /// RPC endpoint used for wallet-specific calls
    wallet_ep: RpcTransport,
}

/// Represents errors that can occur when using [`BitcoinRpcClient`].
#[derive(Debug)]
pub enum BitcoinRpcClientError {
    // RPC Transport errors
    Rpc(RpcError),
    // JSON serialization errors
    Serialization(serde_json::Error),
}

impl From<RpcError> for BitcoinRpcClientError {
    fn from(err: RpcError) -> Self {
        BitcoinRpcClientError::Rpc(err)
    }
}

impl From<serde_json::Error> for BitcoinRpcClientError {
    fn from(err: serde_json::Error) -> Self {
        BitcoinRpcClientError::Serialization(err)
    }
}

/// Alias for results returned from client operations.
pub type BitcoinRpcClientResult<T> = Result<T, BitcoinRpcClientError>;

impl BitcoinRpcClient {
    /// Create a [`BitcoinRpcClient`] from Stacks Configuration, mainly using [`stacks::config::BurnchainConfig`]
    pub fn from_stx_config(config: &Config) -> Result<Self, String> {
        let host = config.burnchain.peer_host.clone();
        let port = config.burnchain.rpc_port;
        let ssl = config.burnchain.rpc_ssl;
        let username_opt = &config.burnchain.username;
        let password_opt = &config.burnchain.password;
        let wallet_name = config.burnchain.wallet_name.clone();
        let timeout = config.burnchain.timeout;
        let client_id = "stacks".to_string();

        let rpc_auth = match (username_opt, password_opt) {
            (Some(username), Some(password)) => RpcAuth::Basic {
                username: username.clone(),
                password: password.clone(),
            },
            _ => return Err("Missing RPC credentials!".to_string()),
        };

        Self::new(host, port, ssl, rpc_auth, wallet_name, timeout, client_id)
    }

    /// Creates a new instance of the Bitcoin RPC client with both global and wallet-specific endpoints.
    ///
    /// # Arguments
    ///
    /// * `host` - Hostname or IP address of the Bitcoin RPC server (e.g., `localhost`).
    /// * `port` - Port number the RPC server is listening on.
    /// * `ssl` - If `true`, uses HTTPS for communication; otherwise, uses HTTP.
    /// * `auth` - RPC authentication credentials (`RpcAuth::None` or `RpcAuth::Basic`).
    /// * `wallet_name` - Name of the wallet to target for wallet-specific RPC calls.
    /// * `timeout` - Timeout for RPC requests, in seconds.
    /// * `client_id` - Identifier used in the `id` field of JSON-RPC requests for traceability.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` if both global and wallet RPC transports are successfully created,  
    /// or `Err(String)` if the underlying HTTP client setup fails.Stacks Configuration, mainly using `BurnchainConfig`
    pub fn new(
        host: String,
        port: u16,
        ssl: bool,
        auth: RpcAuth,
        wallet_name: String,
        timeout: u32,
        client_id: String,
    ) -> Result<Self, String> {
        let protocol = if ssl { "https" } else { "http" };
        let rpc_global_path = format!("{protocol}://{host}:{port}");
        let rpc_wallet_path = format!("{rpc_global_path}/wallet/{wallet_name}");
        let rpc_auth = auth;

        let rpc_timeout = Duration::from_secs(u64::from(timeout));

        let global_ep =
            RpcTransport::new(rpc_global_path, rpc_auth.clone(), Some(rpc_timeout.clone()))
                .map_err(|e| format!("Failed to create global RpcTransport: {e:?}"))?;
        let wallet_ep = RpcTransport::new(rpc_wallet_path, rpc_auth, Some(rpc_timeout))
            .map_err(|e| format!("Failed to create wallet RpcTransport: {e:?}"))?;

        Ok(Self {
            client_id,
            global_ep,
            wallet_ep,
        })
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

        self.global_ep.send::<Value>(
            &self.client_id,
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
            .global_ep
            .send(&self.client_id, "listwallets", vec![])?)
    }

    /// Retrieve a list of unspent transaction outputs (UTXOs) that meet the specified criteria.
    ///
    /// # Arguments
    /// * `min_confirmations` - Minimum number of confirmations required for a UTXO to be included (Default: 0).
    /// * `max_confirmations` - Maximum number of confirmations allowed (Default: 9.999.999).
    /// * `addresses` - Optional list of addresses to filter UTXOs by (Default: no filtering).
    /// * `include_unsafe` - Whether to include UTXOs from unconfirmed unsafe transactions (Default: `true`).
    /// * `minimum_amount` - Minimum amount (in BTC. As String to preserve full precision) a UTXO must have to be included (Default: "0").
    /// * `maximum_count` - Maximum number of UTXOs to return. Use `None` for effectively unlimited (Default: 9.999.999).
    ///
    /// # Returns
    /// A Vec<[`ListUnspentResponse`]> containing the matching UTXOs.
    ///
    /// # Notes
    /// This method supports a subset of available RPC arguments to match current usage.
    /// Additional parameters can be added in the future as needed.
    pub fn list_unspent(
        &self,
        min_confirmations: Option<u64>,
        max_confirmations: Option<u64>,
        addresses: Option<&[&str]>,
        include_unsafe: Option<bool>,
        minimum_amount: Option<&str>,
        maximum_count: Option<u64>,
    ) -> BitcoinRpcClientResult<Vec<ListUnspentResponse>> {
        let min_confirmations = min_confirmations.unwrap_or(0);
        let max_confirmations = max_confirmations.unwrap_or(9999999);
        let addresses = addresses.unwrap_or(&[]);
        let include_unsafe = include_unsafe.unwrap_or(true);
        let minimum_amount = minimum_amount.unwrap_or("0");
        let maximum_count = maximum_count.unwrap_or(9999999);

        Ok(self.wallet_ep.send(
            &self.client_id,
            "listunspent",
            vec![
                min_confirmations.into(),
                max_confirmations.into(),
                addresses.into(),
                include_unsafe.into(),
                json!({
                    "minimumAmount": minimum_amount,
                    "maximumCount": maximum_count
                }),
            ],
        )?)
    }

    /// Mines a specified number of blocks and sends the block rewards to a given address.
    ///
    /// # Arguments
    /// * `num_block` - The number of blocks to mine.
    /// * `address` - The Bitcoin address to receive the block rewards.
    ///
    /// # Returns
    /// A vector of block hashes corresponding to the newly generated blocks.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.17.0**.
    ///
    /// # Notes
    /// Typically used on `regtest` or test networks.
    pub fn generate_to_address(
        &self,
        num_block: u64,
        address: &str,
    ) -> BitcoinRpcClientResult<Vec<String>> {
        Ok(self.global_ep.send(
            &self.client_id,
            "generatetoaddress",
            vec![num_block.into(), address.into()],
        )?)
    }

    /// Retrieves detailed information about an in-wallet transaction.
    ///
    /// This method returns information such as amount, fee, confirmations, block hash,
    /// hex-encoded transaction, and other metadata for a transaction tracked by the wallet.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID (txid) to query, as a hex-encoded string.
    ///
    /// # Returns
    /// A [`GetTransactionResponse`] containing detailed metadata for the specified transaction.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.10.0**.
    pub fn get_transaction(&self, txid: &str) -> BitcoinRpcClientResult<GetTransactionResponse> {
        Ok(self
            .wallet_ep
            .send(&self.client_id, "gettransaction", vec![txid.into()])?)
    }

    /// Broadcasts a raw transaction to the Bitcoin network.
    ///
    /// This method sends a hex-encoded raw Bitcoin transaction. It supports optional limits for the
    /// maximum fee rate and maximum burn amount to prevent accidental overspending.
    ///
    /// # Arguments
    ///
    /// * `tx` - A hex-encoded string representing the raw transaction.
    /// * `max_fee_rate` - Optional maximum fee rate (in BTC/kvB). If `None`, defaults to `0.10` BTC/kvB.
    ///     - Bitcoin Core will reject transactions exceeding this rate unless explicitly overridden.
    ///     - Set to `0.0` to disable fee rate limiting entirely.
    /// * `max_burn_amount` - Optional maximum amount (in satoshis) that can be "burned" in the transaction.
    ///     - Introduced in Bitcoin Core v25 (https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-25.0.md#rpc-and-other-apis)
    ///     - If `None`, defaults to `0`, meaning burning is not allowed.
    ///
    /// # Returns
    /// A transaction ID as a `String`.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.7.0**.
    /// - `maxburnamount` parameter is available starting from **v25.0**.
    pub fn send_raw_transaction(
        &self,
        tx: &str,
        max_fee_rate: Option<f64>,
        max_burn_amount: Option<u64>,
    ) -> BitcoinRpcClientResult<String> {
        let max_fee_rate = max_fee_rate.unwrap_or(0.10);
        let max_burn_amount = max_burn_amount.unwrap_or(0);

        Ok(self.global_ep.send(
            &self.client_id,
            "sendrawtransaction",
            vec![tx.into(), max_fee_rate.into(), max_burn_amount.into()],
        )?)
    }

    /// Returns information about a descriptor, including its checksum.
    ///
    /// # Arguments
    /// * `descriptor` - The descriptor string to analyze.
    ///
    /// # Returns
    /// A `DescriptorInfoResponse` containing parsed descriptor information such as the checksum.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.18.0**.
    pub fn get_descriptor_info(
        &self,
        descriptor: &str,
    ) -> BitcoinRpcClientResult<DescriptorInfoResponse> {
        Ok(self.global_ep.send(
            &self.client_id,
            "getdescriptorinfo",
            vec![descriptor.into()],
        )?)
    }

    /// Imports one or more descriptors into the currently loaded wallet.
    ///
    /// # Arguments
    /// * `descriptors` – A slice of `ImportDescriptorsRequest` items. Each item defines a single
    ///   descriptor and optional metadata for how it should be imported.
    ///
    /// # Returns
    /// A vector of `ImportDescriptorsResponse` results, one for each descriptor import attempt.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.21.0**.
    pub fn import_descriptors(
        &self,
        descriptors: &[&ImportDescriptorsRequest],
    ) -> BitcoinRpcClientResult<Vec<ImportDescriptorsResponse>> {
        let descriptor_values = descriptors
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(self.global_ep.send(
            &self.client_id,
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
    /// A `String` representing the block hash in hexadecimal format.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.9.0**.
    pub fn get_block_hash(&self, height: u64) -> BitcoinRpcClientResult<String> {
        Ok(self
            .global_ep
            .send(&self.client_id, "getblockhash", vec![height.into()])?)
    }
}
