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

use std::time::Duration;

use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use stacks::config::Config;

use crate::burnchains::bitcoin_regtest_controller::{ParsedUTXO, UTXO};
use crate::burnchains::rpc_transport::{RpcAuth, RpcError, RpcTransport};

/// Response structure for the `gettransaction` RPC call.
///
/// Contains metadata about a wallet transaction, currently limited to the confirmation count.
///
/// # Note
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
/// # Note
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Deserialize)]
pub struct DescriptorInfoResponse {
    pub checksum: String,
}

/// Represents the `timestamp` parameter accepted by the `importdescriptors` RPC method.
///
/// This indicates when the imported descriptor starts being relevant for address tracking.
/// It affects wallet rescanning behavior:
///
/// - `Now` — Tells the wallet to start tracking from the current blockchain time.  
/// - `Time(u64)` — A Unix timestamp (in seconds) specifying when the wallet should begin scanning.
///
/// # Serialization
/// This enum serializes to either the string `"now"` or a numeric timestamp,
/// matching the format expected by Bitcoin Core.
#[derive(Debug, Clone)]
pub enum Timestamp {
    Now,
    Time(u64),
}

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
/// # Notes:
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
/// # Notes:
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
    pub error: Option<RpcErrorResponse>,
}

/// Represents a single UTXO (unspent transaction output) returned by the `listunspent` RPC method.
/// 
/// # Notes:
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

#[derive(Debug, Clone, Deserialize)]
pub struct GenerateBlockResponse {
    hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcErrorResponse {
    pub code: i64,
    pub message: String,
}

pub struct BitcoinRpcClient {
    client_id: String,
    global_ep: RpcTransport,
    wallet_ep: RpcTransport,
}

#[derive(Debug)]
pub enum BitcoinRpcClientError {
    // Transport or server-side errors
    Rpc(RpcError),
    // Local JSON issues
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
    pub fn from_params(
        host: String,
        port: u16,
        ssl: bool,
        username: String,
        password: String,
        wallet_name: String,
    ) -> Self {
        let protocol = if ssl { "https" } else { "http" };
        let global_path = format!("{protocol}://{host}:{port}");
        let wallet_path = format!("{global_path}/wallet/{wallet_name}");
        let client_id = "stacks";
        let auth = RpcAuth::Basic { username, password };

        Self {
            client_id: client_id.to_string(),
            global_ep: RpcTransport::new(global_path, auth.clone(), None)
                .expect("Global endpoint should be ok!"),
            wallet_ep: RpcTransport::new(wallet_path, auth, None)
                .expect("Wallet endpoint should be ok!"),
        }
    }

    //TODO: check config and eventually return Result<Self, Err>
    pub fn from_stx_config(config: &Config) -> Self {
        let host = config.burnchain.peer_host.clone();
        let port = config.burnchain.rpc_port;
        let ssl = config.burnchain.rpc_ssl;
        let username = config.burnchain.username.clone().unwrap();
        let password = config.burnchain.password.clone().unwrap();
        let wallet_name = config.burnchain.wallet_name.clone();

        let protocol = if ssl { "https" } else { "http" };
        let global_path = format!("{protocol}://{host}:{port}");
        let wallet_path = format!("{global_path}/wallet/{wallet_name}");

        let client_id = "stacks";
        let auth = RpcAuth::Basic { username, password };
        let timeout = Duration::from_secs(u64::from(config.burnchain.timeout));

        Self {
            client_id: client_id.to_string(),
            global_ep: RpcTransport::new(global_path, auth.clone(), Some(timeout.clone()))
                .expect("Global endpoint should be ok!"),
            wallet_ep: RpcTransport::new(wallet_path, auth, Some(timeout))
                .expect("Wallet endpoint should be ok!"),
        }
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
    /// # Errors
    /// Returns an error if the wallet creation fails. This includes:
    /// - The wallet already exists.
    /// - Invalid parameters.
    /// - Node-level failures or RPC connection issues.
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.17.0**.
    ///
    /// # Notes:
    /// This method supports only a subset of available RPC arguments to match current usage.
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
    /// # Errors
    /// Returns an error if the RPC call fails or if communication with the node is interrupted.
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
    /// * `min_confirmations` - Minimum number of confirmations required for a UTXO to be included.
    /// * `max_confirmations` - Maximum number of confirmations allowed. Use `None` for effectively unlimited.
    /// * `addresses` - Optional list of addresses to filter UTXOs by. If `None`, all UTXOs are returned.
    /// * `include_unsafe` - Whether to include UTXOs from unconfirmed unsafe transactions.
    /// * `minimum_amount` - Minimum amount (in satoshis) a UTXO must have to be included.
    /// * `maximum_count` - Maximum number of UTXOs to return. Use `None` for effectively unlimited.
    ///
    /// Default values are applied for omitted parameters:
    /// - `min_confirmations` defaults to 0
    /// - `max_confirmations` defaults to 9,999,999
    /// - `addresses` defaults to an empty list (no filtering)
    /// - `include_unsafe` defaults to `true`
    /// - `minimum_amount` defaults to 0 satoshis
    /// - `maximum_count` defaults to 9,999,999
    ///
    /// # Returns
    /// A `Vec<ListUnspentResponse>` containing the matching UTXOs.
    ///
    /// # Errors
    /// Returns a `BitcoinRpcClientError` if the RPC call fails or the response cannot be parsed.
    ///
    /// # Notes:
    /// This method supports only a subset of available RPC arguments to match current usage.
    /// Additional parameters can be added in the future as needed.
    pub fn list_unspent(
        &self,
        min_confirmations: Option<u64>,
        max_confirmations: Option<u64>,
        addresses: Option<Vec<String>>,
        include_unsafe: Option<bool>,
        minimum_amount: Option<u64>,
        maximum_count: Option<u64>,
    ) -> BitcoinRpcClientResult<Vec<ListUnspentResponse>> {
        let min_confirmations = min_confirmations.unwrap_or(0);
        let max_confirmations = max_confirmations.unwrap_or(9999999);
        let addresses = addresses.unwrap_or(vec![]);
        let include_unsafe = include_unsafe.unwrap_or(true);
        let minimum_amount = ParsedUTXO::sat_to_serialized_btc(minimum_amount.unwrap_or(0));
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
    /// # Errors
    /// Returns an error if the block generation fails (e.g., invalid address or RPC issues).
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.17.0**.
    /// Typically used on `regtest` or test networks.
    /// NOTE: Candidate to be a test util, but this api is used in production code when a burnchain is configured in `helium` mode
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
    /// # Errors
    /// Returns an error if the transaction is not found in the wallet, or if the RPC request fails.
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.10.0**.
    pub fn get_transaction(&self, txid: &str) -> BitcoinRpcClientResult<GetTransactionResponse> {
        Ok(self
            .wallet_ep
            .send(&self.client_id, "gettransaction", vec![txid.into()])?)
    }

    /// Broadcasts a raw transaction to the Bitcoin network.
    ///
    /// This method sends a hex-encoded raw Bitcoin transaction using the
    /// `sendrawtransaction` RPC endpoint. It supports optional limits for the
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
    ///
    /// * On success, returns the transaction ID (`txid`) as a `String`.
    ///
    /// # Errors
    ///
    /// Returns an `RpcError` if the RPC call fails, the transaction is invalid,
    /// or if fee or burn limits are exceeded.
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
    /// # Errors
    /// Returns an error if the descriptor is invalid or the RPC call fails.
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.18.0**.
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
    ///
    /// # Arguments
    /// * `descriptors` – A slice of `ImportDescriptorsRequest` items. Each item defines a single
    ///   descriptor and optional metadata for how it should be imported.
    ///
    /// # Returns
    /// A vector of `ImportDescriptorsResponse` results, one for each descriptor import attempt.
    ///
    /// # Errors
    /// Returns an error if the request fails, if the input cannot be serialized,
    /// or if the Bitcoin node responds with an error.
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.21.0**.
    pub fn import_descriptors(
        &self,
        descriptors: &[ImportDescriptorsRequest],
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

    //TODO REMOVE:
    pub fn get_blockchaininfo(&self) -> BitcoinRpcClientResult<()> {
        self.global_ep
            .send::<Value>(&self.client_id, "getblockchaininfo", vec![])?;
        Ok(())
    }
}

/// Test-only utilities for `BitcoinRpcClient`
#[cfg(test)]
impl BitcoinRpcClient {
    /// Retrieves the raw hex-encoded transaction by its ID.
    ///
    /// # Arguments
    /// * `txid` - Transaction ID (hash) to fetch.
    ///
    /// # Returns
    /// A raw transaction as a hex-encoded string.
    ///
    /// # Errors
    /// Returns an error if the transaction is not found or if the RPC request fails.
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.7.0**.
    pub fn get_raw_transaction(&self, txid: &str) -> BitcoinRpcClientResult<String> {
        Ok(self
            .global_ep
            .send(&self.client_id, "getrawtransaction", vec![txid.into()])?)
    }

    /// Mines a new block including the given transactions to a specified address.
    ///
    /// # Arguments
    /// * `address` - Address to which the block subsidy will be paid.
    /// * `txs` - List of transactions to include in the block. Each entry can be:
    ///   - A raw hex-encoded transaction
    ///   - A transaction ID (must be present in the mempool)
    ///   If the list is empty, an empty block (with only the coinbase transaction) will be generated.
    ///
    /// # Returns
    /// The block hash of the newly generated block.
    ///
    /// # Errors
    /// Returns an error if block generation fails (e.g., invalid address, missing transactions, or malformed data).
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v22.0**. Requires `regtest` or similar testing networks.
    pub fn generate_block(
        &self,
        address: &str,
        txs: Vec<String>,
    ) -> BitcoinRpcClientResult<String> {
        let response = self.global_ep.send::<GenerateBlockResponse>(
            &self.client_id,
            "generateblock",
            vec![address.into(), txs.into()],
        )?;
        Ok(response.hash)
    }

    /// Gracefully shuts down the Bitcoin Core node.
    ///
    /// Sends the shutdown command to safely terminate `bitcoind`. This ensures all state is written
    /// to disk and the node exits cleanly.
    ///
    /// # Returns
    /// On success, returns the string:
    /// `"Bitcoin Core stopping"`
    ///
    /// # Errors
    /// Returns an error if the RPC command fails (e.g., connection issue or insufficient permissions).
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.1.0**.
    pub fn stop(&self) -> BitcoinRpcClientResult<String> {
        Ok(self.global_ep.send(&self.client_id, "stop", vec![])?)
    }

    /// Retrieves a new Bitcoin address from the wallet.
    ///
    /// # Arguments
    /// * `label` - Optional label to associate with the address.
    /// * `address_type` - Optional address type (`"legacy"`, `"p2sh-segwit"`, `"bech32"`, `"bech32m"`).
    ///   If `None`, the address type defaults to the node’s `-addresstype` setting.
    ///   If `-addresstype` is also unset, the default is `"bech32"` (since v0.20.0).
    ///
    /// # Returns
    /// A string representing the newly generated Bitcoin address.
    ///
    /// # Errors
    /// Returns an error if the wallet is not loaded or if address generation fails.
    ///
    /// # Availability
    /// Available in Bitcoin Core since **v0.1.0**.  
    /// `address_type` parameter supported since **v0.17.0**.
    /// Defaulting to `bech32` (when unset) introduced in **v0.20.0**.
    pub fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<&str>,
    ) -> BitcoinRpcClientResult<String> {
        let mut params = vec![];

        let label = label.unwrap_or("");
        params.push(label.into());

        if let Some(at) = address_type {
            params.push(at.into());
        }

        Ok(self
            .global_ep
            .send(&self.client_id, "getnewaddress", params)?)
    }

    /// Sends a specified amount of BTC to a given address.
    ///
    /// # Arguments
    /// * `address` - The destination Bitcoin address.
    /// * `amount` - Amount to send in BTC (not in satoshis).
    ///
    /// # Returns
    /// The transaction ID as hex string
    pub fn send_to_address(&self, address: &str, amount: f64) -> BitcoinRpcClientResult<String> {
        Ok(self.wallet_ep.send(
            &self.client_id,
            "sendtoaddress",
            vec![address.into(), amount.into()],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    mod unit {

        use serde_json::json;

        use super::*;

        mod utils {
            use super::*;

            pub fn setup_client(server: &mockito::ServerGuard) -> BitcoinRpcClient {
                let url = server.url();
                let parsed = url::Url::parse(&url).unwrap();

                BitcoinRpcClient::from_params(
                    parsed.host_str().unwrap().to_string(),
                    parsed.port_or_known_default().unwrap(),
                    parsed.scheme() == "https",
                    "user".into(),
                    "pass".into(),
                    "mywallet".into(),
                )
            }
        }

        #[test]
        fn test_create_wallet_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "createwallet",
                "params": ["testwallet", true]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "name": "testwallet",
                    "warning": null
                },
                "error": null
            });

            let mut server: mockito::ServerGuard = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            client
                .create_wallet("testwallet", Some(true))
                .expect("create wallet should be ok!");
        }

        #[test]
        fn test_list_wallets_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "listwallets",
                "params": []
            });

            let mock_response = json!({
                "id": "stacks",
                "result": ["wallet1", "wallet2"],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let result = client.list_wallets().expect("Should list wallets");

            assert_eq!(2, result.len());
            assert_eq!("wallet1", result[0]);
            assert_eq!("wallet2", result[1]);
        }

        #[test]
        fn test_list_unspent_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "listunspent",
                "params": [
                    1,
                    10,
                    ["BTC_ADDRESS_1"],
                    true,
                    {
                        "minimumAmount": "0.00001000",
                        "maximumCount": 5
                    }
                ]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": [{
                    "txid": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                    "vout": 0,
                    "scriptPubKey": "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
                    "amount": 0.00001,
                    "confirmations": 6
                }],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .list_unspent(
                    Some(1),
                    Some(10),
                    Some(vec!["BTC_ADDRESS_1".into()]),
                    Some(true),
                    Some(1000), // 1000 sats = 0.00001000 BTC
                    Some(5),
                )
                .expect("Should parse unspent outputs");

            assert_eq!(1, result.len());
            let utxo = &result[0];
            assert_eq!("0.00001", utxo.amount);
            assert_eq!(0, utxo.vout);
            assert_eq!(6, utxo.confirmations);
            assert_eq!(
                "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                utxo.txid,
            );
            assert_eq!(
                "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
                utxo.script_pub_key,
            );
        }

        #[test]
        fn test_generate_to_address_ok() {
            let num_blocks = 3;
            let address = "00000000000000000000000000000000000000000000000000000";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "generatetoaddress",
                "params": [num_blocks, address],
            });

            let mock_response = json!({
                "id": "stacks",
                "result": [
                    "block_hash1",
                    "block_hash2",
                ],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .generate_to_address(num_blocks, address)
                .expect("Should work!");
            assert_eq!(2, result.len());
            assert_eq!("block_hash1", result[0]);
            assert_eq!("block_hash2", result[1]);
        }

        #[test]
        fn test_get_transaction_ok() {
            let txid = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "gettransaction",
                "params": [txid]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "confirmations": 6,
                },
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let info = client.get_transaction(txid).expect("Should be ok!");
            assert_eq!(6, info.confirmations);
        }

        #[test]
        fn test_get_raw_transaction_ok() {
            let txid = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
            let expected_ser_tx = "000111222333444555666";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getrawtransaction",
                "params": [txid]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_ser_tx,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let ser_tx = client.get_raw_transaction(txid).expect("Should be ok!");
            assert_eq!(expected_ser_tx, ser_tx);
        }

        #[test]
        fn test_generate_block_ok() {
            let addr = "myaddr";
            let txid1 = "txid1";
            let txid2 = "txid2";
            let expected_block_hash = "block_hash";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "generateblock",
                "params": [addr, [txid1, txid2]]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "hash" : expected_block_hash
                },
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .generate_block(addr, vec![txid1.to_string(), txid2.to_string()])
                .expect("Should be ok!");
            assert_eq!(expected_block_hash, result);
        }

        #[test]
        fn test_send_raw_transaction_ok_with_defaults() {
            let raw_tx = "raw_tx_hex";
            let expected_txid = "txid1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "sendrawtransaction",
                "params": [raw_tx, 0.10, 0]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_txid,
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let txid = client
                .send_raw_transaction(raw_tx, None, None)
                .expect("Should work!");
            assert_eq!(txid, expected_txid);
        }

        #[test]
        fn test_send_raw_transaction_ok_with_custom_params() {
            let raw_tx = "raw_tx_hex";
            let expected_txid = "txid1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "sendrawtransaction",
                "params": [raw_tx, 0.0, 5_000]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_txid,
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let txid = client
                .send_raw_transaction(raw_tx, Some(0.0), Some(5_000))
                .expect("Should work!");
            assert_eq!(txid, expected_txid);
        }

        #[test]
        fn test_get_descriptor_info_ok() {
            let descriptor = format!("addr(bc1_address)");
            let expected_checksum = "mychecksum";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getdescriptorinfo",
                "params": [descriptor]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "checksum": expected_checksum
                },
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let info = client
                .get_descriptor_info(&descriptor)
                .expect("Should work!");
            assert_eq!(expected_checksum, info.checksum);
        }

        #[test]
        fn test_import_descriptors_ok() {
            let descriptor = "addr(1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)#checksum";
            let timestamp = 0;
            let internal = true;

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "importdescriptors",
                "params": [
                    [
                        {
                            "desc": descriptor,
                            "timestamp": 0,
                            "internal": true
                        }
                    ]
                ]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": [{
                    "success": true,
                    "warnings": []
                }],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let desc_req = ImportDescriptorsRequest {
                descriptor: descriptor.to_string(),
                timestamp: Timestamp::Time(timestamp),
                internal: Some(internal),
            };
            let result = client.import_descriptors(&[desc_req]);
            assert!(result.is_ok());
        }

        #[test]
        fn test_stop_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "stop",
                "params": []
            });

            let mock_response = json!({
                "id": "stacks",
                "result": "Bitcoin Core stopping",
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let result = client.stop().expect("Should work!");
            assert_eq!("Bitcoin Core stopping", result);
        }

        #[test]
        fn test_get_new_address_ok() {
            let expected_address = "btc_addr_1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getnewaddress",
                "params": [""]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_address,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let address = client.get_new_address(None, None).expect("Should be ok!");
            assert_eq!(expected_address, address);
        }

        #[test]
        fn test_send_to_address_ok() {
            let address = "btc_addr_1";
            let amount = 0.5;
            let expected_txid = "txid_1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "sendtoaddress",
                "params": [address, amount]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_txid,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let txid = client
                .send_to_address(address, amount)
                .expect("Should be ok!");
            assert_eq!(expected_txid, txid);
        }
    }

    #[cfg(test)]
    mod inte {
        use super::*;
        use crate::tests::bitcoin_regtest::BitcoinCoreController;

        mod utils {
            use std::net::TcpListener;

            use stacks::config::Config;

            use crate::util::get_epoch_time_ms;

            pub fn create_config() -> Config {
                let mut config = Config::default();
                config.burnchain.magic_bytes = "T3".as_bytes().into();
                config.burnchain.username = Some(String::from("user"));
                config.burnchain.password = Some(String::from("12345"));
                // overriding default "0.0.0.0" because doesn't play nicely on Windows.
                config.burnchain.peer_host = String::from("127.0.0.1");
                // avoiding peer port biding to reduce the number of ports to bind to.
                config.burnchain.peer_port = 0;

                //Ask the OS for a free port. Not guaranteed to stay free,
                //after TcpListner is dropped, but good enough for testing
                //and starting bitcoind right after config is created
                let tmp_listener =
                    TcpListener::bind("127.0.0.1:0").expect("Failed to bind to get a free port");
                let port = tmp_listener.local_addr().unwrap().port();

                config.burnchain.rpc_port = port;

                let now = get_epoch_time_ms();
                let dir = format!("/tmp/rpc-client-{port}-{now}");
                config.node.working_dir = dir;

                config
            }
        }

        #[test]
        fn test_wallet_listing_and_creation_ok() {
            let config = utils::create_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);

            let wallets = client.list_wallets().unwrap();
            assert_eq!(0, wallets.len());

            client
                .create_wallet("mywallet1", Some(false))
                .expect("mywallet1 creation should be ok!");

            let wallets = client.list_wallets().unwrap();
            assert_eq!(1, wallets.len());
            assert_eq!("mywallet1", wallets[0]);

            client
                .create_wallet("mywallet2", Some(false))
                .expect("mywallet2 creation should be ok!");

            let wallets = client.list_wallets().unwrap();
            assert_eq!(2, wallets.len());
            assert_eq!("mywallet1", wallets[0]);
            assert_eq!("mywallet2", wallets[1]);
        }

        #[test]
        fn test_wallet_creation_fails_if_already_exists() {
            let config = utils::create_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);

            client
                .create_wallet("mywallet1", Some(false))
                .expect("mywallet1 creation should be ok!");

            let err = client
                .create_wallet("mywallet1", Some(false))
                .expect_err("mywallet1 creation should fail now!");

            assert!(matches!(
                err,
                BitcoinRpcClientError::Rpc(RpcError::Service(_))
            ));
        }

        #[test]
        fn test_generate_to_address_and_list_unspent_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client.create_wallet("my_wallet", Some(false)).expect("OK");
            let address = client.get_new_address(None, None).expect("Should work!");

            let utxos = client
                .list_unspent(None, None, None, Some(false), Some(1), Some(10))
                .expect("list_unspent should be ok!");
            assert_eq!(0, utxos.len());

            let blocks = client.generate_to_address(102, &address).expect("OK");
            assert_eq!(102, blocks.len());

            let utxos = client
                .list_unspent(None, None, None, Some(false), Some(1), Some(10))
                .expect("list_unspent should be ok!");
            assert_eq!(2, utxos.len());

            let utxos = client
                .list_unspent(None, None, None, Some(false), Some(1), Some(1))
                .expect("list_unspent should be ok!");
            assert_eq!(1, utxos.len());
        }

        #[test]
        fn test_generate_block_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client.create_wallet("my_wallet", Some(false)).expect("OK");
            let address = client.get_new_address(None, None).expect("Should work!");

            let block_hash = client.generate_block(&address, vec![]).expect("OK");
            assert_eq!(64, block_hash.len());
        }

        #[test]
        fn test_get_raw_transaction_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .add_arg("-fallbackfee=0.0002")
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client
                .create_wallet("my_wallet", Some(false))
                .expect("create wallet ok!");

            let address = client
                .get_new_address(None, None)
                .expect("get new address ok!");

            //Create 1 UTXO
            _ = client
                .generate_to_address(101, &address)
                .expect("generate to address ok!");

            //Need `fallbackfee` arg
            let txid = client
                .send_to_address(&address, 2.0)
                .expect("send to address ok!");

            let raw_tx = client
                .get_raw_transaction(&txid)
                .expect("get raw transaction ok!");
            assert_ne!("", raw_tx);
        }

        #[test]
        fn test_get_transaction_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .add_arg("-fallbackfee=0.0002")
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client
                .create_wallet("my_wallet", Some(false))
                .expect("create wallet ok!");
            let address = client
                .get_new_address(None, None)
                .expect("get new address ok!");

            //Create 1 UTXO
            _ = client
                .generate_to_address(101, &address)
                .expect("generate to address ok!");

            //Need `fallbackfee` arg
            let txid = client
                .send_to_address(&address, 2.0)
                .expect("send to address ok!");

            let resp = client.get_transaction(&txid).expect("get transaction ok!");
            assert_eq!(0, resp.confirmations);
        }

        #[test]
        fn test_get_descriptor_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client
                .create_wallet("my_wallet", None)
                .expect("create wallet ok!");

            let address = "mqqxPdP1dsGk75S7ta2nwyU8ujDnB2Yxvu";
            let checksum = "spfcmvsn";

            let descriptor = format!("addr({address})");
            let info = client
                .get_descriptor_info(&descriptor)
                .expect("get descriptor ok!");
            assert_eq!(checksum, info.checksum);
        }

        #[test]
        fn test_import_descriptor_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client
                .create_wallet("my_wallet", Some(true))
                .expect("create wallet ok!");

            let address = "mqqxPdP1dsGk75S7ta2nwyU8ujDnB2Yxvu";
            let checksum = "spfcmvsn";

            let desc_req = ImportDescriptorsRequest {
                descriptor: format!("addr({address})#{checksum}"),
                timestamp: Timestamp::Time(0),
                internal: Some(true),
            };

            let response = client
                .import_descriptors(&[desc_req])
                .expect("import descriptor ok!");
            assert_eq!(1, response.len());
            assert!(response[0].success);
        }

        #[test]
        fn test_stop_bitcoind_ok() {
            let config = utils::create_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            let msg = client.stop().expect("Should shutdown!");
            assert_eq!("Bitcoin Core stopping", msg);
        }
    }
}
