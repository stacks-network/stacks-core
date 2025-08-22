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

//! Test-only utilities for [`BitcoinRpcClient`]

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::Txid;
use stacks::types::chainstate::BurnchainHeaderHash;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize_hex;

use crate::burnchains::rpc::bitcoin_rpc_client::{
    deserialize_string_to_bitcoin_address, BitcoinRpcClient, BitcoinRpcClientResult,
    TxidWrapperResponse,
};

/// Represents the response returned by the `getblockchaininfo` RPC call.
///
/// # Notes
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Deserialize)]
pub struct GetBlockChainInfoResponse {
    /// the network name
    #[serde(deserialize_with = "deserialize_string_to_network_type")]
    pub chain: BitcoinNetworkType,
    /// the height of the most-work fully-validated chain. The genesis block has height 0
    pub blocks: u64,
    /// the current number of headers that have been validated
    pub headers: u64,
    /// the hash of the currently best block
    #[serde(
        rename = "bestblockhash",
        deserialize_with = "deserialize_string_to_burn_header_hash"
    )]
    pub best_block_hash: BurnchainHeaderHash,
}

/// Deserializes a JSON string into [`BitcoinNetworkType`]
fn deserialize_string_to_network_type<'de, D>(
    deserializer: D,
) -> Result<BitcoinNetworkType, D::Error>
where
    D: Deserializer<'de>,
{
    let string: String = Deserialize::deserialize(deserializer)?;
    match string.as_str() {
        "main" => Ok(BitcoinNetworkType::Mainnet),
        "test" => Ok(BitcoinNetworkType::Testnet),
        "regtest" => Ok(BitcoinNetworkType::Regtest),
        other => Err(serde::de::Error::custom(format!(
            "invalid network type: {other}"
        ))),
    }
}

/// Represents the response returned by the `generateblock` RPC call.
#[derive(Debug, Clone, Deserialize)]
struct GenerateBlockResponse {
    /// The hash of the generated block
    #[serde(deserialize_with = "deserialize_string_to_burn_header_hash")]
    hash: BurnchainHeaderHash,
}

/// Deserializes a JSON string into [`BurnchainHeaderHash`]
fn deserialize_string_to_burn_header_hash<'de, D>(
    deserializer: D,
) -> Result<BurnchainHeaderHash, D::Error>
where
    D: Deserializer<'de>,
{
    let string: String = Deserialize::deserialize(deserializer)?;
    BurnchainHeaderHash::from_hex(&string).map_err(serde::de::Error::custom)
}

/// Represents supported Bitcoin address types.
#[derive(Debug, Clone)]
pub enum AddressType {
    /// Legacy P2PKH address
    Legacy,
    /// P2SH-wrapped SegWit address
    P2shSegwit,
    /// Native SegWit address
    Bech32,
    /// Native SegWit v1+ address
    Bech32m,
}

impl ToString for AddressType {
    fn to_string(&self) -> String {
        match self {
            AddressType::Legacy => "legacy",
            AddressType::P2shSegwit => "p2sh-segwit",
            AddressType::Bech32 => "bech32",
            AddressType::Bech32m => "bech32m",
        }
        .to_string()
    }
}

/// Response for `getnewaddress` rpc, mainly used as deserialization wrapper for `BitcoinAddress`
struct GetNewAddressResponse(pub BitcoinAddress);

/// Deserializes a JSON string into [`BitcoinAddress`] and wrap it into [`GetNewAddressResponse`]
impl<'de> Deserialize<'de> for GetNewAddressResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_string_to_bitcoin_address(deserializer).map(GetNewAddressResponse)
    }
}

impl BitcoinRpcClient {
    /// Retrieve general information about the current state of the blockchain.
    ///
    /// # Arguments
    /// None.
    ///
    /// # Returns
    /// A [`GetBlockChainInfoResponse`] struct containing blockchain metadata.
    pub fn get_blockchain_info(&self) -> BitcoinRpcClientResult<GetBlockChainInfoResponse> {
        Ok(self
            .endpoint
            .send(&self.client_id, None, "getblockchaininfo", vec![])?)
    }

    /// Retrieves and deserializes a raw Bitcoin transaction by its ID.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID (as [`Txid`]) to query (in big-endian order).
    ///
    /// # Returns
    /// A [`Transaction`] struct representing the decoded transaction.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.7.0**.
    pub fn get_raw_transaction(&self, txid: &Txid) -> BitcoinRpcClientResult<Transaction> {
        let raw_hex = self.endpoint.send::<String>(
            &self.client_id,
            None,
            "getrawtransaction",
            vec![txid.to_hex().into()],
        )?;
        Ok(deserialize_hex(&raw_hex)?)
    }

    /// Mines a new block including the given transactions to a specified address.
    ///
    /// # Arguments
    /// * `address` - A [`BitcoinAddress`] to which the block subsidy will be paid.
    /// * `txs` - List of transactions to include in the block. Each entry can be:
    ///   - A raw hex-encoded transaction
    ///   - A transaction ID (must be present in the mempool)
    ///   If the list is empty, an empty block (with only the coinbase transaction) will be generated.
    ///
    /// # Returns
    /// A [`BurnchainHeaderHash`] struct containing the block hash of the newly generated block.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v22.0**.
    /// - Requires `regtest` or similar testing networks.
    pub fn generate_block(
        &self,
        address: &BitcoinAddress,
        txs: &[&str],
    ) -> BitcoinRpcClientResult<BurnchainHeaderHash> {
        let response = self.endpoint.send::<GenerateBlockResponse>(
            &self.client_id,
            None,
            "generateblock",
            vec![address.to_string().into(), txs.into()],
        )?;
        Ok(response.hash)
    }

    /// Gracefully shuts down the Bitcoin Core node.
    ///
    /// Sends the shutdown command to safely terminate `bitcoind`. This ensures all state is written
    /// to disk and the node exits cleanly.
    ///
    /// # Returns
    /// On success, returns the string: `"Bitcoin Core stopping"`
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.
    pub fn stop(&self) -> BitcoinRpcClientResult<String> {
        Ok(self.endpoint.send(&self.client_id, None, "stop", vec![])?)
    }

    /// Retrieves a new Bitcoin address from the wallet.
    ///
    /// # Arguments
    /// * `wallet` - The name of the wallet to query. This is used to construct the wallet-specific RPC endpoint.
    /// * `label` - Optional label to associate with the address.
    /// * `address_type` - Optional [`AddressType`] variant to specify the type of address.
    ///   If `None`, the address type defaults to the node’s `-addresstype` setting.
    ///   If `-addresstype` is also unset, the default is `"bech32"` (since v0.20.0).
    ///
    /// # Returns
    /// A [`BitcoinAddress`] variant representing the newly generated Bitcoin address.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.  
    /// - `address_type` parameter supported since **v0.17.0**.
    /// - Defaulting to `bech32` (when unset) introduced in **v0.20.0**.
    pub fn get_new_address(
        &self,
        wallet: &str,
        label: Option<&str>,
        address_type: Option<AddressType>,
    ) -> BitcoinRpcClientResult<BitcoinAddress> {
        let mut params = vec![];

        let label = label.unwrap_or("");
        params.push(label.into());

        if let Some(at) = address_type {
            params.push(at.to_string().into());
        }

        let response = self.endpoint.send::<GetNewAddressResponse>(
            &self.client_id,
            Some(&Self::wallet_path(wallet)),
            "getnewaddress",
            params,
        )?;

        Ok(response.0)
    }

    /// Sends a specified amount of BTC to a given address.
    ///
    /// # Arguments
    /// * `wallet` - The name of the wallet to query. This is used to construct the wallet-specific RPC endpoint.
    /// * `address` - The destination Bitcoin address as a [`BitcoinAddress`].
    /// * `amount` - Amount to send in BTC (not in satoshis).
    ///
    /// # Returns
    /// A [`Txid`] as a transaction ID (in big-endian order)
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.
    pub fn send_to_address(
        &self,
        wallet: &str,
        address: &BitcoinAddress,
        amount: f64,
    ) -> BitcoinRpcClientResult<Txid> {
        let response = self.endpoint.send::<TxidWrapperResponse>(
            &self.client_id,
            Some(&Self::wallet_path(wallet)),
            "sendtoaddress",
            vec![address.to_string().into(), amount.into()],
        )?;
        Ok(response.0)
    }

    /// Invalidate a block by its block hash, forcing the node to reconsider its chain state.
    ///
    /// # Arguments
    /// * `hash` - The block hash (as [`BurnchainHeaderHash`]) of the block to invalidate.
    ///
    /// # Returns
    /// An empty `()` on success.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.
    pub fn invalidate_block(&self, hash: &BurnchainHeaderHash) -> BitcoinRpcClientResult<()> {
        self.endpoint.send::<Value>(
            &self.client_id,
            None,
            "invalidateblock",
            vec![hash.to_hex().into()],
        )?;
        Ok(())
    }
}
