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

use serde_json::Value;
use stacks::burnchains::Txid;
use stacks::util::hash::hex_bytes;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize as btc_deserialize;

use crate::burnchains::rpc::bitcoin_rpc_client::{BitcoinRpcClient, BitcoinRpcClientResult};

/// Represents the response returned by the `getblockchaininfo` RPC call.
///
/// # Notes
/// This struct supports a subset of available fields to match current usage.
/// Additional fields can be added in the future as needed.
#[derive(Debug, Clone, Deserialize)]
pub struct GetBlockChainInfoResponse {
    /// the network name
    pub chain: String,
    /// the height of the most-work fully-validated chain. The genesis block has height 0
    pub blocks: u64,
    /// the current number of headers that have been validated
    pub headers: u64,
    /// the hash of the currently best block
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: String,
}

/// Represents the response returned by the `generateblock` RPC call.
#[derive(Debug, Clone, Deserialize)]
struct GenerateBlockResponse {
    /// The hash of the generated block
    hash: String,
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
            .global_ep
            .send(&self.client_id, "getblockchaininfo", vec![])?)
    }

    /// Retrieves and deserializes a raw Bitcoin transaction by its ID.
    ///
    /// # Arguments
    /// * `txid` - Transaction ID to fetch.
    ///
    /// # Returns
    /// A [`Transaction`] struct representing the decoded transaction.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.7.0**.
    pub fn get_raw_transaction(&self, txid: &Txid) -> BitcoinRpcClientResult<Transaction> {
        let raw_hex = self.global_ep.send::<String>(
            &self.client_id,
            "getrawtransaction",
            vec![txid.to_string().into()],
        )?;
        let raw_bytes = hex_bytes(&raw_hex)?;
        let tx = btc_deserialize(&raw_bytes)?;
        Ok(tx)
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
    /// # Availability
    /// - **Since**: Bitcoin Core **v22.0**.
    /// - Requires `regtest` or similar testing networks.
    pub fn generate_block(&self, address: &str, txs: &[&str]) -> BitcoinRpcClientResult<String> {
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
    /// On success, returns the string: `"Bitcoin Core stopping"`
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.
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
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.  
    /// - `address_type` parameter supported since **v0.17.0**.
    /// - Defaulting to `bech32` (when unset) introduced in **v0.20.0**.
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
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.
    pub fn send_to_address(&self, address: &str, amount: f64) -> BitcoinRpcClientResult<String> {
        Ok(self.wallet_ep.send(
            &self.client_id,
            "sendtoaddress",
            vec![address.into(), amount.into()],
        )?)
    }

    /// Invalidate a block by its block hash, forcing the node to reconsider its chain state.
    ///
    /// # Arguments
    /// * `hash` - The block hash (as a hex string) of the block to invalidate.
    ///
    /// # Returns
    /// An empty `()` on success.
    ///
    /// # Availability
    /// - **Since**: Bitcoin Core **v0.1.0**.
    pub fn invalidate_block(&self, hash: &str) -> BitcoinRpcClientResult<()> {
        self.global_ep
            .send::<Value>(&self.client_id, "invalidateblock", vec![hash.into()])?;
        Ok(())
    }
}
