// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{cmp, io};

use base64::encode;
use serde::Serialize;
use serde_json::json;
use serde_json::value::RawValue;
use stacks::burnchains::bitcoin::address::{
    BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType, SegwitBitcoinAddress,
};
use stacks::burnchains::bitcoin::indexer::{
    BitcoinIndexer, BitcoinIndexerConfig, BitcoinIndexerRuntime,
};
use stacks::burnchains::bitcoin::spv::SpvClient;
use stacks::burnchains::bitcoin::{BitcoinNetworkType, Error as btc_error};
use stacks::burnchains::db::BurnchainDB;
use stacks::burnchains::indexer::BurnchainIndexer;
use stacks::burnchains::{
    Burnchain, BurnchainParameters, BurnchainStateTransitionOps, Error as burnchain_error,
    PoxConstants, PublicKey, Txid,
};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::{
    BlockstackOperationType, DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp,
    StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
#[cfg(test)]
use stacks::chainstate::burn::Opcodes;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
#[cfg(test)]
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::config::BurnchainConfig;
#[cfg(test)]
use stacks::config::{
    OP_TX_ANY_ESTIM_SIZE, OP_TX_DELEGATE_STACKS_ESTIM_SIZE, OP_TX_PRE_STACKS_ESTIM_SIZE,
    OP_TX_STACK_STX_ESTIM_SIZE, OP_TX_TRANSFER_STACKS_ESTIM_SIZE, OP_TX_VOTE_AGG_ESTIM_SIZE,
};
use stacks::core::{EpochList, StacksEpochId};
use stacks::monitoring::{increment_btc_blocks_received_counter, increment_btc_ops_sent_counter};
use stacks::net::http::{HttpRequestContents, HttpResponsePayload};
use stacks::net::httpcore::{send_http_request, StacksHttpRequest};
use stacks::net::Error as NetError;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Builder, Script};
use stacks_common::deps_common::bitcoin::blockdata::transaction::{
    OutPoint, Transaction, TxIn, TxOut,
};
use stacks_common::deps_common::bitcoin::network::serialize::{serialize, serialize_hex};
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::{hex_bytes, Hash160};
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use stacks_common::util::sleep_ms;
use url::Url;

use super::super::operations::BurnchainOpSigner;
use super::super::Config;
use super::{BurnchainController, BurnchainTip, Error as BurnchainControllerError};
use crate::burnchains::rpc::bitcoin_rpc_client::{
    BitcoinRpcClient, BitcoinRpcClientError, ImportDescriptorsRequest, Timestamp,
};

/// The number of bitcoin blocks that can have
///  passed since the UTXO cache was last refreshed before
///  the cache is force-reset.
const UTXO_CACHE_STALENESS_LIMIT: u64 = 6;
const DUST_UTXO_LIMIT: u64 = 5500;

#[cfg(test)]
// Used to inject invalid block commits during testing.
pub static TEST_MAGIC_BYTES: std::sync::Mutex<Option<[u8; 2]>> = std::sync::Mutex::new(None);

pub struct BitcoinRegtestController {
    config: Config,
    indexer: BitcoinIndexer,
    db: Option<SortitionDB>,
    burnchain_db: Option<BurnchainDB>,
    chain_tip: Option<BurnchainTip>,
    use_coordinator: Option<CoordinatorChannels>,
    burnchain_config: Option<Burnchain>,
    ongoing_block_commit: Option<OngoingBlockCommit>,
    should_keep_running: Option<Arc<AtomicBool>>,
    rpc_client: BitcoinRpcClient,
}

#[derive(Clone)]
pub struct OngoingBlockCommit {
    pub payload: LeaderBlockCommitOp,
    utxos: UTXOSet,
    fees: LeaderBlockCommitFees,
    txids: Vec<Txid>,
}

#[derive(Clone)]
struct LeaderBlockCommitFees {
    sunset_fee: u64,
    fee_rate: u64,
    sortition_fee: u64,
    outputs_len: u64,
    default_tx_size: u64,
    spent_in_attempts: u64,
    is_rbf_enabled: bool,
    final_size: u64,
}

// TODO: add tests from mutation testing results #4862
#[cfg_attr(test, mutants::skip)]
pub fn burnchain_params_from_config(config: &BurnchainConfig) -> BurnchainParameters {
    let (network, _) = config.get_bitcoin_network();
    let mut params = BurnchainParameters::from_params(&config.chain, &network)
        .expect("Bitcoin network unsupported");
    if let Some(first_burn_block_height) = config.first_burn_block_height {
        params.first_block_height = first_burn_block_height;
    }
    params
}

// TODO: add tests from mutation testing results #4863
#[cfg_attr(test, mutants::skip)]
/// Helper method to create a BitcoinIndexer
pub fn make_bitcoin_indexer(
    config: &Config,
    should_keep_running: Option<Arc<AtomicBool>>,
) -> BitcoinIndexer {
    let burnchain_params = burnchain_params_from_config(&config.burnchain);
    let indexer_config = {
        let burnchain_config = config.burnchain.clone();
        BitcoinIndexerConfig {
            peer_host: burnchain_config.peer_host,
            peer_port: burnchain_config.peer_port,
            rpc_port: burnchain_config.rpc_port,
            rpc_ssl: burnchain_config.rpc_ssl,
            username: burnchain_config.username,
            password: burnchain_config.password,
            timeout: burnchain_config.timeout,
            socket_timeout: burnchain_config.socket_timeout,
            spv_headers_path: config.get_spv_headers_file_path(),
            first_block: burnchain_params.first_block_height,
            magic_bytes: burnchain_config.magic_bytes,
            epochs: burnchain_config.epochs,
        }
    };

    let (_, network_type) = config.burnchain.get_bitcoin_network();
    let indexer_runtime = BitcoinIndexerRuntime::new(network_type, indexer_config.timeout);
    BitcoinIndexer {
        config: indexer_config,
        runtime: indexer_runtime,
        should_keep_running,
    }
}

pub fn get_satoshis_per_byte(config: &Config) -> u64 {
    config.get_burnchain_config().satoshis_per_byte
}

pub fn get_rbf_fee_increment(config: &Config) -> u64 {
    config.get_burnchain_config().rbf_fee_increment
}

pub fn get_max_rbf(config: &Config) -> u64 {
    config.get_burnchain_config().max_rbf
}

impl LeaderBlockCommitFees {
    pub fn fees_from_previous_tx(
        &self,
        payload: &LeaderBlockCommitOp,
        config: &Config,
    ) -> LeaderBlockCommitFees {
        let mut fees = LeaderBlockCommitFees::estimated_fees_from_payload(payload, config);
        fees.spent_in_attempts = cmp::max(1, self.spent_in_attempts);
        fees.final_size = self.final_size;
        fees.fee_rate = self.fee_rate + get_rbf_fee_increment(config);
        fees.is_rbf_enabled = true;
        fees
    }

    pub fn estimated_fees_from_payload(
        payload: &LeaderBlockCommitOp,
        config: &Config,
    ) -> LeaderBlockCommitFees {
        let sunset_fee = if payload.sunset_burn > 0 {
            cmp::max(payload.sunset_burn, DUST_UTXO_LIMIT)
        } else {
            0
        };

        let number_of_transfers = payload.commit_outs.len() as u64;
        let value_per_transfer = payload.burn_fee / number_of_transfers;
        let sortition_fee = value_per_transfer * number_of_transfers;
        let spent_in_attempts = 0;
        let fee_rate = get_satoshis_per_byte(config);
        let default_tx_size = config.burnchain.block_commit_tx_estimated_size;

        LeaderBlockCommitFees {
            sunset_fee,
            fee_rate,
            sortition_fee,
            outputs_len: number_of_transfers,
            default_tx_size,
            spent_in_attempts,
            is_rbf_enabled: false,
            final_size: 0,
        }
    }

    pub fn estimated_miner_fee(&self) -> u64 {
        self.fee_rate * self.default_tx_size
    }

    pub fn rbf_fee(&self) -> u64 {
        if self.is_rbf_enabled {
            self.spent_in_attempts + self.default_tx_size
        } else {
            0
        }
    }

    pub fn estimated_amount_required(&self) -> u64 {
        self.estimated_miner_fee() + self.rbf_fee() + self.sunset_fee + self.sortition_fee
    }

    pub fn total_spent(&self) -> u64 {
        self.fee_rate * self.final_size
            + self.spent_in_attempts
            + self.sunset_fee
            + self.sortition_fee
    }

    pub fn amount_per_output(&self) -> u64 {
        self.sortition_fee / self.outputs_len
    }

    pub fn total_spent_in_outputs(&self) -> u64 {
        self.sunset_fee + self.sortition_fee
    }

    pub fn min_tx_size(&self) -> u64 {
        cmp::max(self.final_size, self.default_tx_size)
    }

    pub fn register_replacement(&mut self, tx_size: u64) {
        let new_size = cmp::max(tx_size, self.final_size);
        if self.is_rbf_enabled {
            self.spent_in_attempts += new_size;
        }
        self.final_size = new_size;
    }
}

/// Extension methods for working with [`BitcoinRpcClient`] result
/// that log failures and panic.
#[cfg(test)]
trait BitcoinRpcClientResultExt<T> {
    /// Unwraps the result, returning the value if `Ok`.
    ///
    /// If the result is an `Err`, it logs the error with the given context
    /// using the [`error!`] macro and then panics.
    fn unwrap_or_log_panic(self, context: &str) -> T;
    /// Ensure the result is `Ok`, ignoring its value.
    ///
    /// If the result is an `Err`, it logs the error with the given context
    /// using the [`error!`] macro and then panics.
    fn ok_or_log_panic(self, context: &str);
}

#[cfg(test)]
impl<T> BitcoinRpcClientResultExt<T> for Result<T, BitcoinRpcClientError> {
    fn unwrap_or_log_panic(self, context: &str) -> T {
        match self {
            Ok(val) => val,
            Err(e) => {
                error!("Bitcoin RPC failure: {context} {e:?}");
                panic!();
            }
        }
    }

    fn ok_or_log_panic(self, context: &str) {
        _ = self.unwrap_or_log_panic(context);
    }
}

/// Represents errors that can occur when using [`BitcoinRegtestController`].
#[derive(Debug, thiserror::Error)]
pub enum BitcoinRegtestControllerError {
    /// Error related to Bitcoin RPC failures.
    #[error("Bitcoin RPC error: {0}")]
    Rpc(#[from] BitcoinRpcClientError),
    /// Error related to invalid or malformed [`Secp256k1PublicKey`].
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(btc_error),
}

/// Alias for results returned from [`BitcoinRegtestController`] operations.
pub type BitcoinRegtestControllerResult<T> = Result<T, BitcoinRegtestControllerError>;

impl BitcoinRegtestController {
    pub fn new(config: Config, coordinator_channel: Option<CoordinatorChannels>) -> Self {
        BitcoinRegtestController::with_burnchain(config, coordinator_channel, None, None)
    }

    // TODO: add tests from mutation testing results #4864
    #[cfg_attr(test, mutants::skip)]
    pub fn with_burnchain(
        config: Config,
        coordinator_channel: Option<CoordinatorChannels>,
        burnchain: Option<Burnchain>,
        should_keep_running: Option<Arc<AtomicBool>>,
    ) -> Self {
        std::fs::create_dir_all(config.get_burnchain_path_str()).expect("Unable to create workdir");
        let (_, network_id) = config.burnchain.get_bitcoin_network();

        let res = SpvClient::new(
            &config.get_spv_headers_file_path(),
            0,
            None,
            network_id,
            true,
            false,
        );
        if let Err(err) = res {
            error!("Unable to init block headers: {err}");
            panic!()
        }

        let burnchain_params = burnchain_params_from_config(&config.burnchain);

        if network_id == BitcoinNetworkType::Mainnet && config.burnchain.epochs.is_some() {
            panic!("It is an error to set custom epochs while running on Mainnet: network_id {network_id:?} config.burnchain {:#?}",
                   &config.burnchain);
        }

        let indexer_config = {
            let burnchain_config = config.burnchain.clone();
            BitcoinIndexerConfig {
                peer_host: burnchain_config.peer_host,
                peer_port: burnchain_config.peer_port,
                rpc_port: burnchain_config.rpc_port,
                rpc_ssl: burnchain_config.rpc_ssl,
                username: burnchain_config.username,
                password: burnchain_config.password,
                timeout: burnchain_config.timeout,
                socket_timeout: burnchain_config.socket_timeout,
                spv_headers_path: config.get_spv_headers_file_path(),
                first_block: burnchain_params.first_block_height,
                magic_bytes: burnchain_config.magic_bytes,
                epochs: burnchain_config.epochs,
            }
        };

        let (_, network_type) = config.burnchain.get_bitcoin_network();
        let indexer_runtime = BitcoinIndexerRuntime::new(network_type, config.burnchain.timeout);
        let burnchain_indexer = BitcoinIndexer {
            config: indexer_config,
            runtime: indexer_runtime,
            should_keep_running: should_keep_running.clone(),
        };

        let rpc_client = BitcoinRpcClient::from_stx_config(&config)
            .expect("unable to instantiate the RPC client!");

        Self {
            use_coordinator: coordinator_channel,
            config,
            indexer: burnchain_indexer,
            db: None,
            burnchain_db: None,
            chain_tip: None,
            burnchain_config: burnchain,
            ongoing_block_commit: None,
            should_keep_running,
            rpc_client,
        }
    }

    // TODO: add tests from mutation testing results #4864
    #[cfg_attr(test, mutants::skip)]
    /// create a dummy bitcoin regtest controller.
    ///   used just for submitting bitcoin ops.
    pub fn new_dummy(config: Config) -> Self {
        let burnchain_params = burnchain_params_from_config(&config.burnchain);

        let indexer_config = {
            let burnchain_config = config.burnchain.clone();
            BitcoinIndexerConfig {
                peer_host: burnchain_config.peer_host,
                peer_port: burnchain_config.peer_port,
                rpc_port: burnchain_config.rpc_port,
                rpc_ssl: burnchain_config.rpc_ssl,
                username: burnchain_config.username,
                password: burnchain_config.password,
                timeout: burnchain_config.timeout,
                socket_timeout: burnchain_config.socket_timeout,
                spv_headers_path: config.get_spv_headers_file_path(),
                first_block: burnchain_params.first_block_height,
                magic_bytes: burnchain_config.magic_bytes,
                epochs: burnchain_config.epochs,
            }
        };

        let (_, network_type) = config.burnchain.get_bitcoin_network();
        let indexer_runtime = BitcoinIndexerRuntime::new(network_type, config.burnchain.timeout);
        let burnchain_indexer = BitcoinIndexer {
            config: indexer_config,
            runtime: indexer_runtime,
            should_keep_running: None,
        };

        let rpc_client = BitcoinRpcClient::from_stx_config(&config)
            .expect("unable to instantiate the RPC client!");

        Self {
            use_coordinator: None,
            config,
            indexer: burnchain_indexer,
            db: None,
            burnchain_db: None,
            chain_tip: None,
            burnchain_config: None,
            ongoing_block_commit: None,
            should_keep_running: None,
            rpc_client,
        }
    }

    /// Creates a dummy bitcoin regtest controller, with the given ongoing block-commits
    pub fn new_ongoing_dummy(config: Config, ongoing: Option<OngoingBlockCommit>) -> Self {
        let mut ret = Self::new_dummy(config);
        ret.ongoing_block_commit = ongoing;
        ret
    }

    /// Get an owned copy of the ongoing block commit state
    pub fn get_ongoing_commit(&self) -> Option<OngoingBlockCommit> {
        self.ongoing_block_commit.clone()
    }

    /// Set the ongoing block commit state
    pub fn set_ongoing_commit(&mut self, ongoing: Option<OngoingBlockCommit>) {
        self.ongoing_block_commit = ongoing;
    }

    /// Get the default Burnchain instance from our config
    fn default_burnchain(&self) -> Burnchain {
        match &self.burnchain_config {
            Some(burnchain) => burnchain.clone(),
            None => self.config.get_burnchain(),
        }
    }

    /// Get the PoX constants in use
    pub fn get_pox_constants(&self) -> PoxConstants {
        let burnchain = self.get_burnchain();
        burnchain.pox_constants
    }

    /// Get the Burnchain in use
    pub fn get_burnchain(&self) -> Burnchain {
        match self.burnchain_config {
            Some(ref burnchain) => burnchain.clone(),
            None => self.default_burnchain(),
        }
    }

    /// Helium (devnet) blocks receiver.  Returns the new burnchain tip.
    fn receive_blocks_helium(&mut self) -> BurnchainTip {
        let mut burnchain = self.get_burnchain();
        let (block_snapshot, state_transition) = loop {
            match burnchain.sync_with_indexer_deprecated(&mut self.indexer) {
                Ok(x) => {
                    break x;
                }
                Err(e) => {
                    // keep trying
                    error!("Unable to sync with burnchain: {e}");
                    match e {
                        burnchain_error::TrySyncAgain => {
                            // try again immediately
                            continue;
                        }
                        burnchain_error::BurnchainPeerBroken => {
                            // remote burnchain peer broke, and produced a shorter blockchain fork.
                            // just keep trying
                            sleep_ms(5000);
                            continue;
                        }
                        _ => {
                            // delay and try again
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let rest = match (state_transition, &self.chain_tip) {
            (None, Some(chain_tip)) => chain_tip.clone(),
            (Some(state_transition), _) => {
                let burnchain_tip = BurnchainTip {
                    block_snapshot,
                    state_transition: BurnchainStateTransitionOps::from(state_transition),
                    received_at: Instant::now(),
                };
                self.chain_tip = Some(burnchain_tip.clone());
                burnchain_tip
            }
            (None, None) => {
                // can happen at genesis
                let burnchain_tip = BurnchainTip {
                    block_snapshot,
                    state_transition: BurnchainStateTransitionOps::noop(),
                    received_at: Instant::now(),
                };
                self.chain_tip = Some(burnchain_tip.clone());
                burnchain_tip
            }
        };

        debug!("Done receiving blocks");
        rest
    }

    fn receive_blocks(
        &mut self,
        block_for_sortitions: bool,
        target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), BurnchainControllerError> {
        let coordinator_comms = match self.use_coordinator.as_ref() {
            Some(x) => x.clone(),
            None => {
                // pre-PoX helium node
                let tip = self.receive_blocks_helium();
                let height = tip.block_snapshot.block_height;
                return Ok((tip, height));
            }
        };

        let mut burnchain = self.get_burnchain();
        let (block_snapshot, burnchain_height, state_transition) = loop {
            if !self.should_keep_running() {
                return Err(BurnchainControllerError::CoordinatorClosed);
            }

            match burnchain.sync_with_indexer(
                &mut self.indexer,
                coordinator_comms.clone(),
                target_block_height_opt,
                Some(burnchain.pox_constants.reward_cycle_length as u64),
                self.should_keep_running.clone(),
            ) {
                Ok(x) => {
                    increment_btc_blocks_received_counter();

                    // initialize the dbs...
                    self.sortdb_mut();

                    // wait for the chains coordinator to catch up with us.
                    // don't wait for heights beyond the burnchain tip.
                    if block_for_sortitions {
                        self.wait_for_sortitions(
                            coordinator_comms,
                            target_block_height_opt.unwrap_or(x.block_height),
                        )?;
                    }

                    // NOTE: This is the latest _sortition_ on the canonical sortition history, not the latest burnchain block!
                    let sort_tip =
                        SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
                            .expect("Sortition DB error.");

                    let (snapshot, state_transition) = self
                        .sortdb_ref()
                        .get_sortition_result(&sort_tip.sortition_id)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");

                    let burnchain_height = self
                        .indexer
                        .get_highest_header_height()
                        .map_err(BurnchainControllerError::IndexerError)?;
                    break (snapshot, burnchain_height, state_transition);
                }
                Err(e) => {
                    // keep trying
                    error!("Unable to sync with burnchain: {e}");
                    match e {
                        burnchain_error::CoordinatorClosed => {
                            return Err(BurnchainControllerError::CoordinatorClosed)
                        }
                        burnchain_error::TrySyncAgain => {
                            // try again immediately
                            continue;
                        }
                        burnchain_error::BurnchainPeerBroken => {
                            // remote burnchain peer broke, and produced a shorter blockchain fork.
                            // just keep trying
                            sleep_ms(5000);
                            continue;
                        }
                        _ => {
                            // delay and try again
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let burnchain_tip = BurnchainTip {
            block_snapshot,
            state_transition,
            received_at: Instant::now(),
        };

        let received = self
            .chain_tip
            .as_ref()
            .map(|tip| tip.block_snapshot.block_height)
            .unwrap_or(0)
            == burnchain_tip.block_snapshot.block_height;
        self.chain_tip = Some(burnchain_tip.clone());
        debug!("Done receiving blocks");

        if self.config.burnchain.fault_injection_burnchain_block_delay > 0 && received {
            info!(
                "Fault injection: delaying burnchain blocks by {} milliseconds",
                self.config.burnchain.fault_injection_burnchain_block_delay
            );
            sleep_ms(self.config.burnchain.fault_injection_burnchain_block_delay);
        }

        Ok((burnchain_tip, burnchain_height))
    }

    fn should_keep_running(&self) -> bool {
        match self.should_keep_running {
            Some(ref should_keep_running) => should_keep_running.load(Ordering::SeqCst),
            _ => true,
        }
    }

    #[cfg(test)]
    pub fn get_all_utxos(&self, public_key: &Secp256k1PublicKey) -> Vec<UTXO> {
        // Configure UTXO filter, disregard what epoch we're in
        let address = self.get_miner_address(StacksEpochId::Epoch21, public_key);
        let filter_addresses = vec![address.to_string()];

        let pubk = if self.config.miner.segwit {
            let mut p = public_key.clone();
            p.set_compressed(true);
            p
        } else {
            public_key.clone()
        };

        test_debug!("Import public key '{}'", &pubk.to_hex());
        let result = self.import_public_key(&pubk);
        if let Err(error) = result {
            warn!("Import public key '{}' failed: {error:?}", &pubk.to_hex());
        }

        sleep_ms(1000);

        let min_conf = 0i64;
        let max_conf = 9999999i64;
        let minimum_amount = ParsedUTXO::sat_to_serialized_btc(1);

        test_debug!("List unspent for '{address}' ('{}')", pubk.to_hex());
        let payload = BitcoinRPCRequest {
            method: "listunspent".to_string(),
            params: vec![
                min_conf.into(),
                max_conf.into(),
                filter_addresses.into(),
                true.into(),
                json!({ "minimumAmount": minimum_amount, "maximumCount": self.config.burnchain.max_unspent_utxos }),
            ],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let mut res = BitcoinRPCRequest::send(&self.config, payload).unwrap();
        let mut result_vec = vec![];

        if let Some(ref mut object) = res.as_object_mut() {
            match object.get_mut("result") {
                Some(serde_json::Value::Array(entries)) => {
                    while let Some(entry) = entries.pop() {
                        let parsed_utxo: ParsedUTXO = match serde_json::from_value(entry) {
                            Ok(utxo) => utxo,
                            Err(err) => {
                                warn!("Failed parsing UTXO: {err}");
                                continue;
                            }
                        };
                        let amount = match parsed_utxo.get_sat_amount() {
                            Some(amount) => amount,
                            None => continue,
                        };

                        if amount < 1 {
                            continue;
                        }

                        let script_pub_key = match parsed_utxo.get_script_pub_key() {
                            Some(script_pub_key) => script_pub_key,
                            None => {
                                continue;
                            }
                        };

                        let txid = match parsed_utxo.get_txid() {
                            Some(amount) => amount,
                            None => continue,
                        };

                        result_vec.push(UTXO {
                            txid,
                            vout: parsed_utxo.vout,
                            script_pub_key,
                            amount,
                            confirmations: parsed_utxo.confirmations,
                        });
                    }
                }
                _ => {
                    warn!("Failed to get UTXOs");
                }
            }
        }

        result_vec
    }

    /// Retrieve all loaded wallets.
    pub fn list_wallets(&self) -> BitcoinRegtestControllerResult<Vec<String>> {
        Ok(self.rpc_client.list_wallets()?)
    }

    /// Checks if the config-supplied wallet exists.
    /// If it does not exist, this function creates it.
    pub fn create_wallet_if_dne(&self) -> BitcoinRegtestControllerResult<()> {
        let wallets = self.list_wallets()?;
        let wallet = self.get_wallet_name();
        if !wallets.contains(wallet) {
            self.rpc_client.create_wallet(wallet, Some(true))?
        }
        Ok(())
    }

    pub fn get_utxos(
        &self,
        epoch_id: StacksEpochId,
        public_key: &Secp256k1PublicKey,
        total_required: u64,
        utxos_to_exclude: Option<UTXOSet>,
        block_height: u64,
    ) -> Option<UTXOSet> {
        let pubk = if self.config.miner.segwit && epoch_id >= StacksEpochId::Epoch21 {
            let mut p = public_key.clone();
            p.set_compressed(true);
            p
        } else {
            public_key.clone()
        };

        // Configure UTXO filter
        let address = self.get_miner_address(epoch_id, &pubk);
        test_debug!("Get UTXOs for {} ({address})", pubk.to_hex());
        let filter_addresses = vec![address.to_string()];

        let mut utxos = loop {
            let result = BitcoinRPCRequest::list_unspent(
                &self.config,
                filter_addresses.clone(),
                false,
                total_required,
                &utxos_to_exclude,
                block_height,
            );

            // Perform request
            match result {
                Ok(utxos) => {
                    break utxos;
                }
                Err(e) => {
                    error!("Bitcoin RPC failure: error listing utxos {e:?}");
                    sleep_ms(5000);
                    continue;
                }
            };
        };

        let utxos = if utxos.is_empty() {
            let (_, network) = self.config.burnchain.get_bitcoin_network();
            loop {
                if let BitcoinNetworkType::Regtest = network {
                    // Performing this operation on Mainnet / Testnet is very expensive, and can be longer than bitcoin block time.
                    // Assuming that miners are in charge of correctly operating their bitcoind nodes sounds
                    // reasonable to me.
                    // $ bitcoin-cli importaddress mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk
                    let result = self.import_public_key(&pubk);
                    if let Err(error) = result {
                        warn!("Import public key '{}' failed: {error:?}", &pubk.to_hex());
                    }
                    sleep_ms(1000);
                }

                let result = BitcoinRPCRequest::list_unspent(
                    &self.config,
                    filter_addresses.clone(),
                    false,
                    total_required,
                    &utxos_to_exclude,
                    block_height,
                );

                utxos = match result {
                    Ok(utxos) => utxos,
                    Err(e) => {
                        error!("Bitcoin RPC failure: error listing utxos {e:?}");
                        sleep_ms(5000);
                        continue;
                    }
                };

                test_debug!("Unspent for {filter_addresses:?}: {utxos:?}");

                if utxos.is_empty() {
                    return None;
                } else {
                    break utxos;
                }
            }
        } else {
            debug!("Got {} UTXOs for {filter_addresses:?}", utxos.utxos.len(),);
            utxos
        };

        let total_unspent = utxos.total_available();
        if total_unspent < total_required {
            warn!(
                "Total unspent {total_unspent} < {total_required} for {:?}",
                &pubk.to_hex()
            );
            return None;
        }

        Some(utxos)
    }

    fn build_leader_key_register_tx(
        &mut self,
        epoch_id: StacksEpochId,
        payload: LeaderKeyRegisterOp,
        signer: &mut BurnchainOpSigner,
    ) -> Result<Transaction, BurnchainControllerError> {
        let public_key = signer.get_public_key();

        // reload the config to find satoshis_per_byte changes
        let btc_miner_fee = self.config.burnchain.leader_key_tx_estimated_size
            * get_satoshis_per_byte(&self.config);
        let budget_for_outputs = DUST_UTXO_LIMIT;
        let total_required = btc_miner_fee + budget_for_outputs;

        let (mut tx, mut utxos) =
            self.prepare_tx(epoch_id, &public_key, total_required, None, None, 0)?;

        // Serialize the payload
        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            payload
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];

        let fee_rate = get_satoshis_per_byte(&self.config);

        self.finalize_tx(
            epoch_id,
            &mut tx,
            budget_for_outputs,
            0,
            self.config.burnchain.leader_key_tx_estimated_size,
            fee_rate,
            &mut utxos,
            signer,
            true, // key register op requires change output to exist
        );

        increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting leader_key_register op - {}, waiting for its inclusion in the next Bitcoin block",
            public_key.to_hex()
        );

        Ok(tx)
    }

    #[cfg(not(test))]
    fn build_transfer_stacks_tx(
        &mut self,
        _epoch_id: StacksEpochId,
        _payload: TransferStxOp,
        _signer: &mut BurnchainOpSigner,
        _utxo: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        unimplemented!()
    }

    #[cfg(not(test))]
    fn build_delegate_stacks_tx(
        &mut self,
        _epoch_id: StacksEpochId,
        _payload: DelegateStxOp,
        _signer: &mut BurnchainOpSigner,
        _utxo: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        unimplemented!()
    }

    #[cfg(test)]
    pub fn submit_manual(
        &mut self,
        epoch_id: StacksEpochId,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
        utxo: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        let transaction = match operation {
            BlockstackOperationType::LeaderBlockCommit(_)
            | BlockstackOperationType::LeaderKeyRegister(_)
            | BlockstackOperationType::StackStx(_)
            | BlockstackOperationType::DelegateStx(_)
            | BlockstackOperationType::VoteForAggregateKey(_) => {
                unimplemented!();
            }
            BlockstackOperationType::PreStx(payload) => {
                self.build_pre_stacks_tx(epoch_id, payload, op_signer)
            }
            BlockstackOperationType::TransferStx(payload) => {
                self.build_transfer_stacks_tx(epoch_id, payload, op_signer, utxo)
            }
        }?;
        self.send_transaction(&transaction).map(|_| transaction)
    }

    #[cfg(test)]
    /// Build a transfer stacks tx.
    ///   this *only* works if the only existant UTXO is from a PreStx Op
    ///   this is okay for testing, but obviously not okay for actual use.
    ///   The reason for this constraint is that the bitcoin_regtest_controller's UTXO
    ///     and signing logic are fairly intertwined, and untangling the two seems excessive
    ///     for a functionality that won't be implemented for production via this controller.
    fn build_transfer_stacks_tx(
        &mut self,
        epoch_id: StacksEpochId,
        payload: TransferStxOp,
        signer: &mut BurnchainOpSigner,
        utxo_to_use: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        let public_key = signer.get_public_key();
        let max_tx_size = OP_TX_TRANSFER_STACKS_ESTIM_SIZE;
        let (mut tx, mut utxos) = if let Some(utxo) = utxo_to_use {
            (
                Transaction {
                    input: vec![],
                    output: vec![],
                    version: 1,
                    lock_time: 0,
                },
                UTXOSet {
                    bhh: BurnchainHeaderHash::zero(),
                    utxos: vec![utxo],
                },
            )
        } else {
            self.prepare_tx(
                epoch_id,
                &public_key,
                DUST_UTXO_LIMIT + max_tx_size * get_satoshis_per_byte(&self.config),
                None,
                None,
                0,
            )?
        };

        // Serialize the payload
        let op_bytes = {
            let mut bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            payload
                .consensus_serialize(&mut bytes)
                .map_err(BurnchainControllerError::SerializerError)?;
            bytes
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];
        tx.output
            .push(PoxAddress::Standard(payload.recipient, None).to_bitcoin_tx_out(DUST_UTXO_LIMIT));

        self.finalize_tx(
            epoch_id,
            &mut tx,
            DUST_UTXO_LIMIT,
            0,
            max_tx_size,
            get_satoshis_per_byte(&self.config),
            &mut utxos,
            signer,
            false,
        );

        increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting stacks transfer op - {}",
            public_key.to_hex()
        );

        Ok(tx)
    }

    #[cfg(test)]
    /// Build a delegate stacks tx.
    ///   this *only* works if the only existant UTXO is from a PreStx Op
    ///   this is okay for testing, but obviously not okay for actual use.
    ///   The reason for this constraint is that the bitcoin_regtest_controller's UTXO
    ///     and signing logic are fairly intertwined, and untangling the two seems excessive
    ///     for a functionality that won't be implemented for production via this controller.
    fn build_delegate_stacks_tx(
        &mut self,
        epoch_id: StacksEpochId,
        payload: DelegateStxOp,
        signer: &mut BurnchainOpSigner,
        utxo_to_use: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        let public_key = signer.get_public_key();
        let max_tx_size = OP_TX_DELEGATE_STACKS_ESTIM_SIZE;

        let (mut tx, mut utxos) = if let Some(utxo) = utxo_to_use {
            (
                Transaction {
                    input: vec![],
                    output: vec![],
                    version: 1,
                    lock_time: 0,
                },
                UTXOSet {
                    bhh: BurnchainHeaderHash::zero(),
                    utxos: vec![utxo],
                },
            )
        } else {
            self.prepare_tx(
                epoch_id,
                &public_key,
                DUST_UTXO_LIMIT + max_tx_size * get_satoshis_per_byte(&self.config),
                None,
                None,
                0,
            )?
        };

        // Serialize the payload
        let op_bytes = {
            let mut bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            payload
                .consensus_serialize(&mut bytes)
                .map_err(BurnchainControllerError::SerializerError)?;
            bytes
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];
        tx.output.push(
            PoxAddress::Standard(payload.delegate_to, None).to_bitcoin_tx_out(DUST_UTXO_LIMIT),
        );

        self.finalize_tx(
            epoch_id,
            &mut tx,
            DUST_UTXO_LIMIT,
            0,
            max_tx_size,
            get_satoshis_per_byte(&self.config),
            &mut utxos,
            signer,
            false,
        );

        increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting stacks delegate op - {}",
            public_key.to_hex()
        );

        Ok(tx)
    }

    #[cfg(test)]
    /// Build a vote-for-aggregate-key burn op tx
    fn build_vote_for_aggregate_key_tx(
        &mut self,
        epoch_id: StacksEpochId,
        payload: VoteForAggregateKeyOp,
        signer: &mut BurnchainOpSigner,
        utxo_to_use: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        let public_key = signer.get_public_key();
        let max_tx_size = OP_TX_VOTE_AGG_ESTIM_SIZE;

        let (mut tx, mut utxos) = if let Some(utxo) = utxo_to_use {
            (
                Transaction {
                    input: vec![],
                    output: vec![],
                    version: 1,
                    lock_time: 0,
                },
                UTXOSet {
                    bhh: BurnchainHeaderHash::zero(),
                    utxos: vec![utxo],
                },
            )
        } else {
            self.prepare_tx(
                epoch_id,
                &public_key,
                DUST_UTXO_LIMIT + max_tx_size * get_satoshis_per_byte(&self.config),
                None,
                None,
                0,
            )?
        };

        // Serialize the payload
        let op_bytes = {
            let mut bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            payload
                .consensus_serialize(&mut bytes)
                .map_err(BurnchainControllerError::SerializerError)?;
            bytes
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];

        self.finalize_tx(
            epoch_id,
            &mut tx,
            DUST_UTXO_LIMIT,
            0,
            max_tx_size,
            get_satoshis_per_byte(&self.config),
            &mut utxos,
            signer,
            false,
        );

        increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting vote for aggregate key op - {}",
            public_key.to_hex()
        );

        Ok(tx)
    }

    #[cfg(not(test))]
    /// Build a vote-for-aggregate-key burn op tx
    fn build_vote_for_aggregate_key_tx(
        &mut self,
        _epoch_id: StacksEpochId,
        _payload: VoteForAggregateKeyOp,
        _signer: &mut BurnchainOpSigner,
        _utxo_to_use: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        unimplemented!()
    }

    #[cfg(not(test))]
    fn build_pre_stacks_tx(
        &mut self,
        _epoch_id: StacksEpochId,
        _payload: PreStxOp,
        _signer: &mut BurnchainOpSigner,
    ) -> Result<Transaction, BurnchainControllerError> {
        unimplemented!()
    }

    #[cfg(test)]
    fn build_pre_stacks_tx(
        &mut self,
        epoch_id: StacksEpochId,
        payload: PreStxOp,
        signer: &mut BurnchainOpSigner,
    ) -> Result<Transaction, BurnchainControllerError> {
        let public_key = signer.get_public_key();
        let max_tx_size = OP_TX_PRE_STACKS_ESTIM_SIZE;

        let max_tx_size_any_op = OP_TX_ANY_ESTIM_SIZE;
        let output_amt = DUST_UTXO_LIMIT + max_tx_size_any_op * get_satoshis_per_byte(&self.config);

        let (mut tx, mut utxos) =
            self.prepare_tx(epoch_id, &public_key, output_amt, None, None, 0)?;

        // Serialize the payload
        let op_bytes = {
            let mut bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            bytes.push(Opcodes::PreStx as u8);
            bytes
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];
        tx.output
            .push(PoxAddress::Standard(payload.output, None).to_bitcoin_tx_out(output_amt));

        self.finalize_tx(
            epoch_id,
            &mut tx,
            output_amt,
            0,
            max_tx_size,
            get_satoshis_per_byte(&self.config),
            &mut utxos,
            signer,
            false,
        );

        increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting pre_stacks op - {}",
            public_key.to_hex()
        );

        Ok(tx)
    }

    #[cfg_attr(test, mutants::skip)]
    #[cfg(not(test))]
    fn build_stack_stx_tx(
        &mut self,
        _epoch_id: StacksEpochId,
        _payload: StackStxOp,
        _signer: &mut BurnchainOpSigner,
        _utxo_to_use: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        unimplemented!()
    }

    #[cfg(test)]
    fn build_stack_stx_tx(
        &mut self,
        epoch_id: StacksEpochId,
        payload: StackStxOp,
        signer: &mut BurnchainOpSigner,
        utxo_to_use: Option<UTXO>,
    ) -> Result<Transaction, BurnchainControllerError> {
        let public_key = signer.get_public_key();
        let max_tx_size = OP_TX_STACK_STX_ESTIM_SIZE;

        let (mut tx, mut utxos) = if let Some(utxo) = utxo_to_use {
            (
                Transaction {
                    input: vec![],
                    output: vec![],
                    version: 1,
                    lock_time: 0,
                },
                UTXOSet {
                    bhh: BurnchainHeaderHash::zero(),
                    utxos: vec![utxo],
                },
            )
        } else {
            self.prepare_tx(
                epoch_id,
                &public_key,
                DUST_UTXO_LIMIT + max_tx_size * get_satoshis_per_byte(&self.config),
                None,
                None,
                0,
            )?
        };

        // Serialize the payload
        let op_bytes = {
            let mut bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            payload
                .consensus_serialize(&mut bytes)
                .map_err(BurnchainControllerError::SerializerError)?;
            bytes
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];
        tx.output
            .push(payload.reward_addr.to_bitcoin_tx_out(DUST_UTXO_LIMIT));

        self.finalize_tx(
            epoch_id,
            &mut tx,
            DUST_UTXO_LIMIT,
            0,
            max_tx_size,
            get_satoshis_per_byte(&self.config),
            &mut utxos,
            signer,
            false,
        );

        increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting stack-stx op - {}",
            public_key.to_hex()
        );

        Ok(tx)
    }

    fn magic_bytes(&self) -> Vec<u8> {
        #[cfg(test)]
        {
            if let Some(set_bytes) = *TEST_MAGIC_BYTES
                .lock()
                .expect("FATAL: test magic bytes mutex poisoned")
            {
                return set_bytes.to_vec();
            }
        }
        self.config.burnchain.magic_bytes.as_bytes().to_vec()
    }

    #[allow(clippy::too_many_arguments)]
    fn send_block_commit_operation(
        &mut self,
        epoch_id: StacksEpochId,
        payload: LeaderBlockCommitOp,
        signer: &mut BurnchainOpSigner,
        utxos_to_include: Option<UTXOSet>,
        utxos_to_exclude: Option<UTXOSet>,
        previous_fees: Option<LeaderBlockCommitFees>,
        previous_txids: &[Txid],
    ) -> Result<Transaction, BurnchainControllerError> {
        let _ = self.sortdb_mut();
        let burn_chain_tip = self
            .burnchain_db
            .as_ref()
            .ok_or(BurnchainControllerError::BurnchainError)?
            .get_canonical_chain_tip()
            .map_err(|_| BurnchainControllerError::BurnchainError)?;
        let estimated_fees = match previous_fees {
            Some(fees) => fees.fees_from_previous_tx(&payload, &self.config),
            None => LeaderBlockCommitFees::estimated_fees_from_payload(&payload, &self.config),
        };

        self.send_block_commit_operation_at_burnchain_height(
            epoch_id,
            payload,
            signer,
            utxos_to_include,
            utxos_to_exclude,
            estimated_fees,
            previous_txids,
            burn_chain_tip.block_height,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn send_block_commit_operation_at_burnchain_height(
        &mut self,
        epoch_id: StacksEpochId,
        payload: LeaderBlockCommitOp,
        signer: &mut BurnchainOpSigner,
        utxos_to_include: Option<UTXOSet>,
        utxos_to_exclude: Option<UTXOSet>,
        mut estimated_fees: LeaderBlockCommitFees,
        previous_txids: &[Txid],
        burnchain_block_height: u64,
    ) -> Result<Transaction, BurnchainControllerError> {
        let public_key = signer.get_public_key();
        let (mut tx, mut utxos) = self.prepare_tx(
            epoch_id,
            &public_key,
            estimated_fees.estimated_amount_required(),
            utxos_to_include,
            utxos_to_exclude,
            burnchain_block_height,
        )?;

        // Serialize the payload
        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = self.magic_bytes();
            buffer.append(&mut magic_bytes);
            payload
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let consensus_output = TxOut {
            value: estimated_fees.sunset_fee,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];

        for commit_to in payload.commit_outs.iter() {
            tx.output
                .push(commit_to.to_bitcoin_tx_out(estimated_fees.amount_per_output()));
        }

        let fee_rate = estimated_fees.fee_rate;
        self.finalize_tx(
            epoch_id,
            &mut tx,
            estimated_fees.total_spent_in_outputs(),
            estimated_fees.spent_in_attempts,
            estimated_fees.min_tx_size(),
            fee_rate,
            &mut utxos,
            signer,
            true, // block commit op requires change output to exist
        );
        debug!("Transaction relying on UTXOs: {utxos:?}");

        let serialized_tx = serialize(&tx).expect("BUG: failed to serialize to a vec");
        let tx_size = serialized_tx.len() as u64;
        estimated_fees.register_replacement(tx_size);

        let txid = Txid::from_bitcoin_tx_hash(&tx.txid());
        let mut txids = previous_txids.to_vec();
        txids.push(txid);

        let ongoing_block_commit = OngoingBlockCommit {
            payload,
            utxos,
            fees: estimated_fees,
            txids,
        };

        info!(
            "Miner node: submitting leader_block_commit (txid: {}, rbf: {}, total spent: {}, size: {}, fee_rate: {fee_rate})",
            txid.to_hex(),
            ongoing_block_commit.fees.is_rbf_enabled,
            ongoing_block_commit.fees.total_spent(),
            ongoing_block_commit.fees.final_size
        );

        self.ongoing_block_commit = Some(ongoing_block_commit);

        increment_btc_ops_sent_counter();

        Ok(tx)
    }

    fn build_leader_block_commit_tx(
        &mut self,
        epoch_id: StacksEpochId,
        payload: LeaderBlockCommitOp,
        signer: &mut BurnchainOpSigner,
    ) -> Result<Transaction, BurnchainControllerError> {
        // Are we currently tracking an operation?
        if self.ongoing_block_commit.is_none() {
            // Good to go, let's build the transaction and send it.
            let res =
                self.send_block_commit_operation(epoch_id, payload, signer, None, None, None, &[]);
            return res;
        }

        let ongoing_op = self.ongoing_block_commit.take().unwrap();

        let _ = self.sortdb_mut();
        let burnchain_db = self.burnchain_db.as_ref().expect("BurnchainDB not opened");

        for txid in ongoing_op.txids.iter() {
            // check if ongoing_op is in the burnchain_db *or* has been confirmed via the bitcoin RPC
            let mined_op = burnchain_db.find_burnchain_op(&self.indexer, txid);
            let ongoing_tx_confirmed = mined_op.is_some() || self.is_transaction_confirmed(txid);

            test_debug!("Ongoing Tx confirmed: {ongoing_tx_confirmed} - TXID: {txid}");
            if ongoing_tx_confirmed {
                if ongoing_op.payload == payload {
                    info!("Abort attempt to re-submit confirmed LeaderBlockCommit");
                    self.ongoing_block_commit = Some(ongoing_op);
                    return Err(BurnchainControllerError::IdenticalOperation);
                }

                debug!("Was able to retrieve confirmation of ongoing burnchain TXID - {txid}");
                let res = self.send_block_commit_operation(
                    epoch_id,
                    payload,
                    signer,
                    None,
                    None,
                    None,
                    &[],
                );
                return res;
            } else {
                debug!("Was unable to retrieve ongoing TXID - {txid}");
            };
        }

        // Did a re-org occur since we fetched our UTXOs, or are the UTXOs so stale that they should be abandoned?
        let mut traversal_depth = 0;
        let mut burn_chain_tip = burnchain_db
            .get_canonical_chain_tip()
            .map_err(|_| BurnchainControllerError::BurnchainError)?;
        let mut found_last_mined_at = false;
        while traversal_depth < UTXO_CACHE_STALENESS_LIMIT {
            if burn_chain_tip.block_hash == ongoing_op.utxos.bhh {
                found_last_mined_at = true;
                break;
            }

            let parent = BurnchainDB::get_burnchain_block(
                burnchain_db.conn(),
                &burn_chain_tip.parent_block_hash,
            )
            .map_err(|_| BurnchainControllerError::BurnchainError)?;

            burn_chain_tip = parent.header;
            traversal_depth += 1;
        }

        if !found_last_mined_at {
            info!(
                "Possible presence of fork or stale UTXO cache, invalidating cached set of UTXOs.";
                "cached_burn_block_hash" => %ongoing_op.utxos.bhh,
            );
            let res =
                self.send_block_commit_operation(epoch_id, payload, signer, None, None, None, &[]);
            return res;
        }

        // Stop as soon as the fee_rate is ${self.config.burnchain.max_rbf} percent higher, stop RBF
        if ongoing_op.fees.fee_rate
            > (get_satoshis_per_byte(&self.config) * get_max_rbf(&self.config) / 100)
        {
            warn!(
                "RBF'd block commits reached {}% satoshi per byte fee rate, not resubmitting",
                get_max_rbf(&self.config)
            );
            self.ongoing_block_commit = Some(ongoing_op);
            return Err(BurnchainControllerError::MaxFeeRateExceeded);
        }

        // An ongoing operation is in the mempool and we received a new block. The desired behaviour is the following:
        // (1) If the ongoing and the incoming operation are **strictly** identical, we will be idempotent and discard the incoming.
        // (2) If the 2 operations are different, attempt to RBF the outgoing transaction:

        // Let's start by early returning (1)
        if payload == ongoing_op.payload {
            info!("Abort attempt to re-submit identical LeaderBlockCommit");
            self.ongoing_block_commit = Some(ongoing_op);
            return Err(BurnchainControllerError::IdenticalOperation);
        }

        // If we reach this point, we are attempting to RBF the ongoing operation (2)
        info!(
            "Attempt to replace by fee an outdated leader block commit";
            "ongoing_txids" => ?ongoing_op.txids
        );
        let res = self.send_block_commit_operation(
            epoch_id,
            payload,
            signer,
            Some(ongoing_op.utxos.clone()),
            None,
            Some(ongoing_op.fees.clone()),
            &ongoing_op.txids,
        );

        if res.is_err() {
            self.ongoing_block_commit = Some(ongoing_op);
        }

        res
    }

    pub(crate) fn get_miner_address(
        &self,
        epoch_id: StacksEpochId,
        public_key: &Secp256k1PublicKey,
    ) -> BitcoinAddress {
        let (_, network_id) = self.config.burnchain.get_bitcoin_network();

        if self.config.miner.segwit && epoch_id >= StacksEpochId::Epoch21 {
            let hash160 = Hash160::from_data(&public_key.to_bytes_compressed());
            BitcoinAddress::from_bytes_segwit_p2wpkh(network_id, &hash160.0)
                .expect("Public key incorrect")
        } else {
            let hash160 = Hash160::from_data(&public_key.to_bytes());
            BitcoinAddress::from_bytes_legacy(
                network_id,
                LegacyBitcoinAddressType::PublicKeyHash,
                &hash160.0,
            )
            .expect("Public key incorrect")
        }
    }

    // TODO: add tests from mutation testing results #4865
    #[cfg_attr(test, mutants::skip)]
    fn prepare_tx(
        &mut self,
        epoch_id: StacksEpochId,
        public_key: &Secp256k1PublicKey,
        total_required: u64,
        utxos_to_include: Option<UTXOSet>,
        utxos_to_exclude: Option<UTXOSet>,
        block_height: u64,
    ) -> Result<(Transaction, UTXOSet), BurnchainControllerError> {
        let utxos = if let Some(utxos) = utxos_to_include {
            // in RBF, you have to consume the same UTXOs
            utxos
        } else {
            // if mock mining, do not even bother requesting UTXOs
            if self.config.node.mock_mining {
                return Err(BurnchainControllerError::NoUTXOs);
            }

            // Fetch some UTXOs
            let addr = self.get_miner_address(epoch_id, public_key);
            match self.get_utxos(
                epoch_id,
                public_key,
                total_required,
                utxos_to_exclude,
                block_height,
            ) {
                Some(utxos) => utxos,
                None => {
                    warn!(
                        "No UTXOs for {} ({addr}) in epoch {epoch_id}",
                        &public_key.to_hex(),
                    );
                    return Err(BurnchainControllerError::NoUTXOs);
                }
            }
        };

        // Prepare a backbone for the tx
        let transaction = Transaction {
            input: vec![],
            output: vec![],
            version: 1,
            lock_time: 0,
        };

        Ok((transaction, utxos))
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_tx(
        &mut self,
        epoch_id: StacksEpochId,
        tx: &mut Transaction,
        spent_in_outputs: u64,
        spent_in_rbf: u64,
        min_tx_size: u64,
        fee_rate: u64,
        utxos_set: &mut UTXOSet,
        signer: &mut BurnchainOpSigner,
        force_change_output: bool,
    ) {
        // spend UTXOs in order by confirmations.  Spend the least-confirmed UTXO first, and in the
        // event of a tie, spend the smallest-value UTXO first.
        utxos_set.utxos.sort_by(|u1, u2| {
            if u1.confirmations != u2.confirmations {
                u1.confirmations.cmp(&u2.confirmations)
            } else {
                // for block-commits, the smaller value is likely the UTXO-chained value, so
                // continue to prioritize it as the first spend in order to avoid breaking the
                // miner commit chain.
                u1.amount.cmp(&u2.amount)
            }
        });

        let tx_size = {
            // We will be calling 2 times serialize_tx, the first time with an estimated size,
            // Second time with the actual size, computed thanks to the 1st attempt.
            let estimated_rbf = if spent_in_rbf == 0 {
                0
            } else {
                spent_in_rbf + min_tx_size // we're spending 1 sat / byte in RBF
            };
            let mut tx_cloned = tx.clone();
            let mut utxos_cloned = utxos_set.clone();
            self.serialize_tx(
                epoch_id,
                &mut tx_cloned,
                spent_in_outputs + min_tx_size * fee_rate + estimated_rbf,
                &mut utxos_cloned,
                signer,
                force_change_output,
            );
            let serialized_tx = serialize(&tx_cloned).expect("BUG: failed to serialize to a vec");
            cmp::max(min_tx_size, serialized_tx.len() as u64)
        };

        let rbf_fee = if spent_in_rbf == 0 {
            0
        } else {
            spent_in_rbf + tx_size // we're spending 1 sat / byte in RBF
        };
        self.serialize_tx(
            epoch_id,
            tx,
            spent_in_outputs + tx_size * fee_rate + rbf_fee,
            utxos_set,
            signer,
            force_change_output,
        );
        signer.dispose();
    }

    /// Sign and serialize a tx, consuming the UTXOs in utxo_set and spending total_to_spend
    /// satoshis.  Uses the key in signer.
    /// If self.config.miner.segwit is true, the transaction's change address will be a p2wpkh
    /// output. Otherwise, it will be a p2pkh output.
    fn serialize_tx(
        &mut self,
        epoch_id: StacksEpochId,
        tx: &mut Transaction,
        tx_cost: u64,
        utxos_set: &mut UTXOSet,
        signer: &mut BurnchainOpSigner,
        force_change_output: bool,
    ) -> bool {
        let mut public_key = signer.get_public_key();

        let total_target = if force_change_output {
            tx_cost + DUST_UTXO_LIMIT
        } else {
            tx_cost
        };

        // select UTXOs until we have enough to cover the cost
        let mut total_consumed = 0;
        let mut available_utxos = vec![];
        available_utxos.append(&mut utxos_set.utxos);
        for utxo in available_utxos.into_iter() {
            total_consumed += utxo.amount;
            utxos_set.utxos.push(utxo);

            if total_consumed >= total_target {
                break;
            }
        }

        if total_consumed < total_target {
            warn!("Consumed total {total_consumed} is less than intended spend: {total_target}");
            return false;
        }

        // Append the change output
        let value = total_consumed - tx_cost;
        debug!(
            "Payments value: {value:?}, total_consumed: {total_consumed:?}, total_spent: {total_target:?}"
        );
        if value >= DUST_UTXO_LIMIT {
            let change_output = if self.config.miner.segwit && epoch_id >= StacksEpochId::Epoch21 {
                // p2wpkh
                public_key.set_compressed(true);
                let change_address_hash = Hash160::from_data(&public_key.to_bytes());
                SegwitBitcoinAddress::to_p2wpkh_tx_out(&change_address_hash.0, value)
            } else {
                // p2pkh
                let change_address_hash = Hash160::from_data(&public_key.to_bytes());
                LegacyBitcoinAddress::to_p2pkh_tx_out(&change_address_hash, value)
            };
            tx.output.push(change_output);
        } else {
            // Instead of leaving that change to the BTC miner, we could / should bump the sortition fee
            debug!("Not enough change to clear dust limit. Not adding change address.");
        }

        for utxo in utxos_set.utxos.iter() {
            let input = TxIn {
                previous_output: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFD, // allow RBF
                witness: vec![],
            };
            tx.input.push(input);
        }
        for (i, utxo) in utxos_set.utxos.iter().enumerate() {
            let script_pub_key = utxo.script_pub_key.clone();
            let sig_hash_all = 0x01;

            let (sig_hash, is_segwit) = if script_pub_key.as_bytes().len() == 22
                && script_pub_key.as_bytes()[0..2] == [0x00, 0x14]
            {
                // p2wpkh
                (
                    tx.segwit_signature_hash(i, &script_pub_key, utxo.amount, sig_hash_all),
                    true,
                )
            } else {
                // p2pkh
                (tx.signature_hash(i, &script_pub_key, sig_hash_all), false)
            };

            let sig1_der = {
                let message = signer
                    .sign_message(sig_hash.as_bytes())
                    .expect("Unable to sign message");
                message
                    .to_secp256k1_recoverable()
                    .expect("Unable to get recoverable signature")
                    .to_standard()
                    .serialize_der()
            };

            if is_segwit {
                // segwit
                public_key.set_compressed(true);
                tx.input[i].script_sig = Script::from(vec![]);
                tx.input[i].witness = vec![
                    [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec(),
                    public_key.to_bytes(),
                ];
            } else {
                // legacy scriptSig
                tx.input[i].script_sig = Builder::new()
                    .push_slice(&[&*sig1_der, &[sig_hash_all as u8][..]].concat())
                    .push_slice(&public_key.to_bytes())
                    .into_script();
                tx.input[i].witness.clear();
            }
        }
        true
    }

    /// Broadcast a signed raw [`Transaction`] to the underlying Bitcoin node.
    ///
    /// The transaction is submitted with following parameters:
    /// - `max_fee_rate = 0.0` (uncapped, accept any fee rate),
    /// - `max_burn_amount = 1_000_000` (in sats).
    ///
    /// # Arguments
    /// * `transaction` - A fully signed raw [`Transaction`] to broadcast.
    ///
    /// # Returns
    /// On success, returns the [`Txid`] of the broadcasted transaction.
    pub fn send_transaction(&self, tx: &Transaction) -> Result<Txid, BurnchainControllerError> {
        debug!(
            "Sending raw transaction: {}",
            serialize_hex(tx).unwrap_or("SERIALIZATION FAILED".to_string())
        );

        const UNCAPPED_FEE: f64 = 0.0;
        const MAX_BURN_AMOUNT: u64 = 1_000_000;
        self.rpc_client
            .send_raw_transaction(tx, Some(UNCAPPED_FEE), Some(MAX_BURN_AMOUNT))
            .map(|txid| {
                debug!("Transaction {txid} sent successfully");
                txid
            })
            .map_err(|e| {
                error!("Bitcoin RPC error: transaction submission failed - {e:?}");
                BurnchainControllerError::TransactionSubmissionFailed(format!("{e:?}"))
            })
    }

    /// wait until the ChainsCoordinator has processed sortitions up to
    /// height_to_wait
    pub fn wait_for_sortitions(
        &self,
        coord_comms: CoordinatorChannels,
        height_to_wait: u64,
    ) -> Result<BurnchainTip, BurnchainControllerError> {
        let mut debug_ctr = 0;
        loop {
            let canonical_sortition_tip =
                SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn()).unwrap();

            if debug_ctr % 10 == 0 {
                debug!(
                    "Waiting until canonical sortition height reaches {height_to_wait} (currently {})",
                    canonical_sortition_tip.block_height
                );
            }
            debug_ctr += 1;

            if canonical_sortition_tip.block_height >= height_to_wait {
                let (_, state_transition) = self
                    .sortdb_ref()
                    .get_sortition_result(&canonical_sortition_tip.sortition_id)
                    .expect("Sortition DB error.")
                    .expect("BUG: no data for the canonical chain tip");

                return Ok(BurnchainTip {
                    block_snapshot: canonical_sortition_tip,
                    received_at: Instant::now(),
                    state_transition,
                });
            }

            if !self.should_keep_running() {
                return Err(BurnchainControllerError::CoordinatorClosed);
            }

            // help the chains coordinator along
            coord_comms.announce_new_burn_block();
            coord_comms.announce_new_stacks_block();

            // yield some time
            sleep_ms(1000);
        }
    }

    /// Instruct a regtest Bitcoin node to build the next block.
    pub fn build_next_block(&self, num_blocks: u64) {
        debug!("Generate {num_blocks} block(s)");
        let public_key_bytes = match &self.config.burnchain.local_mining_public_key {
            Some(public_key) => hex_bytes(public_key).expect("Invalid byte sequence"),
            None => panic!("Unable to make new block, mining public key"),
        };

        // NOTE: miner address is whatever the configured segwit setting is
        let public_key = Secp256k1PublicKey::from_slice(&public_key_bytes)
            .expect("FATAL: invalid public key bytes");
        let address = self.get_miner_address(StacksEpochId::Epoch21, &public_key);

        let result = self.rpc_client.generate_to_address(num_blocks, &address);
        /*
            Temporary: not using `BitcoinRpcClientResultExt::ok_or_log_panic` (test code related),
            because we need this logic available outside `#[cfg(test)]` due to Helium network.

            After the Helium cleanup (https://github.com/stacks-network/stacks-core/issues/6408),
            we can:
              - move `build_next_block` behind `#[cfg(test)]`
              - simplify this match by using `ok_or_log_panic`.
        */
        match result {
            Ok(_) => {}
            Err(e) => {
                error!("Bitcoin RPC failure: error generating block {e:?}");
                panic!();
            }
        }
    }

    /// Instruct a regtest Bitcoin node to build an empty block.
    #[cfg(test)]
    pub fn build_empty_block(&self) {
        info!("Generate empty block");
        let public_key_bytes = match &self.config.burnchain.local_mining_public_key {
            Some(public_key) => hex_bytes(public_key).expect("Invalid byte sequence"),
            None => panic!("Unable to make new block, mining public key"),
        };

        // NOTE: miner address is whatever the configured segwit setting is
        let public_key = Secp256k1PublicKey::from_slice(&public_key_bytes)
            .expect("FATAL: invalid public key bytes");
        let address = self.get_miner_address(StacksEpochId::Epoch21, &public_key);

        self.rpc_client
            .generate_block(&address, &[])
            .ok_or_log_panic("generating block")
    }

    /// Invalidate a block given its hash as a [`BurnchainHeaderHash`].
    #[cfg(test)]
    pub fn invalidate_block(&self, block: &BurnchainHeaderHash) {
        info!("Invalidating block {block}");
        self.rpc_client
            .invalidate_block(block)
            .ok_or_log_panic("invalidate block")
    }

    /// Retrieve the hash (as a [`BurnchainHeaderHash`]) of the block at the given height.
    #[cfg(test)]
    pub fn get_block_hash(&self, height: u64) -> BurnchainHeaderHash {
        self.rpc_client
            .get_block_hash(height)
            .unwrap_or_log_panic("retrieve block")
    }

    #[cfg(test)]
    pub fn get_mining_pubkey(&self) -> Option<String> {
        self.config.burnchain.local_mining_public_key.clone()
    }

    #[cfg(test)]
    pub fn set_mining_pubkey(&mut self, pubkey: String) -> Option<String> {
        let old_key = self.config.burnchain.local_mining_public_key.take();
        self.config.burnchain.local_mining_public_key = Some(pubkey);
        old_key
    }

    #[cfg(test)]
    pub fn set_use_segwit(&mut self, segwit: bool) {
        self.config.miner.segwit = segwit;
    }

    // TODO: add tests from mutation testing results #4866
    #[cfg_attr(test, mutants::skip)]
    fn make_operation_tx(
        &mut self,
        epoch_id: StacksEpochId,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
    ) -> Result<Transaction, BurnchainControllerError> {
        match operation {
            BlockstackOperationType::LeaderBlockCommit(payload) => {
                self.build_leader_block_commit_tx(epoch_id, payload, op_signer)
            }
            BlockstackOperationType::LeaderKeyRegister(payload) => {
                self.build_leader_key_register_tx(epoch_id, payload, op_signer)
            }
            BlockstackOperationType::PreStx(payload) => {
                self.build_pre_stacks_tx(epoch_id, payload, op_signer)
            }
            BlockstackOperationType::TransferStx(payload) => {
                self.build_transfer_stacks_tx(epoch_id, payload, op_signer, None)
            }
            BlockstackOperationType::StackStx(_payload) => {
                self.build_stack_stx_tx(epoch_id, _payload, op_signer, None)
            }
            BlockstackOperationType::DelegateStx(payload) => {
                self.build_delegate_stacks_tx(epoch_id, payload, op_signer, None)
            }
            BlockstackOperationType::VoteForAggregateKey(payload) => {
                self.build_vote_for_aggregate_key_tx(epoch_id, payload, op_signer, None)
            }
        }
    }

    /// Retrieves a raw [`Transaction`] by its [`Txid`]
    #[cfg(test)]
    pub fn get_raw_transaction(&self, txid: &Txid) -> Transaction {
        self.rpc_client
            .get_raw_transaction(txid)
            .unwrap_or_log_panic("retrieve raw tx")
    }

    /// Produce `num_blocks` regtest bitcoin blocks, sending the bitcoin coinbase rewards
    ///  to the bitcoin single sig addresses corresponding to `pks` in a round robin fashion.
    #[cfg(test)]
    pub fn bootstrap_chain_to_pks(&self, num_blocks: u64, pks: &[Secp256k1PublicKey]) {
        info!("Creating wallet if it does not exist");
        if let Err(e) = self.create_wallet_if_dne() {
            error!("Error when creating wallet: {e:?}");
        }

        for pk in pks {
            debug!("Import public key '{}'", &pk.to_hex());
            if let Err(e) = self.import_public_key(pk) {
                warn!("Error when importing pubkey: {e:?}");
            }
        }

        if pks.len() == 1 {
            // if we only have one pubkey, just generate all the blocks at once
            let address = self.get_miner_address(StacksEpochId::Epoch21, &pks[0]);
            debug!(
                "Generate to address '{address}' for public key '{}'",
                &pks[0].to_hex()
            );
            self.rpc_client
                .generate_to_address(num_blocks, &address)
                .ok_or_log_panic("generating block");
            return;
        }

        // otherwise, round robin generate blocks
        let num_blocks = num_blocks as usize;
        for i in 0..num_blocks {
            let pk = &pks[i % pks.len()];
            let address = self.get_miner_address(StacksEpochId::Epoch21, pk);
            if i < pks.len() {
                debug!(
                    "Generate to address '{}' for public key '{}'",
                    address.to_string(),
                    &pk.to_hex(),
                );
            }
            self.rpc_client
                .generate_to_address(1, &address)
                .ok_or_log_panic("generating block");
        }
    }

    /// Checks whether a transaction has been confirmed by the burnchain
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction ID to check (in big-endian order)
    ///
    /// # Returns
    ///
    /// * `true` if the transaction is confirmed (has at least one confirmation).
    /// * `false` if the transaction is unconfirmed or could not be found.
    pub fn is_transaction_confirmed(&self, txid: &Txid) -> bool {
        match self
            .rpc_client
            .get_transaction(self.get_wallet_name(), txid)
        {
            Ok(info) => info.confirmations > 0,
            Err(e) => {
                error!("Bitcoin RPC failure: checking tx confirmation {e:?}");
                false
            }
        }
    }

    /// Returns the configured wallet name from [`Config`].
    fn get_wallet_name(&self) -> &String {
        &self.config.burnchain.wallet_name
    }

    /// Imports a public key into configured wallet by registering its
    /// corresponding addresses as descriptors.
    ///
    /// This computes both **legacy (P2PKH)** and, if the miner is configured
    /// with `segwit` enabled, also **SegWit (P2WPKH)** addresses, then imports
    /// the related descriptors into the wallet.
    pub fn import_public_key(
        &self,
        public_key: &Secp256k1PublicKey,
    ) -> BitcoinRegtestControllerResult<()> {
        let pkh = Hash160::from_data(&public_key.to_bytes())
            .to_bytes()
            .to_vec();
        let (_, network_id) = self.config.burnchain.get_bitcoin_network();

        // import both the legacy and segwit variants of this public key
        let mut addresses = vec![BitcoinAddress::from_bytes_legacy(
            network_id,
            LegacyBitcoinAddressType::PublicKeyHash,
            &pkh,
        )
        .map_err(BitcoinRegtestControllerError::InvalidPublicKey)?];

        if self.config.miner.segwit {
            addresses.push(
                BitcoinAddress::from_bytes_segwit_p2wpkh(network_id, &pkh)
                    .map_err(BitcoinRegtestControllerError::InvalidPublicKey)?,
            );
        }

        for address in addresses.into_iter() {
            debug!(
                "Import address {address} for public key {}",
                public_key.to_hex()
            );

            let descriptor = format!("addr({address})");
            let info = self.rpc_client.get_descriptor_info(&descriptor)?;

            let descr_req = ImportDescriptorsRequest {
                descriptor: format!("addr({address})#{}", info.checksum),
                timestamp: Timestamp::Time(0),
                internal: Some(true),
            };

            self.rpc_client
                .import_descriptors(self.get_wallet_name(), &[&descr_req])?;
        }
        Ok(())
    }
}

impl BurnchainController for BitcoinRegtestController {
    fn sortdb_ref(&self) -> &SortitionDB {
        self.db
            .as_ref()
            .expect("BUG: did not instantiate the burn DB")
    }

    fn sortdb_mut(&mut self) -> &mut SortitionDB {
        let burnchain = self.get_burnchain();

        let (db, burnchain_db) = burnchain.open_db(true).unwrap();
        self.db = Some(db);
        self.burnchain_db = Some(burnchain_db);

        match self.db {
            Some(ref mut sortdb) => sortdb,
            None => unreachable!(),
        }
    }

    fn get_chain_tip(&self) -> BurnchainTip {
        match &self.chain_tip {
            Some(chain_tip) => chain_tip.clone(),
            None => {
                unreachable!();
            }
        }
    }

    fn get_headers_height(&self) -> u64 {
        let (_, network_id) = self.config.burnchain.get_bitcoin_network();
        let spv_client = SpvClient::new(
            &self.config.get_spv_headers_file_path(),
            0,
            None,
            network_id,
            false,
            false,
        )
        .expect("Unable to open burnchain headers DB");
        spv_client
            .get_headers_height()
            .expect("Unable to query number of burnchain headers")
    }

    fn connect_dbs(&mut self) -> Result<(), BurnchainControllerError> {
        let burnchain = self.get_burnchain();
        burnchain.connect_db(
            true,
            self.indexer.get_first_block_header_hash()?,
            self.indexer.get_first_block_header_timestamp()?,
            self.indexer.get_stacks_epochs(),
        )?;
        Ok(())
    }

    fn get_stacks_epochs(&self) -> EpochList {
        self.indexer.get_stacks_epochs()
    }

    fn start(
        &mut self,
        target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), BurnchainControllerError> {
        // if no target block height is given, just fetch the first burnchain block.
        self.receive_blocks(false, target_block_height_opt.map_or_else(|| Some(1), Some))
    }

    fn sync(
        &mut self,
        target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), BurnchainControllerError> {
        let (burnchain_tip, burnchain_height) = if self.config.burnchain.mode == "helium" {
            // Helium: this node is responsible for mining new burnchain blocks
            self.build_next_block(1);
            self.receive_blocks(true, None)?
        } else {
            // Neon: this node is waiting on a block to be produced
            self.receive_blocks(true, target_block_height_opt)?
        };

        // Evaluate process_exit_at_block_height setting
        if let Some(cap) = self.config.burnchain.process_exit_at_block_height {
            if burnchain_tip.block_snapshot.block_height >= cap {
                info!("Node succesfully reached the end of the ongoing {cap} blocks epoch!");
                info!("This process will automatically terminate in 30s, restart your node for participating in the next epoch.");
                sleep_ms(30000);
                std::process::exit(0);
            }
        }
        Ok((burnchain_tip, burnchain_height))
    }

    // returns true if the operation was submitted successfully, false otherwise
    fn submit_operation(
        &mut self,
        epoch_id: StacksEpochId,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
    ) -> Result<Txid, BurnchainControllerError> {
        let transaction = self.make_operation_tx(epoch_id, operation, op_signer)?;
        self.send_transaction(&transaction)
    }

    #[cfg(test)]
    fn bootstrap_chain(&self, num_blocks: u64) {
        let Some(ref local_mining_pubkey) = &self.config.burnchain.local_mining_public_key else {
            warn!("No local mining pubkey while bootstrapping bitcoin regtest, will not generate bitcoin blocks");
            return;
        };

        // NOTE: miner address is whatever the miner's segwit setting says it is here
        let mut local_mining_pubkey = Secp256k1PublicKey::from_hex(local_mining_pubkey).unwrap();

        if self.config.miner.segwit {
            local_mining_pubkey.set_compressed(true);
        }

        self.bootstrap_chain_to_pks(num_blocks, &[local_mining_pubkey])
    }
}

#[derive(Debug, Clone)]
pub struct UTXOSet {
    bhh: BurnchainHeaderHash,
    utxos: Vec<UTXO>,
}

impl UTXOSet {
    pub fn is_empty(&self) -> bool {
        self.utxos.len() == 0
    }

    pub fn total_available(&self) -> u64 {
        self.utxos.iter().map(|o| o.amount).sum()
    }

    pub fn num_utxos(&self) -> usize {
        self.utxos.len()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ParsedUTXO {
    txid: String,
    vout: u32,
    script_pub_key: String,
    amount: Box<RawValue>,
    confirmations: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UTXO {
    pub txid: Sha256dHash,
    pub vout: u32,
    pub script_pub_key: Script,
    pub amount: u64,
    pub confirmations: u32,
}

impl ParsedUTXO {
    pub fn get_txid(&self) -> Option<Sha256dHash> {
        match hex_bytes(&self.txid) {
            Ok(ref mut txid) => {
                txid.reverse();
                Some(Sha256dHash::from(&txid[..]))
            }
            Err(err) => {
                warn!("Unable to get txid from UTXO {err}");
                None
            }
        }
    }

    pub fn get_sat_amount(&self) -> Option<u64> {
        ParsedUTXO::serialized_btc_to_sat(self.amount.get())
    }

    pub fn serialized_btc_to_sat(amount: &str) -> Option<u64> {
        let comps: Vec<&str> = amount.split('.').collect();
        match comps[..] {
            [lhs, rhs] => {
                if rhs.len() > 8 {
                    warn!("Unexpected amount of decimals");
                    return None;
                }

                match (lhs.parse::<u64>(), rhs.parse::<u64>()) {
                    (Ok(btc), Ok(frac_part)) => {
                        let base: u64 = 10;
                        let btc_to_sat = base.pow(8);
                        let mut amount = btc * btc_to_sat;
                        let sat = frac_part * base.pow(8 - rhs.len() as u32);
                        amount += sat;
                        Some(amount)
                    }
                    (lhs, rhs) => {
                        warn!("Error while converting BTC to sat {lhs:?} - {rhs:?}");
                        None
                    }
                }
            }
            _ => None,
        }
    }

    pub fn sat_to_serialized_btc(amount: u64) -> String {
        let base: u64 = 10;
        let int_part = amount / base.pow(8);
        let frac_part = amount % base.pow(8);
        let amount = format!("{int_part}.{frac_part:08}");
        amount
    }

    pub fn get_script_pub_key(&self) -> Option<Script> {
        match hex_bytes(&self.script_pub_key) {
            Ok(bytes) => Some(bytes.into()),
            Err(_) => {
                warn!("Unable to get script pub key");
                None
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitcoinRPCRequest {
    /// The name of the RPC call
    pub method: String,
    /// Parameters to the RPC call
    pub params: Vec<serde_json::Value>,
    /// Identifier for this Request, which should appear in the response
    pub id: String,
    /// jsonrpc field, MUST be "2.0"
    pub jsonrpc: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RPCError {
    Network(String),
    Parsing(String),
    Bitcoind(String),
}

type RPCResult<T> = Result<T, RPCError>;

impl From<io::Error> for RPCError {
    fn from(ioe: io::Error) -> Self {
        Self::Network(format!("IO Error: {ioe:?}"))
    }
}

impl From<NetError> for RPCError {
    fn from(ne: NetError) -> Self {
        Self::Network(format!("Net Error: {ne:?}"))
    }
}

impl BitcoinRPCRequest {
    fn build_rpc_request(config: &Config, payload: &BitcoinRPCRequest) -> StacksHttpRequest {
        let url = {
            // some methods require a wallet ID
            let wallet_id = match payload.method.as_str() {
                "importaddress" | "listunspent" => Some(config.burnchain.wallet_name.clone()),
                _ => None,
            };
            let url = config.burnchain.get_rpc_url(wallet_id);
            Url::parse(&url).unwrap_or_else(|_| panic!("Unable to parse {url} as a URL"))
        };
        debug!(
            "BitcoinRPC builder '{}': {:?}:{:?}@{url}",
            &payload.method, &config.burnchain.username, &config.burnchain.password
        );

        let host = url
            .host_str()
            .expect("Invalid bitcoin RPC URL: missing host");
        let port = url.port_or_known_default().unwrap_or(8333);
        let peerhost: PeerHost = format!("{host}:{port}")
            .parse()
            .unwrap_or_else(|_| panic!("FATAL: could not parse URL into PeerHost"));

        let mut request = StacksHttpRequest::new_for_peer(
            peerhost,
            "POST".into(),
            url.path().into(),
            HttpRequestContents::new().payload_json(
                serde_json::to_value(payload).unwrap_or_else(|_| {
                    panic!("FATAL: failed to encode Bitcoin RPC request as JSON")
                }),
            ),
        )
        .unwrap_or_else(|_| panic!("FATAL: failed to encode infallible data as HTTP request"));
        request.add_header("Connection".into(), "close".into());

        if let (Some(username), Some(password)) =
            (&config.burnchain.username, &config.burnchain.password)
        {
            let auth_token = format!("Basic {}", encode(format!("{username}:{password}")));
            request.add_header("Authorization".into(), auth_token);
        }
        request
    }

    pub fn list_unspent(
        config: &Config,
        addresses: Vec<String>,
        include_unsafe: bool,
        minimum_sum_amount: u64,
        utxos_to_exclude: &Option<UTXOSet>,
        block_height: u64,
    ) -> RPCResult<UTXOSet> {
        let payload = BitcoinRPCRequest {
            method: "getblockhash".to_string(),
            params: vec![block_height.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let mut res = BitcoinRPCRequest::send(config, payload)?;
        let Some(res) = res.as_object_mut() else {
            return Err(RPCError::Parsing("Failed to get UTXOs".to_string()));
        };
        let res = res
            .get("result")
            .ok_or(RPCError::Parsing("Failed to get bestblockhash".to_string()))?;
        let bhh_string: String = serde_json::from_value(res.to_owned())
            .map_err(|_| RPCError::Parsing("Failed to get bestblockhash".to_string()))?;
        let bhh = BurnchainHeaderHash::from_hex(&bhh_string)
            .map_err(|_| RPCError::Parsing("Failed to get bestblockhash".to_string()))?;
        let min_conf = 0i64;
        let max_conf = 9999999i64;
        let minimum_amount = ParsedUTXO::sat_to_serialized_btc(minimum_sum_amount);

        let payload = BitcoinRPCRequest {
            method: "listunspent".to_string(),
            params: vec![
                min_conf.into(),
                max_conf.into(),
                addresses.into(),
                include_unsafe.into(),
                json!({ "minimumAmount": minimum_amount, "maximumCount": config.burnchain.max_unspent_utxos }),
            ],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let mut res = BitcoinRPCRequest::send(config, payload)?;
        let txids_to_filter = if let Some(utxos_to_exclude) = utxos_to_exclude {
            utxos_to_exclude
                .utxos
                .iter()
                .map(|utxo| utxo.txid)
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        let mut utxos = vec![];

        match res.as_object_mut() {
            Some(ref mut object) => match object.get_mut("result") {
                Some(serde_json::Value::Array(entries)) => {
                    while let Some(entry) = entries.pop() {
                        let parsed_utxo: ParsedUTXO = match serde_json::from_value(entry) {
                            Ok(utxo) => utxo,
                            Err(err) => {
                                warn!("Failed parsing UTXO: {err}");
                                continue;
                            }
                        };
                        let amount = match parsed_utxo.get_sat_amount() {
                            Some(amount) => amount,
                            None => continue,
                        };

                        if amount < minimum_sum_amount {
                            continue;
                        }

                        let script_pub_key = match parsed_utxo.get_script_pub_key() {
                            Some(script_pub_key) => script_pub_key,
                            None => {
                                continue;
                            }
                        };

                        let txid = match parsed_utxo.get_txid() {
                            Some(amount) => amount,
                            None => continue,
                        };

                        // Exclude UTXOs that we want to filter
                        if txids_to_filter.contains(&txid) {
                            continue;
                        }

                        utxos.push(UTXO {
                            txid,
                            vout: parsed_utxo.vout,
                            script_pub_key,
                            amount,
                            confirmations: parsed_utxo.confirmations,
                        });
                    }
                }
                _ => {
                    warn!("Failed to get UTXOs");
                }
            },
            _ => {
                warn!("Failed to get UTXOs");
            }
        };

        Ok(UTXOSet { bhh, utxos })
    }

    pub fn send(config: &Config, payload: BitcoinRPCRequest) -> RPCResult<serde_json::Value> {
        let request = BitcoinRPCRequest::build_rpc_request(config, &payload);
        let timeout = Duration::from_secs(u64::from(config.burnchain.timeout));

        let host = request.preamble().host.hostname();
        let port = request.preamble().host.port();

        let response = send_http_request(&host, port, request, timeout)?;
        if let HttpResponsePayload::JSON(js) = response.destruct().1 {
            Ok(js)
        } else {
            Err(RPCError::Parsing("Did not get a JSON response".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env::{self, temp_dir};
    use std::fs::File;
    use std::io::Write;

    use stacks::burnchains::BurnchainSigner;
    use stacks::config::DEFAULT_SATS_PER_VB;
    use stacks_common::deps_common::bitcoin::blockdata::script::Builder;
    use stacks_common::types::chainstate::{BlockHeaderHash, StacksAddress, VRFSeed};
    use stacks_common::util::hash::to_hex;
    use stacks_common::util::secp256k1::Secp256k1PrivateKey;

    use super::*;
    use crate::burnchains::bitcoin::core_controller::BitcoinCoreController;
    use crate::Keychain;

    mod utils {
        use std::net::TcpListener;

        use stacks::burnchains::MagicBytes;
        use stacks::chainstate::burn::ConsensusHash;
        use stacks::util::vrf::{VRFPrivateKey, VRFPublicKey};

        use super::*;
        use crate::burnchains::bitcoin::core_controller::BURNCHAIN_CONFIG_PEER_PORT_DISABLED;
        use crate::util::get_epoch_time_nanos;

        pub fn create_config() -> Config {
            let mut config = Config::default();
            config.burnchain.magic_bytes = "T3".as_bytes().into();
            config.burnchain.username = Some(String::from("user"));
            config.burnchain.password = Some(String::from("12345"));
            // overriding default "0.0.0.0" because doesn't play nicely on Windows.
            config.burnchain.peer_host = String::from("127.0.0.1");
            // avoiding peer port biding to reduce the number of ports to bind to.
            config.burnchain.peer_port = BURNCHAIN_CONFIG_PEER_PORT_DISABLED;

            //Ask the OS for a free port. Not guaranteed to stay free,
            //after TcpListner is dropped, but good enough for testing
            //and starting bitcoind right after config is created
            let tmp_listener =
                TcpListener::bind("127.0.0.1:0").expect("Failed to bind to get a free port");
            let port = tmp_listener.local_addr().unwrap().port();

            config.burnchain.rpc_port = port;

            let now = get_epoch_time_nanos();
            let dir = format!("/tmp/regtest-ctrl-{port}-{now}");
            config.node.working_dir = dir;

            config
        }

        pub fn create_keychain() -> Keychain {
            create_keychain_with_seed(1)
        }

        pub fn create_keychain_with_seed(value: u8) -> Keychain {
            let seed = vec![value; 4];
            let keychain = Keychain::default(seed);
            keychain
        }

        pub fn create_miner1_pubkey() -> Secp256k1PublicKey {
            create_keychain_with_seed(1).get_pub_key()
        }

        pub fn create_miner2_pubkey() -> Secp256k1PublicKey {
            create_keychain_with_seed(2).get_pub_key()
        }

        pub fn mine_tx(btc_controller: &BitcoinRegtestController, tx: &Transaction) {
            btc_controller
                .send_transaction(tx)
                .expect("Tx should be sent to the burnchain!");
            btc_controller.build_next_block(1); // Now tx is confirmed
        }

        pub fn create_templated_commit_op() -> LeaderBlockCommitOp {
            LeaderBlockCommitOp {
                block_header_hash: BlockHeaderHash::from_hex(
                    "e88c3d30cb59a142f83de3b27f897a43bbb0f13316911bb98a3229973dae32af",
                )
                .unwrap(),
                new_seed: VRFSeed::from_hex(
                    "d5b9f21bc1f40f24e2c101ecd13c55b8619e5e03dad81de2c62a1cc1d8c1b375",
                )
                .unwrap(),
                parent_block_ptr: 2211, // 0x000008a3
                parent_vtxindex: 1,     // 0x0001
                key_block_ptr: 1432,    // 0x00000598
                key_vtxindex: 1,        // 0x0001
                memo: vec![11],         // 0x5a >> 3

                burn_fee: 110_000, //relevant for fee calculation when sending the tx
                input: (Txid([0x00; 32]), 0),
                burn_parent_modulus: 2, // 0x5a & 0b111

                apparent_sender: BurnchainSigner("mgbpit8FvkVJ9kuXY8QSM5P7eibnhcEMBk".to_string()),
                commit_outs: vec![
                    PoxAddress::Standard(StacksAddress::burn_address(false), None),
                    PoxAddress::Standard(StacksAddress::burn_address(false), None),
                ],

                treatment: vec![],
                sunset_burn: 5_500, //relevant for fee calculation when sending the tx

                txid: Txid([0x00; 32]),
                vtxindex: 0,
                block_height: 2212,
                burn_header_hash: BurnchainHeaderHash([0x01; 32]),
            }
        }

        pub fn txout_opreturn<T: StacksMessageCodec>(
            op: &T,
            magic: &MagicBytes,
            value: u64,
        ) -> TxOut {
            let op_bytes = {
                let mut buffer = vec![];
                let mut magic_bytes = magic.as_bytes().to_vec();
                buffer.append(&mut magic_bytes);
                op.consensus_serialize(&mut buffer)
                    .expect("FATAL: invalid operation");
                buffer
            };

            TxOut {
                value,
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::All::OP_RETURN)
                    .push_slice(&op_bytes)
                    .into_script(),
            }
        }

        pub fn txout_opdup_commit_to(addr: &PoxAddress, amount: u64) -> TxOut {
            addr.to_bitcoin_tx_out(amount)
        }

        pub fn txout_opdup_change_legacy(signer: &mut BurnchainOpSigner, amount: u64) -> TxOut {
            let public_key = signer.get_public_key();
            let change_address_hash = Hash160::from_data(&public_key.to_bytes());
            LegacyBitcoinAddress::to_p2pkh_tx_out(&change_address_hash, amount)
        }

        pub fn txin_at_index(
            complete_tx: &Transaction,
            signer: &BurnchainOpSigner,
            utxos: &[UTXO],
            index: usize,
        ) -> TxIn {
            //Refresh op signer
            let mut signer = signer.undisposed();
            let mut public_key = signer.get_public_key();

            let mut tx = Transaction {
                version: complete_tx.version,
                lock_time: complete_tx.lock_time,
                input: vec![],
                output: complete_tx.output.clone(),
            };

            for utxo in utxos.iter() {
                let input = TxIn {
                    previous_output: OutPoint {
                        txid: utxo.txid,
                        vout: utxo.vout,
                    },
                    script_sig: Script::new(),
                    sequence: 0xFFFFFFFD, // allow RBF
                    witness: vec![],
                };
                tx.input.push(input);
            }

            for (i, utxo) in utxos.iter().enumerate() {
                let script_pub_key = utxo.script_pub_key.clone();
                let sig_hash_all = 0x01;

                let (sig_hash, is_segwit) = if script_pub_key.as_bytes().len() == 22
                    && script_pub_key.as_bytes()[0..2] == [0x00, 0x14]
                {
                    // p2wpkh
                    (
                        tx.segwit_signature_hash(i, &script_pub_key, utxo.amount, sig_hash_all),
                        true,
                    )
                } else {
                    // p2pkh
                    (tx.signature_hash(i, &script_pub_key, sig_hash_all), false)
                };

                let sig1_der = {
                    let message = signer
                        .sign_message(sig_hash.as_bytes())
                        .expect("Unable to sign message");
                    message
                        .to_secp256k1_recoverable()
                        .expect("Unable to get recoverable signature")
                        .to_standard()
                        .serialize_der()
                };

                if is_segwit {
                    // segwit
                    public_key.set_compressed(true);
                    tx.input[i].script_sig = Script::from(vec![]);
                    tx.input[i].witness = vec![
                        [&*sig1_der, &[sig_hash_all as u8][..]].concat().to_vec(),
                        public_key.to_bytes(),
                    ];
                } else {
                    // legacy scriptSig
                    tx.input[i].script_sig = Builder::new()
                        .push_slice(&[&*sig1_der, &[sig_hash_all as u8][..]].concat())
                        .push_slice(&public_key.to_bytes())
                        .into_script();
                    tx.input[i].witness.clear();
                }
            }

            tx.input[index].clone()
        }

        pub fn create_templated_leader_key_op() -> LeaderKeyRegisterOp {
            LeaderKeyRegisterOp {
                consensus_hash: ConsensusHash([0u8; 20]),
                public_key: VRFPublicKey::from_private(
                    &VRFPrivateKey::from_bytes(&[0u8; 32]).unwrap(),
                ),
                memo: vec![],
                txid: Txid([3u8; 32]),
                vtxindex: 0,
                block_height: 1,
                burn_header_hash: BurnchainHeaderHash([9u8; 32]),
            }
        }

        pub fn create_templated_pre_stx_op() -> PreStxOp {
            PreStxOp {
                output: StacksAddress::p2pkh_from_hash(false, Hash160::from_data(&[2u8; 20])),
                txid: Txid([0u8; 32]),
                vtxindex: 0,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0u8; 32]),
            }
        }
    }

    #[test]
    fn test_get_satoshis_per_byte() {
        let dir = temp_dir();
        let file_path = dir.as_path().join("config.toml");

        let mut config = Config::default();

        let satoshis_per_byte = get_satoshis_per_byte(&config);
        assert_eq!(satoshis_per_byte, DEFAULT_SATS_PER_VB);

        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "[burnchain]").unwrap();
        writeln!(file, "satoshis_per_byte = 51").unwrap();
        config.config_path = Some(file_path.to_str().unwrap().to_string());

        assert_eq!(get_satoshis_per_byte(&config), 51);
    }

    /// Verify that we can build a valid Bitcoin transaction with multiple UTXOs.
    /// Taken from production data.
    /// Tests `serialize_tx()` and `send_block_commit_operation_at_burnchain_height()`
    #[test]
    fn test_multiple_inputs() {
        let spend_utxos = vec![
            UTXO {
                txid: Sha256dHash::from_hex(
                    "d3eafb3aba3cec925473550ed2e4d00bcb0d00744bb3212e4a8e72878909daee",
                )
                .unwrap(),
                vout: 3,
                script_pub_key: Builder::from(
                    hex_bytes("76a9141dc27eba0247f8cc9575e7d45e50a0bc7e72427d88ac").unwrap(),
                )
                .into_script(),
                amount: 42051,
                confirmations: 1421,
            },
            UTXO {
                txid: Sha256dHash::from_hex(
                    "01132f2d4a98cc715624e033214c8d841098a1ee15b30188ab89589a320b3b24",
                )
                .unwrap(),
                vout: 0,
                script_pub_key: Builder::from(
                    hex_bytes("76a9141dc27eba0247f8cc9575e7d45e50a0bc7e72427d88ac").unwrap(),
                )
                .into_script(),
                amount: 326456,
                confirmations: 1421,
            },
        ];

        // test serialize_tx()
        let config = utils::create_config();

        let mut btc_controller = BitcoinRegtestController::new(config, None);
        let mut utxo_set = UTXOSet {
            bhh: BurnchainHeaderHash([0x01; 32]),
            utxos: spend_utxos.clone(),
        };
        let mut transaction = Transaction {
            input: vec![],
            output: vec![
                TxOut {
                    value: 0,
                    script_pubkey: Builder::from(hex_bytes("6a4c5054335be88c3d30cb59a142f83de3b27f897a43bbb0f13316911bb98a3229973dae32afd5b9f21bc1f40f24e2c101ecd13c55b8619e5e03dad81de2c62a1cc1d8c1b375000008a300010000059800015a").unwrap()).into_script(),
                },
                TxOut {
                    value: 10000,
                    script_pubkey: Builder::from(hex_bytes("76a914000000000000000000000000000000000000000088ac").unwrap()).into_script(),
                },
                TxOut {
                    value: 10000,
                    script_pubkey: Builder::from(hex_bytes("76a914000000000000000000000000000000000000000088ac").unwrap()).into_script(),
                },
            ],
            version: 1,
            lock_time: 0,
        };

        let mut signer = BurnchainOpSigner::new(
            Secp256k1PrivateKey::from_hex(
                "9e446f6b0c6a96cf2190e54bcd5a8569c3e386f091605499464389b8d4e0bfc201",
            )
            .unwrap(),
        );
        assert!(btc_controller.serialize_tx(
            StacksEpochId::Epoch25,
            &mut transaction,
            44950,
            &mut utxo_set,
            &mut signer,
            true
        ));
        assert_eq!(transaction.output[3].value, 323557);

        // test send_block_commit_operation_at_burn_height()
        let utxo_set = UTXOSet {
            bhh: BurnchainHeaderHash([0x01; 32]),
            utxos: spend_utxos,
        };

        let commit_op = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_hex(
                "e88c3d30cb59a142f83de3b27f897a43bbb0f13316911bb98a3229973dae32af",
            )
            .unwrap(),
            new_seed: VRFSeed::from_hex(
                "d5b9f21bc1f40f24e2c101ecd13c55b8619e5e03dad81de2c62a1cc1d8c1b375",
            )
            .unwrap(),
            parent_block_ptr: 2211, // 0x000008a3
            parent_vtxindex: 1,     // 0x0001
            key_block_ptr: 1432,    // 0x00000598
            key_vtxindex: 1,        // 0x0001
            memo: vec![11],         // 0x5a >> 3

            burn_fee: 0,
            input: (Txid([0x00; 32]), 0),
            burn_parent_modulus: 2, // 0x5a & 0b111

            apparent_sender: BurnchainSigner("mgbpit8FvkVJ9kuXY8QSM5P7eibnhcEMBk".to_string()),
            commit_outs: vec![
                PoxAddress::Standard(StacksAddress::burn_address(false), None),
                PoxAddress::Standard(StacksAddress::burn_address(false), None),
            ],

            treatment: vec![],
            sunset_burn: 0,

            txid: Txid([0x00; 32]),
            vtxindex: 0,
            block_height: 2212,
            burn_header_hash: BurnchainHeaderHash([0x01; 32]),
        };

        assert_eq!(to_hex(&commit_op.serialize_to_vec()), "5be88c3d30cb59a142f83de3b27f897a43bbb0f13316911bb98a3229973dae32afd5b9f21bc1f40f24e2c101ecd13c55b8619e5e03dad81de2c62a1cc1d8c1b375000008a300010000059800015a".to_string());

        let leader_fees = LeaderBlockCommitFees {
            sunset_fee: 0,
            fee_rate: 50,
            sortition_fee: 20000,
            outputs_len: 2,
            default_tx_size: 380,
            spent_in_attempts: 0,
            is_rbf_enabled: false,
            final_size: 498,
        };

        assert_eq!(leader_fees.amount_per_output(), 10000);
        assert_eq!(leader_fees.total_spent(), 44900);

        let block_commit = btc_controller
            .send_block_commit_operation_at_burnchain_height(
                StacksEpochId::Epoch30,
                commit_op,
                &mut signer,
                Some(utxo_set),
                None,
                leader_fees,
                &[],
                2212,
            )
            .unwrap();

        debug!("send_block_commit_operation:\n{block_commit:#?}");
        assert_eq!(block_commit.output[3].value, 323507);
        assert_eq!(serialize_hex(&block_commit).unwrap(), "0100000002eeda098987728e4a2e21b34b74000dcb0bd0e4d20e55735492ec3cba3afbead3030000006a4730440220558286e20e10ce31537f0625dae5cc62fac7961b9d2cf272c990de96323d7e2502202255adbea3d2e0509b80c5d8a3a4fe6397a87bcf18da1852740d5267d89a0cb20121035379aa40c02890d253cfa577964116eb5295570ae9f7287cbae5f2585f5b2c7cfdffffff243b0b329a5889ab8801b315eea19810848d4c2133e0245671cc984a2d2f1301000000006a47304402206d9f8de107f9e1eb15aafac66c2bb34331a7523260b30e18779257e367048d34022013c7dabb32a5c281aa00d405e2ccbd00f34f03a65b2336553a4acd6c52c251ef0121035379aa40c02890d253cfa577964116eb5295570ae9f7287cbae5f2585f5b2c7cfdffffff040000000000000000536a4c5054335be88c3d30cb59a142f83de3b27f897a43bbb0f13316911bb98a3229973dae32afd5b9f21bc1f40f24e2c101ecd13c55b8619e5e03dad81de2c62a1cc1d8c1b375000008a300010000059800015a10270000000000001976a914000000000000000000000000000000000000000088ac10270000000000001976a914000000000000000000000000000000000000000088acb3ef0400000000001976a9141dc27eba0247f8cc9575e7d45e50a0bc7e72427d88ac00000000");
    }

    #[test]
    #[ignore]
    fn test_create_wallet_from_default_empty_name() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let config = utils::create_config();

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);

        let wallets = btc_controller.list_wallets().unwrap();
        assert_eq!(0, wallets.len());

        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should now exists!");

        let wallets = btc_controller.list_wallets().unwrap();
        assert_eq!(1, wallets.len());
        assert_eq!("".to_owned(), wallets[0]);
    }

    #[test]
    #[ignore]
    fn test_create_wallet_from_custom_name() {
        let mut config = utils::create_config();
        config.burnchain.wallet_name = String::from("mywallet");

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);

        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should now exists!");

        let wallets = btc_controller.list_wallets().unwrap();
        assert_eq!(1, wallets.len());
        assert_eq!("mywallet".to_owned(), wallets[0]);
    }

    #[test]
    #[ignore]
    fn test_get_all_utxos_with_confirmation() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_config();
        config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);

        btc_controller.bootstrap_chain(100);
        let utxos = btc_controller.get_all_utxos(&miner_pubkey);
        assert_eq!(0, utxos.len());

        btc_controller.build_next_block(1);
        let utxos = btc_controller.get_all_utxos(&miner_pubkey);
        assert_eq!(1, utxos.len());
        assert_eq!(101, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);

        btc_controller.build_next_block(1);
        let mut utxos = btc_controller.get_all_utxos(&miner_pubkey);
        utxos.sort_by(|a, b| b.confirmations.cmp(&a.confirmations));

        assert_eq!(2, utxos.len());
        assert_eq!(102, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);
        assert_eq!(101, utxos[1].confirmations);
        assert_eq!(5_000_000_000, utxos[1].amount);
    }

    #[test]
    #[ignore]
    fn test_get_all_utxos_empty_for_other_pubkey() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();
        let other_pubkey = utils::create_miner2_pubkey();

        let mut config = utils::create_config();
        config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller.bootstrap_chain(101); // one utxo exists

        let utxos = btc_controller.get_all_utxos(&other_pubkey);
        assert_eq!(0, utxos.len());
    }

    #[test]
    #[ignore]
    fn test_get_utxos_ok_with_confirmation() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_config();
        config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller.bootstrap_chain(101);

        let utxos_opt =
            btc_controller.get_utxos(StacksEpochId::Epoch31, &miner_pubkey, 1, None, 101);
        let uxto_set = utxos_opt.expect("Shouldn't be None at height 101!");

        assert_eq!(btc_controller.get_block_hash(101), uxto_set.bhh);
        assert_eq!(1, uxto_set.num_utxos());
        assert_eq!(5_000_000_000, uxto_set.total_available());
        let utxos = uxto_set.utxos;
        assert_eq!(101, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);

        btc_controller.build_next_block(1);

        let utxos_opt =
            btc_controller.get_utxos(StacksEpochId::Epoch31, &miner_pubkey, 1, None, 102);
        let uxto_set = utxos_opt.expect("Shouldn't be None at height 102!");

        assert_eq!(btc_controller.get_block_hash(102), uxto_set.bhh);
        assert_eq!(2, uxto_set.num_utxos());
        assert_eq!(10_000_000_000, uxto_set.total_available());
        let mut utxos = uxto_set.utxos;
        utxos.sort_by(|a, b| b.confirmations.cmp(&a.confirmations));
        assert_eq!(102, utxos[0].confirmations);
        assert_eq!(5_000_000_000, utxos[0].amount);
        assert_eq!(101, utxos[1].confirmations);
        assert_eq!(5_000_000_000, utxos[1].amount);
    }

    #[test]
    #[ignore]
    fn test_get_utxos_none_due_to_filter_total_required() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_config();
        config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller.bootstrap_chain(101); // one utxo exists

        let too_much_required = 10_000_000_000;
        let utxos = btc_controller.get_utxos(
            StacksEpochId::Epoch31,
            &miner_pubkey,
            too_much_required,
            None,
            0,
        );
        assert!(utxos.is_none(), "None because too much required");
    }

    #[test]
    #[ignore]
    fn test_get_utxos_none_due_to_filter_pubkey() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_config();
        config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller.bootstrap_chain(101); // one utxo exists

        let other_pubkey = utils::create_miner2_pubkey();
        let utxos = btc_controller.get_utxos(StacksEpochId::Epoch31, &other_pubkey, 1, None, 0);
        assert!(
            utxos.is_none(),
            "None because utxos for other pubkey don't exist"
        );
    }

    #[test]
    #[ignore]
    fn test_get_utxos_none_due_to_filter_utxo_exclusion() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_config();
        config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller.bootstrap_chain(101); // one utxo exists

        let existent_utxo = btc_controller
            .get_utxos(StacksEpochId::Epoch31, &miner_pubkey, 0, None, 0)
            .expect("utxo set should exist");
        let utxos = btc_controller.get_utxos(
            StacksEpochId::Epoch31,
            &miner_pubkey,
            0,
            Some(existent_utxo),
            0,
        );
        assert!(
            utxos.is_none(),
            "None because filtering exclude existent utxo set"
        );
    }

    #[test]
    #[ignore]
    fn test_tx_confirmed_from_utxo_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_config();
        config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);

        btc_controller.bootstrap_chain(101);
        let utxos = btc_controller.get_all_utxos(&miner_pubkey);
        assert_eq!(1, utxos.len(), "One UTXO should be confirmed!");

        let txid = Txid::from_bitcoin_tx_hash(&utxos[0].txid);
        assert!(
            btc_controller.is_transaction_confirmed(&txid),
            "UTXO tx should be confirmed!"
        );
    }

    #[test]
    #[ignore]
    fn test_import_public_key_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let config = utils::create_config();

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should be created!");

        let result = btc_controller.import_public_key(&miner_pubkey);
        assert!(
            result.is_ok(),
            "Should be ok, got err instead: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    #[ignore]
    fn test_import_public_key_twice_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let config = utils::create_config();

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should be created!");

        btc_controller
            .import_public_key(&miner_pubkey)
            .expect("Import should be ok: first time!");

        //ok, but it is basically a no-op
        let result = btc_controller.import_public_key(&miner_pubkey);
        assert!(
            result.is_ok(),
            "Should be ok, got err instead: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    #[ignore]
    fn test_import_public_key_segwit_ok() {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let miner_pubkey = utils::create_miner1_pubkey();

        let mut config = utils::create_config();
        config.miner.segwit = true;

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
        btcd_controller
            .start_bitcoind()
            .expect("bitcoind should be started!");

        let btc_controller = BitcoinRegtestController::new(config.clone(), None);
        btc_controller
            .create_wallet_if_dne()
            .expect("Wallet should be created!");

        let result = btc_controller.import_public_key(&miner_pubkey);
        assert!(
            result.is_ok(),
            "Should be ok, got err instead: {:?}",
            result.unwrap_err()
        );
    }

    /// Tests related to Leader Block Commit operation
    mod leader_commit_op {
        use super::*;

        #[test]
        #[ignore]
        fn test_build_leader_block_commit_tx_ok_with_new_commit_op() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller
                .connect_dbs()
                .expect("Dbs initialization required!");
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut commit_op = utils::create_templated_commit_op();
            commit_op.sunset_burn = 5_500;
            commit_op.burn_fee = 110_000;

            let tx = btc_controller
                .build_leader_block_commit_tx(
                    StacksEpochId::Epoch31,
                    commit_op.clone(),
                    &mut op_signer,
                )
                .expect("Build leader block commit should work");

            assert!(op_signer.is_disposed());

            assert_eq!(1, tx.version);
            assert_eq!(0, tx.lock_time);
            assert_eq!(1, tx.input.len());
            assert_eq!(4, tx.output.len());

            // utxos list contains the only existing utxo
            let used_utxos = btc_controller.get_all_utxos(&miner_pubkey);
            let input_0 = utils::txin_at_index(&tx, &op_signer, &used_utxos, 0);
            assert_eq!(input_0, tx.input[0]);

            let op_return = utils::txout_opreturn(&commit_op, &config.burnchain.magic_bytes, 5_500);
            let op_commit_1 = utils::txout_opdup_commit_to(&commit_op.commit_outs[0], 55_000);
            let op_commit_2 = utils::txout_opdup_commit_to(&commit_op.commit_outs[1], 55_000);
            let op_change = utils::txout_opdup_change_legacy(&mut op_signer, 4_999_865_300);
            assert_eq!(op_return, tx.output[0]);
            assert_eq!(op_commit_1, tx.output[1]);
            assert_eq!(op_commit_2, tx.output[2]);
            assert_eq!(op_change, tx.output[3]);
        }

        #[test]
        #[ignore]
        fn test_build_leader_block_commit_tx_fails_resub_same_commit_op_while_prev_not_confirmed() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config, None);
            btc_controller
                .connect_dbs()
                .expect("Dbs initialization required!");
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let commit_op = utils::create_templated_commit_op();

            let _first_tx_ok = btc_controller
                .build_leader_block_commit_tx(
                    StacksEpochId::Epoch31,
                    commit_op.clone(),
                    &mut op_signer,
                )
                .expect("At first, building leader block commit should work");

            // re-submitting same commit while previous it is not confirmed by the burnchain
            let resubmit = btc_controller.build_leader_block_commit_tx(
                StacksEpochId::Epoch31,
                commit_op,
                &mut op_signer,
            );

            assert!(resubmit.is_err());
            assert_eq!(
                BurnchainControllerError::IdenticalOperation,
                resubmit.unwrap_err()
            );
        }

        #[test]
        #[ignore]
        fn test_build_leader_block_commit_tx_fails_resub_same_commit_op_while_prev_is_confirmed() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config, None);
            btc_controller
                .connect_dbs()
                .expect("Dbs initialization required!");
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let commit_op = utils::create_templated_commit_op();

            let first_tx_ok = btc_controller
                .build_leader_block_commit_tx(
                    StacksEpochId::Epoch31,
                    commit_op.clone(),
                    &mut op_signer,
                )
                .expect("At first, building leader block commit should work");

            utils::mine_tx(&btc_controller, &first_tx_ok); // Now tx is confirmed

            // re-submitting same commit while previous it is confirmed by the burnchain
            let resubmit = btc_controller.build_leader_block_commit_tx(
                StacksEpochId::Epoch31,
                commit_op,
                &mut op_signer,
            );

            assert!(resubmit.is_err());
            assert_eq!(
                BurnchainControllerError::IdenticalOperation,
                resubmit.unwrap_err()
            );
        }

        #[test]
        #[ignore]
        fn test_build_leader_block_commit_tx_ok_while_prev_is_confirmed() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller
                .connect_dbs()
                .expect("Dbs initialization required!");
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut commit_op = utils::create_templated_commit_op();
            commit_op.sunset_burn = 5_500;
            commit_op.burn_fee = 110_000;

            let first_tx_ok = btc_controller
                .build_leader_block_commit_tx(
                    StacksEpochId::Epoch31,
                    commit_op.clone(),
                    &mut op_signer,
                )
                .expect("At first, building leader block commit should work");

            let first_txid = first_tx_ok.txid();

            // Now tx is confirmed: prev utxo is updated and one more utxo is generated
            utils::mine_tx(&btc_controller, &first_tx_ok);

            // re-gen signer othewise fails because it will be disposed during previous commit tx.
            let mut signer = keychain.generate_op_signer();
            // Modify the commit operation payload slightly, so it no longer matches the confirmed version.
            commit_op.burn_fee += 10;

            let new_tx = btc_controller
                .build_leader_block_commit_tx(
                    StacksEpochId::Epoch31,
                    commit_op.clone(),
                    &mut signer,
                )
                .expect("Commit tx should be created!");

            assert!(op_signer.is_disposed());

            assert_eq!(1, new_tx.version);
            assert_eq!(0, new_tx.lock_time);
            assert_eq!(1, new_tx.input.len());
            assert_eq!(4, new_tx.output.len());

            // utxos list contains the sole utxo used by prev commit operation
            // because has enough amount to cover the new commit
            let used_utxos: Vec<UTXO> = btc_controller
                .get_all_utxos(&miner_pubkey)
                .into_iter()
                .filter(|utxo| utxo.txid == first_txid)
                .collect();

            let input_0 = utils::txin_at_index(&new_tx, &op_signer, &used_utxos, 0);
            assert_eq!(input_0, new_tx.input[0]);

            let op_return = utils::txout_opreturn(&commit_op, &config.burnchain.magic_bytes, 5_500);
            let op_commit_1 = utils::txout_opdup_commit_to(&commit_op.commit_outs[0], 55_005);
            let op_commit_2 = utils::txout_opdup_commit_to(&commit_op.commit_outs[1], 55_005);
            let op_change = utils::txout_opdup_change_legacy(&mut signer, 4_999_730_590);
            assert_eq!(op_return, new_tx.output[0]);
            assert_eq!(op_commit_1, new_tx.output[1]);
            assert_eq!(op_commit_2, new_tx.output[2]);
            assert_eq!(op_change, new_tx.output[3]);
        }

        #[test]
        #[ignore]
        fn test_build_leader_block_commit_tx_ok_rbf_while_prev_not_confirmed() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller
                .connect_dbs()
                .expect("Dbs initialization required!");
            btc_controller.bootstrap_chain(101); // Now, one utxo exists

            let mut commit_op = utils::create_templated_commit_op();
            commit_op.sunset_burn = 5_500;
            commit_op.burn_fee = 110_000;

            let _first_tx_ok = btc_controller
                .build_leader_block_commit_tx(
                    StacksEpochId::Epoch31,
                    commit_op.clone(),
                    &mut op_signer,
                )
                .expect("At first, building leader block commit should work");

            //re-gen signer othewise fails because it will be disposed during previous commit tx.
            let mut signer = keychain.generate_op_signer();
            //small change to the commit op payload
            commit_op.burn_fee += 10;

            let rbf_tx = btc_controller
                .build_leader_block_commit_tx(
                    StacksEpochId::Epoch31,
                    commit_op.clone(),
                    &mut signer,
                )
                .expect("Commit tx should be rbf-ed");

            assert!(op_signer.is_disposed());

            assert_eq!(1, rbf_tx.version);
            assert_eq!(0, rbf_tx.lock_time);
            assert_eq!(1, rbf_tx.input.len());
            assert_eq!(4, rbf_tx.output.len());

            // utxos list contains the only existing utxo
            let used_utxos = btc_controller.get_all_utxos(&miner_pubkey);

            let input_0 = utils::txin_at_index(&rbf_tx, &op_signer, &used_utxos, 0);
            assert_eq!(input_0, rbf_tx.input[0]);

            let op_return = utils::txout_opreturn(&commit_op, &config.burnchain.magic_bytes, 5_500);
            let op_commit_1 = utils::txout_opdup_commit_to(&commit_op.commit_outs[0], 55_005);
            let op_commit_2 = utils::txout_opdup_commit_to(&commit_op.commit_outs[1], 55_005);
            let op_change = utils::txout_opdup_change_legacy(&mut signer, 4_999_862_985);
            assert_eq!(op_return, rbf_tx.output[0]);
            assert_eq!(op_commit_1, rbf_tx.output[1]);
            assert_eq!(op_commit_2, rbf_tx.output[2]);
            assert_eq!(op_change, rbf_tx.output[3]);
        }

        #[test]
        #[ignore]
        fn test_make_operation_leader_block_commit_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller
                .connect_dbs()
                .expect("Dbs initialization required!");
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut commit_op = utils::create_templated_commit_op();
            commit_op.sunset_burn = 5_500;
            commit_op.burn_fee = 110_000;

            let tx = btc_controller
                .make_operation_tx(
                    StacksEpochId::Epoch31,
                    BlockstackOperationType::LeaderBlockCommit(commit_op),
                    &mut op_signer,
                )
                .expect("Make op should work");

            assert!(op_signer.is_disposed());

            assert_eq!(
                "1a74106bd760117892fbd90fca11646b4de46f99fd2b065c9e0706cfdcea0336",
                tx.txid().to_string()
            );
        }

        #[test]
        #[ignore]
        fn test_submit_leader_block_commit_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller
                .connect_dbs()
                .expect("Dbs initialization required!");
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut commit_op = utils::create_templated_commit_op();
            commit_op.sunset_burn = 5_500;
            commit_op.burn_fee = 110_000;

            let tx_id = btc_controller
                .submit_operation(
                    StacksEpochId::Epoch31,
                    BlockstackOperationType::LeaderBlockCommit(commit_op),
                    &mut op_signer,
                )
                .expect("Submit op should work");

            assert!(op_signer.is_disposed());

            assert_eq!(
                "1a74106bd760117892fbd90fca11646b4de46f99fd2b065c9e0706cfdcea0336",
                tx_id.to_hex()
            );
        }
    }

    /// Tests related to Leader Key Register operation
    mod leader_key_op {
        use super::*;

        #[test]
        #[ignore]
        fn test_build_leader_key_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let leader_key_op = utils::create_templated_leader_key_op();

            let tx = btc_controller
                .build_leader_key_register_tx(
                    StacksEpochId::Epoch31,
                    leader_key_op.clone(),
                    &mut op_signer,
                )
                .expect("Build leader key should work");

            assert!(op_signer.is_disposed());

            assert_eq!(1, tx.version);
            assert_eq!(0, tx.lock_time);
            assert_eq!(1, tx.input.len());
            assert_eq!(2, tx.output.len());

            // utxos list contains the only existing utxo
            let used_utxos = btc_controller.get_all_utxos(&miner_pubkey);
            let input_0 = utils::txin_at_index(&tx, &op_signer, &used_utxos, 0);
            assert_eq!(input_0, tx.input[0]);

            let op_return = utils::txout_opreturn(&leader_key_op, &config.burnchain.magic_bytes, 0);
            let op_change = utils::txout_opdup_change_legacy(&mut op_signer, 4_999_980_000);
            assert_eq!(op_return, tx.output[0]);
            assert_eq!(op_change, tx.output[1]);
        }

        #[test]
        #[ignore]
        fn test_build_leader_key_tx_fails_due_to_no_utxos() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(100); // no utxos exist

            let leader_key_op = utils::create_templated_leader_key_op();

            let error = btc_controller
                .build_leader_key_register_tx(
                    StacksEpochId::Epoch31,
                    leader_key_op.clone(),
                    &mut op_signer,
                )
                .expect_err("Leader key build should fail!");

            assert!(!op_signer.is_disposed());
            assert_eq!(BurnchainControllerError::NoUTXOs, error);
        }

        #[test]
        #[ignore]
        fn test_make_operation_leader_key_register_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let leader_key_op = utils::create_templated_leader_key_op();

            let tx = btc_controller
                .make_operation_tx(
                    StacksEpochId::Epoch31,
                    BlockstackOperationType::LeaderKeyRegister(leader_key_op),
                    &mut op_signer,
                )
                .expect("Make op should work");

            assert!(op_signer.is_disposed());

            assert_eq!(
                "4ecd7ba71bebd1aaed49dd63747ee424473f1c571bb9a576361607a669191024",
                tx.txid().to_string()
            );
        }

        #[test]
        #[ignore]
        fn test_submit_operation_leader_key_register_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let leader_key_op = utils::create_templated_leader_key_op();

            let tx_id = btc_controller
                .submit_operation(
                    StacksEpochId::Epoch31,
                    BlockstackOperationType::LeaderKeyRegister(leader_key_op),
                    &mut op_signer,
                )
                .expect("Submit op should work");

            assert!(op_signer.is_disposed());

            assert_eq!(
                "4ecd7ba71bebd1aaed49dd63747ee424473f1c571bb9a576361607a669191024",
                tx_id.to_hex()
            );
        }
    }

    /// Tests related to Pre Stacks operation
    mod pre_stx_op {
        use super::*;

        #[test]
        #[ignore]
        fn test_build_pre_stx_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut pre_stx_op = utils::create_templated_pre_stx_op();
            pre_stx_op.output = keychain.get_address(false);

            let tx = btc_controller
                .build_pre_stacks_tx(StacksEpochId::Epoch31, pre_stx_op.clone(), &mut op_signer)
                .expect("Build leader key should work");

            assert!(op_signer.is_disposed());

            assert_eq!(1, tx.version);
            assert_eq!(0, tx.lock_time);
            assert_eq!(1, tx.input.len());
            assert_eq!(3, tx.output.len());

            // utxos list contains the only existing utxo
            let used_utxos = btc_controller.get_all_utxos(&miner_pubkey);
            let input_0 = utils::txin_at_index(&tx, &op_signer, &used_utxos, 0);
            assert_eq!(input_0, tx.input[0]);

            let op_return = utils::txout_opreturn(&pre_stx_op, &config.burnchain.magic_bytes, 0);
            let op_change = utils::txout_opdup_change_legacy(&mut op_signer, 24_500);
            assert_eq!(op_return, tx.output[0]);
            assert_eq!(op_change, tx.output[1]);
        }

        #[test]
        #[ignore]
        fn test_build_pre_stx_tx_fails_due_to_no_utxos() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(100); // no utxo exists

            let mut pre_stx_op = utils::create_templated_pre_stx_op();
            pre_stx_op.output = keychain.get_address(false);

            let error = btc_controller
                .build_pre_stacks_tx(StacksEpochId::Epoch31, pre_stx_op.clone(), &mut op_signer)
                .expect_err("Leader key build should fail!");

            assert!(!op_signer.is_disposed());
            assert_eq!(BurnchainControllerError::NoUTXOs, error);
        }

        #[test]
        #[ignore]
        fn test_make_operation_pre_stx_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut pre_stx_op = utils::create_templated_pre_stx_op();
            pre_stx_op.output = keychain.get_address(false);

            let tx = btc_controller
                .make_operation_tx(
                    StacksEpochId::Epoch31,
                    BlockstackOperationType::PreStx(pre_stx_op),
                    &mut op_signer,
                )
                .expect("Make op should work");

            assert!(op_signer.is_disposed());

            assert_eq!(
                "2d061c42c6f13a62fd9d80dc9fdcd19bdb4f9e4a07f786e42530c64c52ed9d1d",
                tx.txid().to_string()
            );
        }

        #[test]
        #[ignore]
        fn test_submit_operation_pre_stx_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut pre_stx_op = utils::create_templated_pre_stx_op();
            pre_stx_op.output = keychain.get_address(false);

            let tx_id = btc_controller
                .submit_operation(
                    StacksEpochId::Epoch31,
                    BlockstackOperationType::PreStx(pre_stx_op),
                    &mut op_signer,
                )
                .expect("submit op should work");

            assert!(op_signer.is_disposed());

            assert_eq!(
                "2d061c42c6f13a62fd9d80dc9fdcd19bdb4f9e4a07f786e42530c64c52ed9d1d",
                tx_id.to_hex()
            );
        }
    }
}
