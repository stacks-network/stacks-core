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
use std::collections::HashMap;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use hashbrown::HashSet;
use libsigner::v1::messages::{MessageSlotID, SignerMessage};
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::nakamoto::miner::{NakamotoBlockBuilder, NakamotoTenureInfo};
use stacks::chainstate::nakamoto::signer_set::NakamotoSigners;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stacks::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use stacks::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksTransaction, StacksTransactionSigner,
    TenureChangeCause, TenureChangePayload, ThresholdSignature, TransactionAnchorMode,
    TransactionPayload, TransactionVersion,
};
use stacks::net::stackerdb::StackerDBs;
use stacks_common::codec::read_next;
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::hash::Hash160;
use stacks_common::util::vrf::VRFProof;
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;

use super::relayer::RelayerThread;
use super::sign_coordinator::SignCoordinator;
use super::{Config, Error as NakamotoNodeError, EventDispatcher, Keychain};
use crate::burnchains::bitcoin_regtest_controller::burnchain_params_from_config;
use crate::nakamoto_node::VRF_MOCK_MINER_KEY;
use crate::run_loop::nakamoto::Globals;
use crate::run_loop::RegisteredKey;
use crate::{neon_node, ChainTip};

#[cfg(test)]
lazy_static::lazy_static! {
    pub static ref TEST_BROADCAST_STALL: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);
}

/// If the miner was interrupted while mining a block, how long should the
///  miner thread sleep before trying again?
const ABORT_TRY_AGAIN_MS: u64 = 200;

pub enum MinerDirective {
    /// The miner won sortition so they should begin a new tenure
    BeginTenure {
        parent_tenure_start: StacksBlockId,
        burnchain_tip: BlockSnapshot,
    },
    /// The miner should try to continue their tenure if they are the active miner
    ContinueTenure { new_burn_view: ConsensusHash },
    /// The miner did not win sortition
    StopTenure,
}

struct ParentTenureInfo {
    parent_tenure_blocks: u64,
    parent_tenure_consensus_hash: ConsensusHash,
}

/// Metadata required for beginning a new tenure
struct ParentStacksBlockInfo {
    /// Header metadata for the Stacks block we're going to build on top of
    stacks_parent_header: StacksHeaderInfo,
    /// nonce to use for this new block's coinbase transaction
    coinbase_nonce: u64,
    parent_tenure: Option<ParentTenureInfo>,
}

pub struct BlockMinerThread {
    /// node config struct
    config: Config,
    /// handle to global state
    globals: Globals,
    /// copy of the node's keychain
    keychain: Keychain,
    /// burnchain configuration
    burnchain: Burnchain,
    /// Set of blocks that we have mined
    mined_blocks: Vec<NakamotoBlock>,
    /// Copy of the node's registered VRF key
    registered_key: RegisteredKey,
    /// Burnchain block snapshot which elected this miner
    burn_block: BlockSnapshot,
    /// The start of the parent tenure for this tenure
    parent_tenure_id: StacksBlockId,
    /// Handle to the node's event dispatcher
    event_dispatcher: EventDispatcher,
}

impl BlockMinerThread {
    /// Instantiate the miner thread
    pub fn new(
        rt: &RelayerThread,
        registered_key: RegisteredKey,
        burn_block: BlockSnapshot,
        parent_tenure_id: StacksBlockId,
    ) -> BlockMinerThread {
        BlockMinerThread {
            config: rt.config.clone(),
            globals: rt.globals.clone(),
            keychain: rt.keychain.clone(),
            burnchain: rt.burnchain.clone(),
            mined_blocks: vec![],
            registered_key,
            burn_block,
            event_dispatcher: rt.event_dispatcher.clone(),
            parent_tenure_id,
        }
    }

    /// Stop a miner tenure by blocking the miner and then joining the tenure thread
    pub fn stop_miner(globals: &Globals, prior_miner: JoinHandle<()>) {
        globals.block_miner();
        prior_miner
            .join()
            .expect("FATAL: IO failure joining prior mining thread");
        globals.unblock_miner();
    }

    pub fn run_miner(mut self, prior_miner: Option<JoinHandle<()>>) {
        // when starting a new tenure, block the mining thread if its currently running.
        // the new mining thread will join it (so that the new mining thread stalls, not the relayer)
        debug!(
            "New miner thread starting";
            "had_prior_miner" => prior_miner.is_some(),
            "parent_tenure_id" => %self.parent_tenure_id,
            "thread_id" => ?thread::current().id(),
        );
        if let Some(prior_miner) = prior_miner {
            Self::stop_miner(&self.globals, prior_miner);
        }
        let mut stackerdbs = StackerDBs::connect(&self.config.get_stacker_db_file_path(), true)
            .expect("FATAL: failed to connect to stacker DB");

        let mut attempts = 0;
        // now, actually run this tenure
        loop {
            let new_block = loop {
                match self.mine_block(&stackerdbs) {
                    Ok(x) => break Some(x),
                    Err(NakamotoNodeError::MiningFailure(ChainstateError::MinerAborted)) => {
                        info!("Miner interrupted while mining, will try again");
                        // sleep, and try again. if the miner was interrupted because the burnchain
                        // view changed, the next `mine_block()` invocation will error
                        thread::sleep(Duration::from_millis(ABORT_TRY_AGAIN_MS));
                        continue;
                    }
                    Err(NakamotoNodeError::MiningFailure(
                        ChainstateError::NoTransactionsToMine,
                    )) => {
                        debug!("Miner did not find any transactions to mine");
                        break None;
                    }
                    Err(e) => {
                        warn!("Failed to mine block: {e:?}");
                        return;
                    }
                }
            };

            if let Some(mut new_block) = new_block {
                let (aggregate_public_key, signers_signature) = match self.coordinate_signature(
                    &mut new_block,
                    self.burn_block.block_height,
                    &mut stackerdbs,
                    &mut attempts,
                ) {
                    Ok(x) => x,
                    Err(e) => {
                        error!("Unrecoverable error while proposing block to signer set: {e:?}. Ending tenure.");
                        return;
                    }
                };

                new_block.header.signer_signature = signers_signature;
                if let Err(e) = self.broadcast(new_block.clone(), &aggregate_public_key) {
                    warn!("Error accepting own block: {e:?}. Will try mining again.");
                    continue;
                } else {
                    info!(
                        "Miner: Block signed by signer set and broadcasted";
                        "signer_sighash" => %new_block.header.signer_signature_hash(),
                        "block_hash" => %new_block.header.block_hash(),
                        "stacks_block_id" => %new_block.header.block_id(),
                        "block_height" => new_block.header.chain_length,
                        "consensus_hash" => %new_block.header.consensus_hash,
                    );
                    self.globals.coord().announce_new_stacks_block();
                }

                self.globals.counters.bump_naka_mined_blocks();
                if self.mined_blocks.is_empty() {
                    // this is the first block of the tenure, bump tenure counter
                    self.globals.counters.bump_naka_mined_tenures();
                }
                self.mined_blocks.push(new_block);
            }

            let sort_db = SortitionDB::open(
                &self.config.get_burn_db_file_path(),
                true,
                self.burnchain.pox_constants.clone(),
            )
            .expect("FATAL: could not open sortition DB");
            let wait_start = Instant::now();
            while wait_start.elapsed() < self.config.miner.wait_on_interim_blocks {
                thread::sleep(Duration::from_millis(ABORT_TRY_AGAIN_MS));
                if self.check_burn_tip_changed(&sort_db).is_err() {
                    return;
                }
            }
        }
    }

    fn coordinate_signature(
        &mut self,
        new_block: &mut NakamotoBlock,
        burn_block_height: u64,
        stackerdbs: &mut StackerDBs,
        attempts: &mut u64,
    ) -> Result<(Point, ThresholdSignature), NakamotoNodeError> {
        let Some(miner_privkey) = self.config.miner.mining_key else {
            return Err(NakamotoNodeError::MinerConfigurationFailed(
                "No mining key configured, cannot mine",
            ));
        };
        let sort_db = SortitionDB::open(
            &self.config.get_burn_db_file_path(),
            true,
            self.burnchain.pox_constants.clone(),
        )
        .expect("FATAL: could not open sortition DB");
        let tip = SortitionDB::get_block_snapshot_consensus(
            sort_db.conn(),
            &new_block.header.consensus_hash,
        )
        .expect("FATAL: could not retrieve chain tip")
        .expect("FATAL: could not retrieve chain tip");
        let reward_cycle = self
            .burnchain
            .pox_constants
            .block_height_to_reward_cycle(
                self.burnchain.first_block_height,
                self.burn_block.block_height,
            )
            .expect("FATAL: building on a burn block that is before the first burn block");

        let reward_info = match sort_db.get_preprocessed_reward_set_of(&tip.sortition_id) {
            Ok(Some(x)) => x,
            Ok(None) => {
                return Err(NakamotoNodeError::SigningCoordinatorFailure(
                    "No reward set found. Cannot initialize miner coordinator.".into(),
                ));
            }
            Err(e) => {
                return Err(NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "Failure while fetching reward set. Cannot initialize miner coordinator. {e:?}"
                )));
            }
        };

        let Some(reward_set) = reward_info.known_selected_anchor_block_owned() else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Current reward cycle did not select a reward set. Cannot mine!".into(),
            ));
        };

        let mut chain_state = neon_node::open_chainstate_with_faults(&self.config)
            .expect("FATAL: could not open chainstate DB");
        let sortition_handle = sort_db.index_handle_at_tip();
        let Ok(aggregate_public_key) = NakamotoChainState::get_aggregate_public_key(
            &mut chain_state,
            &sort_db,
            &sortition_handle,
            &new_block,
        ) else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Failed to obtain the active aggregate public key. Cannot mine!".into(),
            ));
        };

        let miner_privkey_as_scalar = Scalar::from(miner_privkey.as_slice().clone());
        let mut coordinator = SignCoordinator::new(
            &reward_set,
            reward_cycle,
            miner_privkey_as_scalar,
            aggregate_public_key,
            &stackerdbs,
            &self.config,
        )
        .map_err(|e| {
            NakamotoNodeError::SigningCoordinatorFailure(format!(
                "Failed to initialize the signing coordinator. Cannot mine! {e:?}"
            ))
        })?;

        *attempts += 1;
        let signature = coordinator.begin_sign(
            new_block,
            burn_block_height,
            *attempts,
            &tip,
            &self.burnchain,
            &sort_db,
            &stackerdbs,
            &self.globals.counters,
        )?;

        Ok((aggregate_public_key, signature))
    }

    fn get_stackerdb_contract_and_slots(
        &self,
        stackerdbs: &StackerDBs,
        msg_id: &MessageSlotID,
        reward_cycle: u64,
    ) -> Result<(QualifiedContractIdentifier, HashMap<u32, StacksAddress>), NakamotoNodeError> {
        let stackerdb_contracts = stackerdbs
            .get_stackerdb_contract_ids()
            .expect("FATAL: could not get the stacker DB contract ids");

        let signers_contract_id =
            msg_id.stacker_db_contract(self.config.is_mainnet(), reward_cycle);
        if !stackerdb_contracts.contains(&signers_contract_id) {
            return Err(NakamotoNodeError::SignerSignatureError(
                "No signers contract found, cannot wait for signers".into(),
            ));
        };
        // Get the slots for every signer
        let signers = stackerdbs
            .get_signers(&signers_contract_id)
            .expect("FATAL: could not get signers from stacker DB");
        let mut slot_ids_addresses = HashMap::with_capacity(signers.len());
        for (slot_id, address) in stackerdbs
            .get_signers(&signers_contract_id)
            .expect("FATAL: could not get signers from stacker DB")
            .into_iter()
            .enumerate()
        {
            slot_ids_addresses.insert(
                u32::try_from(slot_id).expect("FATAL: too many signers to fit into u32 range"),
                address,
            );
        }
        Ok((signers_contract_id, slot_ids_addresses))
    }

    fn get_signer_transactions(
        &self,
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        stackerdbs: &StackerDBs,
    ) -> Result<Vec<StacksTransaction>, NakamotoNodeError> {
        let next_reward_cycle = self
            .burnchain
            .block_height_to_reward_cycle(self.burn_block.block_height)
            .expect("FATAL: no reward cycle for burn block")
            .wrapping_add(1);
        let (signers_contract_id, slot_ids_addresses) = self.get_stackerdb_contract_and_slots(
            stackerdbs,
            &MessageSlotID::Transactions,
            next_reward_cycle,
        )?;
        let slot_ids = slot_ids_addresses.keys().cloned().collect::<Vec<_>>();
        let addresses = slot_ids_addresses.values().cloned().collect::<HashSet<_>>();
        // Get the transactions from the signers for the next block
        let signer_chunks = stackerdbs
            .get_latest_chunks(&signers_contract_id, &slot_ids)
            .expect("FATAL: could not get latest chunks from stacker DB");
        let signer_messages: Vec<(u32, SignerMessage)> = slot_ids
            .iter()
            .zip(signer_chunks.into_iter())
            .filter_map(|(slot_id, chunk)| {
                chunk.and_then(|chunk| {
                    read_next::<SignerMessage, _>(&mut &chunk[..])
                        .ok()
                        .map(|msg| (*slot_id, msg))
                })
            })
            .collect();

        if signer_messages.is_empty() {
            return Ok(vec![]);
        }

        let (consensus_hash, block_bhh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
        let stacks_block_id = StacksBlockId::new(&consensus_hash, &block_bhh);

        // Get all nonces for the signers from clarity DB to use to validate transactions
        let account_nonces = chainstate
            .with_read_only_clarity_tx(&sortdb.index_conn(), &stacks_block_id, |clarity_tx| {
                clarity_tx.with_clarity_db_readonly(|clarity_db| {
                    addresses
                        .iter()
                        .map(|address| {
                            (
                                address.clone(),
                                clarity_db
                                    .get_account_nonce(&address.clone().into())
                                    .unwrap_or(0),
                            )
                        })
                        .collect::<HashMap<StacksAddress, u64>>()
                })
            })
            .unwrap_or_default();
        let mut filtered_transactions: HashMap<StacksAddress, StacksTransaction> = HashMap::new();
        for (_slot, signer_message) in signer_messages {
            match signer_message {
                SignerMessage::Transactions(transactions) => {
                    NakamotoSigners::update_filtered_transactions(
                        &mut filtered_transactions,
                        &account_nonces,
                        self.config.is_mainnet(),
                        transactions,
                    )
                }
                _ => {} // Any other message is ignored
            }
        }
        Ok(filtered_transactions.into_values().collect())
    }

    fn broadcast(
        &self,
        block: NakamotoBlock,
        aggregate_public_key: &Point,
    ) -> Result<(), ChainstateError> {
        #[cfg(test)]
        {
            if *TEST_BROADCAST_STALL.lock().unwrap() == Some(true) {
                // Do an extra check just so we don't log EVERY time.
                warn!("Broadcasting is stalled due to testing directive.";
                    "block_id" => %block.block_id(),
                    "height" => block.header.chain_length,
                );
                while *TEST_BROADCAST_STALL.lock().unwrap() == Some(true) {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                info!("Broadcasting is no longer stalled due to testing directive.";
                    "block_id" => %block.block_id(),
                    "height" => block.header.chain_length,
                );
            }
        }
        let mut chain_state = neon_node::open_chainstate_with_faults(&self.config)
            .expect("FATAL: could not open chainstate DB");
        let chainstate_config = chain_state.config();
        let sort_db = SortitionDB::open(
            &self.config.get_burn_db_file_path(),
            true,
            self.burnchain.pox_constants.clone(),
        )
        .expect("FATAL: could not open sortition DB");

        let mut sortition_handle = sort_db.index_handle_at_tip();
        let (headers_conn, staging_tx) = chain_state.headers_conn_and_staging_tx_begin()?;
        NakamotoChainState::accept_block(
            &chainstate_config,
            block,
            &mut sortition_handle,
            &staging_tx,
            headers_conn,
            &aggregate_public_key,
        )?;
        staging_tx.commit()?;
        Ok(())
    }

    /// Get the coinbase recipient address, if set in the config and if allowed in this epoch
    fn get_coinbase_recipient(&self, epoch_id: StacksEpochId) -> Option<PrincipalData> {
        if epoch_id < StacksEpochId::Epoch21 && self.config.miner.block_reward_recipient.is_some() {
            warn!("Coinbase pay-to-contract is not supported in the current epoch");
            None
        } else {
            self.config.miner.block_reward_recipient.clone()
        }
    }

    fn generate_tenure_change_tx(
        &mut self,
        nonce: u64,
        parent_block_id: StacksBlockId,
        parent_tenure_consensus_hash: ConsensusHash,
        parent_tenure_blocks: u64,
        miner_pkh: Hash160,
    ) -> Result<StacksTransaction, NakamotoNodeError> {
        let is_mainnet = self.config.is_mainnet();
        let chain_id = self.config.burnchain.chain_id;
        let tenure_change_tx_payload = TransactionPayload::TenureChange(TenureChangePayload {
            tenure_consensus_hash: self.burn_block.consensus_hash.clone(),
            prev_tenure_consensus_hash: parent_tenure_consensus_hash,
            burn_view_consensus_hash: self.burn_block.consensus_hash.clone(),
            previous_tenure_end: parent_block_id,
            previous_tenure_blocks: u32::try_from(parent_tenure_blocks)
                .expect("FATAL: more than u32 blocks in a tenure"),
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: miner_pkh,
        });

        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(nonce);

        let version = if is_mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let mut tx = StacksTransaction::new(version, tx_auth, tenure_change_tx_payload);

        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        Ok(tx_signer.get_tx().unwrap())
    }

    /// Create a coinbase transaction.
    fn generate_coinbase_tx(
        &mut self,
        nonce: u64,
        epoch_id: StacksEpochId,
        vrf_proof: VRFProof,
    ) -> StacksTransaction {
        let is_mainnet = self.config.is_mainnet();
        let chain_id = self.config.burnchain.chain_id;
        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(nonce);

        let version = if is_mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let recipient_opt = self.get_coinbase_recipient(epoch_id);

        let mut tx = StacksTransaction::new(
            version,
            tx_auth,
            TransactionPayload::Coinbase(
                CoinbasePayload([0u8; 32]),
                recipient_opt,
                Some(vrf_proof),
            ),
        );
        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        tx_signer.get_tx().unwrap()
    }

    /// Load up the parent block info for mining.
    /// If there's no parent because this is the first block, then return the genesis block's info.
    /// If we can't find the parent in the DB but we expect one, return None.
    fn load_block_parent_info(
        &self,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
    ) -> Result<ParentStacksBlockInfo, NakamotoNodeError> {
        // The nakamoto miner must always build off of a chain tip that is the highest of:
        // 1. The highest block in the miner's current tenure
        // 2. The highest block in the current tenure's parent tenure
        // Where the current tenure's parent tenure is the tenure start block committed to in the current tenure's associated block commit.
        let stacks_block_id = if let Some(block) = self.mined_blocks.last() {
            block.block_id()
        } else {
            self.parent_tenure_id
        };
        let Some(mut stacks_tip_header) =
            NakamotoChainState::get_block_header(chain_state.db(), &stacks_block_id)
                .expect("FATAL: could not query prior stacks block id")
        else {
            debug!("No Stacks chain tip known, will return a genesis block");
            let burnchain_params = burnchain_params_from_config(&self.config.burnchain);

            let chain_tip = ChainTip::genesis(
                &burnchain_params.first_block_hash,
                burnchain_params.first_block_height.into(),
                burnchain_params.first_block_timestamp.into(),
            );

            return Ok(ParentStacksBlockInfo {
                parent_tenure: Some(ParentTenureInfo {
                    parent_tenure_consensus_hash: chain_tip.metadata.consensus_hash,
                    parent_tenure_blocks: 0,
                }),
                stacks_parent_header: chain_tip.metadata,
                coinbase_nonce: 0,
            });
        };

        if self.mined_blocks.is_empty() {
            // We could call this even if self.mined_blocks was not empty, but would return the same value, so save the effort and only do it when necessary.
            // If we are starting a new tenure, then make sure we are building off of the last block of our parent tenure
            if let Some(last_tenure_finish_block_header) =
                NakamotoChainState::get_nakamoto_tenure_finish_block_header(
                    chain_state.db(),
                    &stacks_tip_header.consensus_hash,
                )
                .expect("FATAL: could not query parent tenure finish block")
            {
                stacks_tip_header = last_tenure_finish_block_header;
            }
        }
        let miner_address = self
            .keychain
            .origin_address(self.config.is_mainnet())
            .unwrap();
        match ParentStacksBlockInfo::lookup(
            chain_state,
            burn_db,
            &self.burn_block,
            miner_address,
            &self.parent_tenure_id,
            stacks_tip_header,
        ) {
            Ok(parent_info) => Ok(parent_info),
            Err(NakamotoNodeError::BurnchainTipChanged) => {
                self.globals.counters.bump_missed_tenures();
                Err(NakamotoNodeError::BurnchainTipChanged)
            }
            Err(e) => Err(e),
        }
    }

    /// Generate the VRF proof for the block we're going to build.
    /// Returns Some(proof) if we could make the proof
    /// Return None if we could not make the proof
    fn make_vrf_proof(&mut self) -> Option<VRFProof> {
        // if we're a mock miner, then make sure that the keychain has a keypair for the mocked VRF
        // key
        let vrf_proof = if self.config.get_node_config(false).mock_mining {
            self.keychain.generate_proof(
                VRF_MOCK_MINER_KEY,
                self.burn_block.sortition_hash.as_bytes(),
            )
        } else {
            self.keychain.generate_proof(
                self.registered_key.target_block_height,
                self.burn_block.sortition_hash.as_bytes(),
            )
        };

        debug!(
            "Generated VRF Proof: {} over {} ({},{}) with key {}",
            vrf_proof.to_hex(),
            &self.burn_block.sortition_hash,
            &self.burn_block.block_height,
            &self.burn_block.burn_header_hash,
            &self.registered_key.vrf_public_key.to_hex()
        );
        Some(vrf_proof)
    }

    /// Try to mine a Stacks block by assembling one from mempool transactions and sending a
    /// burnchain block-commit transaction.  If we succeed, then return the assembled block.
    fn mine_block(&mut self, stackerdbs: &StackerDBs) -> Result<NakamotoBlock, NakamotoNodeError> {
        debug!("block miner thread ID is {:?}", thread::current().id());

        let burn_db_path = self.config.get_burn_db_file_path();

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let mut burn_db =
            SortitionDB::open(&burn_db_path, true, self.burnchain.pox_constants.clone())
                .expect("FATAL: could not open sortition DB");

        self.check_burn_tip_changed(&burn_db)?;
        neon_node::fault_injection_long_tenure();

        let mut chain_state = neon_node::open_chainstate_with_faults(&self.config)
            .expect("FATAL: could not open chainstate DB");

        let mut mem_pool = self
            .config
            .connect_mempool_db()
            .expect("Database failure opening mempool");

        let target_epoch_id =
            SortitionDB::get_stacks_epoch(burn_db.conn(), self.burn_block.block_height + 1)
                .map_err(|_| NakamotoNodeError::SnapshotNotFoundForChainTip)?
                .expect("FATAL: no epoch defined")
                .epoch_id;
        let mut parent_block_info = self.load_block_parent_info(&mut burn_db, &mut chain_state)?;
        let vrf_proof = self
            .make_vrf_proof()
            .ok_or_else(|| NakamotoNodeError::BadVrfConstruction)?;

        if self.mined_blocks.is_empty() {
            if parent_block_info.parent_tenure.is_none() {
                warn!(
                    "Miner should be starting a new tenure, but failed to load parent tenure info"
                );
                return Err(NakamotoNodeError::ParentNotFound);
            }
        }

        // create our coinbase if this is the first block we've mined this tenure
        let tenure_start_info = if let Some(ref par_tenure_info) = parent_block_info.parent_tenure {
            let parent_block_id = parent_block_info.stacks_parent_header.index_block_hash();
            let current_miner_nonce = parent_block_info.coinbase_nonce;
            let tenure_change_tx = self.generate_tenure_change_tx(
                current_miner_nonce,
                parent_block_id,
                par_tenure_info.parent_tenure_consensus_hash,
                par_tenure_info.parent_tenure_blocks,
                self.keychain.get_nakamoto_pkh(),
            )?;
            let coinbase_tx =
                self.generate_coinbase_tx(current_miner_nonce + 1, target_epoch_id, vrf_proof);
            NakamotoTenureInfo {
                coinbase_tx: Some(coinbase_tx),
                tenure_change_tx: Some(tenure_change_tx),
            }
        } else {
            NakamotoTenureInfo {
                coinbase_tx: None,
                tenure_change_tx: None,
            }
        };

        parent_block_info.stacks_parent_header.microblock_tail = None;

        let signer_transactions =
            self.get_signer_transactions(&mut chain_state, &burn_db, &stackerdbs)?;

        let signer_bitvec_len =
            &burn_db.get_preprocessed_reward_set_size(&self.burn_block.sortition_id);

        // build the block itself
        let (mut block, consumed, size, tx_events) = NakamotoBlockBuilder::build_nakamoto_block(
            &chain_state,
            &burn_db.index_conn(),
            &mut mem_pool,
            &parent_block_info.stacks_parent_header,
            &self.burn_block.consensus_hash,
            self.burn_block.total_burn,
            tenure_start_info,
            self.config
                .make_nakamoto_block_builder_settings(self.globals.get_miner_status()),
            // we'll invoke the event dispatcher ourselves so that it calculates the
            //  correct signer_sighash for `process_mined_nakamoto_block_event`
            Some(&self.event_dispatcher),
            signer_transactions,
            signer_bitvec_len.unwrap_or(0),
        )
        .map_err(|e| {
            if !matches!(
                e,
                ChainstateError::MinerAborted | ChainstateError::NoTransactionsToMine
            ) {
                error!("Relayer: Failure mining anchored block: {e}");
            }
            NakamotoNodeError::MiningFailure(e)
        })?;

        if block.txs.is_empty() {
            return Err(NakamotoNodeError::MiningFailure(
                ChainstateError::NoTransactionsToMine,
            ));
        }

        let mining_key = self.keychain.get_nakamoto_sk();
        let miner_signature = mining_key
            .sign(block.header.miner_signature_hash().as_bytes())
            .map_err(NakamotoNodeError::MinerSignatureError)?;
        block.header.miner_signature = miner_signature;

        info!(
            "Miner: Assembled block #{} for signer set proposal: {}, with {} txs",
            block.header.chain_length,
            block.header.block_hash(),
            block.txs.len();
            "signer_sighash" => %block.header.signer_signature_hash(),
        );

        self.event_dispatcher.process_mined_nakamoto_block_event(
            self.burn_block.block_height,
            &block,
            size,
            &consumed,
            tx_events,
        );

        // last chance -- confirm that the stacks tip is unchanged (since it could have taken long
        // enough to build this block that another block could have arrived), and confirm that all
        // Stacks blocks with heights higher than the canoincal tip are processed.
        self.check_burn_tip_changed(&burn_db)?;
        Ok(block)
    }

    /// Check if the tenure needs to change -- if so, return a BurnchainTipChanged error
    fn check_burn_tip_changed(&self, sortdb: &SortitionDB) -> Result<(), NakamotoNodeError> {
        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if cur_burn_chain_tip.consensus_hash != self.burn_block.consensus_hash {
            info!("Miner: Cancel block assembly; burnchain tip has changed");
            self.globals.counters.bump_missed_tenures();
            Err(NakamotoNodeError::BurnchainTipChanged)
        } else {
            Ok(())
        }
    }
}

impl ParentStacksBlockInfo {
    /// Determine where in the set of forks to attempt to mine the next anchored block.
    /// `mine_tip_ch` and `mine_tip_bhh` identify the parent block on top of which to mine.
    /// `check_burn_block` identifies what we believe to be the burn chain's sortition history tip.
    /// This is used to mitigate (but not eliminate) a TOCTTOU issue with mining: the caller's
    /// conception of the sortition history tip may have become stale by the time they call this
    /// method, in which case, mining should *not* happen (since the block will be invalid).
    pub fn lookup(
        chain_state: &mut StacksChainState,
        burn_db: &mut SortitionDB,
        check_burn_block: &BlockSnapshot,
        miner_address: StacksAddress,
        parent_tenure_id: &StacksBlockId,
        stacks_tip_header: StacksHeaderInfo,
    ) -> Result<ParentStacksBlockInfo, NakamotoNodeError> {
        // the stacks block I'm mining off of's burn header hash and vtxindex:
        let parent_snapshot = SortitionDB::get_block_snapshot_consensus(
            burn_db.conn(),
            &stacks_tip_header.consensus_hash,
        )
        .expect("Failed to look up block's parent snapshot")
        .expect("Failed to look up block's parent snapshot");

        // don't mine off of an old burnchain block
        let burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if burn_chain_tip.consensus_hash != check_burn_block.consensus_hash {
            info!(
                "New canonical burn chain tip detected. Will not try to mine.";
                "new_consensus_hash" => %burn_chain_tip.consensus_hash,
                "old_consensus_hash" => %check_burn_block.consensus_hash,
                "new_burn_height" => burn_chain_tip.block_height,
                "old_burn_height" => check_burn_block.block_height
            );
            return Err(NakamotoNodeError::BurnchainTipChanged);
        }

        let Ok(Some(parent_tenure_header)) =
            NakamotoChainState::get_block_header(chain_state.db(), &parent_tenure_id)
        else {
            warn!("Failed loading parent tenure ID"; "parent_tenure_id" => %parent_tenure_id);
            return Err(NakamotoNodeError::ParentNotFound);
        };

        // check if we're mining a first tenure block (by checking if our parent block is in the tenure of parent_tenure_id)
        //  and if so, figure out how many blocks there were in the parent tenure
        let parent_tenure_info = if stacks_tip_header.consensus_hash
            == parent_tenure_header.consensus_hash
        {
            let parent_tenure_blocks = if parent_tenure_header
                .anchored_header
                .as_stacks_nakamoto()
                .is_some()
            {
                let Ok(Some(last_parent_tenure_header)) =
                    NakamotoChainState::get_nakamoto_tenure_finish_block_header(
                        chain_state.db(),
                        &parent_tenure_header.consensus_hash,
                    )
                else {
                    warn!("Failed loading last block of parent tenure"; "parent_tenure_id" => %parent_tenure_id);
                    return Err(NakamotoNodeError::ParentNotFound);
                };
                // the last known tenure block of our parent should be the stacks_tip. if not, error.
                if stacks_tip_header.index_block_hash()
                    != last_parent_tenure_header.index_block_hash()
                {
                    return Err(NakamotoNodeError::NewParentDiscovered);
                }
                1 + last_parent_tenure_header.stacks_block_height
                    - parent_tenure_header.stacks_block_height
            } else {
                1
            };
            let parent_tenure_consensus_hash = parent_tenure_header.consensus_hash.clone();
            Some(ParentTenureInfo {
                parent_tenure_blocks,
                parent_tenure_consensus_hash,
            })
        } else {
            None
        };

        debug!(
            "Looked up parent information";
            "parent_tenure_id" => %parent_tenure_id,
            "parent_tenure_consensus_hash" => %parent_tenure_header.consensus_hash,
            "parent_tenure_burn_hash" => %parent_tenure_header.burn_header_hash,
            "parent_tenure_burn_height" => parent_tenure_header.burn_header_height,
            "mining_consensus_hash" => %check_burn_block.consensus_hash,
            "mining_burn_hash" => %check_burn_block.burn_header_hash,
            "mining_burn_height" => check_burn_block.block_height,
            "stacks_tip_consensus_hash" => %parent_snapshot.consensus_hash,
            "stacks_tip_burn_hash" => %parent_snapshot.burn_header_hash,
            "stacks_tip_burn_height" => parent_snapshot.block_height,
        );

        let coinbase_nonce = {
            let principal = miner_address.into();
            let account = chain_state
                .with_read_only_clarity_tx(
                    &burn_db.index_conn(),
                    &stacks_tip_header.index_block_hash(),
                    |conn| StacksChainState::get_account(conn, &principal),
                )
                .unwrap_or_else(|| {
                    panic!(
                        "BUG: stacks tip block {} no longer exists after we queried it",
                        &stacks_tip_header.index_block_hash()
                    )
                });
            account.nonce
        };

        Ok(ParentStacksBlockInfo {
            stacks_parent_header: stacks_tip_header,
            coinbase_nonce,
            parent_tenure: parent_tenure_info,
        })
    }
}
