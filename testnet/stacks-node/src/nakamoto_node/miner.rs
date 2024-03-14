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
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use clarity::boot_util::boot_code_id;
use clarity::vm::types::PrincipalData;
use hashbrown::HashSet;
use libsigner::{
    BlockResponse, RejectCode, SignerMessage, SignerSession, StackerDBSession, BLOCK_SLOT_ID,
    SIGNER_SLOTS_PER_USER,
};
use stacks::burnchains::{Burnchain, BurnchainParameters};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::nakamoto::miner::{NakamotoBlockBuilder, NakamotoTenureInfo};
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stacks::chainstate::stacks::boot::{MINERS_NAME, SIGNERS_NAME};
use stacks::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use stacks::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksTransaction, StacksTransactionSigner,
    TenureChangeCause, TenureChangePayload, ThresholdSignature, TransactionAnchorMode,
    TransactionPayload, TransactionVersion,
};
use stacks::core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks::net::stackerdb::StackerDBs;
use stacks_common::codec::read_next;
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::vrf::VRFProof;
use wsts::curve::point::Point;

use super::relayer::RelayerThread;
use super::{Config, Error as NakamotoNodeError, EventDispatcher, Keychain};
use crate::mockamoto::signer::SelfSigner;
use crate::nakamoto_node::VRF_MOCK_MINER_KEY;
use crate::run_loop::nakamoto::Globals;
use crate::run_loop::RegisteredKey;
use crate::{neon_node, ChainTip};

/// If the miner was interrupted while mining a block, how long should the
///  miner thread sleep before trying again?
const ABORT_TRY_AGAIN_MS: u64 = 200;
/// If the signers have not responded to a block proposal, how long should
///  the miner thread sleep before trying again?
const WAIT_FOR_SIGNERS_MS: u64 = 200;

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
    /// the total amount burned in the sortition that selected the Stacks block parent
    parent_block_total_burn: u64,
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
        if let Some(prior_miner) = prior_miner {
            Self::stop_miner(&self.globals, prior_miner);
        }
        let miners_contract_id = boot_code_id(MINERS_NAME, self.config.is_mainnet());
        let stackerdbs = StackerDBs::connect(&self.config.get_stacker_db_file_path(), true)
            .expect("FATAL: failed to connect to stacker DB");
        let rpc_sock = self.config.node.rpc_bind.parse().expect(&format!(
            "Failed to parse socket: {}",
            &self.config.node.rpc_bind
        ));
        let Some(miner_privkey) = self.config.miner.mining_key else {
            warn!("No mining key configured, cannot mine");
            return;
        };
        // now, actually run this tenure
        loop {
            let new_block = loop {
                match self.mine_block() {
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

            let sort_db = SortitionDB::open(
                &self.config.get_burn_db_file_path(),
                true,
                self.burnchain.pox_constants.clone(),
            )
            .expect("FATAL: could not open sortition DB");
            let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
                .expect("FATAL: could not retrieve chain tip");
            if let Some(new_block) = new_block {
                match NakamotoBlockBuilder::make_stackerdb_block_proposal(
                    &sort_db,
                    &tip,
                    &stackerdbs,
                    &new_block,
                    &miner_privkey,
                    &miners_contract_id,
                ) {
                    Ok(Some(chunk)) => {
                        // Propose the block to the observing signers through the .miners stackerdb instance
                        let miner_contract_id = boot_code_id(MINERS_NAME, self.config.is_mainnet());
                        let mut miners_stackerdb =
                            StackerDBSession::new(rpc_sock, miner_contract_id);
                        match miners_stackerdb.put_chunk(&chunk) {
                            Ok(ack) => {
                                info!("Proposed block to stackerdb: {ack:?}");
                            }
                            Err(e) => {
                                warn!("Failed to propose block to stackerdb {e:?}");
                                return;
                            }
                        }
                    }
                    Ok(None) => {
                        warn!("Failed to propose block to stackerdb: no slot available");
                    }
                    Err(e) => {
                        warn!("Failed to propose block to stackerdb: {e:?}");
                    }
                }

                if let Some(self_signer) = self.config.self_signing() {
                    if let Err(e) = self.self_sign_and_broadcast(self_signer, new_block.clone()) {
                        warn!("Error self-signing block: {e:?}");
                    } else {
                        self.globals.coord().announce_new_stacks_block();
                    }
                } else {
                    if let Err(e) =
                        self.wait_for_signer_signature_and_broadcast(&stackerdbs, new_block.clone())
                    {
                        warn!("Error broadcasting block: {e:?}");
                    } else {
                        self.globals.coord().announce_new_stacks_block();
                    }
                }

                self.globals.counters.bump_naka_mined_blocks();
                if self.mined_blocks.is_empty() {
                    // this is the first block of the tenure, bump tenure counter
                    self.globals.counters.bump_naka_mined_tenures();
                }
                self.mined_blocks.push(new_block);
            }

            let wait_start = Instant::now();
            while wait_start.elapsed() < self.config.miner.wait_on_interim_blocks {
                thread::sleep(Duration::from_millis(ABORT_TRY_AGAIN_MS));
                if self.check_burn_tip_changed(&sort_db).is_err() {
                    return;
                }
            }
        }
    }

    fn wait_for_signer_signature(
        &self,
        stackerdbs: &StackerDBs,
        aggregate_public_key: &Point,
        signer_signature_hash: &Sha512Trunc256Sum,
    ) -> Result<ThresholdSignature, NakamotoNodeError> {
        let stackerdb_contracts = stackerdbs
            .get_stackerdb_contract_ids()
            .expect("FATAL: could not get the stacker DB contract ids");
        // TODO: get this directly instead of this jankiness when .signers is a boot contract
        let signers_contract_id = boot_code_id(SIGNERS_NAME, self.config.is_mainnet());
        if !stackerdb_contracts.contains(&signers_contract_id) {
            return Err(NakamotoNodeError::SignerSignatureError(
                "No signers contract found, cannot wait for signers",
            ));
        };
        // Get the block slot for every signer
        let slot_ids = stackerdbs
            .get_signers(&signers_contract_id)
            .expect("FATAL: could not get signers from stacker DB")
            .iter()
            .enumerate()
            .map(|(id, _)| id as u32 * SIGNER_SLOTS_PER_USER + BLOCK_SLOT_ID)
            .collect::<Vec<u32>>();
        // If more than a threshold percentage of the signers reject the block, we should not wait any further
        let rejection_threshold = slot_ids.len() / 10 * 7;
        let mut rejections = HashSet::new();
        let now = Instant::now();
        while now.elapsed() < self.config.miner.wait_on_signers {
            // Get the block responses from the signers for the block we just proposed
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
            for (signer_id, signer_message) in signer_messages {
                match signer_message {
                    SignerMessage::BlockResponse(BlockResponse::Accepted((hash, signature))) => {
                        // First check that this signature is for the block we proposed and that it is valid
                        if hash == *signer_signature_hash
                            && signature
                                .0
                                .verify(aggregate_public_key, &signer_signature_hash.0)
                        {
                            // The signature is valid across the signer signature hash of the original proposed block
                            // Immediately return and update the block with this new signature before appending it to the chain
                            return Ok(signature);
                        }
                        // We received an accepted block for some unknown block hash...Useless! Ignore it.
                        // Keep waiting for a threshold number of signers to either reject the proposed block
                        // or return valid signature to show up across the proposed block
                    }
                    SignerMessage::BlockResponse(BlockResponse::Rejected(block_rejection)) => {
                        // First check that this block rejection is for the block we proposed
                        if block_rejection.signer_signature_hash != *signer_signature_hash {
                            // This rejection is not for the block we proposed, so we can ignore it
                            continue;
                        }
                        if let RejectCode::SignedRejection(signature) = block_rejection.reason_code
                        {
                            let mut message = signer_signature_hash.0.to_vec();
                            message.push(b'n');
                            if signature.0.verify(aggregate_public_key, &message) {
                                // A threshold number of signers signed a denial of the proposed block
                                // Miner will NEVER get a signed block from the signers for this particular block
                                // Immediately return and attempt to mine a new block
                                return Err(NakamotoNodeError::SignerSignatureError(
                                    "Signers signed a rejection of the proposed block",
                                ));
                            }
                        } else {
                            // We received a rejection that is not signed. We will keep waiting for a threshold number of rejections.
                            // Ensure that we do not double count a rejection from the same signer.
                            rejections.insert(signer_id);
                            if rejections.len() > rejection_threshold {
                                // A threshold number of signers rejected the proposed block.
                                // Miner will likely never get a signed block from the signers for this particular block
                                // Return and attempt to mine a new block
                                return Err(NakamotoNodeError::SignerSignatureError(
                                    "Threshold number of signers rejected the proposed block",
                                ));
                            }
                        }
                    }
                    _ => {} // Any other message is ignored
                }
            }
            // We have not received a signed block or enough information to reject the proposed block. Wait a bit and try again.
            thread::sleep(Duration::from_millis(WAIT_FOR_SIGNERS_MS));
        }
        // We have waited for the signers for too long: stop waiting so we can propose a new block
        Err(NakamotoNodeError::SignerSignatureError(
            "Timed out waiting for signers",
        ))
    }

    fn wait_for_signer_signature_and_broadcast(
        &self,
        stackerdbs: &StackerDBs,
        mut block: NakamotoBlock,
    ) -> Result<(), ChainstateError> {
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
        let aggregate_public_key = NakamotoChainState::get_aggregate_public_key(
            &mut chain_state,
            &sort_db,
            &sortition_handle,
            &block,
        )?;
        let signature = self
            .wait_for_signer_signature(
                &stackerdbs,
                &aggregate_public_key,
                &block.header.signer_signature_hash(),
            )
            .map_err(|e| {
                ChainstateError::InvalidStacksBlock(format!("Invalid Nakamoto block: {e:?}"))
            })?;
        block.header.signer_signature = signature;
        let staging_tx = chain_state.staging_db_tx_begin()?;
        NakamotoChainState::accept_block(
            &chainstate_config,
            block,
            &mut sortition_handle,
            &staging_tx,
            &aggregate_public_key,
        )?;
        staging_tx.commit()?;
        Ok(())
    }

    fn self_sign_and_broadcast(
        &self,
        mut signer: SelfSigner,
        mut block: NakamotoBlock,
    ) -> Result<(), ChainstateError> {
        signer.sign_nakamoto_block(&mut block);
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
        let aggregate_public_key = if block.header.chain_length <= 1 {
            signer.aggregate_public_key.clone()
        } else {
            let aggregate_public_key = NakamotoChainState::get_aggregate_public_key(
                &mut chain_state,
                &sort_db,
                &sortition_handle,
                &block,
            )?;
            aggregate_public_key
        };

        let staging_tx = chain_state.staging_db_tx_begin()?;
        NakamotoChainState::accept_block(
            &chainstate_config,
            block,
            &mut sortition_handle,
            &staging_tx,
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
        let Some(stacks_tip) =
            NakamotoChainState::get_canonical_block_header(chain_state.db(), burn_db)
                .expect("FATAL: could not query chain tip")
        else {
            debug!("No Stacks chain tip known, will return a genesis block");
            let (network, _) = self.config.burnchain.get_bitcoin_network();
            let burnchain_params =
                BurnchainParameters::from_params(&self.config.burnchain.chain, &network)
                    .expect("Bitcoin network unsupported");

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
                parent_block_total_burn: 0,
                coinbase_nonce: 0,
            });
        };

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
            stacks_tip,
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
        let vrf_proof = if self.config.node.mock_mining {
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
    fn mine_block(&mut self) -> Result<NakamotoBlock, NakamotoNodeError> {
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
            let coinbase_tx = self.generate_coinbase_tx(
                current_miner_nonce + 1,
                target_epoch_id,
                vrf_proof.clone(),
            );
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

        let block_num = u64::try_from(self.mined_blocks.len())
            .map_err(|_| NakamotoNodeError::UnexpectedChainState)?
            .saturating_add(1);
        // build the block itself
        let (mut block, _, _) = NakamotoBlockBuilder::build_nakamoto_block(
            &chain_state,
            &burn_db.index_conn(),
            &mut mem_pool,
            &parent_block_info.stacks_parent_header,
            &self.burn_block.consensus_hash,
            self.burn_block.total_burn,
            tenure_start_info,
            self.config.make_block_builder_settings(
                block_num,
                false,
                self.globals.get_miner_status(),
            ),
            Some(&self.event_dispatcher),
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
            "Miner: Succeeded assembling {} block #{}: {}, with {} txs",
            if parent_block_info.parent_block_total_burn == 0 {
                "Genesis"
            } else {
                "Stacks"
            },
            block.header.chain_length,
            block.header.block_hash(),
            block.txs.len(),
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

        let parent_sortition_id = &parent_snapshot.sortition_id;

        let parent_block_total_burn =
            if &stacks_tip_header.consensus_hash == &FIRST_BURNCHAIN_CONSENSUS_HASH {
                0
            } else {
                let parent_burn_block =
                    SortitionDB::get_block_snapshot(burn_db.conn(), parent_sortition_id)
                        .expect("SortitionDB failure.")
                        .ok_or_else(|| {
                            error!(
                                "Failed to find block snapshot for the parent sortition";
                                "parent_sortition_id" => %parent_sortition_id
                            );
                            NakamotoNodeError::SnapshotNotFoundForChainTip
                        })?;

                parent_burn_block.total_burn
            };

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

        debug!("Mining tenure's last consensus hash: {} (height {} hash {}), stacks tip consensus hash: {} (height {} hash {})",
               &check_burn_block.consensus_hash, check_burn_block.block_height, &check_burn_block.burn_header_hash,
               &parent_snapshot.consensus_hash, parent_snapshot.block_height, &parent_snapshot.burn_header_hash);

        let coinbase_nonce = {
            let principal = miner_address.into();
            let account = chain_state
                .with_read_only_clarity_tx(
                    &burn_db.index_conn(),
                    &stacks_tip_header.index_block_hash(),
                    |conn| StacksChainState::get_account(conn, &principal),
                )
                .expect(&format!(
                    "BUG: stacks tip block {} no longer exists after we queried it",
                    &stacks_tip_header.index_block_hash(),
                ));
            account.nonce
        };

        Ok(ParentStacksBlockInfo {
            stacks_parent_header: stacks_tip_header,
            parent_block_total_burn,
            coinbase_nonce,
            parent_tenure: parent_tenure_info,
        })
    }
}
