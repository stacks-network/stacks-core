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

use clarity::vm::types::PrincipalData;
use stacks::burnchains::{Burnchain, BurnchainParameters};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::nakamoto::miner::{NakamotoBlockBuilder, NakamotoTenureInfo};
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stacks::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use stacks::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksTransaction, StacksTransactionSigner,
    TenureChangeCause, TenureChangePayload, ThresholdSignature, TransactionAnchorMode,
    TransactionPayload, TransactionVersion,
};
use stacks::core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::hash::Hash160;
use stacks_common::util::vrf::VRFProof;

use super::relayer::RelayerThread;
use super::{Config, Error as NakamotoNodeError, EventDispatcher, Keychain};
use crate::mockamoto::signer::SelfSigner;
use crate::nakamoto_node::VRF_MOCK_MINER_KEY;
use crate::run_loop::nakamoto::Globals;
use crate::run_loop::RegisteredKey;
use crate::{neon_node, ChainTip};

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
    /// Set of blocks that we have mined, but are still potentially-broadcastable
    /// (copied from RelayerThread since we need the info to determine the strategy for mining the
    /// next block during this tenure).
    last_mined_blocks: Vec<NakamotoBlock>,
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
            last_mined_blocks: vec![],
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

        // now, actually run this tenure
        let new_block = match self.mine_block() {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to mine block: {e:?}");
                return;
            }
        };

        if let Some(self_signer) = self.config.self_signing() {
            if let Err(e) = self.self_sign_and_broadcast(self_signer, new_block.clone()) {
                warn!("Error self-signing block: {e:?}");
            } else {
                self.globals.coord().announce_new_stacks_block();
            }
        } else {
            warn!("Not self-signing: nakamoto node does not support stacker-signer-protocol yet");
        }

        self.globals.counters.bump_naka_mined_blocks();
        self.last_mined_blocks.push(new_block);
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
        let staging_tx = chain_state.staging_db_tx_begin()?;
        NakamotoChainState::accept_block(
            &chainstate_config,
            block,
            &mut sortition_handle,
            &staging_tx,
            &signer.aggregate_public_key,
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
        if self.config.self_signing().is_none() {
            // if we're not self-signing, then we can't generate a tenure change tx: it has to come from the signers.
            warn!("Tried to generate a tenure change transaction, but we aren't self-signing");
            return Err(NakamotoNodeError::CannotSelfSign);
        }
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
            signers: vec![],
            signature: ThresholdSignature::mock(),
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
    /// burnchain block-commit transaction.  If we succeed, then return the assembled block data as
    /// well as the microblock private key to use to produce microblocks.
    /// Return None if we couldn't build a block for whatever reason.
    fn mine_block(&mut self) -> Result<NakamotoBlock, NakamotoNodeError> {
        debug!("block miner thread ID is {:?}", thread::current().id());
        neon_node::fault_injection_long_tenure();

        let burn_db_path = self.config.get_burn_db_file_path();

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let mut burn_db =
            SortitionDB::open(&burn_db_path, true, self.burnchain.pox_constants.clone())
                .expect("FATAL: could not open sortition DB");

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

        if self.last_mined_blocks.is_empty() {
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

        // build the block itself
        let (mut block, _, _) = match NakamotoBlockBuilder::build_nakamoto_block(
            &chain_state,
            &burn_db.index_conn(),
            &mut mem_pool,
            // TODO (refactor): the nakamoto block builder doesn't use the parent tenure ID,
            //  it has to be included in the tenure change tx, which is an arg to the builder.
            //  we should probably just remove this from the nakamoto block builder, so that
            //  there isn't duplicated or unused logic here
            &self.parent_tenure_id,
            &parent_block_info.stacks_parent_header,
            &self.burn_block.consensus_hash,
            self.burn_block.total_burn,
            tenure_start_info,
            self.config.make_block_builder_settings(
                // TODO: the attempt counter needs a different configuration approach in nakamoto
                1,
                false,
                self.globals.get_miner_status(),
            ),
            Some(&self.event_dispatcher),
        ) {
            Ok(block) => block,
            Err(e) => {
                error!("Relayer: Failure mining anchored block: {}", e);
                return Err(NakamotoNodeError::MiningFailure(e));
            }
        };

        let mining_key = self.keychain.get_nakamoto_sk();
        let miner_signature = mining_key
            .sign(
                block
                    .header
                    .signature_hash()
                    .map_err(|_| NakamotoNodeError::SigningError("Could not create sighash"))?
                    .as_bytes(),
            )
            .map_err(NakamotoNodeError::SigningError)?;
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
        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if cur_burn_chain_tip.consensus_hash != block.header.consensus_hash {
            info!("Miner: Cancel block assembly; burnchain tip has changed");
            self.globals.counters.bump_missed_tenures();
            return Err(NakamotoNodeError::BurnchainTipChanged);
        }

        Ok(block)
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
