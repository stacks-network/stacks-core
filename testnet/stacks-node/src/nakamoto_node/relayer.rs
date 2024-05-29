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
use core::fmt;
use std::collections::HashSet;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use stacks::burnchains::{Burnchain, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::leader_block_commit::{
    RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS,
};
use stacks::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::nakamoto::coordinator::get_nakamoto_next_recipients;
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::{
    get_mining_spend_amount, signal_mining_blocked, signal_mining_ready,
};
use stacks::core::mempool::MemPoolDB;
use stacks::core::{
    FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, STACKS_EPOCH_3_0_MARKER,
};
use stacks::monitoring::increment_stx_blocks_mined_counter;
use stacks::net::db::LocalPeer;
use stacks::net::relay::Relayer;
use stacks::net::NetworkResult;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksBlockId, VRFSeed,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::Hash160;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};

use super::{
    BlockCommits, Config, Error as NakamotoNodeError, EventDispatcher, Keychain,
    BLOCK_PROCESSOR_STACK_SIZE,
};
use crate::burnchains::BurnchainController;
use crate::nakamoto_node::miner::{BlockMinerThread, MinerDirective};
use crate::neon_node::{
    fault_injection_skip_mining, open_chainstate_with_faults, LeaderKeyRegistrationState,
};
use crate::run_loop::nakamoto::{Globals, RunLoop};
use crate::run_loop::RegisteredKey;
use crate::BitcoinRegtestController;

#[cfg(test)]
lazy_static::lazy_static! {
    pub static ref TEST_SKIP_COMMIT_OP: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);
}

/// Command types for the Nakamoto relayer thread, issued to it by other threads
pub enum RelayerDirective {
    /// Handle some new data that arrived on the network (such as blocks, transactions, and
    HandleNetResult(NetworkResult),
    /// A new burn block has been processed by the SortitionDB, check if this miner won sortition,
    ///  and if so, start the miner thread
    ProcessedBurnBlock(ConsensusHash, BurnchainHeaderHash, BlockHeaderHash),
    /// Either a new burn block has been processed (without a miner active yet) or a
    ///  nakamoto tenure's first block has been processed, so the relayer should issue
    ///  a block commit
    IssueBlockCommit(ConsensusHash, BlockHeaderHash),
    /// Try to register a VRF public key
    RegisterKey(BlockSnapshot),
    /// Stop the relayer thread
    Exit,
}

impl fmt::Display for RelayerDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayerDirective::HandleNetResult(_) => write!(f, "HandleNetResult"),
            RelayerDirective::ProcessedBurnBlock(_, _, _) => write!(f, "ProcessedBurnBlock"),
            RelayerDirective::IssueBlockCommit(_, _) => write!(f, "IssueBlockCommit"),
            RelayerDirective::RegisterKey(_) => write!(f, "RegisterKey"),
            RelayerDirective::Exit => write!(f, "Exit"),
        }
    }
}

/// Relayer thread
/// * accepts network results and stores blocks and microblocks
/// * forwards new blocks, microblocks, and transactions to the p2p thread
/// * issues (and re-issues) block commits to participate as a miner
/// * processes burnchain state to determine if selected as a miner
/// * if mining, runs the miner and broadcasts blocks (via a subordinate MinerThread)
pub struct RelayerThread {
    /// Node config
    pub(crate) config: Config,
    /// Handle to the sortition DB
    sortdb: SortitionDB,
    /// Handle to the chainstate DB
    chainstate: StacksChainState,
    /// Handle to the mempool DB
    mempool: MemPoolDB,
    /// Handle to global state and inter-thread communication channels
    pub(crate) globals: Globals,
    /// Authoritative copy of the keychain state
    pub(crate) keychain: Keychain,
    /// Burnchian configuration
    pub(crate) burnchain: Burnchain,
    /// height of last VRF key registration request
    last_vrf_key_burn_height: Option<u64>,
    /// Set of blocks that we have mined, but are still potentially-broadcastable
    // TODO: this field is a slow leak!
    pub(crate) last_commits: BlockCommits,
    /// client to the burnchain (used only for sending block-commits)
    pub(crate) bitcoin_controller: BitcoinRegtestController,
    /// client to the event dispatcher
    pub(crate) event_dispatcher: EventDispatcher,
    /// copy of the local peer state
    local_peer: LocalPeer,
    /// last observed burnchain block height from the p2p thread (obtained from network results)
    last_network_block_height: u64,
    /// time at which we observed a change in the network block height (epoch time in millis)
    last_network_block_height_ts: u128,
    /// last observed number of downloader state-machine passes from the p2p thread (obtained from
    /// network results)
    last_network_download_passes: u64,
    /// last observed number of inventory state-machine passes from the p2p thread (obtained from
    /// network results)
    last_network_inv_passes: u64,
    /// minimum number of downloader state-machine passes that must take place before mining (this
    /// is used to ensure that the p2p thread attempts to download new Stacks block data before
    /// this thread tries to mine a block)
    min_network_download_passes: u64,
    /// minimum number of inventory state-machine passes that must take place before mining (this
    /// is used to ensure that the p2p thread attempts to download new Stacks block data before
    /// this thread tries to mine a block)
    min_network_inv_passes: u64,

    /// Inner relayer instance for forwarding broadcasted data back to the p2p thread for dispatch
    /// to neighbors
    relayer: Relayer,

    /// handle to the subordinate miner thread
    miner_thread: Option<JoinHandle<()>>,
    /// The relayer thread reads directives from the relay_rcv, but it also periodically wakes up
    ///  to check if it should issue a block commit or try to register a VRF key
    next_initiative: Instant,
    is_miner: bool,
    /// This is the last snapshot in which the relayer committed, and the parent_tenure_id
    ///  which was committed to
    last_committed: Option<(BlockSnapshot, StacksBlockId)>,
}

impl RelayerThread {
    /// Instantiate relayer thread.
    /// Uses `runloop` to obtain globals, config, and `is_miner`` status
    pub fn new(
        runloop: &RunLoop,
        local_peer: LocalPeer,
        relayer: Relayer,
        keychain: Keychain,
    ) -> RelayerThread {
        let config = runloop.config().clone();
        let globals = runloop.get_globals();
        let burn_db_path = config.get_burn_db_file_path();
        let is_miner = runloop.is_miner();

        let sortdb = SortitionDB::open(&burn_db_path, true, runloop.get_burnchain().pox_constants)
            .expect("FATAL: failed to open burnchain DB");

        let chainstate =
            open_chainstate_with_faults(&config).expect("FATAL: failed to open chainstate DB");

        let mempool = config
            .connect_mempool_db()
            .expect("Database failure opening mempool");

        let bitcoin_controller = BitcoinRegtestController::new_dummy(config.clone());

        let next_initiative_delay = config.node.next_initiative_delay;

        RelayerThread {
            config,
            sortdb,
            chainstate,
            mempool,
            globals,
            keychain,
            burnchain: runloop.get_burnchain(),
            last_vrf_key_burn_height: None,
            last_commits: HashSet::new(),
            bitcoin_controller,
            event_dispatcher: runloop.get_event_dispatcher(),
            local_peer,

            last_network_block_height: 0,
            last_network_block_height_ts: 0,
            last_network_download_passes: 0,
            min_network_download_passes: 0,
            last_network_inv_passes: 0,
            min_network_inv_passes: 0,

            relayer,

            miner_thread: None,
            is_miner,
            next_initiative: Instant::now() + Duration::from_millis(next_initiative_delay),
            last_committed: None,
        }
    }

    /// have we waited for the right conditions under which to start mining a block off of our
    /// chain tip?
    fn has_waited_for_latest_blocks(&self) -> bool {
        // a network download pass took place
        (self.min_network_download_passes <= self.last_network_download_passes
        // a network inv pass took place
        && self.min_network_download_passes <= self.last_network_download_passes)
        // we waited long enough for a download pass, but timed out waiting
        || self.last_network_block_height_ts + (self.config.node.wait_time_for_blocks as u128) < get_epoch_time_ms()
        // we're not supposed to wait at all
        || !self.config.miner.wait_for_block_download
    }

    /// Handle a NetworkResult from the p2p/http state machine.  Usually this is the act of
    /// * preprocessing and storing new blocks and microblocks
    /// * relaying blocks, microblocks, and transacctions
    /// * updating unconfirmed state views
    pub fn process_network_result(&mut self, mut net_result: NetworkResult) {
        debug!(
            "Relayer: Handle network result (from {})",
            net_result.burn_height
        );

        if self.last_network_block_height != net_result.burn_height {
            // burnchain advanced; disable mining until we also do a download pass.
            self.last_network_block_height = net_result.burn_height;
            self.min_network_download_passes = net_result.num_download_passes + 1;
            self.min_network_inv_passes = net_result.num_inv_sync_passes + 1;
            self.last_network_block_height_ts = get_epoch_time_ms();
        }

        let net_receipts = self
            .relayer
            .process_network_result(
                &self.local_peer,
                &mut net_result,
                &mut self.sortdb,
                &mut self.chainstate,
                &mut self.mempool,
                self.globals.sync_comms.get_ibd(),
                Some(&self.globals.coord_comms),
                Some(&self.event_dispatcher),
            )
            .expect("BUG: failure processing network results");

        if net_receipts.num_new_blocks > 0 {
            // if we received any new block data that could invalidate our view of the chain tip,
            // then stop mining until we process it
            debug!("Relayer: block mining to process newly-arrived blocks or microblocks");
            signal_mining_blocked(self.globals.get_miner_status());
        }

        let mempool_txs_added = net_receipts.mempool_txs_added.len();
        if mempool_txs_added > 0 {
            self.event_dispatcher
                .process_new_mempool_txs(net_receipts.mempool_txs_added);
        }

        // Dispatch retrieved attachments, if any.
        if net_result.has_attachments() {
            self.event_dispatcher
                .process_new_attachments(&net_result.attachments);
        }

        // resume mining if we blocked it, and if we've done the requisite download
        // passes
        self.last_network_download_passes = net_result.num_download_passes;
        self.last_network_inv_passes = net_result.num_inv_sync_passes;
        if self.has_waited_for_latest_blocks() {
            debug!("Relayer: did a download pass, so unblocking mining");
            signal_mining_ready(self.globals.get_miner_status());
        }
    }

    /// Given the pointer to a recently processed sortition, see if we won the sortition.
    ///
    /// Returns `true` if we won this last sortition.
    pub fn process_sortition(
        &mut self,
        consensus_hash: ConsensusHash,
        burn_hash: BurnchainHeaderHash,
        committed_index_hash: StacksBlockId,
    ) -> MinerDirective {
        let sn = SortitionDB::get_block_snapshot_consensus(self.sortdb.conn(), &consensus_hash)
            .expect("FATAL: failed to query sortition DB")
            .expect("FATAL: unknown consensus hash");

        self.globals.set_last_sortition(sn.clone());

        let won_sortition = sn.sortition && self.last_commits.remove(&sn.winning_block_txid);

        info!(
            "Relayer: Process sortition";
            "sortition_ch" => %consensus_hash,
            "burn_hash" => %burn_hash,
            "burn_height" => sn.block_height,
            "winning_txid" => %sn.winning_block_txid,
            "committed_parent" => %committed_index_hash,
            "won_sortition?" => won_sortition,
        );

        if won_sortition {
            increment_stx_blocks_mined_counter();
        }

        if sn.sortition {
            if won_sortition {
                MinerDirective::BeginTenure {
                    parent_tenure_start: committed_index_hash,
                    burnchain_tip: sn,
                }
            } else {
                MinerDirective::StopTenure
            }
        } else {
            MinerDirective::ContinueTenure {
                new_burn_view: consensus_hash,
            }
        }
    }

    /// Constructs and returns a LeaderKeyRegisterOp out of the provided params
    fn make_key_register_op(
        vrf_public_key: VRFPublicKey,
        consensus_hash: &ConsensusHash,
        miner_pkh: &Hash160,
    ) -> BlockstackOperationType {
        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: miner_pkh.as_bytes().to_vec(),
            consensus_hash: consensus_hash.clone(),
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        })
    }

    /// Create and broadcast a VRF public key registration transaction.
    /// Returns true if we succeed in doing so; false if not.
    pub fn rotate_vrf_and_register(&mut self, burn_block: &BlockSnapshot) {
        if self.last_vrf_key_burn_height.is_some() {
            // already in-flight
            return;
        }
        let cur_epoch = SortitionDB::get_stacks_epoch(self.sortdb.conn(), burn_block.block_height)
            .expect("FATAL: failed to query sortition DB")
            .expect("FATAL: no epoch defined")
            .epoch_id;
        let (vrf_pk, _) = self.keychain.make_vrf_keypair(burn_block.block_height);
        let burnchain_tip_consensus_hash = &burn_block.consensus_hash;
        let miner_pkh = self.keychain.get_nakamoto_pkh();

        debug!(
            "Submitting LeaderKeyRegister";
            "vrf_pk" => vrf_pk.to_hex(),
            "burn_block_height" => burn_block.block_height,
            "miner_pkh" => miner_pkh.to_hex(),
        );

        let op = Self::make_key_register_op(vrf_pk, burnchain_tip_consensus_hash, &miner_pkh);

        let mut op_signer = self.keychain.generate_op_signer();
        if let Some(txid) =
            self.bitcoin_controller
                .submit_operation(cur_epoch, op, &mut op_signer, 1)
        {
            // advance key registration state
            self.last_vrf_key_burn_height = Some(burn_block.block_height);
            self.globals
                .set_pending_leader_key_registration(burn_block.block_height, txid);
            self.globals.counters.bump_naka_submitted_vrfs();
        }
    }

    /// Produce the block-commit for this anchored block, if we can.
    /// `target_ch` is the consensus-hash of the Tenure we will build off
    /// `target_bh` is the block hash of the Tenure we will build off
    /// Returns the (the most recent burn snapshot, the expected epoch, the commit-op) on success
    /// Returns None if we fail somehow.
    fn make_block_commit(
        &mut self,
        target_ch: &ConsensusHash,
        target_bh: &BlockHeaderHash,
    ) -> Result<(BlockSnapshot, StacksEpochId, LeaderBlockCommitOp), NakamotoNodeError> {
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn())
            .map_err(|_| NakamotoNodeError::SnapshotNotFoundForChainTip)?;

        let parent_vrf_proof =
            NakamotoChainState::get_block_vrf_proof(self.chainstate.db(), &target_ch)
                .map_err(|_e| NakamotoNodeError::ParentNotFound)?
                .unwrap_or_else(|| VRFProof::empty());

        // let's figure out the recipient set!
        let recipients = get_nakamoto_next_recipients(&sort_tip, &mut self.sortdb, &self.burnchain)
            .map_err(|e| {
                error!("Relayer: Failure fetching recipient set: {:?}", e);
                NakamotoNodeError::SnapshotNotFoundForChainTip
            })?;

        let block_header =
            NakamotoChainState::get_block_header_by_consensus_hash(self.chainstate.db(), target_ch)
                .map_err(|e| {
                    error!("Relayer: Failed to get block header for parent tenure: {e:?}");
                    NakamotoNodeError::ParentNotFound
                })?
                .ok_or_else(|| {
                    error!("Relayer: Failed to find block header for parent tenure");
                    NakamotoNodeError::ParentNotFound
                })?;

        let parent_block_id = block_header.index_block_hash();
        if parent_block_id != StacksBlockId::new(target_ch, target_bh) {
            error!("Relayer: Found block header for parent tenure, but mismatched block id";
                   "expected_block_id" => %StacksBlockId::new(target_ch, target_bh),
                   "found_block_id" => %parent_block_id);
            return Err(NakamotoNodeError::UnexpectedChainState);
        }

        let Ok(Some(parent_sortition)) =
            SortitionDB::get_block_snapshot_consensus(self.sortdb.conn(), target_ch)
        else {
            error!("Relayer: Failed to lookup the block snapshot of parent tenure ID"; "tenure_consensus_hash" => %target_ch);
            return Err(NakamotoNodeError::ParentNotFound);
        };

        let Ok(Some(target_epoch)) =
            SortitionDB::get_stacks_epoch(self.sortdb.conn(), sort_tip.block_height + 1)
        else {
            error!("Relayer: Failed to lookup its epoch"; "target_height" => sort_tip.block_height + 1);
            return Err(NakamotoNodeError::SnapshotNotFoundForChainTip);
        };

        let parent_block_burn_height = parent_sortition.block_height;
        let Ok(Some(parent_winning_tx)) = SortitionDB::get_block_commit(
            self.sortdb.conn(),
            &parent_sortition.winning_block_txid,
            &parent_sortition.sortition_id,
        ) else {
            error!("Relayer: Failed to lookup the block commit of parent tenure ID"; "tenure_consensus_hash" => %target_ch);
            return Err(NakamotoNodeError::SnapshotNotFoundForChainTip);
        };

        let parent_winning_vtxindex = parent_winning_tx.vtxindex;

        let burn_fee_cap = get_mining_spend_amount(self.globals.get_miner_status());
        let sunset_burn = self.burnchain.expected_sunset_burn(
            sort_tip.block_height + 1,
            burn_fee_cap,
            target_epoch.epoch_id,
        );
        let rest_commit = burn_fee_cap - sunset_burn;

        let commit_outs = if !self
            .burnchain
            .pox_constants
            .is_after_pox_sunset_end(sort_tip.block_height, target_epoch.epoch_id)
            && !self
                .burnchain
                .is_in_prepare_phase(sort_tip.block_height + 1)
        {
            RewardSetInfo::into_commit_outs(recipients, self.config.is_mainnet())
        } else {
            vec![PoxAddress::standard_burn_address(self.config.is_mainnet())]
        };

        // let's commit, but target the current burnchain tip with our modulus
        let burn_parent_modulus = u8::try_from(sort_tip.block_height % BURN_BLOCK_MINED_AT_MODULUS)
            .map_err(|_| {
                error!("Relayer: Block mining modulus is not u8");
                NakamotoNodeError::UnexpectedChainState
            })?;
        let sender = self.keychain.get_burnchain_signer();
        let key = self
            .globals
            .get_leader_key_registration_state()
            .get_active()
            .ok_or_else(|| NakamotoNodeError::NoVRFKeyActive)?;
        let op = LeaderBlockCommitOp {
            sunset_burn,
            block_header_hash: BlockHeaderHash(parent_block_id.0),
            burn_fee: rest_commit,
            input: (Txid([0; 32]), 0),
            apparent_sender: sender,
            key_block_ptr: u32::try_from(key.block_height)
                .expect("FATAL: burn block height exceeded u32"),
            key_vtxindex: u16::try_from(key.op_vtxindex).expect("FATAL: vtxindex exceeded u16"),
            memo: vec![STACKS_EPOCH_3_0_MARKER],
            new_seed: VRFSeed::from_proof(&parent_vrf_proof),
            parent_block_ptr: u32::try_from(parent_block_burn_height)
                .expect("FATAL: burn block height exceeded u32"),
            parent_vtxindex: u16::try_from(parent_winning_vtxindex)
                .expect("FATAL: vtxindex exceeded u16"),
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
            burn_parent_modulus,
            commit_outs,
        };

        Ok((sort_tip, target_epoch.epoch_id, op))
    }

    /// Create the block miner thread state.
    /// Only proceeds if all of the following are true:
    /// * the miner is not blocked
    /// * last_burn_block corresponds to the canonical sortition DB's chain tip
    /// * the time of issuance is sufficiently recent
    /// * there are no unprocessed stacks blocks in the staging DB
    /// * the relayer has already tried a download scan that included this sortition (which, if a
    /// block was found, would have placed it into the staging DB and marked it as
    /// unprocessed)
    /// * a miner thread is not running already
    fn create_block_miner(
        &mut self,
        registered_key: RegisteredKey,
        last_burn_block: BlockSnapshot,
        parent_tenure_id: StacksBlockId,
    ) -> Result<BlockMinerThread, NakamotoNodeError> {
        if fault_injection_skip_mining(&self.config.node.rpc_bind, last_burn_block.block_height) {
            debug!(
                "Relayer: fault injection skip mining at block height {}",
                last_burn_block.block_height
            );
            return Err(NakamotoNodeError::FaultInjection);
        }

        let burn_header_hash = last_burn_block.burn_header_hash.clone();
        let burn_chain_sn = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        let burn_chain_tip = burn_chain_sn.burn_header_hash.clone();

        if burn_chain_tip != burn_header_hash {
            debug!(
                "Relayer: Drop stale RunTenure for {}: current sortition is for {}",
                &burn_header_hash, &burn_chain_tip
            );
            self.globals.counters.bump_missed_tenures();
            return Err(NakamotoNodeError::MissedMiningOpportunity);
        }

        debug!(
            "Relayer: Spawn tenure thread";
            "height" => last_burn_block.block_height,
            "burn_header_hash" => %burn_header_hash,
            "parent_tenure_id" => %parent_tenure_id,
        );

        let miner_thread_state =
            BlockMinerThread::new(self, registered_key, last_burn_block, parent_tenure_id);
        Ok(miner_thread_state)
    }

    fn start_new_tenure(
        &mut self,
        parent_tenure_start: StacksBlockId,
        burn_tip: BlockSnapshot,
    ) -> Result<(), NakamotoNodeError> {
        // when starting a new tenure, block the mining thread if its currently running.
        // the new mining thread will join it (so that the new mining thread stalls, not the relayer)
        let prior_tenure_thread = self.miner_thread.take();
        let vrf_key = self
            .globals
            .get_leader_key_registration_state()
            .get_active()
            .ok_or_else(|| {
                warn!("Trying to start new tenure, but no VRF key active");
                NakamotoNodeError::NoVRFKeyActive
            })?;
        let new_miner_state = self.create_block_miner(vrf_key, burn_tip, parent_tenure_start)?;

        let new_miner_handle = std::thread::Builder::new()
            .name(format!("miner.{parent_tenure_start}"))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || new_miner_state.run_miner(prior_tenure_thread))
            .map_err(|e| {
                error!("Relayer: Failed to start tenure thread: {:?}", &e);
                NakamotoNodeError::SpawnError(e)
            })?;
        debug!(
            "Relayer: started tenure thread ID {:?}",
            new_miner_handle.thread().id()
        );
        self.miner_thread.replace(new_miner_handle);

        Ok(())
    }

    fn stop_tenure(&mut self) -> Result<(), NakamotoNodeError> {
        // when stopping a tenure, block the mining thread if its currently running, then join it.
        // do this in a new thread will (so that the new thread stalls, not the relayer)
        let Some(prior_tenure_thread) = self.miner_thread.take() else {
            debug!("Relayer: no tenure thread to stop");
            return Ok(());
        };
        let id = prior_tenure_thread.thread().id();
        let globals = self.globals.clone();

        let stop_handle = std::thread::Builder::new()
            .name(format!("tenure-stop-{}", self.local_peer.data_url))
            .spawn(move || BlockMinerThread::stop_miner(&globals, prior_tenure_thread))
            .map_err(|e| {
                error!("Relayer: Failed to spawn a stop-tenure thread: {:?}", &e);
                NakamotoNodeError::SpawnError(e)
            })?;

        self.miner_thread.replace(stop_handle);
        debug!("Relayer: stopped tenure thread ID {id:?}");
        Ok(())
    }

    fn handle_sortition(
        &mut self,
        consensus_hash: ConsensusHash,
        burn_hash: BurnchainHeaderHash,
        committed_index_hash: StacksBlockId,
    ) -> bool {
        let miner_instruction =
            self.process_sortition(consensus_hash, burn_hash, committed_index_hash);

        match miner_instruction {
            MinerDirective::BeginTenure {
                parent_tenure_start,
                burnchain_tip,
            } => match self.start_new_tenure(parent_tenure_start, burnchain_tip) {
                Ok(()) => {
                    debug!("Relayer: successfully started new tenure.");
                }
                Err(e) => {
                    error!("Relayer: Failed to start new tenure: {:?}", e);
                }
            },
            MinerDirective::ContinueTenure { new_burn_view: _ } => {
                // TODO: in this case, we eventually want to undergo a tenure
                //  change to switch to the new burn view, but right now, we will
                //  simply end our current tenure if it exists
                match self.stop_tenure() {
                    Ok(()) => {
                        debug!("Relayer: successfully stopped tenure.");
                    }
                    Err(e) => {
                        error!("Relayer: Failed to stop tenure: {:?}", e);
                    }
                }
            }
            MinerDirective::StopTenure => match self.stop_tenure() {
                Ok(()) => {
                    debug!("Relayer: successfully stopped tenure.");
                }
                Err(e) => {
                    error!("Relayer: Failed to stop tenure: {:?}", e);
                }
            },
        }

        true
    }

    fn issue_block_commit(
        &mut self,
        tenure_start_ch: ConsensusHash,
        tenure_start_bh: BlockHeaderHash,
    ) -> Result<(), NakamotoNodeError> {
        let (last_committed_at, target_epoch_id, commit) =
            self.make_block_commit(&tenure_start_ch, &tenure_start_bh)?;
        #[cfg(test)]
        {
            if TEST_SKIP_COMMIT_OP.lock().unwrap().unwrap_or(false) {
                //if let Some((last_committed, ..)) = self.last_committed.as_ref() {
                //    if last_committed.consensus_hash == last_committed_at.consensus_hash {
                warn!("Relayer: not submitting block-commit to bitcoin network due to test directive.");
                return Ok(());
                //}
            }
        }
        let mut op_signer = self.keychain.generate_op_signer();
        let txid = self
            .bitcoin_controller
            .submit_operation(
                target_epoch_id,
                BlockstackOperationType::LeaderBlockCommit(commit),
                &mut op_signer,
                1,
            )
            .ok_or_else(|| {
                warn!("Failed to submit block-commit bitcoin transaction");
                NakamotoNodeError::BurnchainSubmissionFailed
            })?;
        info!(
            "Relayer: Submitted block-commit";
            "parent_consensus_hash" => %tenure_start_ch,
            "parent_block_hash" => %tenure_start_bh,
            "txid" => %txid,
        );

        self.last_commits.insert(txid);
        self.last_committed = Some((
            last_committed_at,
            StacksBlockId::new(&tenure_start_ch, &tenure_start_bh),
        ));
        self.globals.counters.bump_naka_submitted_commits();

        Ok(())
    }

    fn initiative(&mut self) -> Option<RelayerDirective> {
        if !self.is_miner {
            return None;
        }

        // do we need a VRF key registration?
        if matches!(
            self.globals.get_leader_key_registration_state(),
            LeaderKeyRegistrationState::Inactive
        ) {
            let Ok(sort_tip) = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn()) else {
                warn!("Failed to fetch sortition tip while needing to register VRF key");
                return None;
            };
            return Some(RelayerDirective::RegisterKey(sort_tip));
        }

        // are we still waiting on a pending registration?
        if !matches!(
            self.globals.get_leader_key_registration_state(),
            LeaderKeyRegistrationState::Active(_)
        ) {
            return None;
        }

        // has there been a new sortition
        let Ok(sort_tip) = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn()) else {
            return None;
        };

        // check if the burnchain changed, if so, we should issue a commit.
        //  if not, we may still want to update a commit if we've received a new tenure start block
        let burnchain_changed = if let Some((last_committed_at, ..)) = self.last_committed.as_ref()
        {
            // if the new sortition tip has a different consesus hash than the last commit,
            //  issue a new commit
            sort_tip.consensus_hash != last_committed_at.consensus_hash
        } else {
            // if there was no last commit, issue a new commit
            true
        };

        let Ok(Some(chain_tip_header)) =
            NakamotoChainState::get_canonical_block_header(self.chainstate.db(), &self.sortdb)
        else {
            info!("No known canonical tip, will issue a genesis block commit");
            return Some(RelayerDirective::IssueBlockCommit(
                FIRST_BURNCHAIN_CONSENSUS_HASH,
                FIRST_STACKS_BLOCK_HASH,
            ));
        };

        // get the starting block of the chain tip's tenure
        let Ok(Some(chain_tip_tenure_start)) =
            NakamotoChainState::get_block_header_by_consensus_hash(
                self.chainstate.db(),
                &chain_tip_header.consensus_hash,
            )
        else {
            warn!("Failure getting the first block of tenure in order to assemble block commit";
                  "tenure_consensus_hash" => %chain_tip_header.consensus_hash,
                  "tip_block_hash" => %chain_tip_header.anchored_header.block_hash());
            return None;
        };

        let chain_tip_tenure_id = chain_tip_tenure_start.index_block_hash();
        let should_commit = burnchain_changed
            || if let Some((_, last_committed_tenure_id)) = self.last_committed.as_ref() {
                // if the tenure ID of the chain tip has changed, issue a new commit
                last_committed_tenure_id != &chain_tip_tenure_id
            } else {
                // should be unreachable, but either way, if
                //  `self.last_committed` is None, we should issue a commit
                true
            };

        if should_commit {
            Some(RelayerDirective::IssueBlockCommit(
                chain_tip_tenure_start.consensus_hash,
                chain_tip_tenure_start.anchored_header.block_hash(),
            ))
        } else {
            None
        }
    }

    /// Main loop of the relayer.
    /// Runs in a separate thread.
    /// Continuously receives
    pub fn main(mut self, relay_rcv: Receiver<RelayerDirective>) {
        debug!("relayer thread ID is {:?}", std::thread::current().id());

        self.next_initiative =
            Instant::now() + Duration::from_millis(self.config.node.next_initiative_delay);
        while self.globals.keep_running() {
            let directive = if Instant::now() >= self.next_initiative {
                self.next_initiative =
                    Instant::now() + Duration::from_millis(self.config.node.next_initiative_delay);
                self.initiative()
            } else {
                None
            };

            let Some(timeout) = self.next_initiative.checked_duration_since(Instant::now()) else {
                // next_initiative timeout occurred, so go to next loop iteration.
                continue;
            };

            let directive = if let Some(directive) = directive {
                directive
            } else {
                match relay_rcv.recv_timeout(timeout) {
                    Ok(directive) => directive,
                    // timed out, so go to next loop iteration
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            };

            if !self.handle_directive(directive) {
                break;
            }
        }

        // kill miner if it's running
        signal_mining_blocked(self.globals.get_miner_status());

        // set termination flag so other threads die
        self.globals.signal_stop();

        debug!("Relayer exit!");
    }

    /// Top-level dispatcher
    pub fn handle_directive(&mut self, directive: RelayerDirective) -> bool {
        debug!("Relayer: handling directive"; "directive" => %directive);
        let continue_running = match directive {
            RelayerDirective::HandleNetResult(net_result) => {
                self.process_network_result(net_result);
                true
            }
            // RegisterKey directives mean that the relayer should try to register a new VRF key.
            // These are triggered by the relayer waking up without an active VRF key.
            RelayerDirective::RegisterKey(last_burn_block) => {
                if !self.is_miner {
                    return true;
                }
                if self.globals.in_initial_block_download() {
                    info!("In initial block download, will not submit VRF registration");
                    return true;
                }
                self.rotate_vrf_and_register(&last_burn_block);
                self.globals.counters.bump_blocks_processed();
                true
            }
            // ProcessedBurnBlock directives correspond to a new sortition perhaps occurring.
            //  relayer should invoke `handle_sortition` to determine if they won the sortition,
            //  and to start their miner, or stop their miner if an active tenure is now ending
            RelayerDirective::ProcessedBurnBlock(consensus_hash, burn_hash, block_header_hash) => {
                if !self.is_miner {
                    return true;
                }
                if self.globals.in_initial_block_download() {
                    debug!("In initial block download, will not check sortition for miner");
                    return true;
                }
                self.handle_sortition(
                    consensus_hash,
                    burn_hash,
                    StacksBlockId(block_header_hash.0),
                )
            }
            // These are triggered by the relayer waking up, seeing a new consensus hash *or* a new first tenure block
            RelayerDirective::IssueBlockCommit(consensus_hash, block_hash) => {
                if !self.is_miner {
                    return true;
                }
                if self.globals.in_initial_block_download() {
                    debug!("In initial block download, will not issue block commit");
                    return true;
                }
                if let Err(e) = self.issue_block_commit(consensus_hash, block_hash) {
                    warn!("Relayer failed to issue block commit"; "err" => ?e);
                }
                true
            }
            RelayerDirective::Exit => false,
        };
        debug!("Relayer: handled directive"; "continue_running" => continue_running);
        continue_running
    }
}
