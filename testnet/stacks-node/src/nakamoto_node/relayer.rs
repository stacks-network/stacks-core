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
use stacks::core::STACKS_EPOCH_3_0_MARKER;
use stacks::monitoring::increment_stx_blocks_mined_counter;
use stacks::net::db::LocalPeer;
use stacks::net::p2p::NetworkHandle;
use stacks::net::relay::Relayer;
use stacks::net::NetworkResult;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksBlockId, StacksPublicKey, VRFSeed,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::Hash160;
use stacks_common::util::vrf::VRFPublicKey;

use super::miner::MinerReason;
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

/// Last commitment data
/// This represents the tenure that the last-sent block-commit committed to.
pub struct LastCommit {
    /// block-commit sent
    block_commit: LeaderBlockCommitOp,
    /// the sortition tip at the time the block-commit was sent
    burn_tip: BlockSnapshot,
    /// the stacks tip at the time the block-commit was sent
    stacks_tip: StacksBlockId,
    /// the tenure consensus hash for the tip's tenure
    tenure_consensus_hash: ConsensusHash,
    /// the start-block hash of the tip's tenure
    start_block_hash: BlockHeaderHash,
    /// What is the epoch in which this was sent?
    epoch_id: StacksEpochId,
    /// commit txid (to be filled in on submission)
    txid: Option<Txid>,
}

impl LastCommit {
    pub fn new(
        commit: LeaderBlockCommitOp,
        burn_tip: BlockSnapshot,
        stacks_tip: StacksBlockId,
        tenure_consensus_hash: ConsensusHash,
        start_block_hash: BlockHeaderHash,
        epoch_id: StacksEpochId,
    ) -> Self {
        Self {
            block_commit: commit,
            burn_tip,
            stacks_tip,
            tenure_consensus_hash,
            start_block_hash,
            epoch_id,
            txid: None,
        }
    }

    /// Get the commit
    pub fn get_block_commit(&self) -> &LeaderBlockCommitOp {
        &self.block_commit
    }

    /// What's the parent tenure's tenure-start block hash?
    pub fn parent_tenure_id(&self) -> StacksBlockId {
        StacksBlockId(self.block_commit.block_header_hash.clone().0)
    }

    /// What's the stacks tip at the time of commit?
    pub fn get_stacks_tip(&self) -> &StacksBlockId {
        &self.stacks_tip
    }

    /// What's the burn tip at the time of commit?
    pub fn get_burn_tip(&self) -> &BlockSnapshot {
        &self.burn_tip
    }

    /// What's the epoch in which this was sent?
    pub fn get_epoch_id(&self) -> &StacksEpochId {
        &self.epoch_id
    }

    /// Get the tenure ID of the tenure this commit builds on
    pub fn get_tenure_id(&self) -> &ConsensusHash {
        &self.tenure_consensus_hash
    }

    /// Set our txid
    pub fn set_txid(&mut self, txid: &Txid) {
        self.txid = Some(txid.clone());
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
    miner_thread: Option<JoinHandle<Result<(), NakamotoNodeError>>>,
    /// The relayer thread reads directives from the relay_rcv, but it also periodically wakes up
    ///  to check if it should issue a block commit or try to register a VRF key
    next_initiative: Instant,
    is_miner: bool,
    /// Information about the last-sent block commit, and the relayer's view of the chain at the
    /// time it was sent.
    last_committed: Option<LastCommit>,
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

    /// Get a handle to the p2p thread
    pub fn get_p2p_handle(&self) -> NetworkHandle {
        self.relayer.get_p2p_handle()
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
                &self.burnchain,
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
    /// Returns a directive to the relayer thread to either start, stop, or continue a tenure.
    pub fn process_sortition(
        &mut self,
        consensus_hash: ConsensusHash,
        burn_hash: BurnchainHeaderHash,
        committed_index_hash: StacksBlockId,
    ) -> Result<MinerDirective, NakamotoNodeError> {
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

        let directive = if sn.sortition {
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
        };
        Ok(directive)
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

    /// Produce the block-commit for this upcoming tenure, if we can.
    ///
    /// Takes the Nakamoto chain tip (consensus hash, block header hash).
    ///
    /// Returns the (the most recent burn snapshot, the most recent stakcs tip, the commit-op) on success
    /// Returns None if we fail somehow.
    ///
    /// TODO: unit test
    pub(crate) fn make_block_commit(
        &mut self,
        tip_block_ch: &ConsensusHash,
        tip_block_bh: &BlockHeaderHash,
    ) -> Result<LastCommit, NakamotoNodeError> {
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn())
            .map_err(|_| NakamotoNodeError::SnapshotNotFoundForChainTip)?;

        let stacks_tip = StacksBlockId::new(tip_block_ch, tip_block_bh);

        // sanity check -- this block must exist and have been processed locally
        let highest_tenure_start_block_header = NakamotoChainState::get_tenure_start_block_header(
            &mut self.chainstate.index_conn(),
            &stacks_tip,
            &tip_block_ch,
        )
        .map_err(|e| {
            error!(
                "Relayer: Failed to get tenure-start block header for stacks tip {}: {:?}",
                &stacks_tip, &e
            );
            NakamotoNodeError::ParentNotFound
        })?
        .ok_or_else(|| {
            error!(
                "Relayer: Failed to find tenure-start block header for stacks tip {}",
                &stacks_tip
            );
            NakamotoNodeError::ParentNotFound
        })?;

        // load the VRF proof generated in this tenure, so we can use it to seed the VRF in the
        // upcoming tenure.  This may be an epoch2x VRF proof.
        let tip_vrf_proof = NakamotoChainState::get_block_vrf_proof(
            &mut self.chainstate.index_conn(),
            &stacks_tip,
            tip_block_ch,
        )
        .map_err(|e| {
            error!(
                "Failed to load VRF proof for {} off of {}: {:?}",
                tip_block_ch, &stacks_tip, &e
            );
            NakamotoNodeError::ParentNotFound
        })?
        .ok_or_else(|| {
            error!(
                "No block VRF proof for {} off of {}",
                tip_block_ch, &stacks_tip
            );
            NakamotoNodeError::ParentNotFound
        })?;

        // let's figure out the recipient set!
        let recipients = get_nakamoto_next_recipients(
            &sort_tip,
            &mut self.sortdb,
            &mut self.chainstate,
            &stacks_tip,
            &self.burnchain,
        )
        .map_err(|e| {
            error!("Relayer: Failure fetching recipient set: {:?}", e);
            NakamotoNodeError::SnapshotNotFoundForChainTip
        })?;

        let commit_outs = if self
            .burnchain
            .is_in_prepare_phase(sort_tip.block_height + 1)
        {
            vec![PoxAddress::standard_burn_address(self.config.is_mainnet())]
        } else {
            RewardSetInfo::into_commit_outs(recipients, self.config.is_mainnet())
        };

        // find the sortition that kicked off this tenure (it may be different from the sortition
        // tip, such as when there is no sortition or when the miner of the current sortition never
        // produces a block).  This is used to find the parent block-commit of the block-commit
        // we'll submit.
        let Ok(Some(tip_tenure_sortition)) =
            SortitionDB::get_block_snapshot_consensus(self.sortdb.conn(), tip_block_ch)
        else {
            error!("Relayer: Failed to lookup the block snapshot of highest tenure ID"; "tenure_consensus_hash" => %tip_block_ch);
            return Err(NakamotoNodeError::ParentNotFound);
        };

        // find the parent block-commit of this commit
        let commit_parent_block_burn_height = tip_tenure_sortition.block_height;
        let Ok(Some(parent_winning_tx)) = SortitionDB::get_block_commit(
            self.sortdb.conn(),
            &tip_tenure_sortition.winning_block_txid,
            &tip_tenure_sortition.sortition_id,
        ) else {
            error!("Relayer: Failed to lookup the block commit of parent tenure ID"; "tenure_consensus_hash" => %tip_block_ch);
            return Err(NakamotoNodeError::SnapshotNotFoundForChainTip);
        };

        let commit_parent_winning_vtxindex = parent_winning_tx.vtxindex;

        // epoch in which this commit will be sent (affects how the burnchain client processes it)
        let Ok(Some(target_epoch)) =
            SortitionDB::get_stacks_epoch(self.sortdb.conn(), sort_tip.block_height + 1)
        else {
            error!("Relayer: Failed to lookup its epoch"; "target_height" => sort_tip.block_height + 1);
            return Err(NakamotoNodeError::SnapshotNotFoundForChainTip);
        };

        // amount of burnchain tokens (e.g. sats) we'll spend across the PoX outputs
        let burn_fee_cap = get_mining_spend_amount(self.globals.get_miner_status());

        // let's commit, but target the current burnchain tip with our modulus so the commit is
        // only valid if it lands in the targeted burnchain block height
        let burn_parent_modulus = u8::try_from(sort_tip.block_height % BURN_BLOCK_MINED_AT_MODULUS)
            .map_err(|_| {
                error!("Relayer: Block mining modulus is not u8");
                NakamotoNodeError::UnexpectedChainState
            })?;

        // burnchain signer for this commit
        let sender = self.keychain.get_burnchain_signer();

        // VRF key this commit uses (i.e. the one we registered)
        let key = self
            .globals
            .get_leader_key_registration_state()
            .get_active()
            .ok_or_else(|| NakamotoNodeError::NoVRFKeyActive)?;

        let commit = LeaderBlockCommitOp {
            // NOTE: to be filled in
            treatment: vec![],
            // NOTE: PoX sunset has been disabled prior to taking effect
            sunset_burn: 0,
            // block-commits in Nakamoto commit to the ongoing tenure's tenure-start block (which,
            // when processed, become the start-block of the tenure atop which this miner will
            // produce blocks)
            block_header_hash: BlockHeaderHash(
                highest_tenure_start_block_header.index_block_hash().0,
            ),
            // the rest of this is the same as epoch2x commits, modulo the new epoch marker
            burn_fee: burn_fee_cap,
            apparent_sender: sender,
            key_block_ptr: u32::try_from(key.block_height)
                .expect("FATAL: burn block height exceeded u32"),
            key_vtxindex: u16::try_from(key.op_vtxindex).expect("FATAL: vtxindex exceeded u16"),
            memo: vec![STACKS_EPOCH_3_0_MARKER],
            new_seed: VRFSeed::from_proof(&tip_vrf_proof),
            parent_block_ptr: u32::try_from(commit_parent_block_burn_height)
                .expect("FATAL: burn block height exceeded u32"),
            parent_vtxindex: u16::try_from(commit_parent_winning_vtxindex)
                .expect("FATAL: vtxindex exceeded u16"),
            burn_parent_modulus,
            commit_outs,

            // NOTE: to be filled in
            input: (Txid([0; 32]), 0),
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        };

        Ok(LastCommit::new(
            commit,
            sort_tip,
            stacks_tip,
            highest_tenure_start_block_header.consensus_hash,
            highest_tenure_start_block_header
                .anchored_header
                .block_hash(),
            target_epoch.epoch_id,
        ))
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
        burn_election_block: BlockSnapshot,
        burn_tip: BlockSnapshot,
        parent_tenure_id: StacksBlockId,
        reason: MinerReason,
    ) -> Result<BlockMinerThread, NakamotoNodeError> {
        if fault_injection_skip_mining(&self.config.node.rpc_bind, burn_tip.block_height) {
            debug!(
                "Relayer: fault injection skip mining at block height {}",
                burn_tip.block_height
            );
            return Err(NakamotoNodeError::FaultInjection);
        }

        let burn_header_hash = burn_tip.burn_header_hash.clone();
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
            "height" => burn_tip.block_height,
            "burn_header_hash" => %burn_header_hash,
            "parent_tenure_id" => %parent_tenure_id,
            "reason" => %reason,
            "burn_election_block.consensus_hash" => %burn_election_block.consensus_hash,
            "burn_tip.consensus_hash" => %burn_tip.consensus_hash,
        );

        let miner_thread_state = BlockMinerThread::new(
            self,
            registered_key,
            burn_election_block,
            burn_tip,
            parent_tenure_id,
            reason,
        );
        Ok(miner_thread_state)
    }

    fn start_new_tenure(
        &mut self,
        parent_tenure_start: StacksBlockId,
        block_election_snapshot: BlockSnapshot,
        burn_tip: BlockSnapshot,
        reason: MinerReason,
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
        let new_miner_state = self.create_block_miner(
            vrf_key,
            block_election_snapshot,
            burn_tip,
            parent_tenure_start,
            reason,
        )?;

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

    fn continue_tenure(&mut self, new_burn_view: ConsensusHash) -> Result<(), NakamotoNodeError> {
        if let Err(e) = self.stop_tenure() {
            error!("Relayer: Failed to stop tenure: {:?}", e);
            return Ok(());
        }
        debug!("Relayer: successfully stopped tenure.");
        // Check if we should undergo a tenure change to switch to the new burn view
        let burn_tip =
            SortitionDB::get_block_snapshot_consensus(self.sortdb.conn(), &new_burn_view)
                .map_err(|e| {
                    error!("Relayer: failed to get block snapshot for new burn view: {e:?}");
                    NakamotoNodeError::SnapshotNotFoundForChainTip
                })?
                .ok_or_else(|| {
                    error!("Relayer: failed to get block snapshot for new burn view");
                    NakamotoNodeError::SnapshotNotFoundForChainTip
                })?;

        let (canonical_stacks_tip_ch, canonical_stacks_tip_bh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(self.sortdb.conn()).unwrap();
        let canonical_stacks_tip =
            StacksBlockId::new(&canonical_stacks_tip_ch, &canonical_stacks_tip_bh);
        let block_election_snapshot =
            SortitionDB::get_block_snapshot_consensus(self.sortdb.conn(), &canonical_stacks_tip_ch)
                .map_err(|e| {
                    error!("Relayer: failed to get block snapshot for canonical tip: {e:?}");
                    NakamotoNodeError::SnapshotNotFoundForChainTip
                })?
                .ok_or_else(|| {
                    error!("Relayer: failed to get block snapshot for canonical tip");
                    NakamotoNodeError::SnapshotNotFoundForChainTip
                })?;

        let Some(ref mining_key) = self.config.miner.mining_key else {
            return Ok(());
        };
        let mining_pkh = Hash160::from_node_public_key(&StacksPublicKey::from_private(mining_key));

        let last_winner_snapshot = {
            let ih = self.sortdb.index_handle(&burn_tip.sortition_id);
            ih.get_last_snapshot_with_sortition(burn_tip.block_height)
                .map_err(|e| {
                    error!("Relayer: failed to get last snapshot with sortition: {e:?}");
                    NakamotoNodeError::SnapshotNotFoundForChainTip
                })?
        };

        if last_winner_snapshot.miner_pk_hash != Some(mining_pkh) {
            debug!("Relayer: the miner did not win the last sortition. No tenure to continue.";
                   "current_mining_pkh" => %mining_pkh,
                   "last_winner_snapshot.miner_pk_hash" => ?last_winner_snapshot.miner_pk_hash,
            );
            return Ok(());
        } else {
            debug!("Relayer: the miner won the last sortition. Continuing tenure.");
        }

        match self.start_new_tenure(
            canonical_stacks_tip, // For tenure extend, we should be extending off the canonical tip
            block_election_snapshot,
            burn_tip,
            MinerReason::Extended {
                burn_view_consensus_hash: new_burn_view,
            },
        ) {
            Ok(()) => {
                debug!("Relayer: successfully started new tenure.");
            }
            Err(e) => {
                error!("Relayer: Failed to start new tenure: {:?}", e);
            }
        }
        Ok(())
    }

    fn handle_sortition(
        &mut self,
        consensus_hash: ConsensusHash,
        burn_hash: BurnchainHeaderHash,
        committed_index_hash: StacksBlockId,
    ) -> bool {
        let miner_instruction =
            match self.process_sortition(consensus_hash, burn_hash, committed_index_hash) {
                Ok(mi) => mi,
                Err(_) => {
                    return false;
                }
            };

        match miner_instruction {
            MinerDirective::BeginTenure {
                parent_tenure_start,
                burnchain_tip,
            } => match self.start_new_tenure(
                parent_tenure_start,
                burnchain_tip.clone(),
                burnchain_tip,
                MinerReason::BlockFound,
            ) {
                Ok(()) => {
                    debug!("Relayer: successfully started new tenure.");
                }
                Err(e) => {
                    error!("Relayer: Failed to start new tenure: {:?}", e);
                }
            },
            MinerDirective::ContinueTenure { new_burn_view } => {
                match self.continue_tenure(new_burn_view) {
                    Ok(()) => {
                        debug!("Relayer: successfully handled continue tenure.");
                    }
                    Err(e) => {
                        error!("Relayer: Failed to continue tenure: {:?}", e);
                        return false;
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

    /// Generate and submit the next block-commit, and record it locally
    fn issue_block_commit(
        &mut self,
        tip_block_ch: ConsensusHash,
        tip_block_bh: BlockHeaderHash,
    ) -> Result<(), NakamotoNodeError> {
        let mut last_committed = self.make_block_commit(&tip_block_ch, &tip_block_bh)?;
        #[cfg(test)]
        {
            if TEST_SKIP_COMMIT_OP.lock().unwrap().unwrap_or(false) {
                warn!("Relayer: not submitting block-commit to bitcoin network due to test directive.");
                return Ok(());
            }
        }

        // sign and broadcast
        let mut op_signer = self.keychain.generate_op_signer();
        let txid = self
            .bitcoin_controller
            .submit_operation(
                last_committed.get_epoch_id().clone(),
                BlockstackOperationType::LeaderBlockCommit(
                    last_committed.get_block_commit().clone(),
                ),
                &mut op_signer,
                1,
            )
            .ok_or_else(|| {
                warn!("Failed to submit block-commit bitcoin transaction");
                NakamotoNodeError::BurnchainSubmissionFailed
            })?;

        info!(
            "Relayer: Submitted block-commit";
            "tip_consensus_hash" => %tip_block_ch,
            "tip_block_hash" => %tip_block_bh,
            "txid" => %txid,
        );

        // update local state
        last_committed.set_txid(&txid);
        self.last_commits.insert(txid);
        self.last_committed = Some(last_committed);
        self.globals.counters.bump_naka_submitted_commits();

        Ok(())
    }

    /// Determine what the relayer should do to advance the chain.
    /// * If this isn't a miner, then it's always nothing.
    /// * Otherwise, if we haven't done so already, go register a VRF public key
    fn initiative(&mut self) -> Option<RelayerDirective> {
        if !self.is_miner {
            return None;
        }

        match self.globals.get_leader_key_registration_state() {
            // do we need a VRF key registration?
            LeaderKeyRegistrationState::Inactive => {
                let Ok(sort_tip) = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn())
                else {
                    warn!("Failed to fetch sortition tip while needing to register VRF key");
                    return None;
                };
                return Some(RelayerDirective::RegisterKey(sort_tip));
            }
            // are we still waiting on a pending registration?
            LeaderKeyRegistrationState::Pending(..) => {
                return None;
            }
            LeaderKeyRegistrationState::Active(_) => {}
        };

        // load up canonical sortition and stacks tips
        let Ok(sort_tip) =
            SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn()).map_err(|e| {
                error!("Failed to load canonical sortition tip: {:?}", &e);
                e
            })
        else {
            return None;
        };

        // NOTE: this may be an epoch2x tip
        let Ok((stacks_tip_ch, stacks_tip_bh)) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(self.sortdb.conn()).map_err(|e| {
                error!("Failed to load canonical stacks tip: {:?}", &e);
                e
            })
        else {
            return None;
        };
        let stacks_tip = StacksBlockId::new(&stacks_tip_ch, &stacks_tip_bh);

        // check stacks and sortition tips to see if any chainstate change has happened.
        // did our view of the sortition history change?
        // if so, then let's try and confirm the highest tenure so far.
        let burnchain_changed = self
            .last_committed
            .as_ref()
            .map(|cmt| cmt.get_burn_tip().consensus_hash != sort_tip.consensus_hash)
            .unwrap_or(true);

        let highest_tenure_changed = self
            .last_committed
            .as_ref()
            .map(|cmt| cmt.get_tenure_id() != &stacks_tip_ch)
            .unwrap_or(true);

        debug!("Relayer: initiative to commit";
               "sortititon tip" => %sort_tip.consensus_hash,
               "stacks tip" => %stacks_tip,
               "last-commit burn view" => %self.last_committed.as_ref().map(|cmt| cmt.get_burn_tip().consensus_hash.to_string()).unwrap_or("(not set)".to_string()),
               "last-commit ongoing tenure" => %self.last_committed.as_ref().map(|cmt| cmt.get_tenure_id().to_string()).unwrap_or("(not set)".to_string()),
               "burnchain view changed?" => %burnchain_changed,
               "highest tenure changed?" => %highest_tenure_changed);

        if !burnchain_changed && !highest_tenure_changed {
            // nothing to do
            return None;
        }

        // burnchain view or highest-tenure view changed, so we need to send (or RBF) a commit
        Some(RelayerDirective::IssueBlockCommit(
            stacks_tip_ch,
            stacks_tip_bh,
        ))
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
