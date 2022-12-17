// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

/// Main body of code for the Stacks node and miner.
///
/// System schematic.
/// Legend:
///    |------|    Thread
///    /------\    Shared memory
///    @------@    Database
///    .------.    Code module
///
///
///                           |------------------|
///                           |  RunLoop thread  |   [1,7]
///                           |   .----------.   |--------------------------------------.
///                           |   .StacksNode.   |                                      |
///                           |---.----------.---|                                      |
///                    [1,12]     |     |    |     [1]                                  |
///              .----------------*     |    *---------------.                          |
///              |                  [3] |                    |                          |
///              V                      |                    V                          V
///      |----------------|             |    [9,10]   |---------------| [11] |--------------------------|
/// .--- | Relayer thread | <-----------|-----------> |   P2P Thread  | <--- | ChainsCoordinator thread | <--.
/// |    |----------------|             V             |---------------|      |--------------------------|    |
/// |            |     |          /-------------\    [2,3]    |    |              |          |               |
/// |        [1] |     *--------> /   Globals   \ <-----------*----|--------------*          | [4]           |
/// |            |     [2,3,7]    /-------------\                  |                         |               |
/// |            V                                                 V [5]                     V               |
/// |    |----------------|                                 @--------------@        @------------------@     |
/// |    |  Miner thread  | <------------------------------ @  Mempool DB  @        @  Chainstate DBs  @     |
/// |    |----------------|             [6]                 @--------------@        @------------------@     |
/// |                                                                                        ^               |
/// |                                               [8]                                      |               |
/// *----------------------------------------------------------------------------------------*               |
/// |                                               [7]                                                      |
/// *--------------------------------------------------------------------------------------------------------*
///
/// [1]  Spawns
/// [2]  Synchronize unconfirmed state
/// [3]  Enable/disable miner
/// [4]  Processes block data
/// [5]  Stores unconfirmed transactions
/// [6]  Reads unconfirmed transactions
/// [7]  Signals block arrival
/// [8]  Store blocks and microblocks
/// [9]  Pushes retrieved blocks and microblocks
/// [10] Broadcasts new blocks, microblocks, and transactions
/// [11] Notifies about new transaction attachment events
/// [12] Signals VRF key registration
///
/// When the node is running, there are 4-5 active threads at once.  They are:
///
/// * **RunLoop Thread**:  This is the main thread, whose code body lives in src/run_loop/neon.rs.
/// This thread is responsible for:
///    * Bootup
///    * Running the burnchain indexer
///    * Notifying the ChainsCoordinator thread when there are new burnchain blocks to process
///
/// * **Relayer Thread**:  This is the thread that stores and relays blocks and microblocks.  Both
/// it and the ChainsCoordinator thread are very I/O-heavy threads, and care has been taken to
/// ensure that neither one attempts to acquire a write-lock in the underlying databases.
/// Specifically, this thread directs the ChainsCoordinator thread when to process new Stacks
/// blocks, and it directs the miner thread (if running) to stop when either it or the
/// ChainsCoordinator thread needs to acquire the write-lock.
/// This thread is responsible for:
///    * Receiving new blocks and microblocks from the P2P thread via a shared channel
///    * (Sychronously) requesting the CoordinatorThread to process newly-stored Stacks blocks and
///    microblocks
///    * Building up the node's unconfirmed microblock stream state, and sharing it with the P2P
///    thread so it can answer queries about the unconfirmed microblock chain
///    * Pushing newly-discovered blocks and microblocks to the P2P thread for broadcast
///    * Registering the VRF public key for the miner
///    * Spawning the block and microblock miner threads, and stopping them if their continued
///    execution would inhibit block or microblock storage or processing.
///    * Submitting the burnchain operation to commit to a freshly-mined block
///
/// * **Miner thread**:  This is the thread that actually produces new blocks and microblocks.  It
/// is spawned only by the Relayer thread to carry out mining activity when the underlying
/// chainstate is not needed by either the Relayer or ChainsCoordinator threeads.
/// This thread does the following:
///    * Walk the mempool DB to build a new block or microblock
///    * Return the block or microblock to the Relayer thread
///
/// * **P2P Thread**:  This is the thread that communicates with the rest of the p2p network, and
/// handles RPC requests.  It is meant to do as little storage-write I/O as possible to avoid lock
/// contention with the Miner, Relayer, and ChainsCoordinator threads.  In particular, it forwards
/// data it receives from the p2p thread to the Relayer thread for I/O-bound processing.  At the
/// time of this writing, it still requires holding a write-lock to handle some RPC request, but
/// future work will remove this so that this thread's execution will not interfere with the
/// others.  This is the only thread that does socket I/O.
/// This thread runs the PeerNetwork state machines, which include the following:
///    * Learning the node's public IP address
///    * Discovering neighbor nodes
///    * Forwarding newly-discovered blocks, microblocks, and transactions from the Relayer thread to
///    other neighbors
///    * Synchronizing block and microblock inventory state with other neighbors
///    * Downloading blocks and microblocks, and passing them to the Relayer for storage and processing
///    * Downloading transaction attachments as their hashes are discovered during block processing
///    * Synchronizing the local mempool database with other neighbors
///    (notifications for new attachments come from a shared channel in the ChainsCoordinator thread)
///    * Handling HTTP requests
///
/// * **ChainsCoordinator Thread**:  This thread process sortitions and Stacks blocks and
/// microblocks, and handles PoX reorgs should they occur (this mainly happens in boot-up).  It,
/// like the Relayer thread, is a very I/O-heavy thread, and it will hold a write-lock on the
/// chainstate DBs while it works.  Its actions are controlled by a CoordinatorComms structure in
/// the Globals shared state, which the Relayer thread and RunLoop thread both drive (the former
/// drives Stacks blocks processing, the latter sortitions).
/// This thread is responsible for:
///    * Responding to requests from other threads to process sortitions
///    * Responding to requests from other threads to process Stacks blocks and microblocks
///    * Processing PoX chain reorgs, should they ever happen
///    * Detecting attachment creation events, and informing the P2P thread of them so it can go
///    and download them
///
/// In addition to the mempool and chainstate databases, these threads share access to a Globals
/// singleton that contains soft state shared between threads.  Mainly, the Globals struct is meant
/// to store inter-thread shared singleton communication media all in one convenient struct.  Each
/// thread has a handle to the struct's shared state handles.  Global state includes:
///    * The global flag as to whether or not the miner thread can be running
///    * The global shutdown flag that, when set, causes all threads to terminate
///    * Sender channel endpoints that can be shared between threads
///    * Metrics about the node's behavior (e.g. number of blocks processed, etc.)
///
/// This file may be refactored in the future into a full-fledged module.
use std::cmp;
use std::collections::HashMap;
use std::collections::{HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::default::Default;
use std::mem;
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, Mutex};
use std::time::Duration;
use std::{thread, thread::JoinHandle};

use stacks::burnchains::{Burnchain, BurnchainParameters, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::{
    leader_block_commit::{RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS},
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::coordinator::{get_next_recipients, OnChainRewardSetProvider};
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::db::unconfirmed::UnconfirmedTxMap;
use stacks::chainstate::stacks::db::StacksHeaderInfo;
use stacks::chainstate::stacks::db::{StacksChainState, MINER_REWARD_MATURITY};
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::chainstate::stacks::StacksPublicKey;
use stacks::chainstate::stacks::{
    miner::signal_mining_blocked, miner::signal_mining_ready, miner::BlockBuilderSettings,
    miner::MinerStatus, miner::StacksMicroblockBuilder, StacksBlockBuilder, StacksBlockHeader,
};
use stacks::chainstate::stacks::{
    CoinbasePayload, StacksBlock, StacksMicroblock, StacksTransaction, StacksTransactionSigner,
    TransactionAnchorMode, TransactionPayload, TransactionVersion,
};
use stacks::codec::StacksMessageCodec;
use stacks::core::mempool::MemPoolDB;
use stacks::core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks::core::STACKS_EPOCH_2_1_MARKER;
use stacks::cost_estimates::metrics::CostMetric;
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::cost_estimates::{CostEstimator, FeeEstimator};
use stacks::monitoring::{increment_stx_blocks_mined_counter, update_active_miners_count_gauge};
use stacks::net::{
    atlas::{AtlasConfig, AtlasDB, AttachmentInstance},
    db::{LocalPeer, PeerDB},
    dns::DNSClient,
    dns::DNSResolver,
    p2p::PeerNetwork,
    relay::Relayer,
    rpc::RPCHandlerArgs,
    Error as NetError, NetworkResult, PeerAddress, ServiceFlags,
};
use stacks::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, VRFSeed,
};
use stacks::types::StacksEpochId;
use stacks::util::get_epoch_time_ms;
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::{to_hex, Hash160, Sha256Sum};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks::util::vrf::VRFPublicKey;
use stacks::util_lib::strings::{UrlString, VecDisplay};
use stacks::vm::costs::ExecutionCost;

use crate::burnchains::bitcoin_regtest_controller::BitcoinRegtestController;
use crate::burnchains::bitcoin_regtest_controller::OngoingBlockCommit;
use crate::run_loop::neon::Counters;
use crate::run_loop::neon::RunLoop;
use crate::run_loop::RegisteredKey;
use crate::ChainTip;

use super::{BurnchainController, Config, EventDispatcher, Keychain};
use crate::syncctl::PoxSyncWatchdogComms;
use stacks::monitoring;

use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::util::vrf::VRFProof;

use clarity::vm::ast::ASTRules;
use clarity::vm::types::PrincipalData;

pub const RELAYER_MAX_BUFFER: usize = 100;
const VRF_MOCK_MINER_KEY: u64 = 1;

pub const BLOCK_PROCESSOR_STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

type MinedBlocks = HashMap<BlockHeaderHash, (AssembledAnchorBlock, Secp256k1PrivateKey)>;

/// Result of running the miner thread.  It could produce a Stacks block or a microblock.
enum MinerThreadResult {
    Block(
        AssembledAnchorBlock,
        Secp256k1PrivateKey,
        Option<OngoingBlockCommit>,
    ),
    Microblock(
        Result<Option<(StacksMicroblock, ExecutionCost)>, NetError>,
        MinerTip,
    ),
}

/// Fully-assembled Stacks anchored, block as well as some extra metadata pertaining to how it was
/// linked to the burnchain and what view(s) the miner had of the burnchain before and after
/// completing the block.
#[derive(Clone)]
struct AssembledAnchorBlock {
    /// Consensus hash of the parent Stacks block
    parent_consensus_hash: ConsensusHash,
    /// Burnchain tip's block hash when we finished mining
    my_burn_hash: BurnchainHeaderHash,
    /// Burnchain tip's block height when we finished mining
    my_block_height: u64,
    /// Burnchain tip's block hash when we started mining (could be different)
    orig_burn_hash: BurnchainHeaderHash,
    /// The block we produced
    anchored_block: StacksBlock,
    /// The attempt count of this block (multiple blocks will be attempted per burnchain block)
    attempt: u64,
    /// Epoch timestamp in milliseconds when we started producing the block.
    tenure_begin: u128,
}

/// Command types for the relayer thread, issued to it by other threads
pub enum RelayerDirective {
    /// Handle some new data that arrived on the network (such as blocks, transactions, and
    /// microblocks)
    HandleNetResult(NetworkResult),
    /// Announce a new sortition.  Process and broadcast the block if we won.
    ProcessTenure(ConsensusHash, BurnchainHeaderHash, BlockHeaderHash),
    /// Try to mine a block
    RunTenure(RegisteredKey, BlockSnapshot, u128), // (vrf key, chain tip, time of issuance in ms)
    /// Try to register a VRF public key
    RegisterKey(BlockSnapshot),
    /// Stop the relayer thread
    Exit,
}

/// Inter-thread communication structure, shared between threads
#[derive(Clone)]
pub struct Globals {
    /// Last sortition processed
    last_sortition: Arc<Mutex<Option<BlockSnapshot>>>,
    /// Status of the miner
    miner_status: Arc<Mutex<MinerStatus>>,
    /// Communication link to the coordinator thread
    coord_comms: CoordinatorChannels,
    /// Unconfirmed transactions (shared between the relayer and p2p threads)
    unconfirmed_txs: Arc<Mutex<UnconfirmedTxMap>>,
    /// Writer endpoint to the relayer thread
    relay_send: SyncSender<RelayerDirective>,
    /// Cointer state in the main thread
    counters: Counters,
    /// Connection to the PoX sync watchdog
    sync_comms: PoxSyncWatchdogComms,
    /// Global flag to see if we should keep running
    pub should_keep_running: Arc<AtomicBool>,
    /// Status of our VRF key registration state (shared between the main thread and the relayer)
    leader_key_registration_state: Arc<Mutex<LeaderKeyRegistrationState>>,
}

/// Miner chain tip, on top of which to build microblocks
#[derive(Debug, Clone, PartialEq)]
pub struct MinerTip {
    /// tip's consensus hash
    consensus_hash: ConsensusHash,
    /// tip's Stacks block header hash
    block_hash: BlockHeaderHash,
    /// Microblock private key to use to sign microblocks
    microblock_privkey: Secp256k1PrivateKey,
    /// Stacks height
    stacks_height: u64,
    /// burnchain height
    burn_height: u64,
}

impl MinerTip {
    pub fn new(
        ch: ConsensusHash,
        bh: BlockHeaderHash,
        pk: Secp256k1PrivateKey,
        stacks_height: u64,
        burn_height: u64,
    ) -> MinerTip {
        MinerTip {
            consensus_hash: ch,
            block_hash: bh,
            microblock_privkey: pk,
            stacks_height,
            burn_height,
        }
    }
}

impl Globals {
    pub fn new(
        coord_comms: CoordinatorChannels,
        miner_status: Arc<Mutex<MinerStatus>>,
        relay_send: SyncSender<RelayerDirective>,
        counters: Counters,
        sync_comms: PoxSyncWatchdogComms,
        should_keep_running: Arc<AtomicBool>,
    ) -> Globals {
        Globals {
            last_sortition: Arc::new(Mutex::new(None)),
            miner_status,
            coord_comms,
            unconfirmed_txs: Arc::new(Mutex::new(UnconfirmedTxMap::new())),
            relay_send,
            counters,
            sync_comms,
            should_keep_running,
            leader_key_registration_state: Arc::new(Mutex::new(
                LeaderKeyRegistrationState::Inactive,
            )),
        }
    }

    /// Get the last sortition processed by the relayer thread
    pub fn get_last_sortition(&self) -> Option<BlockSnapshot> {
        match self.last_sortition.lock() {
            Ok(sort_opt) => sort_opt.clone(),
            Err(_) => {
                error!("Sortition mutex poisoned!");
                panic!();
            }
        }
    }

    /// Set the last sortition processed
    pub fn set_last_sortition(&self, block_snapshot: BlockSnapshot) {
        match self.last_sortition.lock() {
            Ok(mut sortition_opt) => {
                sortition_opt.replace(block_snapshot);
            }
            Err(_) => {
                error!("Sortition mutex poisoned!");
                panic!();
            }
        };
    }

    /// Get the status of the miner (blocked or ready)
    pub fn get_miner_status(&self) -> Arc<Mutex<MinerStatus>> {
        self.miner_status.clone()
    }

    /// Get the main thread's counters
    pub fn get_counters(&self) -> Counters {
        self.counters.clone()
    }

    /// Called by the relayer to pass unconfirmed txs to the p2p thread, so the p2p thread doesn't
    /// need to do the disk I/O needed to instantiate the unconfirmed state trie they represent.
    /// Clears the unconfirmed transactions, and replaces them with the chainstate's.
    pub fn send_unconfirmed_txs(&self, chainstate: &StacksChainState) {
        if let Some(ref unconfirmed) = chainstate.unconfirmed_state {
            match self.unconfirmed_txs.lock() {
                Ok(mut txs) => {
                    txs.clear();
                    txs.extend(unconfirmed.mined_txs.clone());
                }
                Err(e) => {
                    // can only happen due to a thread panic in the relayer
                    error!("FATAL: unconfirmed tx arc mutex is poisoned: {:?}", &e);
                    panic!();
                }
            };
        }
    }

    /// Called by the p2p thread to accept the unconfirmed tx state processed by the relayer.
    /// Puts the shared unconfirmed transactions to chainstate.
    pub fn recv_unconfirmed_txs(&self, chainstate: &mut StacksChainState) {
        if let Some(ref mut unconfirmed) = chainstate.unconfirmed_state {
            match self.unconfirmed_txs.lock() {
                Ok(txs) => {
                    unconfirmed.mined_txs.clear();
                    unconfirmed.mined_txs.extend(txs.clone());
                }
                Err(e) => {
                    // can only happen due to a thread panic in the relayer
                    error!("FATAL: unconfirmed arc mutex is poisoned: {:?}", &e);
                    panic!();
                }
            };
        }
    }

    /// Signal system-wide stop
    pub fn signal_stop(&self) {
        self.should_keep_running.store(false, Ordering::SeqCst);
    }

    /// Should we keep running?
    pub fn keep_running(&self) -> bool {
        self.should_keep_running.load(Ordering::SeqCst)
    }

    /// Get the handle to the coordinator
    pub fn coord(&self) -> &CoordinatorChannels {
        &self.coord_comms
    }

    /// Get the current leader key registration state.
    /// Called from the runloop thread and relayer thread.
    fn get_leader_key_registration_state(&self) -> LeaderKeyRegistrationState {
        match self.leader_key_registration_state.lock() {
            Ok(state) => (*state).clone(),
            Err(e) => {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: leader key registration mutex is poisoned: {:?}", &e);
                panic!();
            }
        }
    }

    /// Set the initial leader key registration state.
    /// Called from the runloop thread when booting up.
    fn set_initial_leader_key_registration_state(&self, new_state: LeaderKeyRegistrationState) {
        match self.leader_key_registration_state.lock() {
            Ok(mut state) => {
                *state = new_state;
            }
            Err(e) => {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: leader key registration mutex is poisoned: {:?}", &e);
                panic!();
            }
        }
    }

    /// Advance the leader key registration state to pending, given a txid we just sent.
    /// Only the relayer thread calls this.
    fn set_pending_leader_key_registration(&self, target_block_height: u64, txid: Txid) {
        match self.leader_key_registration_state.lock() {
            Ok(ref mut leader_key_registration_state) => {
                **leader_key_registration_state =
                    LeaderKeyRegistrationState::Pending(target_block_height, txid);
            }
            Err(_e) => {
                error!("FATAL: failed to lock leader key registration state mutex");
                panic!();
            }
        }
    }

    /// Advance the leader key registration state to active, given the VRF key registration ops
    /// we've discovered in a given snapshot.
    /// The runloop thread calls this whenever it processes a sortition.
    pub fn try_activate_leader_key_registration(
        &self,
        burn_block_height: u64,
        key_registers: Vec<LeaderKeyRegisterOp>,
    ) -> bool {
        let mut activated = false;
        match self.leader_key_registration_state.lock() {
            Ok(ref mut leader_key_registration_state) => {
                for op in key_registers.into_iter() {
                    if let LeaderKeyRegistrationState::Pending(target_block_height, txid) =
                        **leader_key_registration_state
                    {
                        info!(
                            "Received burnchain block #{} including key_register_op - {}",
                            burn_block_height, txid
                        );
                        if txid == op.txid {
                            **leader_key_registration_state =
                                LeaderKeyRegistrationState::Active(RegisteredKey {
                                    target_block_height,
                                    vrf_public_key: op.public_key,
                                    block_height: op.block_height as u64,
                                    op_vtxindex: op.vtxindex as u32,
                                });
                            activated = true;
                        } else {
                            debug!(
                                "key_register_op {} does not match our pending op {}",
                                txid, &op.txid
                            );
                        }
                    }
                }
            }
            Err(_e) => {
                error!("FATAL: failed to lock leader key registration state mutex");
                panic!();
            }
        }
        activated
    }
}

/// Node implementation for both miners and followers.
/// This struct is used to set up the node proper and launch the p2p thread and relayer thread.
/// It is further used by the main thread to communicate with these two threads.
pub struct StacksNode {
    /// Atlas network configuration
    pub atlas_config: AtlasConfig,
    /// Global inter-thread communication handle
    pub globals: Globals,
    /// True if we're a miner
    is_miner: bool,
    /// handle to the p2p thread
    pub p2p_thread_handle: JoinHandle<()>,
    /// handle to the relayer thread
    pub relayer_thread_handle: JoinHandle<()>,
}

/// Fault injection logic to artificially increase the length of a tenure.
/// Only used in testing
#[cfg(test)]
fn fault_injection_long_tenure() {
    // simulated slow block
    match std::env::var("STX_TEST_SLOW_TENURE") {
        Ok(tenure_str) => match tenure_str.parse::<u64>() {
            Ok(tenure_time) => {
                info!(
                    "Fault injection: sleeping for {} milliseconds to simulate a long tenure",
                    tenure_time
                );
                stacks::util::sleep_ms(tenure_time);
            }
            Err(_) => {
                error!("Parse error for STX_TEST_SLOW_TENURE");
                panic!();
            }
        },
        _ => {}
    }
}

#[cfg(not(test))]
fn fault_injection_long_tenure() {}

/// Fault injection to skip mining in this bitcoin block height
/// Only used in testing
#[cfg(test)]
fn fault_injection_skip_mining(rpc_bind: &str, target_burn_height: u64) -> bool {
    match std::env::var("STACKS_DISABLE_MINER") {
        Ok(disable_heights) => {
            let disable_schedule: serde_json::Value =
                serde_json::from_str(&disable_heights).unwrap();
            let disable_schedule = disable_schedule.as_array().unwrap();
            for disabled in disable_schedule {
                let target_miner_rpc_bind = disabled
                    .get("rpc_bind")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                if target_miner_rpc_bind != rpc_bind {
                    continue;
                }
                let target_block_heights = disabled.get("blocks").unwrap().as_array().unwrap();
                for target_block_value in target_block_heights {
                    let target_block = target_block_value.as_i64().unwrap() as u64;
                    if target_block == target_burn_height {
                        return true;
                    }
                }
            }
            return false;
        }
        Err(_) => {
            return false;
        }
    }
}

#[cfg(not(test))]
fn fault_injection_skip_mining(_rpc_bind: &str, _target_burn_height: u64) -> bool {
    false
}

/// Open the chainstate, and inject faults from the config file
fn open_chainstate_with_faults(config: &Config) -> Result<StacksChainState, ChainstateError> {
    let stacks_chainstate_path = config.get_chainstate_path_str();
    let (mut chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        &stacks_chainstate_path,
        Some(config.node.get_marf_opts()),
    )?;

    chainstate.fault_injection.hide_blocks = config.node.fault_injection_hide_blocks;
    Ok(chainstate)
}

/// Types of errors that can arise during mining
enum Error {
    /// Can't find the header record for the chain tip
    HeaderNotFoundForChainTip,
    /// Can't find the stacks block's offset in the burnchain block
    WinningVtxNotFoundForChainTip,
    /// Can't find the block sortition snapshot for the chain tip
    SnapshotNotFoundForChainTip,
    /// The burnchain tip changed while this operation was in progress
    BurnchainTipChanged,
    /// The coordinator channel closed
    CoordinatorClosed,
}

/// Metadata required for beginning a new tenure
struct ParentStacksBlockInfo {
    /// Header metadata for the Stacks block we're going to build on top of
    stacks_parent_header: StacksHeaderInfo,
    /// the consensus hash of the sortition that selected the Stacks block parent
    parent_consensus_hash: ConsensusHash,
    /// the burn block height of the sortition that selected the Stacks block parent
    parent_block_burn_height: u64,
    /// the total amount burned in the sortition that selected the Stacks block parent
    parent_block_total_burn: u64,
    /// offset in the burnchain block where the parent's block-commit was
    parent_winning_vtxindex: u16,
    /// nonce to use for this new block's coinbase transaction
    coinbase_nonce: u64,
}

#[derive(Clone)]
enum LeaderKeyRegistrationState {
    /// Not started yet
    Inactive,
    /// Waiting for burnchain confirmation
    /// `u64` is the target block height in which we intend this key to land
    /// `txid` is the burnchain transaction ID
    Pending(u64, Txid),
    /// Ready to go!
    Active(RegisteredKey),
}

/// Relayer thread
/// * accepts network results and stores blocks and microblocks
/// * forwards new blocks, microblocks, and transactions to the p2p thread
/// * processes burnchain state
/// * if mining, runs the miner and broadcasts blocks (via a subordinate MinerThread)
pub struct RelayerThread {
    /// Node config
    config: Config,
    /// Handle to the sortition DB (optional so we can take/replace it)
    sortdb: Option<SortitionDB>,
    /// Handle to the chainstate DB (optional so we can take/replace it)
    chainstate: Option<StacksChainState>,
    /// Handle to the mempool DB (optional so we can take/replace it)
    mempool: Option<MemPoolDB>,
    /// Handle to global state and inter-thread communication channels
    globals: Globals,
    /// Authoritative copy of the keychain state
    keychain: Keychain,
    /// Burnchian configuration
    burnchain: Burnchain,
    /// height of last VRF key registration request
    last_vrf_key_burn_height: u64,
    /// Set of blocks that we have mined, but are still potentially-broadcastable
    last_mined_blocks: MinedBlocks,
    /// client to the burnchain (used only for sending block-commits)
    bitcoin_controller: BitcoinRegtestController,
    /// client to the event dispatcher
    event_dispatcher: EventDispatcher,
    /// copy of the local peer state
    local_peer: LocalPeer,
    /// last time we tried to mine a block (in millis)
    last_tenure_issue_time: u128,
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
    /// consensus hash of the last sortition we saw, even if we weren't the winner
    last_tenure_consensus_hash: Option<ConsensusHash>,
    /// tip of last tenure we won (used for mining microblocks)
    miner_tip: Option<MinerTip>,
    /// last time we mined a microblock, in millis
    last_microblock_tenure_time: u128,
    /// when should we run the next microblock tenure, in millis
    microblock_deadline: u128,
    /// cost of the last-produced microblock stream
    microblock_stream_cost: ExecutionCost,

    /// Inner relayer instance for forwarding broadcasted data back to the p2p thread for dispatch
    /// to neighbors
    relayer: Relayer,

    /// handle to the subordinate miner thread
    miner_thread: Option<JoinHandle<Option<MinerThreadResult>>>,
    /// if true, then the last time the miner thread was launched, it was used to mine a Stacks
    /// block (used to alternate between mining microblocks and Stacks blocks that confirm them)
    mined_stacks_block: bool,
}

struct BlockMinerThread {
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
    last_mined_blocks: MinedBlocks,
    /// Copy of the node's last ongoing block commit from the last time this thread was run
    ongoing_commit: Option<OngoingBlockCommit>,
    /// Copy of the node's registered VRF key
    registered_key: RegisteredKey,
    /// Burnchain block snapshot at the time this thread was initialized
    burn_block: BlockSnapshot,
    /// Handle to the node's event dispatcher
    event_dispatcher: EventDispatcher,
}

/// State representing the microblock miner.
struct MicroblockMinerThread {
    /// handle to global state
    globals: Globals,
    /// handle to chainstate DB (optional so we can take/replace it)
    chainstate: Option<StacksChainState>,
    /// handle to sortition DB (optional so we can take/replace it)
    sortdb: Option<SortitionDB>,
    /// handle to mempool DB (optional so we can take/replace it)
    mempool: Option<MemPoolDB>,
    /// Handle to the node's event dispatcher
    event_dispatcher: EventDispatcher,
    /// Parent Stacks block's sortition's consensus hash
    parent_consensus_hash: ConsensusHash,
    /// Parent Stacks block's hash
    parent_block_hash: BlockHeaderHash,
    /// Microblock signing key
    miner_key: Secp256k1PrivateKey,
    /// How often to make microblocks, in milliseconds
    frequency: u64,
    /// Epoch timestamp, in milliseconds, when the last microblock was produced
    last_mined: u128,
    /// How many microblocks produced so far
    quantity: u64,
    /// Block budget consumed so far by this tenure (initialized to the cost of the Stacks block
    /// itself; microblocks fill up the remaining budget)
    cost_so_far: ExecutionCost,
    /// Block builder settings for the microblock miner.
    settings: BlockBuilderSettings,
}

impl MicroblockMinerThread {
    /// Instantiate the miner thread state from the relayer thread.
    /// May fail if:
    /// * we didn't win the last sortition
    /// * we couldn't open or read the DBs for some reason
    /// * we couldn't find the anchored block (i.e. it's not processed yet)
    pub fn from_relayer_thread(relayer_thread: &RelayerThread) -> Option<MicroblockMinerThread> {
        let globals = relayer_thread.globals.clone();
        let config = relayer_thread.config.clone();
        let burnchain = relayer_thread.burnchain.clone();
        let miner_tip = match relayer_thread.miner_tip.clone() {
            Some(tip) => tip,
            None => {
                debug!("Relayer: cannot instantiate microblock miner: did not win Stacks tip sortition");
                return None;
            }
        };

        let stacks_chainstate_path = config.get_chainstate_path_str();
        let burn_db_path = config.get_burn_db_file_path();
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let sortdb = SortitionDB::open(&burn_db_path, true, burnchain.pox_constants.clone())
            .map_err(|e| {
                error!(
                    "Relayer: Could not open sortdb '{}' ({:?}); skipping tenure",
                    &burn_db_path, &e
                );
                e
            })
            .ok()?;

        let mut chainstate = open_chainstate_with_faults(&config)
            .map_err(|e| {
                error!(
                    "Relayer: Could not open chainstate '{}' ({:?}); skipping microblock tenure",
                    &stacks_chainstate_path, &e
                );
                e
            })
            .ok()?;

        let mempool = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let MinerTip {
            consensus_hash: ch,
            block_hash: bhh,
            microblock_privkey: miner_key,
            ..
        } = miner_tip;

        debug!(
            "Relayer: Instantiate microblock mining state off of {}/{}",
            &ch, &bhh
        );

        // we won a block! proceed to build a microblock tail if we've stored it
        match StacksChainState::get_anchored_block_header_info(chainstate.db(), &ch, &bhh) {
            Ok(Some(_)) => {
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(&ch, &bhh);
                let cost_so_far = if relayer_thread.microblock_stream_cost == ExecutionCost::zero()
                {
                    // unknown cost, or this is idempotent.
                    StacksChainState::get_stacks_block_anchored_cost(
                        chainstate.db(),
                        &parent_index_hash,
                    )
                    .expect("FATAL: failed to get anchored block cost")
                    .expect("FATAL: no anchored block cost stored for processed anchored block")
                } else {
                    relayer_thread.microblock_stream_cost.clone()
                };

                let frequency = config.node.microblock_frequency;
                let settings =
                    config.make_block_builder_settings(0, true, globals.get_miner_status());

                // port over unconfirmed state to this thread
                chainstate.unconfirmed_state = if let Some(unconfirmed_state) =
                    relayer_thread.chainstate_ref().unconfirmed_state.as_ref()
                {
                    Some(unconfirmed_state.make_readonly_owned().ok()?)
                } else {
                    None
                };

                Some(MicroblockMinerThread {
                    globals,
                    chainstate: Some(chainstate),
                    sortdb: Some(sortdb),
                    mempool: Some(mempool),
                    event_dispatcher: relayer_thread.event_dispatcher.clone(),
                    parent_consensus_hash: ch.clone(),
                    parent_block_hash: bhh.clone(),
                    miner_key,
                    frequency,
                    last_mined: 0,
                    quantity: 0,
                    cost_so_far: cost_so_far,
                    settings,
                })
            }
            Ok(None) => {
                warn!(
                    "Relayer: No such anchored block: {}/{}.  Cannot mine microblocks",
                    ch, bhh
                );
                None
            }
            Err(e) => {
                warn!(
                    "Relayer: Failed to get anchored block cost for {}/{}: {:?}",
                    ch, bhh, &e
                );
                None
            }
        }
    }

    /// Do something with the inner chainstate DBs (borrowed mutably).
    /// Used to fool the borrow-checker.
    /// NOT COMPOSIBLE - WILL PANIC IF CALLED FROM WITHIN ITSELF.
    fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut Self, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self.sortdb.take().expect("FATAL: already took sortdb");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("FATAL: already took chainstate");
        let mut mempool = self.mempool.take().expect("FATAL: already took mempool");

        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);

        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);

        res
    }

    /// Unconditionally mine one microblock.
    /// Can fail if the miner thread gets cancelled (most likely cause), or if there's some kind of
    /// DB error.
    fn inner_mine_one_microblock(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
    ) -> Result<StacksMicroblock, ChainstateError> {
        debug!(
            "Try to mine one microblock off of {}/{} (total: {})",
            &self.parent_consensus_hash,
            &self.parent_block_hash,
            chainstate
                .unconfirmed_state
                .as_ref()
                .map(|us| us.num_microblocks())
                .unwrap_or(0)
        );

        let burn_height =
            SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &self.parent_consensus_hash)
                .map_err(|e| {
                    error!("Failed to find block snapshot for mined block: {}", e);
                    e
                })?
                .ok_or_else(|| {
                    error!("Failed to find block snapshot for mined block");
                    ChainstateError::NoSuchBlockError
                })?
                .block_height;

        let ast_rules = SortitionDB::get_ast_rules(sortdb.conn(), burn_height).map_err(|e| {
            error!("Failed to get AST rules for microblock: {}", e);
            e
        })?;

        let epoch_id = SortitionDB::get_stacks_epoch(sortdb.conn(), burn_height)
            .map_err(|e| {
                error!("Failed to get epoch for microblock: {}", e);
                e
            })?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        let mint_result = {
            let ic = sortdb.index_conn();
            let mut microblock_miner = match StacksMicroblockBuilder::resume_unconfirmed(
                chainstate,
                &ic,
                &self.cost_so_far,
                self.settings.clone(),
            ) {
                Ok(x) => x,
                Err(e) => {
                    let msg = format!(
                        "Failed to create a microblock miner at chaintip {}/{}: {:?}",
                        &self.parent_consensus_hash, &self.parent_block_hash, &e
                    );
                    error!("{}", msg);
                    return Err(e);
                }
            };

            let t1 = get_epoch_time_ms();

            let mblock = microblock_miner.mine_next_microblock(
                mempool,
                &self.miner_key,
                &self.event_dispatcher,
            )?;
            let new_cost_so_far = microblock_miner.get_cost_so_far().expect("BUG: cannot read cost so far from miner -- indicates that the underlying Clarity Tx is somehow in use still.");
            let t2 = get_epoch_time_ms();

            info!(
                "Mined microblock {} ({}) with {} transactions in {}ms",
                mblock.block_hash(),
                mblock.header.sequence,
                mblock.txs.len(),
                t2.saturating_sub(t1)
            );

            Ok((mblock, new_cost_so_far))
        };

        let (mined_microblock, new_cost) = match mint_result {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to mine microblock: {}", e);
                return Err(e);
            }
        };

        // failsafe
        if !Relayer::static_check_problematic_relayed_microblock(
            chainstate.mainnet,
            epoch_id,
            &mined_microblock,
            ASTRules::PrecheckSize,
        ) {
            // nope!
            warn!(
                "Our mined microblock {} was problematic",
                &mined_microblock.block_hash()
            );

            #[cfg(any(test, feature = "testing"))]
            {
                use std::fs;
                use std::io::Write;
                use std::path::Path;
                if let Ok(path) = std::env::var("STACKS_BAD_BLOCKS_DIR") {
                    // record this microblock somewhere
                    if !fs::metadata(&path).is_ok() {
                        fs::create_dir_all(&path)
                            .expect(&format!("FATAL: could not create '{}'", &path));
                    }

                    let path = Path::new(&path);
                    let path = path.join(Path::new(&format!("{}", &mined_microblock.block_hash())));
                    let mut file = fs::File::create(&path)
                        .expect(&format!("FATAL: could not create '{:?}'", &path));

                    let mblock_bits = mined_microblock.serialize_to_vec();
                    let mblock_bits_hex = to_hex(&mblock_bits);

                    let mblock_json = format!(
                        r#"{{"microblock":"{}","parent_consensus":"{}","parent_block":"{}"}}"#,
                        &mblock_bits_hex, &self.parent_consensus_hash, &self.parent_block_hash
                    );
                    file.write_all(&mblock_json.as_bytes()).expect(&format!(
                        "FATAL: failed to write microblock bits to '{:?}'",
                        &path
                    ));
                    info!(
                        "Fault injection: bad microblock {} saved to {}",
                        &mined_microblock.block_hash(),
                        &path.to_str().unwrap()
                    );
                }
            }
            if !Relayer::process_mined_problematic_blocks(ast_rules, ASTRules::PrecheckSize) {
                // don't process it
                warn!(
                    "Will NOT process our problematic mined microblock {}",
                    &mined_microblock.block_hash()
                );
                return Err(ChainstateError::NoTransactionsToMine);
            } else {
                warn!(
                    "Will process our problematic mined microblock {}",
                    &mined_microblock.block_hash()
                )
            }
        }

        // cancelled?
        let is_miner_blocked = self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked();
        if is_miner_blocked {
            return Err(ChainstateError::MinerAborted);
        }

        // preprocess the microblock locally
        chainstate.preprocess_streamed_microblock(
            &self.parent_consensus_hash,
            &self.parent_block_hash,
            &mined_microblock,
        )?;

        // update unconfirmed state cost
        self.cost_so_far = new_cost;
        self.quantity += 1;
        return Ok(mined_microblock);
    }

    /// Can this microblock miner mine off of this given tip?
    pub fn can_mine_on_tip(
        &self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> bool {
        self.parent_consensus_hash == *consensus_hash && self.parent_block_hash == *block_hash
    }

    /// Body of try_mine_microblock()
    fn inner_try_mine_microblock(
        &mut self,
        miner_tip: MinerTip,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mem_pool: &mut MemPoolDB,
    ) -> Result<Option<(StacksMicroblock, ExecutionCost)>, NetError> {
        if !self.can_mine_on_tip(&self.parent_consensus_hash, &self.parent_block_hash) {
            // not configured to mine on this tip
            return Ok(None);
        }
        if !self.can_mine_on_tip(&miner_tip.consensus_hash, &miner_tip.block_hash) {
            // this tip isn't what this miner is meant to mine on
            return Ok(None);
        }

        if self.last_mined + (self.frequency as u128) >= get_epoch_time_ms() {
            // too soon to mine
            return Ok(None);
        }

        let mut next_microblock_and_runtime = None;

        // opportunistically try and mine, but only if there are no attachable blocks in
        // recent history (i.e. in the last 10 minutes)
        let num_attachable = StacksChainState::count_attachable_staging_blocks(
            chainstate.db(),
            1,
            get_epoch_time_secs() - 600,
        )?;
        if num_attachable == 0 {
            match self.inner_mine_one_microblock(sortdb, chainstate, mem_pool) {
                Ok(microblock) => {
                    // will need to relay this
                    next_microblock_and_runtime = Some((microblock, self.cost_so_far.clone()));
                }
                Err(ChainstateError::NoTransactionsToMine) => {
                    info!("Will keep polling mempool for transactions to include in a microblock");
                }
                Err(e) => {
                    warn!("Failed to mine one microblock: {:?}", &e);
                }
            }
        } else {
            debug!("Will not mine microblocks yet -- have {} attachable blocks that arrived in the last 10 minutes", num_attachable);
        }

        self.last_mined = get_epoch_time_ms();

        Ok(next_microblock_and_runtime)
    }

    /// Try to mine one microblock, given the current chain tip and access to the chain state DBs.
    /// If we succeed, return the microblock and log the tx events to the given event dispatcher.
    /// May return None if any of the following are true:
    /// * `miner_tip` does not match this miner's miner tip
    /// * it's been too soon (less than microblock_frequency milliseconds) since we tried this call
    /// * there are simply no transactions to mine
    /// * there are still stacks blocks to be processed in the staging db
    /// * the miner thread got cancelled
    pub fn try_mine_microblock(
        &mut self,
        cur_tip: MinerTip,
    ) -> Result<Option<(StacksMicroblock, ExecutionCost)>, NetError> {
        debug!("microblock miner thread ID is {:?}", thread::current().id());
        self.with_chainstate(|mblock_miner, sortdb, chainstate, mempool| {
            mblock_miner.inner_try_mine_microblock(cur_tip, sortdb, chainstate, mempool)
        })
    }
}

impl BlockMinerThread {
    /// Instantiate the miner thread from its parent RelayerThread
    pub fn from_relayer_thread(
        rt: &RelayerThread,
        registered_key: RegisteredKey,
        burn_block: BlockSnapshot,
    ) -> BlockMinerThread {
        BlockMinerThread {
            config: rt.config.clone(),
            globals: rt.globals.clone(),
            keychain: rt.keychain.clone(),
            burnchain: rt.burnchain.clone(),
            last_mined_blocks: rt.last_mined_blocks.clone(),
            ongoing_commit: rt.bitcoin_controller.get_ongoing_commit(),
            registered_key,
            burn_block,
            event_dispatcher: rt.event_dispatcher.clone(),
        }
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

    /// Create a coinbase transaction.
    fn inner_generate_coinbase_tx(
        &mut self,
        nonce: u64,
        epoch_id: StacksEpochId,
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
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), recipient_opt),
        );
        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        tx_signer.get_tx().unwrap()
    }

    /// Create a poison microblock transaction.
    fn inner_generate_poison_microblock_tx(
        &mut self,
        nonce: u64,
        poison_payload: TransactionPayload,
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
        let mut tx = StacksTransaction::new(version, tx_auth, poison_payload);
        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        tx_signer.get_tx().unwrap()
    }

    /// Constructs and returns a LeaderBlockCommitOp out of the provided params.
    fn inner_generate_block_commit_op(
        &self,
        block_header_hash: BlockHeaderHash,
        burn_fee: u64,
        key: &RegisteredKey,
        parent_burnchain_height: u32,
        parent_winning_vtx: u16,
        vrf_seed: VRFSeed,
        commit_outs: Vec<PoxAddress>,
        sunset_burn: u64,
        current_burn_height: u64,
    ) -> BlockstackOperationType {
        let (parent_block_ptr, parent_vtxindex) = (parent_burnchain_height, parent_winning_vtx);
        let burn_parent_modulus = (current_burn_height % BURN_BLOCK_MINED_AT_MODULUS) as u8;
        let sender = self.keychain.get_burnchain_signer();
        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            sunset_burn,
            block_header_hash,
            burn_fee,
            input: (Txid([0; 32]), 0),
            apparent_sender: sender,
            key_block_ptr: key.block_height as u32,
            key_vtxindex: key.op_vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_1_MARKER],
            new_seed: vrf_seed,
            parent_block_ptr,
            parent_vtxindex,
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
            burn_parent_modulus,
            commit_outs,
        })
    }

    /// Get references to the inner assembled anchor block data we've produced for a given burnchain block height
    fn find_inflight_mined_blocks(
        burn_height: u64,
        last_mined_blocks: &MinedBlocks,
    ) -> Vec<&AssembledAnchorBlock> {
        let mut ret = vec![];
        for (_, (assembled_block, _)) in last_mined_blocks.iter() {
            if assembled_block.my_block_height >= burn_height {
                ret.push(assembled_block);
            }
        }
        ret
    }

    /// Load up the parent block info for mining.
    /// If there's no parent because this is the first block, then return the genesis block's info.
    /// If we can't find the parent in the DB but we expect one, return None.
    fn load_block_parent_info(
        &self,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
    ) -> Option<ParentStacksBlockInfo> {
        if let Some(stacks_tip) = chain_state
            .get_stacks_chain_tip(burn_db)
            .expect("FATAL: could not query chain tip")
        {
            let miner_address = self
                .keychain
                .origin_address(self.config.is_mainnet())
                .unwrap();
            match ParentStacksBlockInfo::lookup(
                chain_state,
                burn_db,
                &self.burn_block,
                miner_address,
                &stacks_tip.consensus_hash,
                &stacks_tip.anchored_block_hash,
            ) {
                Ok(parent_info) => Some(parent_info),
                Err(Error::BurnchainTipChanged) => {
                    self.globals.counters.bump_missed_tenures();
                    None
                }
                Err(..) => None,
            }
        } else {
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

            Some(ParentStacksBlockInfo {
                stacks_parent_header: chain_tip.metadata,
                parent_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                parent_block_burn_height: 0,
                parent_block_total_burn: 0,
                parent_winning_vtxindex: 0,
                coinbase_nonce: 0,
            })
        }
    }

    /// Determine which attempt this will be when mining a block, and whether or not an attempt
    /// should even be made.
    /// Returns Some(attempt) if we should attempt to mine (and what attempt it will be)
    /// Returns None if we should not mine.
    fn get_mine_attempt(
        &self,
        chain_state: &StacksChainState,
        parent_block_info: &ParentStacksBlockInfo,
    ) -> Option<u64> {
        let parent_consensus_hash = &parent_block_info.parent_consensus_hash;
        let stacks_parent_header = &parent_block_info.stacks_parent_header;
        let parent_block_burn_height = parent_block_info.parent_block_burn_height;

        let last_mined_blocks =
            Self::find_inflight_mined_blocks(self.burn_block.block_height, &self.last_mined_blocks);

        // has the tip changed from our previously-mined block for this epoch?
        let attempt = if last_mined_blocks.len() <= 1 {
            // always mine if we've not mined a block for this epoch yet, or
            // if we've mined just one attempt, unconditionally try again (so we
            // can use `subsequent_miner_time_ms` in this attempt)
            if last_mined_blocks.len() == 1 {
                debug!("Have only attempted one block; unconditionally trying again");
            }
            last_mined_blocks.len() as u64 + 1
        } else {
            let mut best_attempt = 0;
            debug!(
                "Consider {} in-flight Stacks tip(s)",
                &last_mined_blocks.len()
            );
            for prev_block in last_mined_blocks.iter() {
                debug!(
                    "Consider in-flight block {} on Stacks tip {}/{} in {} with {} txs",
                    &prev_block.anchored_block.block_hash(),
                    &prev_block.parent_consensus_hash,
                    &prev_block.anchored_block.header.parent_block,
                    &prev_block.my_burn_hash,
                    &prev_block.anchored_block.txs.len()
                );

                if prev_block.anchored_block.txs.len() == 1 && prev_block.attempt == 1 {
                    // Don't let the fact that we've built an empty block during this sortition
                    // prevent us from trying again.
                    best_attempt = 1;
                    continue;
                }
                if prev_block.parent_consensus_hash == *parent_consensus_hash
                    && prev_block.my_burn_hash == self.burn_block.burn_header_hash
                    && prev_block.anchored_block.header.parent_block
                        == stacks_parent_header.anchored_header.block_hash()
                {
                    // the anchored chain tip hasn't changed since we attempted to build a block.
                    // But, have discovered any new microblocks worthy of being mined?
                    if let Ok(Some(stream)) =
                        StacksChainState::load_descendant_staging_microblock_stream(
                            chain_state.db(),
                            &StacksBlockHeader::make_index_block_hash(
                                &prev_block.parent_consensus_hash,
                                &stacks_parent_header.anchored_header.block_hash(),
                            ),
                            0,
                            u16::MAX,
                        )
                    {
                        if (prev_block.anchored_block.header.parent_microblock
                            == BlockHeaderHash([0u8; 32])
                            && stream.len() == 0)
                            || (prev_block.anchored_block.header.parent_microblock
                                != BlockHeaderHash([0u8; 32])
                                && stream.len()
                                    <= (prev_block.anchored_block.header.parent_microblock_sequence
                                        as usize)
                                        + 1)
                        {
                            // the chain tip hasn't changed since we attempted to build a block.  Use what we
                            // already have.
                            debug!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {}, and no new microblocks ({} <= {} + 1)",
                                   &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                   prev_block.anchored_block.txs.len(), prev_block.my_burn_hash, parent_block_burn_height, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                            return None;
                        } else {
                            // there are new microblocks!
                            // TODO: only consider rebuilding our anchored block if we (a) have
                            // time, and (b) the new microblocks are worth more than the new BTC
                            // fee minus the old BTC fee
                            debug!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {}, but there are new microblocks ({} > {} + 1)",
                                   &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                   prev_block.anchored_block.txs.len(), prev_block.my_burn_hash, parent_block_burn_height, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                            best_attempt = cmp::max(best_attempt, prev_block.attempt);
                        }
                    } else {
                        // no microblock stream to confirm, and the stacks tip hasn't changed
                        debug!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {}, and no microblocks present",
                               &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                               prev_block.anchored_block.txs.len(), prev_block.my_burn_hash, parent_block_burn_height);

                        return None;
                    }
                } else {
                    if self.burn_block.burn_header_hash == prev_block.my_burn_hash {
                        // only try and re-mine if there was no sortition since the last chain tip
                        debug!("Relayer: Stacks tip has changed to {}/{} since we last tried to mine a block in {} at burn height {}; attempt was {} (for Stacks tip {}/{})",
                               parent_consensus_hash, stacks_parent_header.anchored_header.block_hash(), prev_block.my_burn_hash, parent_block_burn_height, prev_block.attempt, &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block);
                        best_attempt = cmp::max(best_attempt, prev_block.attempt);
                    } else {
                        debug!("Relayer: Burn tip has changed to {} ({}) since we last tried to mine a block in {}",
                               &self.burn_block.burn_header_hash, self.burn_block.block_height, &prev_block.my_burn_hash);
                    }
                }
            }
            best_attempt + 1
        };
        Some(attempt)
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

    /// Get the microblock private key we'll be using for this tenure, should we win.
    /// Return the private key.
    ///
    /// In testing, we ignore the parent stacks block hash because we don't have an easy way to
    /// reproduce it in integration tests.
    #[cfg(not(any(test, feature = "testing")))]
    fn make_microblock_private_key(
        &mut self,
        parent_stacks_hash: &StacksBlockId,
    ) -> Secp256k1PrivateKey {
        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        self.keychain
            .make_microblock_secret_key(self.burn_block.block_height, &parent_stacks_hash.0)
    }

    /// Get the microblock private key we'll be using for this tenure, should we win.
    /// Return the private key on success
    #[cfg(any(test, feature = "testing"))]
    fn make_microblock_private_key(
        &mut self,
        _parent_stacks_hash: &StacksBlockId,
    ) -> Secp256k1PrivateKey {
        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        warn!("test version of make_microblock_secret_key");
        self.keychain.make_microblock_secret_key(
            self.burn_block.block_height,
            &self.burn_block.block_height.to_be_bytes(),
        )
    }

    /// Load the parent microblock stream and vet it for the absence of forks.
    /// If there is a fork, then mine and relay a poison microblock transaction.
    /// Update stacks_parent_header's microblock tail to point to the end of the stream we load.
    /// Return the microblocks we'll confirm, if there are any.
    fn load_and_vet_parent_microblocks(
        &mut self,
        chain_state: &mut StacksChainState,
        mem_pool: &mut MemPoolDB,
        parent_block_info: &mut ParentStacksBlockInfo,
    ) -> Option<Vec<StacksMicroblock>> {
        let parent_consensus_hash = &parent_block_info.parent_consensus_hash;
        let stacks_parent_header = &mut parent_block_info.stacks_parent_header;

        let microblock_info_opt =
            match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                chain_state.db(),
                &StacksBlockHeader::make_index_block_hash(
                    parent_consensus_hash,
                    &stacks_parent_header.anchored_header.block_hash(),
                ),
                0,
                u16::MAX,
            ) {
                Ok(x) => {
                    let num_mblocks = x.as_ref().map(|(mblocks, ..)| mblocks.len()).unwrap_or(0);
                    debug!(
                        "Loaded {} microblocks descending from {}/{} (data: {})",
                        num_mblocks,
                        parent_consensus_hash,
                        &stacks_parent_header.anchored_header.block_hash(),
                        x.is_some()
                    );
                    x
                }
                Err(e) => {
                    warn!(
                        "Failed to load descendant microblock stream from {}/{}: {:?}",
                        parent_consensus_hash,
                        &stacks_parent_header.anchored_header.block_hash(),
                        &e
                    );
                    None
                }
            };

        if let Some((ref microblocks, ref poison_opt)) = &microblock_info_opt {
            if let Some(ref tail) = microblocks.last() {
                debug!(
                    "Confirm microblock stream tailed at {} (seq {})",
                    &tail.block_hash(),
                    tail.header.sequence
                );
            }

            // try and confirm as many microblocks as we can (but note that the stream itself may
            // be too long; we'll try again if that happens).
            stacks_parent_header.microblock_tail =
                microblocks.last().clone().map(|blk| blk.header.clone());

            if let Some(poison_payload) = poison_opt {
                debug!("Detected poisoned microblock fork: {:?}", &poison_payload);

                // submit it multiple times with different nonces, so it'll have a good chance of
                // eventually getting picked up (even if the miner sends other transactions from
                // the same address)
                for i in 0..10 {
                    let poison_microblock_tx = self.inner_generate_poison_microblock_tx(
                        parent_block_info.coinbase_nonce + 1 + i,
                        poison_payload.clone(),
                    );

                    // submit the poison payload, privately, so we'll mine it when building the
                    // anchored block.
                    if let Err(e) = mem_pool.miner_submit(
                        chain_state,
                        &parent_consensus_hash,
                        &stacks_parent_header.anchored_header.block_hash(),
                        &poison_microblock_tx,
                        Some(&self.event_dispatcher),
                        1_000_000_000.0, // prioritize this for inclusion
                    ) {
                        warn!(
                            "Detected but failed to mine poison-microblock transaction: {:?}",
                            &e
                        );
                    } else {
                        debug!(
                            "Submit poison-microblock transaction {:?}",
                            &poison_microblock_tx
                        );
                    }
                }
            }
        }

        microblock_info_opt.map(|(stream, _)| stream)
    }

    /// Produce the block-commit for this anchored block, if we can.
    /// Returns the op on success
    /// Returns None if we fail somehow.
    pub fn make_block_commit(
        &self,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
        block_hash: BlockHeaderHash,
        parent_block_burn_height: u64,
        parent_winning_vtxindex: u16,
        vrf_proof: &VRFProof,
        target_epoch_id: StacksEpochId,
    ) -> Option<BlockstackOperationType> {
        // let's figure out the recipient set!
        let recipients = match get_next_recipients(
            &self.burn_block,
            chain_state,
            burn_db,
            &self.burnchain,
            &OnChainRewardSetProvider(),
            self.config.node.always_use_affirmation_maps,
        ) {
            Ok(x) => x,
            Err(e) => {
                error!("Relayer: Failure fetching recipient set: {:?}", e);
                return None;
            }
        };

        let burn_fee_cap = self.config.burnchain.burn_fee_cap;
        let sunset_burn = self.burnchain.expected_sunset_burn(
            self.burn_block.block_height + 1,
            burn_fee_cap,
            target_epoch_id,
        );
        let rest_commit = burn_fee_cap - sunset_burn;

        let commit_outs = if !self
            .burnchain
            .pox_constants
            .is_after_pox_sunset_end(self.burn_block.block_height, target_epoch_id)
            && !self
                .burnchain
                .is_in_prepare_phase(self.burn_block.block_height + 1)
        {
            RewardSetInfo::into_commit_outs(recipients, self.config.is_mainnet())
        } else {
            vec![PoxAddress::standard_burn_address(self.config.is_mainnet())]
        };

        // let's commit, but target the current burnchain tip with our modulus
        let op = self.inner_generate_block_commit_op(
            block_hash,
            rest_commit,
            &self.registered_key,
            parent_block_burn_height
                .try_into()
                .expect("Could not convert parent block height into u32"),
            parent_winning_vtxindex,
            VRFSeed::from_proof(vrf_proof),
            commit_outs,
            sunset_burn,
            self.burn_block.block_height,
        );
        Some(op)
    }

    /// Are there enough unprocessed blocks that we shouldn't mine?
    fn unprocessed_blocks_prevent_mining(
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
    ) -> bool {
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: could not query canonical sortition DB tip");

        if let Some(stacks_tip) = chainstate
            .get_stacks_chain_tip(sortdb)
            .expect("FATAL: could not query canonical Stacks chain tip")
        {
            let has_unprocessed =
                StacksChainState::has_higher_unprocessed_blocks(chainstate.db(), stacks_tip.height)
                    .expect("FATAL: failed to query staging blocks");
            if has_unprocessed {
                let highest_unprocessed_opt =
                    StacksChainState::get_highest_unprocessed_block(chainstate.db())
                        .expect("FATAL: failed to query staging blocks");

                if let Some(highest_unprocessed) = highest_unprocessed_opt {
                    let highest_unprocessed_block_sn_opt =
                        SortitionDB::get_block_snapshot_consensus(
                            sortdb.conn(),
                            &highest_unprocessed.consensus_hash,
                        )
                        .expect("FATAL: could not query sortition DB");

                    // NOTE: this could be None if it's not part of the canonical PoX fork any
                    // longer
                    if let Some(highest_unprocessed_block_sn) = highest_unprocessed_block_sn_opt {
                        if stacks_tip.height + (burnchain.pox_constants.prepare_length as u64) - 1
                            >= highest_unprocessed.height
                            && highest_unprocessed_block_sn.block_height
                                + (burnchain.pox_constants.prepare_length as u64)
                                - 1
                                >= sort_tip.block_height
                        {
                            // we're close enough to the chain tip that it's a bad idea for us to mine
                            // -- we'll likely create an orphan
                            return true;
                        }
                    }
                }
            }
        }
        // we can mine
        return false;
    }

    /// Try to mine a Stacks block by assembling one from mempool transactions and sending a
    /// burnchain block-commit transaction.  If we succeed, then return the assembled block data as
    /// well as the microblock private key to use to produce microblocks.
    /// Return None if we couldn't build a block for whatever reason.
    pub fn run_tenure(&mut self) -> Option<MinerThreadResult> {
        debug!("block miner thread ID is {:?}", thread::current().id());
        fault_injection_long_tenure();

        let burn_db_path = self.config.get_burn_db_file_path();
        let stacks_chainstate_path = self.config.get_chainstate_path_str();

        let cost_estimator = self
            .config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = self
            .config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mut bitcoin_controller = BitcoinRegtestController::new_ongoing_dummy(
            self.config.clone(),
            self.ongoing_commit.clone(),
        );

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let mut burn_db =
            SortitionDB::open(&burn_db_path, true, self.burnchain.pox_constants.clone())
                .expect("FATAL: could not open sortition DB");

        let mut chain_state =
            open_chainstate_with_faults(&self.config).expect("FATAL: could not open chainstate DB");

        let mut mem_pool = MemPoolDB::open(
            self.config.is_mainnet(),
            self.config.burnchain.chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let tenure_begin = get_epoch_time_ms();

        let target_epoch_id =
            SortitionDB::get_stacks_epoch(burn_db.conn(), self.burn_block.block_height + 1)
                .ok()?
                .expect("FATAL: no epoch defined")
                .epoch_id;
        let mut parent_block_info = self.load_block_parent_info(&mut burn_db, &mut chain_state)?;
        let attempt = self.get_mine_attempt(&chain_state, &parent_block_info)?;
        let vrf_proof = self.make_vrf_proof()?;

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_private_key = self.make_microblock_private_key(
            &parent_block_info.stacks_parent_header.index_block_hash(),
        );
        let mblock_pubkey_hash = {
            let mut pubkh = Hash160::from_node_public_key(&StacksPublicKey::from_private(
                &microblock_private_key,
            ));
            if cfg!(test) {
                if let Ok(mblock_pubkey_hash_str) = std::env::var("STACKS_MICROBLOCK_PUBKEY_HASH") {
                    if let Ok(bad_pubkh) = Hash160::from_hex(&mblock_pubkey_hash_str) {
                        debug!(
                            "Fault injection: set microblock public key hash to {}",
                            &bad_pubkh
                        );
                        pubkh = bad_pubkh
                    }
                }
            }
            pubkh
        };

        // create our coinbase
        let coinbase_tx =
            self.inner_generate_coinbase_tx(parent_block_info.coinbase_nonce, target_epoch_id);

        // find the longest microblock tail we can build off of.
        // target it to the microblock tail in parent_block_info
        let microblocks_opt = self.load_and_vet_parent_microblocks(
            &mut chain_state,
            &mut mem_pool,
            &mut parent_block_info,
        );

        // build the block itself
        let (anchored_block, _, _) = match StacksBlockBuilder::build_anchored_block(
            &chain_state,
            &burn_db.index_conn(),
            &mut mem_pool,
            &parent_block_info.stacks_parent_header,
            parent_block_info.parent_block_total_burn,
            vrf_proof.clone(),
            mblock_pubkey_hash,
            &coinbase_tx,
            self.config.make_block_builder_settings(
                attempt,
                false,
                self.globals.get_miner_status(),
            ),
            Some(&self.event_dispatcher),
        ) {
            Ok(block) => block,
            Err(ChainstateError::InvalidStacksMicroblock(msg, mblock_header_hash)) => {
                // part of the parent microblock stream is invalid, so try again
                info!("Parent microblock stream is invalid; trying again without the offender {} (msg: {})", &mblock_header_hash, &msg);

                // truncate the stream
                parent_block_info.stacks_parent_header.microblock_tail = match microblocks_opt {
                    Some(microblocks) => {
                        let mut tail = None;
                        for mblock in microblocks.into_iter() {
                            if mblock.block_hash() == mblock_header_hash {
                                break;
                            }
                            tail = Some(mblock);
                        }
                        if let Some(ref t) = &tail {
                            debug!(
                                "New parent microblock stream tail is {} (seq {})",
                                t.block_hash(),
                                t.header.sequence
                            );
                        }
                        tail.map(|t| t.header)
                    }
                    None => None,
                };

                // try again
                match StacksBlockBuilder::build_anchored_block(
                    &chain_state,
                    &burn_db.index_conn(),
                    &mut mem_pool,
                    &parent_block_info.stacks_parent_header,
                    parent_block_info.parent_block_total_burn,
                    vrf_proof.clone(),
                    mblock_pubkey_hash,
                    &coinbase_tx,
                    self.config.make_block_builder_settings(
                        attempt,
                        false,
                        self.globals.get_miner_status(),
                    ),
                    Some(&self.event_dispatcher),
                ) {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Relayer: Failure mining anchor block even after removing offending microblock {}: {}", &mblock_header_hash, &e);
                        return None;
                    }
                }
            }
            Err(e) => {
                error!("Relayer: Failure mining anchored block: {}", e);
                return None;
            }
        };

        info!(
            "Relayer: Succeeded assembling {} block #{}: {}, with {} txs, attempt {}",
            if parent_block_info.parent_block_total_burn == 0 {
                "Genesis"
            } else {
                "Stacks"
            },
            anchored_block.header.total_work.work,
            anchored_block.block_hash(),
            anchored_block.txs.len(),
            attempt
        );

        // let's commit
        let op = self.make_block_commit(
            &mut burn_db,
            &mut chain_state,
            anchored_block.block_hash(),
            parent_block_info.parent_block_burn_height,
            parent_block_info.parent_winning_vtxindex,
            &vrf_proof,
            target_epoch_id,
        )?;

        // last chance -- confirm that the stacks tip is unchanged (since it could have taken long
        // enough to build this block that another block could have arrived), and confirm that all
        // Stacks blocks with heights higher than the canoincal tip are processed.
        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if let Some(stacks_tip) = chain_state
            .get_stacks_chain_tip(&burn_db)
            .expect("FATAL: could not query chain tip")
        {
            let is_miner_blocked = self
                .globals
                .get_miner_status()
                .lock()
                .expect("FATAL: mutex poisoned")
                .is_blocked();

            let has_unprocessed =
                Self::unprocessed_blocks_prevent_mining(&self.burnchain, &burn_db, &chain_state);
            if stacks_tip.anchored_block_hash != anchored_block.header.parent_block
                || parent_block_info.parent_consensus_hash != stacks_tip.consensus_hash
                || cur_burn_chain_tip.burn_header_hash != self.burn_block.burn_header_hash
                || is_miner_blocked
                || has_unprocessed
            {
                debug!(
                    "Relayer: Cancel block-commit; chain tip(s) have changed or cancelled";
                    "block_hash" => %anchored_block.block_hash(),
                    "tx_count" => anchored_block.txs.len(),
                    "target_height" => %anchored_block.header.total_work.work,
                    "parent_consensus_hash" => %parent_block_info.parent_consensus_hash,
                    "parent_block_hash" => %anchored_block.header.parent_block,
                    "parent_microblock_hash" => %anchored_block.header.parent_microblock,
                    "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
                    "old_tip_burn_block_hash" => %self.burn_block.burn_header_hash,
                    "old_tip_burn_block_height" => self.burn_block.block_height,
                    "old_tip_burn_block_sortition_id" => %self.burn_block.sortition_id,
                    "attempt" => attempt,
                    "new_stacks_tip_block_hash" => %stacks_tip.anchored_block_hash,
                    "new_stacks_tip_consensus_hash" => %stacks_tip.consensus_hash,
                    "new_tip_burn_block_height" => cur_burn_chain_tip.block_height,
                    "new_tip_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
                    "new_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
                    "miner_blocked" => %is_miner_blocked,
                    "has_unprocessed" => %has_unprocessed
                );
                self.globals.counters.bump_missed_tenures();
                return None;
            }
        }

        let mut op_signer = self.keychain.generate_op_signer();
        debug!(
            "Relayer: Submit block-commit";
            "block_hash" => %anchored_block.block_hash(),
            "tx_count" => anchored_block.txs.len(),
            "target_height" => anchored_block.header.total_work.work,
            "parent_consensus_hash" => %parent_block_info.parent_consensus_hash,
            "parent_block_hash" => %anchored_block.header.parent_block,
            "parent_microblock_hash" => %anchored_block.header.parent_microblock,
            "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
            "tip_burn_block_hash" => %self.burn_block.burn_header_hash,
            "tip_burn_block_height" => self.burn_block.block_height,
            "tip_burn_block_sortition_id" => %self.burn_block.sortition_id,
            "cur_burn_block_hash" => %cur_burn_chain_tip.burn_header_hash,
            "cur_burn_block_height" => %cur_burn_chain_tip.block_height,
            "cur_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
            "attempt" => attempt
        );

        let res = bitcoin_controller.submit_operation(target_epoch_id, op, &mut op_signer, attempt);
        if res.is_none() {
            if !self.config.node.mock_mining {
                warn!("Relayer: Failed to submit Bitcoin transaction");
                return None;
            } else {
                debug!("Relayer: Mock-mining enabled; not sending Bitcoin transaction");
            }
        }

        Some(MinerThreadResult::Block(
            AssembledAnchorBlock {
                parent_consensus_hash: parent_block_info.parent_consensus_hash,
                my_burn_hash: cur_burn_chain_tip.burn_header_hash,
                my_block_height: cur_burn_chain_tip.block_height,
                orig_burn_hash: self.burn_block.burn_header_hash,
                anchored_block,
                attempt,
                tenure_begin,
            },
            microblock_private_key,
            bitcoin_controller.get_ongoing_commit(),
        ))
    }
}

impl RelayerThread {
    /// Instantiate off of a StacksNode, a runloop, and a relayer.
    pub fn new(runloop: &RunLoop, local_peer: LocalPeer, relayer: Relayer) -> RelayerThread {
        let config = runloop.config().clone();
        let globals = runloop.get_globals();
        let burn_db_path = config.get_burn_db_file_path();
        let stacks_chainstate_path = config.get_chainstate_path_str();
        let is_mainnet = config.is_mainnet();
        let chain_id = config.burnchain.chain_id;

        let sortdb = SortitionDB::open(&burn_db_path, true, runloop.get_burnchain().pox_constants)
            .expect("FATAL: failed to open burnchain DB");

        let chainstate =
            open_chainstate_with_faults(&config).expect("FATAL: failed to open chainstate DB");

        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mempool = MemPoolDB::open(
            is_mainnet,
            chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let keychain = Keychain::default(config.node.seed.clone());
        let bitcoin_controller = BitcoinRegtestController::new_dummy(config.clone());

        RelayerThread {
            config: config.clone(),
            sortdb: Some(sortdb),
            chainstate: Some(chainstate),
            mempool: Some(mempool),
            globals,
            keychain,
            burnchain: runloop.get_burnchain(),
            last_vrf_key_burn_height: 0,
            last_mined_blocks: MinedBlocks::new(),
            bitcoin_controller,
            event_dispatcher: runloop.get_event_dispatcher(),
            local_peer,

            last_tenure_issue_time: 0,
            last_network_block_height: 0,
            last_network_block_height_ts: 0,
            last_network_download_passes: 0,
            min_network_download_passes: 0,
            last_network_inv_passes: 0,
            min_network_inv_passes: 0,

            last_tenure_consensus_hash: None,
            miner_tip: None,
            last_microblock_tenure_time: 0,
            microblock_deadline: 0,
            microblock_stream_cost: ExecutionCost::zero(),

            relayer,

            miner_thread: None,
            mined_stacks_block: false,
        }
    }

    /// Get an immutible ref to the sortdb
    pub fn sortdb_ref(&self) -> &SortitionDB {
        self.sortdb
            .as_ref()
            .expect("FATAL: tried to access sortdb while taken")
    }

    /// Get an immutible ref to the chainstate
    pub fn chainstate_ref(&self) -> &StacksChainState {
        self.chainstate
            .as_ref()
            .expect("FATAL: tried to access chainstate while it was taken")
    }

    /// Fool the borrow checker into letting us do something with the chainstate databases.
    /// DOES NOT COMPOSE -- do NOT call this, or self.sortdb_ref(), or self.chainstate_ref(), within
    /// `func`.  You will get a runtime panic.
    pub fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut RelayerThread, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self
            .sortdb
            .take()
            .expect("FATAL: tried to take sortdb while taken");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("FATAL: tried to take chainstate while taken");
        let mut mempool = self
            .mempool
            .take()
            .expect("FATAL: tried to take mempool while taken");
        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);
        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);
        res
    }

    /// have we waited for the right conditions under which to start mining a block off of our
    /// chain tip?
    pub fn has_waited_for_latest_blocks(&self) -> bool {
        // a network download pass took place
        (self.min_network_download_passes <= self.last_network_download_passes
        // a network inv pass took place
        && self.min_network_download_passes <= self.last_network_download_passes)
        // we waited long enough for a download pass, but timed out waiting
        || self.last_network_block_height_ts + (self.config.node.wait_time_for_blocks as u128) < get_epoch_time_ms()
        // we're not supposed to wait at all
        || !self.config.miner.wait_for_block_download
    }

    /// Return debug string for waiting for latest blocks
    pub fn debug_waited_for_latest_blocks(&self) -> String {
        format!(
            "({} <= {} && {} <= {}) || {} + {} < {} || {}",
            self.min_network_download_passes,
            self.last_network_download_passes,
            self.min_network_inv_passes,
            self.last_network_inv_passes,
            self.last_network_block_height_ts,
            self.config.node.wait_time_for_blocks,
            get_epoch_time_ms(),
            self.config.miner.wait_for_block_download
        )
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
            debug!(
                "Relayer: block mining until the next download pass {}",
                self.min_network_download_passes
            );
            signal_mining_blocked(self.globals.get_miner_status());
        }

        let net_receipts = self.with_chainstate(|relayer_thread, sortdb, chainstate, mempool| {
            relayer_thread
                .relayer
                .process_network_result(
                    &relayer_thread.local_peer,
                    &mut net_result,
                    sortdb,
                    chainstate,
                    mempool,
                    relayer_thread.globals.sync_comms.get_ibd(),
                    Some(&relayer_thread.globals.coord_comms),
                    Some(&relayer_thread.event_dispatcher),
                )
                .expect("BUG: failure processing network results")
        });

        if net_receipts.num_new_blocks > 0 || net_receipts.num_new_confirmed_microblocks > 0 {
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

        let num_unconfirmed_microblock_tx_receipts =
            net_receipts.processed_unconfirmed_state.receipts.len();
        if num_unconfirmed_microblock_tx_receipts > 0 {
            if let Some(unconfirmed_state) = self.chainstate_ref().unconfirmed_state.as_ref() {
                let canonical_tip = unconfirmed_state.confirmed_chain_tip.clone();
                self.event_dispatcher.process_new_microblocks(
                    canonical_tip,
                    net_receipts.processed_unconfirmed_state,
                );
            } else {
                warn!("Relayer: oops, unconfirmed state is uninitialized but there are microblock events");
            }
        }

        // Dispatch retrieved attachments, if any.
        if net_result.has_attachments() {
            self.event_dispatcher
                .process_new_attachments(&net_result.attachments);
        }

        // synchronize unconfirmed tx index to p2p thread
        self.with_chainstate(|relayer_thread, _sortdb, chainstate, _mempool| {
            relayer_thread.globals.send_unconfirmed_txs(chainstate);
        });

        // resume mining if we blocked it, and if we've done the requisite download
        // passes
        self.last_network_download_passes = net_result.num_download_passes;
        self.last_network_inv_passes = net_result.num_inv_sync_passes;
        if self.has_waited_for_latest_blocks() {
            debug!("Relayer: did a download pass, so unblocking mining");
            signal_mining_ready(self.globals.get_miner_status());
        }
    }

    /// Process the block and microblocks from a sortition that we won.
    /// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
    /// Blocks until the given stacks block is processed.
    /// Returns true if we accepted this block as new.
    /// Returns false if we already processed this block.
    fn accept_winning_tenure(
        &mut self,
        anchored_block: &StacksBlock,
        consensus_hash: &ConsensusHash,
        parent_consensus_hash: &ConsensusHash,
    ) -> Result<bool, ChainstateError> {
        if StacksChainState::has_stored_block(
            self.chainstate_ref().db(),
            &self.chainstate_ref().blocks_path,
            consensus_hash,
            &anchored_block.block_hash(),
        )? {
            // already processed my tenure
            return Ok(false);
        }
        let burn_height =
            SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), consensus_hash)
                .map_err(|e| {
                    error!("Failed to find block snapshot for mined block: {}", e);
                    e
                })?
                .ok_or_else(|| {
                    error!("Failed to find block snapshot for mined block");
                    ChainstateError::NoSuchBlockError
                })?
                .block_height;

        let ast_rules = SortitionDB::get_ast_rules(self.sortdb_ref().conn(), burn_height)?;
        let epoch_id = SortitionDB::get_stacks_epoch(self.sortdb_ref().conn(), burn_height)?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        // failsafe
        if !Relayer::static_check_problematic_relayed_block(
            self.chainstate_ref().mainnet,
            epoch_id,
            &anchored_block,
            ASTRules::PrecheckSize,
        ) {
            // nope!
            warn!(
                "Our mined block {} was problematic",
                &anchored_block.block_hash()
            );
            #[cfg(any(test, feature = "testing"))]
            {
                use std::fs;
                use std::io::Write;
                use std::path::Path;
                if let Ok(path) = std::env::var("STACKS_BAD_BLOCKS_DIR") {
                    // record this block somewhere
                    if !fs::metadata(&path).is_ok() {
                        fs::create_dir_all(&path)
                            .expect(&format!("FATAL: could not create '{}'", &path));
                    }

                    let path = Path::new(&path);
                    let path = path.join(Path::new(&format!("{}", &anchored_block.block_hash())));
                    let mut file = fs::File::create(&path)
                        .expect(&format!("FATAL: could not create '{:?}'", &path));

                    let block_bits = anchored_block.serialize_to_vec();
                    let block_bits_hex = to_hex(&block_bits);
                    let block_json = format!(
                        r#"{{"block":"{}","consensus":"{}"}}"#,
                        &block_bits_hex, &consensus_hash
                    );
                    file.write_all(&block_json.as_bytes()).expect(&format!(
                        "FATAL: failed to write block bits to '{:?}'",
                        &path
                    ));
                    info!(
                        "Fault injection: bad block {} saved to {}",
                        &anchored_block.block_hash(),
                        &path.to_str().unwrap()
                    );
                }
            }
            if !Relayer::process_mined_problematic_blocks(ast_rules, ASTRules::PrecheckSize) {
                // don't process it
                warn!(
                    "Will NOT process our problematic mined block {}",
                    &anchored_block.block_hash()
                );
                return Err(ChainstateError::NoTransactionsToMine);
            } else {
                warn!(
                    "Will process our problematic mined block {}",
                    &anchored_block.block_hash()
                )
            }
        }

        // Preprocess the anchored block
        self.with_chainstate(|_relayer_thread, sort_db, chainstate, _mempool| {
            let ic = sort_db.index_conn();
            chainstate.preprocess_anchored_block(
                &ic,
                consensus_hash,
                &anchored_block,
                &parent_consensus_hash,
                0,
            )
        })?;

        Ok(true)
    }

    /// Process a new block we mined
    /// Return true if we processed it
    /// Return false if we timed out waiting for it
    /// Return Err(..) if we couldn't reach the chains coordiantor thread
    fn process_new_block(&self) -> Result<bool, Error> {
        // process the block
        let stacks_blocks_processed = self.globals.coord_comms.get_stacks_blocks_processed();
        if !self.globals.coord_comms.announce_new_stacks_block() {
            return Err(Error::CoordinatorClosed);
        }
        if !self
            .globals
            .coord_comms
            .wait_for_stacks_blocks_processed(stacks_blocks_processed, u64::MAX)
        {
            // basically unreachable
            warn!("ChainsCoordinator timed out while waiting for new stacks block to be processed");
            return Ok(false);
        }
        debug!("Relayer: Stacks block has been processed");

        Ok(true)
    }

    /// Given the two miner tips, return the newer tip.
    fn pick_higher_tip(cur: Option<MinerTip>, new: Option<MinerTip>) -> Option<MinerTip> {
        match (cur, new) {
            (Some(cur), None) => Some(cur),
            (None, Some(new)) => Some(new),
            (None, None) => None,
            (Some(cur), Some(new)) => {
                if cur.stacks_height < new.stacks_height {
                    Some(new)
                } else if cur.stacks_height > new.stacks_height {
                    Some(cur)
                } else if cur.burn_height < new.burn_height {
                    Some(new)
                } else if cur.burn_height > new.burn_height {
                    Some(cur)
                } else {
                    assert_eq!(cur, new);
                    Some(cur)
                }
            }
        }
    }

    /// Given the pointer to a recently-discovered tenure, see if we won the sortition and if so,
    /// store it, preprocess it, and forward it to our neighbors.  All the while, keep track of the
    /// latest Stacks mining tip we have produced so far.
    ///
    /// Returns (true, Some(tip)) if the coordinator is still running and we have a miner tip to
    /// build on (i.e. we won this last sortition).
    ///
    /// Returns (true, None) if the coordinator is still running, and we do NOT have a miner tip to
    /// build on (i.e. we did not win this last sortition)
    ///
    /// Returns (false, _) if the coordinator could not be reached, meaning this thread should die.
    pub fn process_one_tenure(
        &mut self,
        consensus_hash: ConsensusHash,
        block_header_hash: BlockHeaderHash,
        burn_hash: BurnchainHeaderHash,
    ) -> (bool, Option<MinerTip>) {
        let mut miner_tip = None;
        let sn =
            SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), &consensus_hash)
                .expect("FATAL: failed to query sortition DB")
                .expect("FATAL: unknown consensus hash");

        debug!(
            "Relayer: Process tenure {}/{} in {} burn height {}",
            &consensus_hash, &block_header_hash, &burn_hash, sn.block_height
        );

        if let Some((last_mined_block_data, microblock_privkey)) =
            self.last_mined_blocks.remove(&block_header_hash)
        {
            // we won!
            let AssembledAnchorBlock {
                parent_consensus_hash,
                anchored_block: mined_block,
                my_burn_hash: mined_burn_hash,
                attempt: _,
                ..
            } = last_mined_block_data;

            let reward_block_height = mined_block.header.total_work.work + MINER_REWARD_MATURITY;
            info!(
                "Relayer: Won sortition! Mining reward will be received in {} blocks (block #{})",
                MINER_REWARD_MATURITY, reward_block_height
            );
            debug!("Relayer: Won sortition!";
                  "stacks_header" => %block_header_hash,
                  "burn_hash" => %mined_burn_hash,
            );

            increment_stx_blocks_mined_counter();
            let has_new_data = match self.accept_winning_tenure(
                &mined_block,
                &consensus_hash,
                &parent_consensus_hash,
            ) {
                Ok(accepted) => accepted,
                Err(ChainstateError::ChannelClosed(_)) => {
                    warn!("Coordinator stopped, stopping relayer thread...");
                    return (false, None);
                }
                Err(e) => {
                    warn!("Error processing my tenure, bad block produced: {}", e);
                    warn!(
                        "Bad block";
                        "stacks_header" => %block_header_hash,
                        "data" => %to_hex(&mined_block.serialize_to_vec()),
                    );
                    return (true, None);
                }
            };

            // advertize _and_ push blocks for now
            let blocks_available = Relayer::load_blocks_available_data(
                self.sortdb_ref(),
                vec![consensus_hash.clone()],
            )
            .expect("Failed to obtain block information for a block we mined.");

            let block_data = {
                let mut bd = HashMap::new();
                bd.insert(consensus_hash.clone(), mined_block.clone());
                bd
            };

            if let Err(e) = self.relayer.advertize_blocks(blocks_available, block_data) {
                warn!("Failed to advertise new block: {}", e);
            }

            let snapshot = SortitionDB::get_block_snapshot_consensus(
                self.sortdb_ref().conn(),
                &consensus_hash,
            )
            .expect("Failed to obtain snapshot for block")
            .expect("Failed to obtain snapshot for block");

            if !snapshot.pox_valid {
                warn!(
                    "Snapshot for {} is no longer valid; discarding {}...",
                    &consensus_hash,
                    &mined_block.block_hash()
                );
                miner_tip = Self::pick_higher_tip(miner_tip, None);
            } else {
                let ch = snapshot.consensus_hash.clone();
                let bh = mined_block.block_hash();
                let height = mined_block.header.total_work.work;

                let mut broadcast = true;
                if self.chainstate_ref().fault_injection.hide_blocks
                    && Relayer::fault_injection_is_block_hidden(
                        &mined_block.header,
                        snapshot.block_height,
                    )
                {
                    broadcast = false;
                }
                if broadcast {
                    if let Err(e) = self
                        .relayer
                        .broadcast_block(snapshot.consensus_hash, mined_block)
                    {
                        warn!("Failed to push new block: {}", e);
                    }
                }

                // proceed to mine microblocks
                miner_tip = Some(MinerTip::new(
                    ch,
                    bh,
                    microblock_privkey,
                    height,
                    snapshot.block_height,
                ));
            }

            if has_new_data {
                // process the block, now that we've advertized it
                if let Err(Error::CoordinatorClosed) = self.process_new_block() {
                    // coordiantor stopped
                    return (false, None);
                }
            }
        } else {
            debug!(
                "Relayer: Did not win sortition in {}, winning block was {}/{}",
                &burn_hash, &consensus_hash, &block_header_hash
            );
            miner_tip = None;
        }

        (true, miner_tip)
    }

    /// Process all new tenures that we're aware of.
    /// Clear out stale tenure artifacts as well.
    /// Update the miner tip if we won the highest tenure (or clear it if we didn't).
    /// If we won any sortitions, send the block and microblock data to the p2p thread.
    /// Return true if we can still continue to run; false if not.
    pub fn process_new_tenures(
        &mut self,
        consensus_hash: ConsensusHash,
        burn_hash: BurnchainHeaderHash,
        block_header_hash: BlockHeaderHash,
    ) -> bool {
        let mut miner_tip = None;
        let mut num_sortitions = 0;

        // process all sortitions between the last-processed consensus hash and this
        // one.  ProcessTenure(..) messages can get lost.
        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to read current burnchain tip");

        let tenures = if let Some(last_ch) = self.last_tenure_consensus_hash.as_ref() {
            let mut tenures = vec![];
            let last_sn =
                SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), &last_ch)
                    .expect("FATAL: failed to query sortition DB")
                    .expect("FATAL: unknown prior consensus hash");

            debug!(
                "Relayer: query tenures between burn block heights {} and {}",
                last_sn.block_height + 1,
                burn_tip.block_height + 1
            );
            for block_to_process in (last_sn.block_height + 1)..(burn_tip.block_height + 1) {
                num_sortitions += 1;
                let sn = {
                    let ic = self.sortdb_ref().index_conn();
                    SortitionDB::get_ancestor_snapshot(
                        &ic,
                        block_to_process,
                        &burn_tip.sortition_id,
                    )
                    .expect("FATAL: failed to read ancestor snapshot from sortition DB")
                    .expect("Failed to find block in fork processed by burnchain indexer")
                };
                if !sn.sortition {
                    debug!(
                        "Relayer: Skipping tenure {}/{} at burn hash/height {},{} -- no sortition",
                        &sn.consensus_hash,
                        &sn.winning_stacks_block_hash,
                        &sn.burn_header_hash,
                        sn.block_height
                    );
                    continue;
                }
                debug!(
                    "Relayer: Will process tenure {}/{} at burn hash/height {},{}",
                    &sn.consensus_hash,
                    &sn.winning_stacks_block_hash,
                    &sn.burn_header_hash,
                    sn.block_height
                );
                tenures.push((
                    sn.consensus_hash,
                    sn.burn_header_hash,
                    sn.winning_stacks_block_hash,
                ));
            }
            tenures
        } else {
            // first-ever tenure processed
            vec![(consensus_hash, burn_hash, block_header_hash)]
        };

        debug!("Relayer: will process {} tenures", &tenures.len());
        let num_tenures = tenures.len();
        if num_tenures > 0 {
            // temporarily halt mining
            debug!(
                "Relayer: block mining to process {} tenures",
                &tenures.len()
            );
            signal_mining_blocked(self.globals.get_miner_status());
        }

        for (consensus_hash, burn_hash, block_header_hash) in tenures.into_iter() {
            self.miner_thread_try_join();
            let (continue_thread, new_miner_tip) =
                self.process_one_tenure(consensus_hash, block_header_hash, burn_hash);
            if !continue_thread {
                // coordinator thread hang-up
                return false;
            }
            miner_tip = Self::pick_higher_tip(miner_tip, new_miner_tip);

            // clear all blocks up to this consensus hash
            let this_burn_tip = SortitionDB::get_block_snapshot_consensus(
                self.sortdb_ref().conn(),
                &consensus_hash,
            )
            .expect("FATAL: failed to query sortition DB")
            .expect("FATAL: no snapshot for consensus hash");

            let old_last_mined_blocks =
                mem::replace(&mut self.last_mined_blocks, MinedBlocks::new());
            self.last_mined_blocks =
                Self::clear_stale_mined_blocks(this_burn_tip.block_height, old_last_mined_blocks);

            // update last-tenure pointer
            self.last_tenure_consensus_hash = Some(consensus_hash);
        }

        if let Some(mtip) = miner_tip.take() {
            // sanity check -- is this also the canonical tip?
            let (stacks_tip_consensus_hash, stacks_tip_block_hash) =
                self.with_chainstate(|_relayer_thread, sortdb, _chainstate, _| {
                    SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).expect(
                        "FATAL: failed to query sortition DB for canonical stacks chain tip hashes",
                    )
                });

            if mtip.consensus_hash != stacks_tip_consensus_hash
                || mtip.block_hash != stacks_tip_block_hash
            {
                debug!(
                    "Relayer: miner tip {}/{} is NOT canonical ({}/{})",
                    &mtip.consensus_hash,
                    &mtip.block_hash,
                    &stacks_tip_consensus_hash,
                    &stacks_tip_block_hash
                );
                miner_tip = None;
            } else {
                debug!(
                    "Relayer: Microblock miner tip is now {}/{} ({})",
                    mtip.consensus_hash,
                    mtip.block_hash,
                    StacksBlockHeader::make_index_block_hash(
                        &mtip.consensus_hash,
                        &mtip.block_hash
                    )
                );

                self.with_chainstate(|relayer_thread, sortdb, chainstate, _mempool| {
                    Relayer::refresh_unconfirmed(chainstate, sortdb);
                    relayer_thread.globals.send_unconfirmed_txs(chainstate);
                });

                miner_tip = Some(mtip);
            }
        }

        // update state for microblock mining
        self.setup_microblock_mining_state(miner_tip);

        // resume mining if we blocked it
        if num_tenures > 0 || num_sortitions > 0 {
            if self.miner_tip.is_some() {
                // we won the highest tenure
                if self.config.node.mine_microblocks {
                    // mine a microblock first
                    self.mined_stacks_block = true;
                } else {
                    // mine a Stacks block first -- we won't build microblocks
                    self.mined_stacks_block = false;
                }
            } else {
                // mine a Stacks block first -- we didn't win
                self.mined_stacks_block = false;
            }
            signal_mining_ready(self.globals.get_miner_status());
        }
        true
    }

    /// Update the miner tip with a new tip.  If it's changed, then clear out the microblock stream
    /// cost since we won't be mining it anymore.
    fn setup_microblock_mining_state(&mut self, new_miner_tip: Option<MinerTip>) {
        // update state
        let my_miner_tip = std::mem::replace(&mut self.miner_tip, None);
        let best_tip = Self::pick_higher_tip(my_miner_tip.clone(), new_miner_tip.clone());
        if best_tip == new_miner_tip && best_tip != my_miner_tip {
            // tip has changed
            debug!(
                "Relayer: Best miner tip went from {:?} to {:?}",
                &my_miner_tip, &new_miner_tip
            );
            self.microblock_stream_cost = ExecutionCost::zero();
        }
        self.miner_tip = best_tip;
    }

    /// Try to resume microblock mining if we don't need to build an anchored block
    fn try_resume_microblock_mining(&mut self) {
        if self.miner_tip.is_some() {
            // we won the highest tenure
            if self.config.node.mine_microblocks {
                // mine a microblock first
                self.mined_stacks_block = true;
            } else {
                // mine a Stacks block first -- we won't build microblocks
                self.mined_stacks_block = false;
            }
        } else {
            // mine a Stacks block first -- we didn't win
            self.mined_stacks_block = false;
        }
    }

    /// Constructs and returns a LeaderKeyRegisterOp out of the provided params
    fn inner_generate_leader_key_register_op(
        vrf_public_key: VRFPublicKey,
        consensus_hash: &ConsensusHash,
    ) -> BlockstackOperationType {
        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
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
        if burn_block.block_height == self.last_vrf_key_burn_height {
            // already in-flight
            return;
        }
        let cur_epoch =
            SortitionDB::get_stacks_epoch(self.sortdb_ref().conn(), burn_block.block_height)
                .expect("FATAL: failed to query sortition DB")
                .expect("FATAL: no epoch defined")
                .epoch_id;
        let (vrf_pk, _) = self.keychain.make_vrf_keypair(burn_block.block_height);

        debug!(
            "Submit leader-key-register for {} {}",
            &vrf_pk.to_hex(),
            burn_block.block_height
        );

        let burnchain_tip_consensus_hash = &burn_block.consensus_hash;
        let op = Self::inner_generate_leader_key_register_op(vrf_pk, burnchain_tip_consensus_hash);

        let mut one_off_signer = self.keychain.generate_op_signer();
        if let Some(txid) =
            self.bitcoin_controller
                .submit_operation(cur_epoch, op, &mut one_off_signer, 1)
        {
            // advance key registration state
            self.last_vrf_key_burn_height = burn_block.block_height;
            self.globals
                .set_pending_leader_key_registration(burn_block.block_height, txid);
        }
    }

    /// Remove any block state we've mined for the given burnchain height.
    /// Return the filtered `last_mined_blocks`
    fn clear_stale_mined_blocks(burn_height: u64, last_mined_blocks: MinedBlocks) -> MinedBlocks {
        let mut ret = HashMap::new();
        for (stacks_bhh, (assembled_block, microblock_privkey)) in last_mined_blocks.into_iter() {
            if assembled_block.my_block_height < burn_height {
                debug!(
                    "Stale mined block: {} (as of {},{})",
                    &stacks_bhh, &assembled_block.my_burn_hash, assembled_block.my_block_height
                );
                continue;
            }
            debug!(
                "Mined block in-flight: {} (as of {},{})",
                &stacks_bhh, &assembled_block.my_burn_hash, assembled_block.my_block_height
            );
            ret.insert(stacks_bhh, (assembled_block, microblock_privkey));
        }
        ret
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
        issue_timestamp_ms: u128,
    ) -> Option<BlockMinerThread> {
        if self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked()
        {
            debug!(
                "Relayer: miner is blocked as of {}; cannot mine Stacks block at this time",
                &last_burn_block.burn_header_hash
            );
            return None;
        }

        if fault_injection_skip_mining(&self.config.node.rpc_bind, last_burn_block.block_height) {
            debug!(
                "Relayer: fault injection skip mining at block height {}",
                last_burn_block.block_height
            );
            return None;
        }

        // start a new tenure
        if let Some(cur_sortition) = self.globals.get_last_sortition() {
            if last_burn_block.sortition_id != cur_sortition.sortition_id {
                debug!(
                    "Relayer: Drop stale RunTenure for {}: current sortition is for {}",
                    &last_burn_block.burn_header_hash, &cur_sortition.burn_header_hash
                );
                self.globals.counters.bump_missed_tenures();
                return None;
            }
        }

        let burn_header_hash = last_burn_block.burn_header_hash.clone();
        let burn_chain_sn = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        let burn_chain_tip = burn_chain_sn.burn_header_hash.clone();

        if burn_chain_tip != burn_header_hash {
            debug!(
                "Relayer: Drop stale RunTenure for {}: current sortition is for {}",
                &burn_header_hash, &burn_chain_tip
            );
            self.globals.counters.bump_missed_tenures();
            return None;
        }

        let has_unprocessed = BlockMinerThread::unprocessed_blocks_prevent_mining(
            &self.burnchain,
            self.sortdb_ref(),
            self.chainstate_ref(),
        );
        if has_unprocessed {
            debug!(
                "Relayer: Drop RunTenure for {} because there are fewer than {} pending blocks",
                &burn_header_hash,
                self.burnchain.pox_constants.prepare_length - 1
            );
            return None;
        }

        if burn_chain_sn.block_height != self.last_network_block_height
            || !self.has_waited_for_latest_blocks()
        {
            debug!("Relayer: network has not had a chance to process in-flight blocks ({} != {} || !({}))",
                    burn_chain_sn.block_height, self.last_network_block_height, self.debug_waited_for_latest_blocks());
            return None;
        }

        let tenure_cooldown = if self.config.node.mine_microblocks {
            self.config.node.wait_time_for_microblocks as u128
        } else {
            0
        };

        // no burnchain change, so only re-run block tenure every so often in order
        // to give microblocks a chance to collect
        if issue_timestamp_ms < self.last_tenure_issue_time + tenure_cooldown {
            debug!("Relayer: will NOT run tenure since issuance at {} is too fresh (wait until {} + {} = {})",
                    issue_timestamp_ms / 1000, self.last_tenure_issue_time / 1000, tenure_cooldown / 1000, (self.last_tenure_issue_time + tenure_cooldown) / 1000);
            return None;
        }

        // if we're still mining on this burn block, then do nothing
        if self.miner_thread.is_some() {
            debug!("Relayer: will NOT run tenure since miner thread is already running for burn tip {}", &burn_chain_tip);
            return None;
        }

        debug!(
            "Relayer: Spawn tenure thread";
            "height" => last_burn_block.block_height,
            "burn_header_hash" => %burn_header_hash,
        );

        let miner_thread_state =
            BlockMinerThread::from_relayer_thread(self, registered_key, last_burn_block);
        Some(miner_thread_state)
    }

    /// Try to start up a block miner thread with this given VRF key and current burnchain tip.
    /// Returns true if the thread was started; false if it was not (for any reason)
    pub fn block_miner_thread_try_start(
        &mut self,
        registered_key: RegisteredKey,
        last_burn_block: BlockSnapshot,
        issue_timestamp_ms: u128,
    ) -> bool {
        if !self.miner_thread_try_join() {
            return false;
        }

        if !self.config.node.mock_mining {
            // mock miner can't mine microblocks yet, so don't stop it from trying multiple
            // anchored blocks
            if self.mined_stacks_block && self.config.node.mine_microblocks {
                debug!("Relayer: mined a Stacks block already; waiting for microblock miner");
                return false;
            }
        }

        let mut miner_thread_state =
            match self.create_block_miner(registered_key, last_burn_block, issue_timestamp_ms) {
                Some(state) => state,
                None => {
                    return false;
                }
            };

        if let Ok(miner_handle) = thread::Builder::new()
            .name(format!("miner-block-{}", self.local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || miner_thread_state.run_tenure())
            .map_err(|e| {
                error!("Relayer: Failed to start tenure thread: {:?}", &e);
                e
            })
        {
            self.miner_thread = Some(miner_handle);
        }

        true
    }

    /// See if we should run a microblock tenure now.
    /// Return true if so; false if not
    fn can_run_microblock_tenure(&mut self) -> bool {
        if !self.config.node.mine_microblocks {
            // not enabled
            test_debug!("Relayer: not configured to mine microblocks");
            return false;
        }
        if !self.miner_thread_try_join() {
            // already running (for an anchored block or microblock)
            test_debug!("Relayer: miner thread already running so cannot mine microblock");
            return false;
        }
        if self.microblock_deadline > get_epoch_time_ms() {
            debug!(
                "Relayer: Too soon to start a microblock tenure ({} > {})",
                self.microblock_deadline,
                get_epoch_time_ms()
            );
            return false;
        }
        if self.miner_tip.is_none() {
            debug!("Relayer: did not win last block, so cannot mine microblocks");
            return false;
        }
        if !self.mined_stacks_block {
            // have not tried to mine a stacks block yet that confirms previously-mined unconfirmed
            // state (or have not tried to mine a new Stacks block yet for this active tenure);
            debug!("Relayer: Did not mine a block yet, so will not mine a microblock");
            return false;
        }
        if self.globals.get_last_sortition().is_none() {
            debug!("Relayer: no first sortition yet");
            return false;
        }

        // go ahead
        true
    }

    /// Start up a microblock miner thread if we can:
    /// * no miner thread must be running already
    /// * the miner must not be blocked
    /// * we must have won the sortition on the stacks chain tip
    /// Returns true if the thread was started; false if not.
    pub fn microblock_miner_thread_try_start(&mut self) -> bool {
        let miner_tip = match self.miner_tip.as_ref() {
            Some(tip) => tip.clone(),
            None => {
                debug!("Relayer: did not win last block, so cannot mine microblocks");
                return false;
            }
        };

        let burnchain_tip = match self.globals.get_last_sortition() {
            Some(sn) => sn,
            None => {
                debug!("Relayer: no first sortition yet");
                return false;
            }
        };

        debug!(
            "Relayer: mined Stacks block {}/{} so can mine microblocks",
            &miner_tip.consensus_hash, &miner_tip.block_hash
        );

        if !self.miner_thread_try_join() {
            // already running (for an anchored block or microblock)
            debug!("Relayer: miner thread already running so cannot mine microblock");
            return false;
        }
        if self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked()
        {
            debug!(
                "Relayer: miner is blocked as of {}; cannot mine microblock at this time",
                &burnchain_tip.burn_header_hash
            );
            self.globals.counters.set_microblocks_processed(0);
            return false;
        }

        let parent_consensus_hash = &miner_tip.consensus_hash;
        let parent_block_hash = &miner_tip.block_hash;

        debug!(
            "Relayer: Run microblock tenure for {}/{}",
            parent_consensus_hash, parent_block_hash
        );

        let mut microblock_thread_state = match MicroblockMinerThread::from_relayer_thread(self) {
            Some(ts) => ts,
            None => {
                return false;
            }
        };

        if let Ok(miner_handle) = thread::Builder::new()
            .name(format!("miner-microblock-{}", self.local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                Some(MinerThreadResult::Microblock(
                    microblock_thread_state.try_mine_microblock(miner_tip.clone()),
                    miner_tip,
                ))
            })
            .map_err(|e| {
                error!("Relayer: Failed to start tenure thread: {:?}", &e);
                e
            })
        {
            // thread started!
            self.miner_thread = Some(miner_handle);
            self.microblock_deadline =
                get_epoch_time_ms() + (self.config.node.microblock_frequency as u128);
        }

        true
    }

    /// Inner body of Self::miner_thread_try_join
    fn inner_miner_thread_try_join(
        &mut self,
        thread_handle: JoinHandle<Option<MinerThreadResult>>,
    ) -> Option<JoinHandle<Option<MinerThreadResult>>> {
        // tenure run already in progress; try and join
        if !thread_handle.is_finished() {
            debug!("Relayer: RunTenure thread not finished / is in-progress");
            return Some(thread_handle);
        }
        let last_mined_block_opt = thread_handle
            .join()
            .expect("FATAL: failed to join miner thread");
        if let Some(miner_result) = last_mined_block_opt {
            match miner_result {
                MinerThreadResult::Block(
                    last_mined_block,
                    microblock_privkey,
                    ongoing_commit_opt,
                ) => {
                    // finished mining a block
                    if BlockMinerThread::find_inflight_mined_blocks(
                        last_mined_block.my_block_height,
                        &self.last_mined_blocks,
                    )
                    .len()
                        == 0
                    {
                        // first time we've mined a block in this burnchain block
                        self.globals.counters.bump_blocks_processed();
                    }

                    debug!(
                        "Relayer: RunTenure thread joined; got Stacks block {}",
                        &last_mined_block.anchored_block.block_hash()
                    );

                    let bhh = last_mined_block.my_burn_hash.clone();
                    let orig_bhh = last_mined_block.orig_burn_hash.clone();
                    let tenure_begin = last_mined_block.tenure_begin;

                    self.last_mined_blocks.insert(
                        last_mined_block.anchored_block.block_hash(),
                        (last_mined_block, microblock_privkey),
                    );

                    self.last_tenure_issue_time = get_epoch_time_ms();
                    self.bitcoin_controller
                        .set_ongoing_commit(ongoing_commit_opt);

                    debug!(
                        "Relayer: RunTenure finished at {} (in {}ms) targeting {} (originally {})",
                        self.last_tenure_issue_time,
                        self.last_tenure_issue_time.saturating_sub(tenure_begin),
                        &bhh,
                        &orig_bhh
                    );

                    // this stacks block confirms all in-flight microblocks we know about,
                    // including the ones we produced.
                    self.mined_stacks_block = true;
                }
                MinerThreadResult::Microblock(microblock_result, miner_tip) => {
                    // finished mining a microblock
                    match microblock_result {
                        Ok(Some((next_microblock, new_cost))) => {
                            // apply it
                            let microblock_hash = next_microblock.block_hash();

                            let (processed_unconfirmed_state, num_mblocks) = self.with_chainstate(
                                |_relayer_thread, sortdb, chainstate, _mempool| {
                                    let processed_unconfirmed_state =
                                        Relayer::refresh_unconfirmed(chainstate, sortdb);
                                    let num_mblocks = chainstate
                                        .unconfirmed_state
                                        .as_ref()
                                        .map(|ref unconfirmed| unconfirmed.num_microblocks())
                                        .unwrap_or(0);

                                    (processed_unconfirmed_state, num_mblocks)
                                },
                            );

                            info!(
                                "Mined one microblock: {} seq {} txs {} (total processed: {})",
                                &microblock_hash,
                                next_microblock.header.sequence,
                                next_microblock.txs.len(),
                                num_mblocks
                            );
                            self.globals.counters.set_microblocks_processed(num_mblocks);

                            let parent_index_block_hash = StacksBlockHeader::make_index_block_hash(
                                &miner_tip.consensus_hash,
                                &miner_tip.block_hash,
                            );
                            self.event_dispatcher.process_new_microblocks(
                                parent_index_block_hash,
                                processed_unconfirmed_state,
                            );

                            // send it off
                            if let Err(e) = self.relayer.broadcast_microblock(
                                &miner_tip.consensus_hash,
                                &miner_tip.block_hash,
                                next_microblock,
                            ) {
                                error!(
                                    "Failure trying to broadcast microblock {}: {}",
                                    microblock_hash, e
                                );
                            }

                            self.last_microblock_tenure_time = get_epoch_time_ms();
                            self.microblock_stream_cost = new_cost;

                            // synchronise state
                            self.with_chainstate(
                                |relayer_thread, _sortdb, chainstate, _mempool| {
                                    relayer_thread.globals.send_unconfirmed_txs(chainstate);
                                },
                            );

                            // have not yet mined a stacks block that confirms this microblock, so
                            // do that on the next run
                            self.mined_stacks_block = false;
                        }
                        Ok(None) => {
                            debug!("Relayer: did not mine microblock in this tenure");

                            // switch back to block mining
                            self.mined_stacks_block = false;
                        }
                        Err(e) => {
                            warn!("Relayer: Failed to mine next microblock: {:?}", &e);

                            // switch back to block mining
                            self.mined_stacks_block = false;
                        }
                    }
                }
            }
        } else {
            // if we tried and failed to make an anchored block (e.g. because there's nothing to
            // do), then resume microblock mining
            if !self.mined_stacks_block {
                self.try_resume_microblock_mining();
            }
        }
        None
    }

    /// Try to join with the miner thread.  If we succeed, join the thread and return true.
    /// Otherwise, if the thread is still running, return false;
    /// Updates internal state gleaned from the miner, such as:
    /// * new stacks block data
    /// * new keychain state
    /// * new metrics
    /// * new unconfirmed state
    /// Returns true if joined; false if not.
    pub fn miner_thread_try_join(&mut self) -> bool {
        if let Some(thread_handle) = self.miner_thread.take() {
            let new_thread_handle = self.inner_miner_thread_try_join(thread_handle);
            self.miner_thread = new_thread_handle;
        }
        self.miner_thread.is_none()
    }

    /// Top-level dispatcher
    pub fn handle_directive(&mut self, directive: RelayerDirective) -> bool {
        debug!("Relayer: received next directive");
        let continue_running = match directive {
            RelayerDirective::HandleNetResult(net_result) => {
                debug!("Relayer: directive Handle network result");
                self.process_network_result(net_result);
                debug!("Relayer: directive Handled network result");
                true
            }
            RelayerDirective::RegisterKey(last_burn_block) => {
                debug!("Relayer: directive Register VRF key");
                self.rotate_vrf_and_register(&last_burn_block);
                self.globals.counters.bump_blocks_processed();
                debug!("Relayer: directive Registered VRF key");
                true
            }
            RelayerDirective::ProcessTenure(consensus_hash, burn_hash, block_header_hash) => {
                debug!("Relayer: directive Process tenures");
                let res = self.process_new_tenures(consensus_hash, burn_hash, block_header_hash);
                debug!("Relayer: directive Processed tenures");
                res
            }
            RelayerDirective::RunTenure(registered_key, last_burn_block, issue_timestamp_ms) => {
                debug!("Relayer: directive Run tenure");
                self.block_miner_thread_try_start(
                    registered_key,
                    last_burn_block,
                    issue_timestamp_ms,
                );
                debug!("Relayer: directive Ran tenure");
                true
            }
            RelayerDirective::Exit => false,
        };
        if !continue_running {
            return false;
        }

        // see if we need to run a microblock tenure
        if self.can_run_microblock_tenure() {
            self.microblock_miner_thread_try_start();
        }
        continue_running
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
        mine_tip_ch: &ConsensusHash,
        mine_tip_bh: &BlockHeaderHash,
    ) -> Result<ParentStacksBlockInfo, Error> {
        let stacks_tip_header = StacksChainState::get_anchored_block_header_info(
            chain_state.db(),
            &mine_tip_ch,
            &mine_tip_bh,
        )
        .unwrap()
        .ok_or_else(|| {
            error!(
                "Could not mine new tenure, since could not find header for known chain tip.";
                "tip_consensus_hash" => %mine_tip_ch,
                "tip_stacks_block_hash" => %mine_tip_bh
            );
            Error::HeaderNotFoundForChainTip
        })?;

        // the stacks block I'm mining off of's burn header hash and vtxindex:
        let parent_snapshot =
            SortitionDB::get_block_snapshot_consensus(burn_db.conn(), mine_tip_ch)
                .expect("Failed to look up block's parent snapshot")
                .expect("Failed to look up block's parent snapshot");

        let parent_sortition_id = &parent_snapshot.sortition_id;
        let parent_winning_vtxindex =
            SortitionDB::get_block_winning_vtxindex(burn_db.conn(), parent_sortition_id)
                .expect("SortitionDB failure.")
                .ok_or_else(|| {
                    error!(
                        "Failed to find winning vtx index for the parent sortition";
                        "parent_sortition_id" => %parent_sortition_id
                    );
                    Error::WinningVtxNotFoundForChainTip
                })?;

        let parent_block = SortitionDB::get_block_snapshot(burn_db.conn(), parent_sortition_id)
            .expect("SortitionDB failure.")
            .ok_or_else(|| {
                error!(
                    "Failed to find block snapshot for the parent sortition";
                    "parent_sortition_id" => %parent_sortition_id
                );
                Error::SnapshotNotFoundForChainTip
            })?;

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
            return Err(Error::BurnchainTipChanged);
        }

        debug!("Mining tenure's last consensus hash: {} (height {} hash {}), stacks tip consensus hash: {} (height {} hash {})",
               &check_burn_block.consensus_hash, check_burn_block.block_height, &check_burn_block.burn_header_hash,
               mine_tip_ch, parent_snapshot.block_height, &parent_snapshot.burn_header_hash);

        let coinbase_nonce = {
            let principal = miner_address.into();
            let account = chain_state
                .with_read_only_clarity_tx(
                    &burn_db.index_conn(),
                    &StacksBlockHeader::make_index_block_hash(mine_tip_ch, mine_tip_bh),
                    |conn| StacksChainState::get_account(conn, &principal),
                )
                .expect(&format!(
                    "BUG: stacks tip block {}/{} no longer exists after we queried it",
                    mine_tip_ch, mine_tip_bh
                ));
            account.nonce
        };

        Ok(ParentStacksBlockInfo {
            stacks_parent_header: stacks_tip_header,
            parent_consensus_hash: mine_tip_ch.clone(),
            parent_block_burn_height: parent_block.block_height,
            parent_block_total_burn: parent_block.total_burn,
            parent_winning_vtxindex,
            coinbase_nonce,
        })
    }
}

/// Thread that runs the network state machine, handling both p2p and http requests.
pub struct PeerThread {
    /// Node config
    config: Config,
    /// instance of the peer network. Made optional in order to trick the borrow checker.
    net: Option<PeerNetwork>,
    /// handle to global inter-thread comms
    globals: Globals,
    /// how long to wait for network messages on each poll, in millis
    poll_timeout: u64,
    /// receiver for attachments discovered by the chains coordinator thread
    attachments_rx: Receiver<HashSet<AttachmentInstance>>,
    /// handle to the sortition DB (optional so we can take/replace it)
    sortdb: Option<SortitionDB>,
    /// handle to the chainstate DB (optional so we can take/replace it)
    chainstate: Option<StacksChainState>,
    /// handle to the mempool DB (optional so we can take/replace it)
    mempool: Option<MemPoolDB>,
    /// buffer of relayer commands with block data that couldn't be sent to the relayer just yet
    /// (i.e. due to backpressure).  We track this separately, instead of just using a bigger
    /// channel, because we need to know when backpressure occurs in order to throttle the p2p
    /// thread's downloader.
    results_with_data: VecDeque<RelayerDirective>,
    /// total number of p2p state-machine passes so far. Used to signal when to download the next
    /// reward cycle of blocks
    num_p2p_state_machine_passes: u64,
    /// total number of inventory state-machine passes so far. Used to signal when to download the
    /// next reward cycle of blocks.
    num_inv_sync_passes: u64,
    /// total number of download state-machine passes so far. Used to signal when to download the
    /// next reward cycle of blocks.
    num_download_passes: u64,
    /// last burnchain block seen in the PeerNetwork's chain view since the last run
    last_burn_block_height: u64,
}

impl PeerThread {
    /// set up the mempool DB connection
    fn connect_mempool_db(config: &Config) -> MemPoolDB {
        // create estimators, metric instances for RPC handler
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mempool = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        mempool
    }

    /// Instantiate the p2p thread.
    /// Binds the addresses in the config (which may panic if the port is blocked).
    /// This is so the node will crash "early" before any new threads start if there's going to be
    /// a bind error anyway.
    pub fn new(
        runloop: &RunLoop,
        mut net: PeerNetwork,
        attachments_rx: Receiver<HashSet<AttachmentInstance>>,
    ) -> PeerThread {
        let config = runloop.config().clone();
        let mempool = Self::connect_mempool_db(&config);
        let burn_db_path = config.get_burn_db_file_path();

        let sortdb = SortitionDB::open(&burn_db_path, false, runloop.get_burnchain().pox_constants)
            .expect("FATAL: could not open sortition DB");

        let chainstate =
            open_chainstate_with_faults(&config).expect("FATAL: could not open chainstate DB");

        let p2p_sock: SocketAddr = config.node.p2p_bind.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.p2p_bind
        ));
        let rpc_sock = config.node.rpc_bind.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.rpc_bind
        ));

        net.bind(&p2p_sock, &rpc_sock)
            .expect("BUG: PeerNetwork could not bind or is already bound");

        let poll_timeout = cmp::min(5000, config.miner.first_attempt_time_ms / 2);

        PeerThread {
            config,
            net: Some(net),
            globals: runloop.get_globals(),
            poll_timeout,
            attachments_rx,
            sortdb: Some(sortdb),
            chainstate: Some(chainstate),
            mempool: Some(mempool),
            results_with_data: VecDeque::new(),
            num_p2p_state_machine_passes: 0,
            num_inv_sync_passes: 0,
            num_download_passes: 0,
            last_burn_block_height: 0,
        }
    }

    /// Do something with mutable references to the mempool, sortdb, and chainstate
    /// Fools the borrow checker.
    /// NOT COMPOSIBLE
    fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut PeerThread, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self.sortdb.take().expect("BUG: sortdb already taken");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("BUG: chainstate already taken");
        let mut mempool = self.mempool.take().expect("BUG: mempool already taken");

        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);

        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);

        res
    }

    /// Get an immutable ref to the inner network.
    /// DO NOT USE WITHIN with_network()
    fn get_network(&self) -> &PeerNetwork {
        self.net.as_ref().expect("BUG: did not replace net")
    }

    /// Do something with mutable references to the network.
    /// Fools the borrow checker.
    /// NOT COMPOSIBLE. DO NOT CALL THIS OR get_network() IN func
    fn with_network<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut PeerThread, &mut PeerNetwork) -> R,
    {
        let mut net = self.net.take().expect("BUG: net already taken");

        let res = func(self, &mut net);

        self.net = Some(net);
        res
    }

    /// Run one pass of the p2p/http state machine
    /// Return true if we should continue running passes; false if not
    pub fn run_one_pass(
        &mut self,
        dns_client_opt: Option<&mut DNSClient>,
        event_dispatcher: &EventDispatcher,
        cost_estimator: &Box<dyn CostEstimator>,
        cost_metric: &Box<dyn CostMetric>,
        fee_estimator: Option<&Box<dyn FeeEstimator>>,
    ) -> bool {
        // initial block download?
        let ibd = self.globals.sync_comms.get_ibd();
        let download_backpressure = self.results_with_data.len() > 0;
        let poll_ms = if !download_backpressure && self.get_network().has_more_downloads() {
            // keep getting those blocks -- drive the downloader state-machine
            debug!(
                "P2P: backpressure: {}, more downloads: {}",
                download_backpressure,
                self.get_network().has_more_downloads()
            );
            1
        } else {
            self.poll_timeout
        };

        let mut expected_attachments = match self.attachments_rx.try_recv() {
            Ok(expected_attachments) => {
                debug!("Atlas: received attachments: {:?}", &expected_attachments);
                expected_attachments
            }
            _ => {
                debug!("Atlas: attachment channel is empty");
                HashSet::new()
            }
        };

        // move over unconfirmed state obtained from the relayer
        self.with_chainstate(|p2p_thread, sortdb, chainstate, _mempool| {
            let _ = Relayer::setup_unconfirmed_state_readonly(chainstate, sortdb);
            p2p_thread.globals.recv_unconfirmed_txs(chainstate);
        });

        // do one pass
        let p2p_res = self.with_chainstate(|p2p_thread, sortdb, chainstate, mempool| {
            // NOTE: handler_args must be created such that it outlives the inner net.run() call and
            // doesn't ref anything within p2p_thread.
            let handler_args = RPCHandlerArgs {
                exit_at_block_height: p2p_thread
                    .config
                    .burnchain
                    .process_exit_at_block_height
                    .clone(),
                genesis_chainstate_hash: Sha256Sum::from_hex(stx_genesis::GENESIS_CHAINSTATE_HASH)
                    .unwrap(),
                event_observer: Some(event_dispatcher),
                cost_estimator: Some(cost_estimator.as_ref()),
                cost_metric: Some(cost_metric.as_ref()),
                fee_estimator: fee_estimator.map(|boxed_estimator| boxed_estimator.as_ref()),
                ..RPCHandlerArgs::default()
            };
            p2p_thread.with_network(|_, net| {
                net.run(
                    sortdb,
                    chainstate,
                    mempool,
                    dns_client_opt,
                    download_backpressure,
                    ibd,
                    poll_ms,
                    &handler_args,
                    &mut expected_attachments,
                )
            })
        });

        match p2p_res {
            Ok(network_result) => {
                let mut have_update = false;
                if self.num_p2p_state_machine_passes < network_result.num_state_machine_passes {
                    // p2p state-machine did a full pass. Notify anyone listening.
                    self.globals.sync_comms.notify_p2p_state_pass();
                    self.num_p2p_state_machine_passes = network_result.num_state_machine_passes;
                }

                if self.num_inv_sync_passes < network_result.num_inv_sync_passes {
                    // inv-sync state-machine did a full pass. Notify anyone listening.
                    self.globals.sync_comms.notify_inv_sync_pass();
                    self.num_inv_sync_passes = network_result.num_inv_sync_passes;

                    // the relayer cares about the number of inventory passes, so pass this along
                    have_update = true;
                }

                if self.num_download_passes < network_result.num_download_passes {
                    // download state-machine did a full pass.  Notify anyone listening.
                    self.globals.sync_comms.notify_download_pass();
                    self.num_download_passes = network_result.num_download_passes;

                    // the relayer cares about the number of download passes, so pass this along
                    have_update = true;
                }

                if network_result.has_data_to_store()
                    || self.last_burn_block_height != network_result.burn_height
                    || have_update
                {
                    // pass along if we have blocks, microblocks, or transactions, or a status
                    // update on the network's view of the burnchain
                    self.last_burn_block_height = network_result.burn_height;
                    self.results_with_data
                        .push_back(RelayerDirective::HandleNetResult(network_result));
                }
            }
            Err(e) => {
                // this is only reachable if the network is not instantiated correctly --
                // i.e. you didn't connect it
                panic!("P2P: Failed to process network dispatch: {:?}", &e);
            }
        };

        while let Some(next_result) = self.results_with_data.pop_front() {
            // have blocks, microblocks, and/or transactions (don't care about anything else),
            // or a directive to mine microblocks
            if let Err(e) = self.globals.relay_send.try_send(next_result) {
                debug!(
                    "P2P: {:?}: download backpressure detected (bufferred {})",
                    &self.get_network().local_peer,
                    self.results_with_data.len()
                );
                match e {
                    TrySendError::Full(directive) => {
                        if let RelayerDirective::RunTenure(..) = directive {
                            // can drop this
                        } else {
                            // don't lose this data -- just try it again
                            self.results_with_data.push_front(directive);
                        }
                        break;
                    }
                    TrySendError::Disconnected(_) => {
                        info!("P2P: Relayer hang up with p2p channel");
                        self.globals.signal_stop();
                        return false;
                    }
                }
            } else {
                debug!("P2P: Dispatched result to Relayer!");
            }
        }

        true
    }
}

impl StacksNode {
    /// Create a StacksPrivateKey from a given seed buffer
    pub fn make_node_private_key_from_seed(seed: &[u8]) -> StacksPrivateKey {
        let node_privkey = {
            let mut re_hashed_seed = seed.to_vec();
            let my_private_key = loop {
                match Secp256k1PrivateKey::from_slice(&re_hashed_seed[..]) {
                    Ok(sk) => break sk,
                    Err(_) => {
                        re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                            .as_bytes()
                            .to_vec()
                    }
                }
            };
            my_private_key
        };
        node_privkey
    }

    /// Set up the AST size-precheck height, if configured
    fn setup_ast_size_precheck(config: &Config, sortdb: &mut SortitionDB) {
        if let Some(ast_precheck_size_height) = config.burnchain.ast_precheck_size_height {
            info!(
                "Override burnchain height of {:?} to {}",
                ASTRules::PrecheckSize,
                ast_precheck_size_height
            );
            let mut tx = sortdb
                .tx_begin()
                .expect("FATAL: failed to begin tx on sortition DB");
            SortitionDB::override_ast_rule_height(
                &mut tx,
                ASTRules::PrecheckSize,
                ast_precheck_size_height,
            )
            .expect("FATAL: failed to override AST PrecheckSize rule height");
            tx.commit()
                .expect("FATAL: failed to commit sortition DB transaction");
        }
    }

    /// Set up the mempool DB by making sure it exists.
    /// Panics on failure.
    fn setup_mempool_db(config: &Config) -> MemPoolDB {
        // force early mempool instantiation
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mempool = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            cost_estimator,
            metric,
        )
        .expect("BUG: failed to instantiate mempool");

        mempool
    }

    /// Set up the Peer DB and update any soft state from the config file.  This includes:
    /// * blacklisted/whitelisted nodes
    /// * node keys
    /// * bootstrap nodes
    /// Returns the instantiated PeerDB
    /// Panics on failure.
    fn setup_peer_db(config: &Config, burnchain: &Burnchain) -> PeerDB {
        let data_url = UrlString::try_from(format!("{}", &config.node.data_url)).unwrap();
        let initial_neighbors = config.node.bootstrap_node.clone();
        if initial_neighbors.len() > 0 {
            info!(
                "Will bootstrap from peers {}",
                VecDisplay(&initial_neighbors)
            );
        } else {
            warn!("Without a peer to bootstrap from, the node will start mining a new chain");
        }

        let p2p_sock: SocketAddr = config.node.p2p_bind.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.p2p_bind
        ));
        let p2p_addr: SocketAddr = config.node.p2p_address.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.p2p_address
        ));
        let node_privkey =
            StacksNode::make_node_private_key_from_seed(&config.node.local_peer_seed);

        let mut peerdb = PeerDB::connect(
            &config.get_peer_db_file_path(),
            true,
            config.burnchain.chain_id,
            burnchain.network_id,
            Some(node_privkey),
            config.connection_options.private_key_lifetime.clone(),
            PeerAddress::from_socketaddr(&p2p_addr),
            p2p_sock.port(),
            data_url,
            &vec![],
            Some(&initial_neighbors),
        )
        .map_err(|e| {
            eprintln!(
                "Failed to open {}: {:?}",
                &config.get_peer_db_file_path(),
                &e
            );
            panic!();
        })
        .unwrap();

        // allow all bootstrap nodes
        {
            let mut tx = peerdb.tx_begin().unwrap();
            for initial_neighbor in initial_neighbors.iter() {
                // update peer in case public key changed
                PeerDB::update_peer(&mut tx, &initial_neighbor).unwrap();
                PeerDB::set_allow_peer(
                    &mut tx,
                    initial_neighbor.addr.network_id,
                    &initial_neighbor.addr.addrbytes,
                    initial_neighbor.addr.port,
                    -1,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        if !config.node.deny_nodes.is_empty() {
            warn!("Will ignore nodes {:?}", &config.node.deny_nodes);
        }

        // deny all config-denied peers
        {
            let mut tx = peerdb.tx_begin().unwrap();
            for denied in config.node.deny_nodes.iter() {
                PeerDB::set_deny_peer(
                    &mut tx,
                    denied.addr.network_id,
                    &denied.addr.addrbytes,
                    denied.addr.port,
                    get_epoch_time_secs() + 24 * 365 * 3600,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        // update services to indicate we can support mempool sync
        {
            let mut tx = peerdb.tx_begin().unwrap();
            PeerDB::set_local_services(
                &mut tx,
                (ServiceFlags::RPC as u16) | (ServiceFlags::RELAY as u16),
            )
            .unwrap();
            tx.commit().unwrap();
        }

        peerdb
    }

    /// Set up the PeerNetwork, but do not bind it.
    pub fn setup_peer_network(
        config: &Config,
        atlas_config: &AtlasConfig,
        burnchain: Burnchain,
    ) -> PeerNetwork {
        let sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sor/tition db");

        let epochs = SortitionDB::get_stacks_epochs(sortdb.conn())
            .expect("Error while loading stacks epochs");

        let view = {
            let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn())
                .expect("Failed to get sortition tip");
            SortitionDB::get_burnchain_view(&sortdb.conn(), &burnchain, &sortition_tip).unwrap()
        };

        let peerdb = Self::setup_peer_db(config, &burnchain);

        let atlasdb =
            AtlasDB::connect(atlas_config.clone(), &config.get_atlas_db_file_path(), true).unwrap();

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer"),
        };

        let p2p_net = PeerNetwork::new(
            peerdb,
            atlasdb,
            local_peer,
            config.burnchain.peer_version,
            burnchain,
            view,
            config.connection_options.clone(),
            epochs,
        );

        p2p_net
    }

    /// Main loop of the relayer.
    /// Runs in a separate thread.
    /// Continuously receives
    pub fn relayer_main(mut relayer_thread: RelayerThread, relay_recv: Receiver<RelayerDirective>) {
        while let Ok(directive) = relay_recv.recv() {
            if !relayer_thread.globals.keep_running() {
                break;
            }

            if !relayer_thread.handle_directive(directive) {
                break;
            }
        }

        // kill miner if it's running
        signal_mining_blocked(relayer_thread.globals.get_miner_status());

        // set termination flag so other threads die
        relayer_thread.globals.signal_stop();

        debug!("Relayer exit!");
    }

    /// Main loop of the p2p thread.
    /// Runs in a separate thread.
    /// Continuously receives, until told otherwise.
    pub fn p2p_main(mut p2p_thread: PeerThread, event_dispatcher: EventDispatcher) {
        let (mut dns_resolver, mut dns_client) = DNSResolver::new(10);

        // spawn a daemon thread that runs the DNS resolver.
        // It will die when the rest of the system dies.
        {
            let _jh = thread::Builder::new()
                .name("dns-resolver".to_string())
                .spawn(move || {
                    debug!("DNS resolver thread ID is {:?}", thread::current().id());
                    dns_resolver.thread_main();
                })
                .unwrap();
        }

        // NOTE: these must be instantiated in the thread context, since it can't be safely sent
        // between threads
        let fee_estimator_opt = p2p_thread.config.make_fee_estimator();
        let cost_estimator = p2p_thread
            .config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let cost_metric = p2p_thread
            .config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        // receive until we can't reach the receiver thread
        loop {
            if !p2p_thread.globals.keep_running() {
                break;
            }
            if !p2p_thread.run_one_pass(
                Some(&mut dns_client),
                &event_dispatcher,
                &cost_estimator,
                &cost_metric,
                fee_estimator_opt.as_ref(),
            ) {
                break;
            }
        }

        // kill miner
        signal_mining_blocked(p2p_thread.globals.get_miner_status());

        // set termination flag so other threads die
        p2p_thread.globals.signal_stop();

        // thread exited, so signal to the relayer thread to die.
        while let Err(TrySendError::Full(_)) = p2p_thread
            .globals
            .relay_send
            .try_send(RelayerDirective::Exit)
        {
            warn!("Failed to direct relayer thread to exit, sleeping and trying again");
            thread::sleep(Duration::from_secs(5));
        }
        info!("P2P thread exit!");
    }

    pub fn spawn(
        runloop: &RunLoop,
        globals: Globals,
        // relay receiver endpoint for the p2p thread, so the relayer can feed it data to push
        relay_recv: Receiver<RelayerDirective>,
        // attachments receiver endpoint for the p2p thread, so the chains coordinator can feed it
        // attachments it discovers
        attachments_receiver: Receiver<HashSet<AttachmentInstance>>,
    ) -> StacksNode {
        let config = runloop.config().clone();
        let is_miner = runloop.is_miner();
        let burnchain = runloop.get_burnchain();
        let atlas_config = AtlasConfig::default(config.is_mainnet());
        let keychain = Keychain::default(config.node.seed.clone());

        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let mut sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sor/tition db");

        Self::setup_ast_size_precheck(&config, &mut sortdb);

        let _ = Self::setup_mempool_db(&config);

        let mut p2p_net = Self::setup_peer_network(&config, &atlas_config, burnchain.clone());
        let relayer = Relayer::from_p2p(&mut p2p_net);

        let local_peer = p2p_net.local_peer.clone();

        let burnchain_signer = keychain.get_burnchain_signer();
        match monitoring::set_burnchain_signer(burnchain_signer.clone()) {
            Err(e) => {
                warn!("Failed to set global burnchain signer: {:?}", &e);
            }
            _ => {}
        }

        // setup initial key registration
        let leader_key_registration_state = if config.node.mock_mining {
            // mock mining, pretend to have a registered key
            let (vrf_public_key, _) = keychain.make_vrf_keypair(VRF_MOCK_MINER_KEY);
            LeaderKeyRegistrationState::Active(RegisteredKey {
                target_block_height: VRF_MOCK_MINER_KEY,
                block_height: 1,
                op_vtxindex: 1,
                vrf_public_key,
            })
        } else {
            LeaderKeyRegistrationState::Inactive
        };
        globals.set_initial_leader_key_registration_state(leader_key_registration_state);

        let relayer_thread = RelayerThread::new(runloop, local_peer.clone(), relayer);
        let relayer_thread_handle = thread::Builder::new()
            .name(format!("relayer-{}", &local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                debug!("relayer thread ID is {:?}", thread::current().id());
                Self::relayer_main(relayer_thread, relay_recv);
            })
            .expect("FATAL: failed to start relayer thread");

        let p2p_event_dispatcher = runloop.get_event_dispatcher();
        let p2p_thread = PeerThread::new(runloop, p2p_net, attachments_receiver);
        let p2p_thread_handle = thread::Builder::new()
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .name(format!(
                "p2p-({},{})",
                &config.node.p2p_bind, &config.node.rpc_bind
            ))
            .spawn(move || {
                debug!("p2p thread ID is {:?}", thread::current().id());
                Self::p2p_main(p2p_thread, p2p_event_dispatcher);
            })
            .expect("FATAL: failed to start p2p thread");

        info!("Start HTTP server on: {}", &config.node.rpc_bind);
        info!("Start P2P server on: {}", &config.node.p2p_bind);

        StacksNode {
            atlas_config,
            globals,
            is_miner,
            p2p_thread_handle,
            relayer_thread_handle,
        }
    }

    /// Manage the VRF public key registration state machine.
    /// Tell the relayer thread to fire off a tenure and a block commit op,
    /// if it is time to do so.
    /// `ibd` indicates whether or not we're in the initial block download.  Used to control when
    /// to try and register VRF keys.
    /// Called from the main thread.
    /// Return true if we succeeded in carrying out the next task of the operation.
    pub fn relayer_issue_tenure(&mut self, ibd: bool) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to issue a tenure
            return true;
        }

        if let Some(burnchain_tip) = self.globals.get_last_sortition() {
            if !ibd {
                // try and register a VRF key before issuing a tenure
                let leader_key_registration_state =
                    self.globals.get_leader_key_registration_state();
                match leader_key_registration_state {
                    LeaderKeyRegistrationState::Active(ref key) => {
                        debug!(
                            "Tenure: Using key {:?} off of {}",
                            &key.vrf_public_key, &burnchain_tip.burn_header_hash
                        );

                        self.globals
                            .relay_send
                            .send(RelayerDirective::RunTenure(
                                key.clone(),
                                burnchain_tip,
                                get_epoch_time_ms(),
                            ))
                            .is_ok()
                    }
                    LeaderKeyRegistrationState::Inactive => {
                        warn!(
                            "Tenure: skipped tenure because no active VRF key. Trying to register one."
                        );
                        self.globals
                            .relay_send
                            .send(RelayerDirective::RegisterKey(burnchain_tip))
                            .is_ok()
                    }
                    LeaderKeyRegistrationState::Pending(..) => true,
                }
            } else {
                // still sync'ing so just try again later
                true
            }
        } else {
            warn!("Tenure: Do not know the last burn block. As a miner, this is bad.");
            true
        }
    }

    /// Notify the relayer of a sortition, telling it to process the block
    ///  and advertize it if it was mined by the node.
    /// returns _false_ if the relayer hung up the channel.
    /// Called from the main thread.
    pub fn relayer_sortition_notify(&self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to process my own tenure.
            return true;
        }

        if let Some(snapshot) = self.globals.get_last_sortition() {
            debug!(
                "Tenure: Notify sortition!";
                "consensus_hash" => %snapshot.consensus_hash,
                "burn_block_hash" => %snapshot.burn_header_hash,
                "winning_stacks_block_hash" => %snapshot.winning_stacks_block_hash,
                "burn_block_height" => &snapshot.block_height,
                "sortition_id" => %snapshot.sortition_id
            );
            if snapshot.sortition {
                return self
                    .globals
                    .relay_send
                    .send(RelayerDirective::ProcessTenure(
                        snapshot.consensus_hash.clone(),
                        snapshot.parent_burn_header_hash.clone(),
                        snapshot.winning_stacks_block_hash.clone(),
                    ))
                    .is_ok();
            }
        } else {
            debug!("Tenure: Notify sortition! No last burn block");
        }
        true
    }

    /// Process a state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    /// `ibd`: boolean indicating whether or not we are in the initial block download
    /// Called from the main thread.
    pub fn process_burnchain_state(
        &mut self,
        sortdb: &SortitionDB,
        sort_id: &SortitionId,
        ibd: bool,
    ) -> Option<BlockSnapshot> {
        let mut last_sortitioned_block = None;

        let ic = sortdb.index_conn();

        let block_snapshot = SortitionDB::get_block_snapshot(&ic, sort_id)
            .expect("Failed to obtain block snapshot for processed burn block.")
            .expect("Failed to obtain block snapshot for processed burn block.");
        let block_height = block_snapshot.block_height;

        let block_commits =
            SortitionDB::get_block_commits_by_block(&ic, &block_snapshot.sortition_id)
                .expect("Unexpected SortitionDB error fetching block commits");

        update_active_miners_count_gauge(block_commits.len() as i64);

        for op in block_commits.into_iter() {
            if op.txid == block_snapshot.winning_block_txid {
                info!(
                    "Received burnchain block #{} including block_commit_op (winning) - {} ({})",
                    block_height, op.apparent_sender, &op.block_header_hash
                );
                last_sortitioned_block = Some((block_snapshot.clone(), op.vtxindex));
            } else {
                if self.is_miner {
                    info!(
                        "Received burnchain block #{} including block_commit_op - {} ({})",
                        block_height, op.apparent_sender, &op.block_header_hash
                    );
                }
            }
        }

        let key_registers =
            SortitionDB::get_leader_keys_by_block(&ic, &block_snapshot.sortition_id)
                .expect("Unexpected SortitionDB error fetching key registers");

        if !ibd {
            // only bother with this if we're sync'ed
            self.globals
                .try_activate_leader_key_registration(block_height, key_registers);
        }

        self.globals.set_last_sortition(block_snapshot);
        last_sortitioned_block.map(|x| x.0)
    }

    /// Join all inner threads
    pub fn join(self) {
        self.relayer_thread_handle.join().unwrap();
        self.p2p_thread_handle.join().unwrap();
    }
}
