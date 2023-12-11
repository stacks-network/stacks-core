use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use stacks::burnchains::Txid;
use stacks::chainstate::burn::operations::LeaderKeyRegisterOp;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::stacks::db::unconfirmed::UnconfirmedTxMap;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::MinerStatus;
use stacks::net::NetworkResult;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, ConsensusHash};

use crate::neon::Counters;
use crate::neon_node::LeaderKeyRegistrationState;
use crate::run_loop::RegisteredKey;
use crate::syncctl::PoxSyncWatchdogComms;

pub type NeonGlobals = Globals<RelayerDirective>;

/// Command types for the relayer thread, issued to it by other threads
pub enum RelayerDirective {
    /// Handle some new data that arrived on the network (such as blocks, transactions, and
    HandleNetResult(NetworkResult),
    /// Announce a new sortition.  Process and broadcast the block if we won.
    ProcessTenure(ConsensusHash, BurnchainHeaderHash, BlockHeaderHash),
    /// Try to mine a block
    RunTenure(RegisteredKey, BlockSnapshot, u128), // (vrf key, chain tip, time of issuance in ms)
    /// A nakamoto tenure's first block has been processed.
    NakamotoTenureStartProcessed(ConsensusHash, BlockHeaderHash),
    /// Try to register a VRF public key
    RegisterKey(BlockSnapshot),
    /// Stop the relayer thread
    Exit,
}

/// Inter-thread communication structure, shared between threads. This
/// is generic over the relayer communication channel: nakamoto and
/// neon nodes use different relayer directives.
pub struct Globals<T> {
    /// Last sortition processed
    last_sortition: Arc<Mutex<Option<BlockSnapshot>>>,
    /// Status of the miner
    miner_status: Arc<Mutex<MinerStatus>>,
    /// Communication link to the coordinator thread
    pub(crate) coord_comms: CoordinatorChannels,
    /// Unconfirmed transactions (shared between the relayer and p2p threads)
    unconfirmed_txs: Arc<Mutex<UnconfirmedTxMap>>,
    /// Writer endpoint to the relayer thread
    pub relay_send: SyncSender<T>,
    /// Cointer state in the main thread
    pub counters: Counters,
    /// Connection to the PoX sync watchdog
    pub sync_comms: PoxSyncWatchdogComms,
    /// Global flag to see if we should keep running
    pub should_keep_running: Arc<AtomicBool>,
    /// Status of our VRF key registration state (shared between the main thread and the relayer)
    leader_key_registration_state: Arc<Mutex<LeaderKeyRegistrationState>>,
}

// Need to manually implement Clone, because [derive(Clone)] requires
//  all trait bounds to implement Clone, even though T doesn't need Clone
//  because it's behind SyncSender.
impl<T> Clone for Globals<T> {
    fn clone(&self) -> Self {
        Self {
            last_sortition: self.last_sortition.clone(),
            miner_status: self.miner_status.clone(),
            coord_comms: self.coord_comms.clone(),
            unconfirmed_txs: self.unconfirmed_txs.clone(),
            relay_send: self.relay_send.clone(),
            counters: self.counters.clone(),
            sync_comms: self.sync_comms.clone(),
            should_keep_running: self.should_keep_running.clone(),
            leader_key_registration_state: self.leader_key_registration_state.clone(),
        }
    }
}

impl<T> Globals<T> {
    pub fn new(
        coord_comms: CoordinatorChannels,
        miner_status: Arc<Mutex<MinerStatus>>,
        relay_send: SyncSender<T>,
        counters: Counters,
        sync_comms: PoxSyncWatchdogComms,
        should_keep_running: Arc<AtomicBool>,
    ) -> Globals<T> {
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

    /// Does the inventory sync watcher think we still need to
    /// catch up to the chain tip?
    pub fn in_initial_block_download(&self) -> bool {
        self.sync_comms.get_ibd()
    }

    /// Get the last sortition processed by the relayer thread
    pub fn get_last_sortition(&self) -> Option<BlockSnapshot> {
        self.last_sortition
            .lock()
            .unwrap_or_else(|_| {
                error!("Sortition mutex poisoned!");
                panic!();
            })
            .clone()
    }

    /// Set the last sortition processed
    pub fn set_last_sortition(&self, block_snapshot: BlockSnapshot) {
        let mut last_sortition = self.last_sortition.lock().unwrap_or_else(|_| {
            error!("Sortition mutex poisoned!");
            panic!();
        });
        last_sortition.replace(block_snapshot);
    }

    /// Get the status of the miner (blocked or ready)
    pub fn get_miner_status(&self) -> Arc<Mutex<MinerStatus>> {
        self.miner_status.clone()
    }

    pub fn block_miner(&self) {
        self.miner_status
            .lock()
            .expect("FATAL: mutex poisoned")
            .add_blocked()
    }

    pub fn unblock_miner(&self) {
        self.miner_status
            .lock()
            .expect("FATAL: mutex poisoned")
            .remove_blocked()
    }

    /// Get the main thread's counters
    pub fn get_counters(&self) -> Counters {
        self.counters.clone()
    }

    /// Called by the relayer to pass unconfirmed txs to the p2p thread, so the p2p thread doesn't
    /// need to do the disk I/O needed to instantiate the unconfirmed state trie they represent.
    /// Clears the unconfirmed transactions, and replaces them with the chainstate's.
    pub fn send_unconfirmed_txs(&self, chainstate: &StacksChainState) {
        let Some(ref unconfirmed) = chainstate.unconfirmed_state else {
            return;
        };
        let mut txs = self.unconfirmed_txs.lock().unwrap_or_else(|e| {
            // can only happen due to a thread panic in the relayer
            error!("FATAL: unconfirmed tx arc mutex is poisoned: {e:?}");
            panic!();
        });
        txs.clear();
        txs.extend(unconfirmed.mined_txs.clone());
    }

    /// Called by the p2p thread to accept the unconfirmed tx state processed by the relayer.
    /// Puts the shared unconfirmed transactions to chainstate.
    pub fn recv_unconfirmed_txs(&self, chainstate: &mut StacksChainState) {
        let Some(ref mut unconfirmed) = chainstate.unconfirmed_state else {
            return;
        };
        let txs = self.unconfirmed_txs.lock().unwrap_or_else(|e| {
            // can only happen due to a thread panic in the relayer
            error!("FATAL: unconfirmed tx arc mutex is poisoned: {e:?}");
            panic!();
        });
        unconfirmed.mined_txs.clear();
        unconfirmed.mined_txs.extend(txs.clone());
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
    pub fn get_leader_key_registration_state(&self) -> LeaderKeyRegistrationState {
        let key_state = self
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|e| {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: leader key registration mutex is poisoned: {e:?}");
                panic!();
            });
        key_state.clone()
    }

    /// Set the initial leader key registration state.
    /// Called from the runloop thread when booting up.
    pub fn set_initial_leader_key_registration_state(&self, new_state: LeaderKeyRegistrationState) {
        let mut key_state = self
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|e| {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: leader key registration mutex is poisoned: {e:?}");
                panic!();
            });
        *key_state = new_state;
    }

    /// Advance the leader key registration state to pending, given a txid we just sent.
    /// Only the relayer thread calls this.
    pub fn set_pending_leader_key_registration(&self, target_block_height: u64, txid: Txid) {
        let mut key_state = self
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|_e| {
                error!("FATAL: failed to lock leader key registration state mutex");
                panic!();
            });
        *key_state = LeaderKeyRegistrationState::Pending(target_block_height, txid);
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
        let mut key_state = self
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|e| {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: leader key registration mutex is poisoned: {e:?}");
                panic!();
            });
        // if key_state is anything but pending, then we don't activate
        let LeaderKeyRegistrationState::Pending(target_block_height, txid) = *key_state else {
            return false;
        };
        for op in key_registers.into_iter() {
            info!(
                "Processing burnchain block with key_register_op";
                "burn_block_height" => burn_block_height,
                "txid" => %op.txid,
                "checking_txid" => %txid,
            );

            if txid == op.txid {
                *key_state = LeaderKeyRegistrationState::Active(RegisteredKey {
                    target_block_height,
                    vrf_public_key: op.public_key,
                    block_height: u64::from(op.block_height),
                    op_vtxindex: u32::from(op.vtxindex),
                });
                activated = true;
            } else {
                debug!(
                    "key_register_op {} does not match our pending op {}",
                    txid, &op.txid
                );
            }
        }

        activated
    }
}
