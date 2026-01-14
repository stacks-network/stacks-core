// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
#[cfg(test)]
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::sync::{LazyLock, Weak};
use std::time::{Duration, SystemTime};

use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::{FTEventType, NFTEventType, STXEventType};
use clarity::vm::types::{AssetIdentifier, QualifiedContractIdentifier};
#[cfg(any(test, feature = "testing"))]
use lazy_static::lazy_static;
use serde_json::json;
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::coordinator::BlockEventDispatcher;
use stacks::chainstate::nakamoto::NakamotoBlock;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::boot::RewardSetData;
use stacks::chainstate::stacks::db::accounts::MinerReward;
use stacks::chainstate::stacks::db::unconfirmed::ProcessedUnconfirmedState;
use stacks::chainstate::stacks::db::{MinerRewardInfo, StacksHeaderInfo};
use stacks::chainstate::stacks::events::{
    StackerDBChunksEvent, StacksBlockEventData, StacksTransactionEvent, StacksTransactionReceipt,
};
use stacks::chainstate::stacks::miner::TransactionEvent;
use stacks::chainstate::stacks::{StacksBlock, StacksMicroblock, StacksTransaction};
use stacks::config::{EventKeyType, EventObserverConfig};
use stacks::core::mempool::{MemPoolDropReason, MemPoolEventDispatcher, ProposalCallbackReceiver};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::api::postblock_proposal::{
    BlockValidateOk, BlockValidateReject, BlockValidateResponse,
};
use stacks::net::atlas::{Attachment, AttachmentInstance};
use stacks::net::stackerdb::StackerDBEventDispatcher;
#[cfg(any(test, feature = "testing"))]
use stacks::util::tests::TestFlag;
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
use url::Url;

mod db;
mod payloads;
mod stacker_db;
mod worker;

use db::EventDispatcherDbConnection;
use payloads::*;
pub use payloads::{
    MinedBlockEvent, MinedMicroblockEvent, MinedNakamotoBlockEvent, NakamotoSignerEntryPayload,
    RewardSetEventPayload, TransactionEventPayload,
};
pub use stacker_db::StackerDBChannel;

use crate::event_dispatcher::db::PendingPayload;
use crate::event_dispatcher::worker::{EventDispatcherResult, EventDispatcherWorker};

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "testing"))]
lazy_static! {
    /// Do not announce a signed/mined block to the network when set to true.
    pub static ref TEST_SKIP_BLOCK_ANNOUNCEMENT: TestFlag<bool> = TestFlag::default();
}

#[derive(Debug, thiserror::Error)]
enum EventDispatcherError {
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    HttpError(#[from] std::io::Error),
    #[error("Database error: {0}")]
    DbError(#[from] stacks::util_lib::db::Error),
    #[error("Channel receive error: {0}")]
    RecvError(#[from] std::sync::mpsc::RecvError),
    #[error("Channel send error: {0}")]
    SendError(String), // not capturing the underlying because it's a generic type
}

impl<T> From<std::sync::mpsc::SendError<T>> for EventDispatcherError {
    fn from(value: std::sync::mpsc::SendError<T>) -> Self {
        EventDispatcherError::SendError(format!("{value}"))
    }
}

#[derive(Debug, Clone)]
struct EventObserver {
    /// URL to which events will be sent
    endpoint: String,
    /// Timeout for sending events to this observer
    timeout: Duration,
    /// If true, the stacks-node will not retry if event delivery fails for any reason.
    /// WARNING: This should not be set on observers that require successful delivery of all events.
    disable_retries: bool,
}

/// Update `serve()` in `neon_integrations.rs` with any new paths that need to be tested
pub const PATH_MICROBLOCK_SUBMIT: &str = "new_microblocks";
pub const PATH_MEMPOOL_TX_SUBMIT: &str = "new_mempool_tx";
pub const PATH_MEMPOOL_TX_DROP: &str = "drop_mempool_tx";
pub const PATH_MINED_BLOCK: &str = "mined_block";
pub const PATH_MINED_MICROBLOCK: &str = "mined_microblock";
pub const PATH_MINED_NAKAMOTO_BLOCK: &str = "mined_nakamoto_block";
pub const PATH_STACKERDB_CHUNKS: &str = "stackerdb_chunks";
pub const PATH_BURN_BLOCK_SUBMIT: &str = "new_burn_block";
pub const PATH_BLOCK_PROCESSED: &str = "new_block";
pub const PATH_ATTACHMENT_PROCESSED: &str = "attachments/new";
pub const PATH_PROPOSAL_RESPONSE: &str = "proposal_response";

#[cfg(test)]
static TEST_EVENT_OBSERVER_SKIP_RETRY: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

impl EventObserver {
    fn new(endpoint: String, timeout: Duration, disable_retries: bool) -> Self {
        EventObserver {
            endpoint,
            timeout,
            disable_retries,
        }
    }
}

struct EventRequestData {
    pub url: String,
    pub payload_bytes: Arc<[u8]>,
    pub timeout: Duration,
}

/// Events received from block-processing.
/// Stacks events are structured as JSON, and are grouped by topic.  An event observer can
/// subscribe to one or more specific event streams, or the "any" stream to receive all of them.
#[derive(Clone)]
pub struct EventDispatcher {
    /// List of configured event observers to which events will be posted.
    /// The fields below this contain indexes into this list.
    registered_observers: Vec<EventObserver>,
    /// Smart contract-specific events, keyed by (contract-id, event-name). Values are indexes into `registered_observers`.
    contract_events_observers_lookup: HashMap<(QualifiedContractIdentifier, String), HashSet<u16>>,
    /// Asset event observers, keyed by fully-qualified asset identifier. Values are indexes into
    /// `registered_observers.
    assets_observers_lookup: HashMap<AssetIdentifier, HashSet<u16>>,
    /// Index into `registered_observers` that will receive burn block events
    burn_block_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive mempool events
    mempool_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive microblock events
    microblock_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive STX events
    stx_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive all events
    any_event_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive block miner events (Stacks 2.5 and
    /// lower)
    miner_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive microblock miner events (Stacks 2.5 and
    /// lower)
    mined_microblocks_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive StackerDB events
    stackerdb_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive block proposal events (Nakamoto and
    /// later)
    block_proposal_observers_lookup: HashSet<u16>,
    /// Channel for sending StackerDB events to the miner coordinator
    pub stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
    /// Path to the database where pending payloads are stored.
    db_path: PathBuf,
    /// The worker thread that performs the actuall HTTP requests so that they don't block
    /// the main operation of the node. It's wrapped in an `Arc` only to make some test helpers
    /// work (see `ALL_WORKERS`); in release code it wouldn't be necessary.
    worker: Arc<EventDispatcherWorker>,
}

/// This struct is used specifically for receiving proposal responses.
/// It's constructed separately to play nicely with threading.
struct ProposalCallbackHandler {
    observers: Vec<EventObserver>,
    dispatcher: EventDispatcher,
}

impl ProposalCallbackReceiver for ProposalCallbackHandler {
    fn notify_proposal_result(&self, result: Result<BlockValidateOk, BlockValidateReject>) {
        let response = match serde_json::to_value(BlockValidateResponse::from(result)) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "Failed to serialize block proposal validation response, will not notify over event observer";
                    "error" => ?e
                );
                return;
            }
        };

        for observer in self.observers.iter() {
            self.dispatcher
                .dispatch_to_observer(observer, &response, PATH_PROPOSAL_RESPONSE)
                .unwrap()
                .wait_until_complete();
        }
    }
}

impl MemPoolEventDispatcher for EventDispatcher {
    fn mempool_txs_dropped(
        &self,
        txids: Vec<Txid>,
        new_txid: Option<Txid>,
        reason: MemPoolDropReason,
    ) {
        if !txids.is_empty() {
            self.process_dropped_mempool_txs(txids, new_txid, reason)
        }
    }

    fn mined_block_event(
        &self,
        target_burn_height: u64,
        block: &StacksBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        confirmed_microblock_cost: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        self.process_mined_block_event(
            target_burn_height,
            block,
            block_size_bytes,
            consumed,
            confirmed_microblock_cost,
            tx_events,
        )
    }

    fn mined_microblock_event(
        &self,
        microblock: &StacksMicroblock,
        tx_events: Vec<TransactionEvent>,
        anchor_block_consensus_hash: ConsensusHash,
        anchor_block: BlockHeaderHash,
    ) {
        self.process_mined_microblock_event(
            microblock,
            tx_events,
            anchor_block_consensus_hash,
            anchor_block,
        );
    }

    fn mined_nakamoto_block_event(
        &self,
        target_burn_height: u64,
        block: &NakamotoBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        self.process_mined_nakamoto_block_event(
            target_burn_height,
            block,
            block_size_bytes,
            consumed,
            tx_events,
        )
    }

    fn get_proposal_callback_receiver(&self) -> Option<Box<dyn ProposalCallbackReceiver>> {
        let callback_receivers: Vec<_> = self
            .block_proposal_observers_lookup
            .iter()
            .filter_map(|observer_ix|
                match self.registered_observers.get(usize::from(*observer_ix)) {
                    Some(x) => Some(x.clone()),
                    None => {
                        warn!(
                            "Event observer index not found in registered observers. Ignoring that index.";
                            "index" => observer_ix,
                            "observers_len" => self.registered_observers.len()
                        );
                        None
                    }
                }
            )
            .collect();
        if callback_receivers.is_empty() {
            return None;
        }
        let handler = ProposalCallbackHandler {
            observers: callback_receivers,
            dispatcher: self.clone(),
        };
        Some(Box::new(handler))
    }
}

impl StackerDBEventDispatcher for EventDispatcher {
    /// Relay new StackerDB chunks
    fn new_stackerdb_chunks(
        &self,
        contract_id: QualifiedContractIdentifier,
        chunks: Vec<StackerDBChunkData>,
    ) {
        self.process_new_stackerdb_chunks(contract_id, chunks);
    }
}

impl BlockEventDispatcher for EventDispatcher {
    fn announce_block(
        &self,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent: &StacksBlockId,
        winner_txid: &Txid,
        mature_rewards: &[MinerReward],
        mature_rewards_info: Option<&MinerRewardInfo>,
        parent_burn_block_hash: &BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec: &Option<BitVec<4000>>,
        block_timestamp: Option<u64>,
        coinbase_height: u64,
    ) {
        self.process_chain_tip(
            block,
            metadata,
            receipts,
            parent,
            winner_txid,
            mature_rewards,
            mature_rewards_info,
            parent_burn_block_hash,
            parent_burn_block_height,
            parent_burn_block_timestamp,
            anchored_consumed,
            mblock_confirmed_consumed,
            pox_constants,
            reward_set_data,
            signer_bitvec,
            block_timestamp,
            coinbase_height,
        );
    }

    fn announce_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        recipient_info: Vec<PoxAddress>,
        consensus_hash: &ConsensusHash,
        parent_burn_block_hash: &BurnchainHeaderHash,
    ) {
        self.process_burn_block(
            burn_block,
            burn_block_height,
            rewards,
            burns,
            recipient_info,
            consensus_hash,
            parent_burn_block_hash,
        )
    }
}

/// During integration tests, the `test_observer` needs to ensure that all events
/// that were triggered have actually been delivered, before it can pass on the
/// captured data. To make that work, during test we store weak references to
/// all the workers and make it possible to wait for all of them to catch up
/// in a single function call (see `catch_up_all_event_dispatchers`).
#[cfg(test)]
static ALL_WORKERS: Mutex<Vec<Weak<EventDispatcherWorker>>> = Mutex::new(Vec::new());

#[cfg(test)]
pub fn catch_up_all_event_dispatchers() {
    let mut results = Vec::new();
    let mut guard = ALL_WORKERS.lock().unwrap();

    // remove all items that have been dropped; call .noop() the rest
    guard.retain_mut(|w| {
        let Some(worker) = w.upgrade() else {
            return false;
        };
        results.push(worker.noop().unwrap());
        return true;
    });
    // unlock the mutex
    drop(guard);

    // block until all workers have caught up
    for result in results {
        result.wait_until_complete();
    }
}

impl EventDispatcher {
    pub fn new(working_dir: PathBuf) -> EventDispatcher {
        let mut db_path = working_dir;
        db_path.push("event_observers.sqlite");
        EventDispatcherDbConnection::new(&db_path).expect("Failed to initialize database");

        let worker =
            EventDispatcherWorker::new(db_path.clone()).expect("Failed to start worker thread");

        let worker = Arc::new(worker);

        #[cfg(test)]
        {
            ALL_WORKERS.lock().unwrap().push(Arc::downgrade(&worker));
        }

        EventDispatcher {
            stackerdb_channel: Arc::new(Mutex::new(StackerDBChannel::new())),
            registered_observers: vec![],
            contract_events_observers_lookup: HashMap::new(),
            assets_observers_lookup: HashMap::new(),
            stx_observers_lookup: HashSet::new(),
            any_event_observers_lookup: HashSet::new(),
            burn_block_observers_lookup: HashSet::new(),
            mempool_observers_lookup: HashSet::new(),
            microblock_observers_lookup: HashSet::new(),
            miner_observers_lookup: HashSet::new(),
            mined_microblocks_observers_lookup: HashSet::new(),
            stackerdb_observers_lookup: HashSet::new(),
            block_proposal_observers_lookup: HashSet::new(),
            db_path,
            worker,
        }
    }

    /// Sends a noop task to the worker and waits until its completion is acknowledged.
    /// This has the effect that all payloads that have been submitted before this point
    /// are also done, which is a useful thing to wait for in some tests where you want
    /// to assert on certain event deliveries.
    #[cfg(test)]
    pub fn catch_up(&self) {
        self.worker.noop().unwrap().wait_until_complete();
    }

    pub fn process_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        recipient_info: Vec<PoxAddress>,
        consensus_hash: &ConsensusHash,
        parent_burn_block_hash: &BurnchainHeaderHash,
    ) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.burn_block_observers_lookup, true);
        if interested_observers.is_empty() {
            return;
        }

        let payload = make_new_burn_block_payload(
            burn_block,
            burn_block_height,
            rewards,
            burns,
            recipient_info,
            consensus_hash,
            parent_burn_block_hash,
        );

        for observer in interested_observers.iter() {
            self.send_new_burn_block(&observer, &payload);
        }
    }

    /// Iterates through tx receipts, and then the events corresponding to each receipt to
    /// generate a dispatch matrix & event vector.
    ///
    /// # Returns
    /// - dispatch_matrix: a vector where each index corresponds to the hashset of event indexes
    ///     that each respective event observer is subscribed to
    /// - events: a vector of all events from all the tx receipts
    #[allow(clippy::type_complexity)]
    fn create_dispatch_matrix_and_event_vector<'a>(
        &self,
        receipts: &'a [StacksTransactionReceipt],
    ) -> (
        Vec<HashSet<usize>>,
        Vec<(bool, Txid, &'a StacksTransactionEvent)>,
    ) {
        let mut dispatch_matrix: Vec<HashSet<usize>> = self
            .registered_observers
            .iter()
            .map(|_| HashSet::new())
            .collect();
        let mut events: Vec<(bool, Txid, &StacksTransactionEvent)> = vec![];
        let mut i: usize = 0;

        for receipt in receipts {
            let tx_hash = receipt.transaction.txid();
            for event in receipt.events.iter() {
                match event {
                    StacksTransactionEvent::SmartContractEvent(event_data) => {
                        if let Some(observer_indexes) =
                            self.contract_events_observers_lookup.get(&event_data.key)
                        {
                            for o_i in observer_indexes {
                                dispatch_matrix[*o_i as usize].insert(i);
                            }
                        }
                    }
                    StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(_))
                    | StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(_))
                    | StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(_))
                    | StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(_)) => {
                        for o_i in &self.stx_observers_lookup {
                            dispatch_matrix[*o_i as usize].insert(i);
                        }
                    }
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(
                        event_data,
                    )) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTBurnEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::FTEvent(FTEventType::FTBurnEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                }
                events.push((!receipt.post_condition_aborted, tx_hash.clone(), event));
                for o_i in &self.any_event_observers_lookup {
                    dispatch_matrix[*o_i as usize].insert(i);
                }
                i += 1;
            }
        }

        (dispatch_matrix, events)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_chain_tip(
        &self,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent_index_hash: &StacksBlockId,
        winner_txid: &Txid,
        mature_rewards: &[MinerReward],
        mature_rewards_info: Option<&MinerRewardInfo>,
        parent_burn_block_hash: &BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec: &Option<BitVec<4000>>,
        block_timestamp: Option<u64>,
        coinbase_height: u64,
    ) {
        let (dispatch_matrix, events) = self.create_dispatch_matrix_and_event_vector(receipts);

        if !dispatch_matrix.is_empty() {
            let mature_rewards_vec = if let Some(rewards_info) = mature_rewards_info {
                mature_rewards
                    .iter()
                    .map(|reward| {
                        json!({
                            "recipient": reward.recipient.to_string(),
                            "miner_address": reward.address.to_string(),
                            "coinbase_amount": reward.coinbase.to_string(),
                            "tx_fees_anchored": reward.tx_fees_anchored.to_string(),
                            "tx_fees_streamed_confirmed": reward.tx_fees_streamed_confirmed.to_string(),
                            "tx_fees_streamed_produced": reward.tx_fees_streamed_produced.to_string(),
                            "from_stacks_block_hash": format!("0x{}", rewards_info.from_stacks_block_hash),
                            "from_index_consensus_hash": format!("0x{}", StacksBlockId::new(&rewards_info.from_block_consensus_hash,
                                                                                            &rewards_info.from_stacks_block_hash)),
                        })
                    })
                    .collect()
            } else {
                vec![]
            };

            let mature_rewards = serde_json::Value::Array(mature_rewards_vec);

            #[cfg(any(test, feature = "testing"))]
            if test_skip_block_announcement(block) {
                return;
            }

            for (observer_id, filtered_events_ids) in dispatch_matrix.iter().enumerate() {
                let filtered_events: Vec<_> = filtered_events_ids
                    .iter()
                    .map(|event_id| (*event_id, &events[*event_id]))
                    .collect();

                let payload = make_new_block_processed_payload(
                    filtered_events,
                    block,
                    metadata,
                    receipts,
                    parent_index_hash,
                    &winner_txid,
                    &mature_rewards,
                    parent_burn_block_hash,
                    parent_burn_block_height,
                    parent_burn_block_timestamp,
                    anchored_consumed,
                    mblock_confirmed_consumed,
                    pox_constants,
                    reward_set_data,
                    signer_bitvec,
                    block_timestamp,
                    coinbase_height,
                );

                // Send payload
                self.dispatch_to_observer_or_log_error(
                    &self.registered_observers[observer_id],
                    &payload,
                    PATH_BLOCK_PROCESSED,
                );
            }
        }
    }

    /// Creates a list of observers that are interested in the new microblocks event,
    /// creates a mapping from observers to the event ids that are relevant to each, and then
    /// sends the event to each interested observer.
    pub fn process_new_microblocks(
        &self,
        parent_index_block_hash: &StacksBlockId,
        processed_unconfirmed_state: &ProcessedUnconfirmedState,
    ) {
        // lazily assemble payload only if we have observers
        let interested_observers: Vec<_> = self
            .registered_observers
            .iter()
            .enumerate()
            .filter(|(obs_id, _observer)| {
                self.microblock_observers_lookup
                    .contains(&(u16::try_from(*obs_id).expect("FATAL: more than 2^16 observers")))
                    || self.any_event_observers_lookup.contains(
                        &(u16::try_from(*obs_id).expect("FATAL: more than 2^16 observers")),
                    )
            })
            .collect();
        if interested_observers.is_empty() {
            return;
        }
        let flattened_receipts: Vec<_> = processed_unconfirmed_state
            .receipts
            .iter()
            .flat_map(|(_, _, r)| r.clone())
            .collect();
        let (dispatch_matrix, events) =
            self.create_dispatch_matrix_and_event_vector(&flattened_receipts);

        // Serialize receipts
        let mut tx_index;
        let mut serialized_txs = Vec::new();

        for (_, _, receipts) in processed_unconfirmed_state.receipts.iter() {
            tx_index = 0;
            for receipt in receipts.iter() {
                let payload = make_new_block_txs_payload(receipt, tx_index);
                serialized_txs.push(payload);
                tx_index += 1;
            }
        }

        for (obs_id, observer) in interested_observers.iter() {
            let filtered_events_ids = &dispatch_matrix[*obs_id];
            let filtered_events: Vec<_> = filtered_events_ids
                .iter()
                .map(|event_id| (*event_id, &events[*event_id]))
                .collect();

            self.send_new_microblocks(
                observer,
                &parent_index_block_hash,
                &filtered_events,
                &serialized_txs,
                &processed_unconfirmed_state.burn_block_hash,
                processed_unconfirmed_state.burn_block_height,
                processed_unconfirmed_state.burn_block_timestamp,
            );
        }
    }

    fn filter_observers(&self, lookup: &HashSet<u16>, include_any: bool) -> Vec<&EventObserver> {
        self.registered_observers
            .iter()
            .enumerate()
            .filter_map(|(obs_id, observer)| {
                let lookup_ix = u16::try_from(obs_id).expect("FATAL: more than 2^16 observers");
                if lookup.contains(&lookup_ix)
                    || (include_any && self.any_event_observers_lookup.contains(&lookup_ix))
                {
                    Some(observer)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn process_new_mempool_txs(&self, txs: Vec<StacksTransaction>) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.mempool_observers_lookup, true);

        if interested_observers.is_empty() {
            return;
        }

        let payload = make_new_mempool_txs_payload(txs);

        for observer in interested_observers.iter() {
            self.send_new_mempool_txs(observer, &payload);
        }
    }

    pub fn process_mined_block_event(
        &self,
        target_burn_height: u64,
        block: &StacksBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        confirmed_microblock_cost: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        let interested_observers = self.filter_observers(&self.miner_observers_lookup, false);

        if interested_observers.is_empty() {
            return;
        }

        let payload = serde_json::to_value(MinedBlockEvent {
            target_burn_height,
            block_hash: block.block_hash().to_string(),
            stacks_height: block.header.total_work.work,
            block_size: block_size_bytes,
            anchored_cost: consumed.clone(),
            confirmed_microblocks_cost: confirmed_microblock_cost.clone(),
            tx_events,
        })
        .unwrap();

        for observer in interested_observers.iter() {
            self.send_mined_block(observer, &payload);
        }
    }

    pub fn process_mined_microblock_event(
        &self,
        microblock: &StacksMicroblock,
        tx_events: Vec<TransactionEvent>,
        anchor_block_consensus_hash: ConsensusHash,
        anchor_block: BlockHeaderHash,
    ) {
        let interested_observers =
            self.filter_observers(&self.mined_microblocks_observers_lookup, false);
        if interested_observers.is_empty() {
            return;
        }

        let payload = serde_json::to_value(MinedMicroblockEvent {
            block_hash: microblock.block_hash().to_string(),
            sequence: microblock.header.sequence,
            tx_events,
            anchor_block_consensus_hash,
            anchor_block,
        })
        .unwrap();

        for observer in interested_observers.iter() {
            self.send_mined_microblock(observer, &payload);
        }
    }

    pub fn process_mined_nakamoto_block_event(
        &self,
        target_burn_height: u64,
        block: &NakamotoBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        let interested_observers = self.filter_observers(&self.miner_observers_lookup, false);
        if interested_observers.is_empty() {
            return;
        }

        let signer_bitvec = serde_json::to_value(block.header.pox_treatment.clone())
            .unwrap_or_default()
            .as_str()
            .unwrap_or_default()
            .to_string();

        let payload = serde_json::to_value(MinedNakamotoBlockEvent {
            target_burn_height,
            parent_block_id: block.header.parent_block_id.to_string(),
            block_hash: block.header.block_hash().to_string(),
            block_id: block.header.block_id().to_string(),
            stacks_height: block.header.chain_length,
            block_size: block_size_bytes,
            cost: consumed.clone(),
            tx_events,
            miner_signature: block.header.miner_signature.clone(),
            miner_signature_hash: block.header.miner_signature_hash(),
            signer_signature_hash: block.header.signer_signature_hash(),
            signer_signature: block.header.signer_signature.clone(),
            signer_bitvec,
        })
        .unwrap();

        for observer in interested_observers.iter() {
            self.send_mined_nakamoto_block(observer, &payload);
        }
    }

    /// Forward newly-accepted StackerDB chunk metadata to downstream `stackerdb` observers.
    /// Infallible.
    pub fn process_new_stackerdb_chunks(
        &self,
        contract_id: QualifiedContractIdentifier,
        modified_slots: Vec<StackerDBChunkData>,
    ) {
        debug!(
            "event_dispatcher: New StackerDB chunk events for {contract_id}: {modified_slots:?}"
        );

        let interested_observers = self.filter_observers(&self.stackerdb_observers_lookup, false);

        let stackerdb_channel = self
            .stackerdb_channel
            .lock()
            .expect("FATAL: failed to lock StackerDB channel mutex");
        let interested_receiver = stackerdb_channel.is_active(&contract_id);
        if interested_observers.is_empty() && interested_receiver.is_none() {
            return;
        }

        let event = StackerDBChunksEvent {
            contract_id,
            modified_slots,
        };
        let payload = serde_json::to_value(&event)
            .expect("FATAL: failed to serialize StackerDBChunksEvent to JSON");

        if let Some(channel) = interested_receiver {
            if let Err(send_err) = channel.send(event) {
                warn!(
                    "Failed to send StackerDB event to signer coordinator channel. Miner thread may have exited.";
                    "err" => ?send_err
                );
            }
        }

        for observer in interested_observers.iter() {
            self.send_stackerdb_chunks(observer, &payload);
        }
    }

    pub fn process_dropped_mempool_txs(
        &self,
        txs: Vec<Txid>,
        new_txid: Option<Txid>,
        reason: MemPoolDropReason,
    ) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.mempool_observers_lookup, true);

        if interested_observers.is_empty() {
            return;
        }

        let dropped_txids: Vec<_> = txs
            .into_iter()
            .map(|tx| serde_json::Value::String(format!("0x{tx}")))
            .collect();

        let payload = match new_txid {
            Some(id) => {
                json!({
                    "dropped_txids": serde_json::Value::Array(dropped_txids),
                    "reason": reason.to_string(),
                    "new_txid": format!("0x{}", &id),
                })
            }
            None => {
                json!({
                    "dropped_txids": serde_json::Value::Array(dropped_txids),
                    "reason": reason.to_string(),
                    "new_txid": null,
                })
            }
        };

        for observer in interested_observers.iter() {
            self.send_dropped_mempool_txs(observer, &payload);
        }
    }

    pub fn process_new_attachments(&self, attachments: &[(AttachmentInstance, Attachment)]) {
        let interested_observers: Vec<_> = self.registered_observers.iter().enumerate().collect();
        if interested_observers.is_empty() {
            return;
        }

        let mut serialized_attachments = vec![];
        for attachment in attachments.iter() {
            let payload = make_new_attachment_payload(attachment);
            serialized_attachments.push(payload);
        }

        for (_, observer) in interested_observers.iter() {
            self.send_new_attachments(observer, &json!(serialized_attachments));
        }
    }

    fn update_dispatch_matrix_if_observer_subscribed(
        &self,
        asset_identifier: &AssetIdentifier,
        event_index: usize,
        dispatch_matrix: &mut [HashSet<usize>],
    ) {
        if let Some(observer_indexes) = self.assets_observers_lookup.get(asset_identifier) {
            for o_i in observer_indexes {
                dispatch_matrix[*o_i as usize].insert(event_index);
            }
        }
    }

    pub fn register_observer(&mut self, conf: &EventObserverConfig) {
        self.register_observer_private(conf);
    }

    fn register_observer_private(&mut self, conf: &EventObserverConfig) -> EventObserver {
        info!("Registering event observer at: {}", conf.endpoint);
        let event_observer = EventObserver::new(
            conf.endpoint.clone(),
            Duration::from_millis(conf.timeout_ms),
            conf.disable_retries,
        );

        if conf.disable_retries {
            warn!(
                "Observer {} is configured in \"disable_retries\" mode: events are not guaranteed to be delivered",
                conf.endpoint
            );
        }

        let observer_index = self.registered_observers.len() as u16;

        for event_key_type in conf.events_keys.iter() {
            match event_key_type {
                EventKeyType::SmartContractEvent(event_key) => {
                    match self
                        .contract_events_observers_lookup
                        .entry(event_key.clone())
                    {
                        Entry::Occupied(observer_indexes) => {
                            observer_indexes.into_mut().insert(observer_index);
                        }
                        Entry::Vacant(v) => {
                            let mut observer_indexes = HashSet::new();
                            observer_indexes.insert(observer_index);
                            v.insert(observer_indexes);
                        }
                    };
                }
                EventKeyType::BurnchainBlocks => {
                    self.burn_block_observers_lookup.insert(observer_index);
                }
                EventKeyType::MemPoolTransactions => {
                    self.mempool_observers_lookup.insert(observer_index);
                }
                EventKeyType::Microblocks => {
                    self.microblock_observers_lookup.insert(observer_index);
                }
                EventKeyType::STXEvent => {
                    self.stx_observers_lookup.insert(observer_index);
                }
                EventKeyType::AssetEvent(event_key) => {
                    match self.assets_observers_lookup.entry(event_key.clone()) {
                        Entry::Occupied(observer_indexes) => {
                            observer_indexes.into_mut().insert(observer_index);
                        }
                        Entry::Vacant(v) => {
                            let mut observer_indexes = HashSet::new();
                            observer_indexes.insert(observer_index);
                            v.insert(observer_indexes);
                        }
                    };
                }
                EventKeyType::AnyEvent => {
                    self.any_event_observers_lookup.insert(observer_index);
                }
                EventKeyType::MinedBlocks => {
                    self.miner_observers_lookup.insert(observer_index);
                }
                EventKeyType::MinedMicroblocks => {
                    self.mined_microblocks_observers_lookup
                        .insert(observer_index);
                }
                EventKeyType::StackerDBChunks => {
                    self.stackerdb_observers_lookup.insert(observer_index);
                }
                EventKeyType::BlockProposal => {
                    self.block_proposal_observers_lookup.insert(observer_index);
                }
            }
        }

        self.registered_observers.push(event_observer.clone());

        event_observer
    }

    /// Process any pending payloads in the database. This is meant to be called at startup, in order to
    /// handle anything that was enqueued but not sent before shutdown. This method blocks until all
    /// requests are made (or, if the observer is no longer registered, removed from the DB).
    pub fn process_pending_payloads(&self) {
        let conn =
            EventDispatcherDbConnection::new(&self.db_path).expect("Failed to initialize database");
        let pending_payloads = match conn.get_pending_payloads() {
            Ok(payloads) => payloads,
            Err(e) => {
                error!(
                    "Event observer: failed to retrieve pending payloads from database";
                    "error" => ?e
                );
                return;
            }
        };

        info!(
            "Event dispatcher: processing {} pending payloads",
            pending_payloads.len()
        );

        for PendingPayload {
            id, request_data, ..
        } in pending_payloads
        {
            info!(
                "Event dispatcher: processing pending payload: {}",
                request_data.url
            );
            let full_url = Url::parse(request_data.url.as_str()).unwrap_or_else(|_| {
                panic!(
                    "Event dispatcher: unable to parse {} as a URL",
                    request_data.url
                )
            });
            // find the right observer
            let observer = self.registered_observers.iter().find(|observer| {
                let endpoint_url = Url::parse(format!("http://{}", &observer.endpoint).as_str())
                    .unwrap_or_else(|_| {
                        panic!(
                            "Event dispatcher: unable to parse {} as a URL",
                            observer.endpoint
                        )
                    });
                full_url.origin() == endpoint_url.origin()
            });

            let Some(observer) = observer else {
                // This observer is no longer registered, skip and delete
                info!(
                    "Event dispatcher: observer {} no longer registered, skipping",
                    request_data.url
                );
                if let Err(e) = conn.delete_payload(id) {
                    error!(
                        "Event observer: failed to delete pending payload from database";
                        "error" => ?e
                    );
                }
                continue;
            };

            // If the timeout configuration for this observer is different from what it was
            // originally, the updated config wins.
            self.worker
                .initiate_send(id, observer.disable_retries, Some(observer.timeout))
                .expect("failed to dispatch pending event payload to worker thread")
                .wait_until_complete();
        }
    }

    /// A successful result from this method only indicates that that payload was successfully
    /// enqueued, not that the HTTP request was actually made. If you need to wait until that's
    /// the case, call `wait_until_complete()` on the `EventDispatcherResult`.
    fn dispatch_to_observer(
        &self,
        event_observer: &EventObserver,
        payload: &serde_json::Value,
        path: &str,
    ) -> Result<EventDispatcherResult, EventDispatcherError> {
        let full_url = Self::get_full_url(event_observer, path);
        let bytes = match Self::get_payload_bytes(payload) {
            Ok(bytes) => bytes,
            Err(err) => {
                error!(
                    "Event dispatcher: failed to serialize payload"; "path" => path, "error" => ?err
                );
                return Err(err);
            }
        };

        let data = EventRequestData {
            payload_bytes: bytes,
            url: full_url,
            timeout: event_observer.timeout,
        };

        let id = self.save_to_db(&data);

        self.worker
            .initiate_send(id, event_observer.disable_retries, None)
    }

    /// This fire-and-forget version of `dispatch_to_observer` logs any error from enqueueing the
    /// request, and does not give you a way to wait for blocking until it's sent. If you need
    /// more control, use `dispatch_to_observer()` directly and handle the result yourself.
    ///
    /// This method exists because we generally don't want the event dispatcher to interrupt the node's
    /// processing.
    fn dispatch_to_observer_or_log_error(
        &self,
        event_observer: &EventObserver,
        payload: &serde_json::Value,
        path: &str,
    ) {
        if let Err(err) = self.dispatch_to_observer(event_observer, payload, path) {
            error!("Event dispatcher: Failed to enqueue payload for sending to observer: {err:?}");
        }
    }

    fn get_payload_bytes(payload: &serde_json::Value) -> Result<Arc<[u8]>, EventDispatcherError> {
        let payload_bytes = serde_json::to_vec(payload)?;
        Ok(Arc::<[u8]>::from(payload_bytes))
    }

    fn get_full_url(event_observer: &EventObserver, path: &str) -> String {
        let url_str = if path.starts_with('/') {
            format!("{}{path}", &event_observer.endpoint)
        } else {
            format!("{}/{path}", &event_observer.endpoint)
        };
        format!("http://{url_str}")
    }

    fn save_to_db(&self, data: &EventRequestData) -> i64 {
        // Because the DB is initialized in the call to process_pending_payloads() during startup,
        // it is *probably* ok to skip initialization here. That said, at the time of writing this is the
        // only call to new_without_init(), and we might want to revisit the question whether it's
        // really worth it.
        let conn = EventDispatcherDbConnection::new_without_init(&self.db_path)
            .expect("Failed to open database for event observer");

        conn.insert_payload_with_retry(data, SystemTime::now())
    }

    fn send_new_attachments(&self, event_observer: &EventObserver, payload: &serde_json::Value) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_ATTACHMENT_PROCESSED);
    }

    fn send_new_mempool_txs(&self, event_observer: &EventObserver, payload: &serde_json::Value) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_MEMPOOL_TX_SUBMIT);
    }

    /// Serializes new microblocks data into a JSON payload and sends it off to the correct path
    fn send_new_microblocks(
        &self,
        event_observer: &EventObserver,
        parent_index_block_hash: &StacksBlockId,
        filtered_events: &[(usize, &(bool, Txid, &StacksTransactionEvent))],
        serialized_txs: &[TransactionEventPayload],
        burn_block_hash: &BurnchainHeaderHash,
        burn_block_height: u32,
        burn_block_timestamp: u64,
    ) {
        // Serialize events to JSON
        let serialized_events: Vec<serde_json::Value> = filtered_events
            .iter()
            .map(|(event_index, (committed, txid, event))| {
                event
                    .json_serialize(*event_index, txid, *committed)
                    .unwrap()
            })
            .collect();

        let payload = json!({
            "parent_index_block_hash": format!("0x{parent_index_block_hash}"),
            "events": serialized_events,
            "transactions": serialized_txs,
            "burn_block_hash": format!("0x{burn_block_hash}"),
            "burn_block_height": burn_block_height,
            "burn_block_timestamp": burn_block_timestamp,
        });

        self.dispatch_to_observer_or_log_error(event_observer, &payload, PATH_MICROBLOCK_SUBMIT);
    }

    fn send_dropped_mempool_txs(
        &self,
        event_observer: &EventObserver,
        payload: &serde_json::Value,
    ) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_MEMPOOL_TX_DROP);
    }

    fn send_mined_block(&self, event_observer: &EventObserver, payload: &serde_json::Value) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_MINED_BLOCK);
    }

    fn send_mined_microblock(&self, event_observer: &EventObserver, payload: &serde_json::Value) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_MINED_MICROBLOCK);
    }

    fn send_mined_nakamoto_block(
        &self,
        event_observer: &EventObserver,
        payload: &serde_json::Value,
    ) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_MINED_NAKAMOTO_BLOCK);
    }

    fn send_stackerdb_chunks(&self, event_observer: &EventObserver, payload: &serde_json::Value) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_STACKERDB_CHUNKS);
    }

    fn send_new_burn_block(&self, event_observer: &EventObserver, payload: &serde_json::Value) {
        self.dispatch_to_observer_or_log_error(event_observer, payload, PATH_BURN_BLOCK_SUBMIT);
    }
}

#[cfg(any(test, feature = "testing"))]
fn test_skip_block_announcement(block: &StacksBlockEventData) -> bool {
    if TEST_SKIP_BLOCK_ANNOUNCEMENT.get() {
        warn!(
            "Skipping new block announcement due to testing directive";
            "block_hash" => %block.block_hash
        );
        return true;
    }
    false
}
