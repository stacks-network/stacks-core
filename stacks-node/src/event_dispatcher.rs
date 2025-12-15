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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::mpsc::channel;
#[cfg(test)]
use std::sync::LazyLock;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::{FTEventType, NFTEventType, STXEventType};
use clarity::vm::types::{AssetIdentifier, QualifiedContractIdentifier};
#[cfg(any(test, feature = "testing"))]
use lazy_static::lazy_static;
use rand::Rng;
use rusqlite::{params, Connection};
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
use stacks::net::http::HttpRequestContents;
use stacks::net::httpcore::{send_http_request, StacksHttpRequest};
use stacks::net::stackerdb::StackerDBEventDispatcher;
#[cfg(any(test, feature = "testing"))]
use stacks::util::tests::TestFlag;
use stacks::util_lib::db::Error as db_error;
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
use stacks_common::types::net::PeerHost;
use url::Url;

mod payloads;
mod stacker_db;

use payloads::*;
pub use payloads::{
    MinedBlockEvent, MinedMicroblockEvent, MinedNakamotoBlockEvent, NakamotoSignerEntryPayload,
    RewardSetEventPayload, TransactionEventPayload,
};
pub use stacker_db::StackerDBChannel;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "testing"))]
lazy_static! {
    /// Do not announce a signed/mined block to the network when set to true.
    pub static ref TEST_SKIP_BLOCK_ANNOUNCEMENT: TestFlag<bool> = TestFlag::default();
}

#[derive(Debug, Clone)]
struct EventObserver {
    /// Path to the database where pending payloads are stored. If `None`, then
    /// the database is not used and events are not recoverable across restarts.
    db_path: Option<PathBuf>,
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
    fn new(
        db_path: Option<PathBuf>,
        endpoint: String,
        timeout: Duration,
        disable_retries: bool,
    ) -> Self {
        EventObserver {
            db_path,
            endpoint,
            timeout,
            disable_retries,
        }
    }
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
    /// Database path for pending payloads
    db_path: Option<PathBuf>,
}

/// This struct is used specifically for receiving proposal responses.
/// It's constructed separately to play nicely with threading.
struct ProposalCallbackHandler {
    observers: Vec<EventObserver>,
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
            EventDispatcher::send_payload(observer, &response, PATH_PROPOSAL_RESPONSE, None);
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

impl Default for EventDispatcher {
    fn default() -> Self {
        EventDispatcher::new(None)
    }
}

impl EventDispatcher {
    pub fn new(working_dir: Option<PathBuf>) -> EventDispatcher {
        let db_path = if let Some(mut db_path) = working_dir {
            db_path.push("event_observers.sqlite");
            Some(db_path)
        } else {
            None
        };
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
        }
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
            EventDispatcher::send_new_burn_block(&observer, &payload);
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
                EventDispatcher::send_payload(
                    &self.registered_observers[observer_id],
                    &payload,
                    PATH_BLOCK_PROCESSED,
                    None,
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

            EventDispatcher::send_new_microblocks(
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
            EventDispatcher::send_new_mempool_txs(observer, &payload);
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
            EventDispatcher::send_mined_block(observer, &payload);
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
            EventDispatcher::send_mined_microblock(observer, &payload);
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
            EventDispatcher::send_mined_nakamoto_block(observer, &payload);
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
            EventDispatcher::send_stackerdb_chunks(observer, &payload);
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
            EventDispatcher::send_dropped_mempool_txs(observer, &payload);
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
            EventDispatcher::send_new_attachments(observer, &json!(serialized_attachments));
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
            self.db_path.clone(),
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

    fn init_db(db_path: &PathBuf) -> Result<Connection, db_error> {
        let mut conn = Connection::open(db_path.to_str().unwrap())?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload BLOB NOT NULL,
                timeout INTEGER NOT NULL
            )",
            [],
        )?;
        if let Some(col_type) = EventDispatcher::get_payload_column_type(&conn)? {
            if col_type.eq_ignore_ascii_case("TEXT") {
                info!("Event observer: migrating pending_payloads.payload from TEXT to BLOB");
                EventDispatcher::migrate_payload_column_to_blob(&mut conn)?;
            }
        }
        Ok(conn)
    }

    fn get_pending_payloads(
        conn: &Connection,
    ) -> Result<Vec<(i64, String, Arc<[u8]>, u64)>, db_error> {
        let mut stmt =
            conn.prepare("SELECT id, url, payload, timeout FROM pending_payloads ORDER BY id")?;
        let payload_iter = stmt.query_and_then(
            [],
            |row| -> Result<(i64, String, Arc<[u8]>, u64), db_error> {
                let id: i64 = row.get(0)?;
                let url: String = row.get(1)?;
                let payload_bytes: Vec<u8> = row.get(2)?;
                let payload_bytes = Arc::<[u8]>::from(payload_bytes);
                let timeout_ms: u64 = row.get(3)?;
                Ok((id, url, payload_bytes, timeout_ms))
            },
        )?;
        payload_iter.collect()
    }

    fn delete_payload(conn: &Connection, id: i64) -> Result<(), db_error> {
        conn.execute("DELETE FROM pending_payloads WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Process any pending payloads in the database.
    /// This is called when the event dispatcher is first instantiated.
    pub fn process_pending_payloads(&self) {
        let Some(db_path) = &self.db_path else {
            return;
        };
        let conn = EventDispatcher::init_db(db_path).expect("Failed to initialize database");
        let pending_payloads = match Self::get_pending_payloads(&conn) {
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

        for (id, url, payload_bytes, _timeout_ms) in pending_payloads {
            info!("Event dispatcher: processing pending payload: {url}");
            let full_url = Url::parse(url.as_str())
                .unwrap_or_else(|_| panic!("Event dispatcher: unable to parse {url} as a URL"));
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
                    url
                );
                if let Err(e) = Self::delete_payload(&conn, id) {
                    error!(
                        "Event observer: failed to delete pending payload from database";
                        "error" => ?e
                    );
                }
                continue;
            };

            EventDispatcher::send_payload_with_bytes(
                observer,
                payload_bytes,
                full_url.path(),
                Some(id),
            );

            #[cfg(test)]
            if TEST_EVENT_OBSERVER_SKIP_RETRY.get() {
                warn!("Fault injection: delete_payload");
                return;
            }

            if let Err(e) = Self::delete_payload(&conn, id) {
                error!(
                    "Event observer: failed to delete pending payload from database";
                    "error" => ?e
                );
            }
        }
    }

    fn get_payload_column_type(conn: &Connection) -> Result<Option<String>, db_error> {
        let mut stmt = conn.prepare("PRAGMA table_info(pending_payloads)")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            let col_type: String = row.get(2)?;
            Ok((name, col_type))
        })?;

        for row in rows {
            let (name, col_type) = row?;
            if name == "payload" {
                return Ok(Some(col_type));
            }
        }

        Ok(None)
    }

    fn migrate_payload_column_to_blob(conn: &mut Connection) -> Result<(), db_error> {
        let tx = conn.transaction()?;
        tx.execute(
            "ALTER TABLE pending_payloads RENAME TO pending_payloads_old",
            [],
        )?;
        tx.execute(
            "CREATE TABLE pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload BLOB NOT NULL,
                timeout INTEGER NOT NULL
            )",
            [],
        )?;
        tx.execute(
            "INSERT INTO pending_payloads (id, url, payload, timeout)
                SELECT id, url, CAST(payload AS BLOB), timeout FROM pending_payloads_old",
            [],
        )?;
        tx.execute("DROP TABLE pending_payloads_old", [])?;
        tx.commit()?;
        Ok(())
    }

    fn insert_payload(
        conn: &Connection,
        url: &str,
        payload_bytes: &[u8],
        timeout: Duration,
    ) -> Result<(), db_error> {
        let timeout_ms: u64 = timeout.as_millis().try_into().expect("Timeout too large");
        conn.execute(
            "INSERT INTO pending_payloads (url, payload, timeout) VALUES (?1, ?2, ?3)",
            params![url, payload_bytes, timeout_ms],
        )?;
        Ok(())
    }

    /// Insert a payload into the database, retrying on failure.
    fn insert_payload_with_retry(
        conn: &Connection,
        url: &str,
        payload_bytes: &[u8],
        timeout: Duration,
    ) {
        let mut attempts = 0i64;
        let mut backoff = Duration::from_millis(100); // Initial backoff duration
        let max_backoff = Duration::from_secs(5); // Cap the backoff duration

        loop {
            match Self::insert_payload(conn, url, payload_bytes, timeout) {
                Ok(_) => {
                    // Successful insert, break the loop
                    return;
                }
                Err(err) => {
                    // Log the error, then retry after a delay
                    warn!("Failed to insert payload into event observer database: {err:?}";
                        "backoff" => ?backoff,
                        "attempts" => attempts
                    );

                    // Wait for the backoff duration
                    sleep(backoff);

                    // Increase the backoff duration (with exponential backoff)
                    backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);

                    attempts = attempts.saturating_add(1);
                }
            }
        }
    }

    fn send_payload_directly(
        payload_bytes: &Arc<[u8]>,
        full_url: &str,
        timeout: Duration,
        disable_retries: bool,
    ) -> bool {
        debug!(
            "Event dispatcher: Sending payload"; "url" => %full_url, "bytes" => payload_bytes.len()
        );

        let url = Url::parse(full_url)
            .unwrap_or_else(|_| panic!("Event dispatcher: unable to parse {full_url} as a URL"));

        let host = url.host_str().expect("Invalid URL: missing host");
        let port = url.port_or_known_default().unwrap_or(80);
        let peerhost: PeerHost = format!("{host}:{port}")
            .parse()
            .unwrap_or(PeerHost::DNS(host.to_string(), port));

        let mut backoff = Duration::from_millis(100);
        let mut attempts: i32 = 0;
        // Cap the backoff at 3x the timeout
        let max_backoff = timeout.saturating_mul(3);

        loop {
            let mut request = StacksHttpRequest::new_for_peer(
                peerhost.clone(),
                "POST".into(),
                url.path().into(),
                HttpRequestContents::new().payload_json_bytes(Arc::clone(payload_bytes)),
            )
            .unwrap_or_else(|_| panic!("FATAL: failed to encode infallible data as HTTP request"));
            request.add_header("Connection".into(), "close".into());
            match send_http_request(host, port, request, timeout) {
                Ok(response) => {
                    if response.preamble().status_code == 200 {
                        debug!(
                            "Event dispatcher: Successful POST"; "url" => %url
                        );
                        break;
                    } else {
                        error!(
                            "Event dispatcher: Failed POST"; "url" => %url, "response" => ?response.preamble()
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        "Event dispatcher: connection or request failed to {host}:{port} - {err:?}";
                        "backoff" => ?backoff,
                        "attempts" => attempts
                    );
                }
            }

            if disable_retries {
                warn!("Observer is configured in disable_retries mode: skipping retry of payload");
                return false;
            }

            #[cfg(test)]
            if TEST_EVENT_OBSERVER_SKIP_RETRY.get() {
                warn!("Fault injection: skipping retry of payload");
                return false;
            }

            sleep(backoff);
            let jitter: u64 = rand::thread_rng().gen_range(0..100);
            backoff = std::cmp::min(
                backoff.saturating_mul(2) + Duration::from_millis(jitter),
                max_backoff,
            );
            attempts = attempts.saturating_add(1);
        }
        true
    }

    /// Send the payload to the given URL.
    /// Before sending this payload, any pending payloads in the database will be sent first.
    fn send_payload(
        event_observer: &EventObserver,
        payload: &serde_json::Value,
        path: &str,
        id: Option<i64>,
    ) {
        let payload_bytes = match serde_json::to_vec(payload) {
            Ok(bytes) => Arc::<[u8]>::from(bytes),
            Err(err) => {
                error!(
                    "Event dispatcher: failed to serialize payload"; "path" => path, "error" => ?err
                );
                return;
            }
        };
        EventDispatcher::send_payload_with_bytes(event_observer, payload_bytes, path, id);
    }

    fn send_payload_with_bytes(
        event_observer: &EventObserver,
        payload_bytes: Arc<[u8]>,
        path: &str,
        id: Option<i64>,
    ) {
        // Construct the full URL
        let url_str = if path.starts_with('/') {
            format!("{}{path}", &event_observer.endpoint)
        } else {
            format!("{}/{path}", &event_observer.endpoint)
        };
        let full_url = format!("http://{url_str}");

        // if the observer is in "disable_retries" mode quickly send the payload without checking for the db
        if event_observer.disable_retries {
            Self::send_payload_directly(&payload_bytes, &full_url, event_observer.timeout, true);
        } else if let Some(db_path) = &event_observer.db_path {
            let conn =
                Connection::open(db_path).expect("Failed to open database for event observer");

            let id = match id {
                Some(id) => id,
                None => {
                    Self::insert_payload_with_retry(
                        &conn,
                        &full_url,
                        payload_bytes.as_ref(),
                        event_observer.timeout,
                    );
                    conn.last_insert_rowid()
                }
            };

            let success = Self::send_payload_directly(
                &payload_bytes,
                &full_url,
                event_observer.timeout,
                false,
            );
            // This is only `false` when the TestFlag is set to skip retries
            if !success {
                return;
            }

            if let Err(e) = Self::delete_payload(&conn, id) {
                error!(
                    "Event observer: failed to delete pending payload from database";
                    "error" => ?e
                );
            }
        } else {
            // No database, just send the payload
            Self::send_payload_directly(&payload_bytes, &full_url, event_observer.timeout, false);
        }
    }

    fn send_new_attachments(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_ATTACHMENT_PROCESSED, None);
    }

    fn send_new_mempool_txs(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_MEMPOOL_TX_SUBMIT, None);
    }

    /// Serializes new microblocks data into a JSON payload and sends it off to the correct path
    fn send_new_microblocks(
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

        Self::send_payload(event_observer, &payload, PATH_MICROBLOCK_SUBMIT, None);
    }

    fn send_dropped_mempool_txs(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_MEMPOOL_TX_DROP, None);
    }

    fn send_mined_block(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_MINED_BLOCK, None);
    }

    fn send_mined_microblock(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_MINED_MICROBLOCK, None);
    }

    fn send_mined_nakamoto_block(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_MINED_NAKAMOTO_BLOCK, None);
    }

    fn send_stackerdb_chunks(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_STACKERDB_CHUNKS, None);
    }

    fn send_new_burn_block(event_observer: &EventObserver, payload: &serde_json::Value) {
        Self::send_payload(event_observer, payload, PATH_BURN_BLOCK_SUBMIT, None);
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
