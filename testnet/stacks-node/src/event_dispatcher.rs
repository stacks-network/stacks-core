use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::Duration;

use async_h1::client;
use async_std::net::TcpStream;
use clarity::vm::analysis::contract_interface_builder::build_contract_interface;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::{FTEventType, NFTEventType, STXEventType};
use clarity::vm::types::{AssetIdentifier, QualifiedContractIdentifier, Value};
use http_types::{Method, Request, Url};
use serde_json::json;
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::coordinator::BlockEventDispatcher;
use stacks::chainstate::nakamoto::NakamotoBlock;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::boot::{
    NakamotoSignerEntry, PoxStartCycleInfo, RewardSet, RewardSetData, SIGNERS_NAME,
};
use stacks::chainstate::stacks::db::accounts::MinerReward;
use stacks::chainstate::stacks::db::unconfirmed::ProcessedUnconfirmedState;
use stacks::chainstate::stacks::db::{MinerRewardInfo, StacksBlockHeaderTypes, StacksHeaderInfo};
use stacks::chainstate::stacks::events::{
    StackerDBChunksEvent, StacksBlockEventData, StacksTransactionEvent, StacksTransactionReceipt,
    TransactionOrigin,
};
use stacks::chainstate::stacks::miner::TransactionEvent;
use stacks::chainstate::stacks::{
    StacksBlock, StacksMicroblock, StacksTransaction, TransactionPayload,
};
use stacks::core::mempool::{MemPoolDropReason, MemPoolEventDispatcher, ProposalCallbackReceiver};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::api::postblock_proposal::{
    BlockValidateOk, BlockValidateReject, BlockValidateResponse,
};
use stacks::net::atlas::{Attachment, AttachmentInstance};
use stacks::net::stackerdb::StackerDBEventDispatcher;
use stacks::util::hash::to_hex;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
use stacks_common::util::hash::{bytes_to_hex, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;

use super::config::{EventKeyType, EventObserverConfig};

#[derive(Debug, Clone)]
struct EventObserver {
    endpoint: String,
}

struct ReceiptPayloadInfo<'a> {
    txid: String,
    success: &'a str,
    raw_result: String,
    raw_tx: String,
    contract_interface_json: serde_json::Value,
    burnchain_op_json: serde_json::Value,
}

const STATUS_RESP_TRUE: &str = "success";
const STATUS_RESP_NOT_COMMITTED: &str = "abort_by_response";
const STATUS_RESP_POST_CONDITION: &str = "abort_by_post_condition";

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

pub static STACKER_DB_CHANNEL: StackerDBChannel = StackerDBChannel::new();

/// This struct receives StackerDB event callbacks without registering
/// over the JSON/RPC interface. To ensure that any event observer
/// uses the same channel, we use a lazy_static global for the channel (this
/// implements a singleton using STACKER_DB_CHANNEL).
///
/// This is in place because a Nakamoto miner needs to receive
/// StackerDB events. It could either poll the database (seems like a
/// bad idea) or listen for events. Registering for RPC callbacks
/// seems bad. So instead, it uses a singleton sync channel.
pub struct StackerDBChannel {
    sender_info: Mutex<Option<InnerStackerDBChannel>>,
}

#[derive(Clone)]
struct InnerStackerDBChannel {
    /// A channel for sending the chunk events to the listener
    sender: Sender<StackerDBChunksEvent>,
    /// Does the listener want to receive `.signers` chunks?
    interested_in_signers: bool,
    /// Which StackerDB contracts is the listener interested in?
    other_interests: Vec<QualifiedContractIdentifier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinedBlockEvent {
    pub target_burn_height: u64,
    pub block_hash: String,
    pub stacks_height: u64,
    pub block_size: u64,
    pub anchored_cost: ExecutionCost,
    pub confirmed_microblocks_cost: ExecutionCost,
    pub tx_events: Vec<TransactionEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinedMicroblockEvent {
    pub block_hash: String,
    pub sequence: u16,
    pub tx_events: Vec<TransactionEvent>,
    pub anchor_block_consensus_hash: ConsensusHash,
    pub anchor_block: BlockHeaderHash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinedNakamotoBlockEvent {
    pub target_burn_height: u64,
    pub parent_block_id: String,
    pub block_hash: String,
    pub block_id: String,
    pub stacks_height: u64,
    pub block_size: u64,
    pub cost: ExecutionCost,
    pub miner_signature: MessageSignature,
    pub signer_signature_hash: Sha512Trunc256Sum,
    pub tx_events: Vec<TransactionEvent>,
    pub signer_bitvec: String,
}

impl InnerStackerDBChannel {
    pub fn new_miner_receiver() -> (Receiver<StackerDBChunksEvent>, Self) {
        let (sender, recv) = channel();
        let sender_info = Self {
            sender,
            interested_in_signers: true,
            other_interests: vec![],
        };

        (recv, sender_info)
    }
}

impl StackerDBChannel {
    pub const fn new() -> Self {
        Self {
            sender_info: Mutex::new(None),
        }
    }

    /// Consume the receiver for the StackerDBChannel and drop the senders. This should be done
    /// before another interested thread can subscribe to events, but it is not absolutely necessary
    /// to do so (it would just result in temporary over-use of memory while the prior channel is still
    /// open).
    ///
    /// The StackerDBChnnel's receiver is guarded with a Mutex, so that ownership can
    /// be taken by different threads without unsafety.
    pub fn replace_receiver(&self, receiver: Receiver<StackerDBChunksEvent>) {
        // not strictly necessary, but do this rather than mark the `receiver` argument as unused
        // so that we're explicit about the fact that `replace_receiver` consumes.
        drop(receiver);
        let mut guard = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        guard.take();
    }

    /// Create a new event receiver channel for receiving events relevant to the miner coordinator,
    /// dropping the old StackerDB event sender channels if they are still registered.
    ///  Returns the new receiver channel and a bool indicating whether or not sender channels were
    ///   still in place.
    ///
    /// The StackerDBChannel senders are guarded by mutexes so that they can be replaced
    /// by different threads without unsafety.
    pub fn register_miner_coordinator(&self) -> (Receiver<StackerDBChunksEvent>, bool) {
        let mut sender_info = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        let (recv, new_sender) = InnerStackerDBChannel::new_miner_receiver();
        let replaced_receiver = sender_info.replace(new_sender).is_some();

        (recv, replaced_receiver)
    }

    /// Is there a thread holding the receiver, and is it interested in chunks events from `stackerdb`?
    /// Returns the a sending channel to broadcast the event to if so, and `None` if not.
    pub fn is_active(
        &self,
        stackerdb: &QualifiedContractIdentifier,
    ) -> Option<Sender<StackerDBChunksEvent>> {
        // if the receiver field is empty (i.e., None), then there is no listening thread, return None
        let guard = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        let sender_info = guard.as_ref()?;
        if sender_info.interested_in_signers
            && stackerdb.is_boot()
            && stackerdb.name.starts_with(SIGNERS_NAME)
        {
            return Some(sender_info.sender.clone());
        }
        if sender_info.other_interests.contains(stackerdb) {
            return Some(sender_info.sender.clone());
        }
        None
    }
}

fn serialize_u128_as_string<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn serialize_pox_addresses<S>(value: &Vec<PoxAddress>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_seq(value.iter().cloned().map(|a| a.to_b58()))
}

fn serialize_optional_u128_as_string<S>(
    value: &Option<u128>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(v) => serializer.serialize_str(&v.to_string()),
        None => serializer.serialize_none(),
    }
}

fn hex_serialize<S: serde::Serializer>(addr: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&to_hex(addr))
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct RewardSetEventPayload {
    #[serde(serialize_with = "serialize_pox_addresses")]
    pub rewarded_addresses: Vec<PoxAddress>,
    pub start_cycle_state: PoxStartCycleInfo,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    // only generated for nakamoto reward sets
    pub signers: Option<Vec<NakamotoSignerEntryPayload>>,
    #[serde(serialize_with = "serialize_optional_u128_as_string")]
    pub pox_ustx_threshold: Option<u128>,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct NakamotoSignerEntryPayload {
    #[serde(serialize_with = "hex_serialize")]
    pub signing_key: [u8; 33],
    #[serde(serialize_with = "serialize_u128_as_string")]
    pub stacked_amt: u128,
    pub weight: u32,
}

impl RewardSetEventPayload {
    pub fn signer_entry_to_payload(entry: &NakamotoSignerEntry) -> NakamotoSignerEntryPayload {
        NakamotoSignerEntryPayload {
            signing_key: entry.signing_key,
            stacked_amt: entry.stacked_amt,
            weight: entry.weight,
        }
    }
    pub fn from_reward_set(reward_set: &RewardSet) -> Self {
        Self {
            rewarded_addresses: reward_set.rewarded_addresses.clone(),
            start_cycle_state: reward_set.start_cycle_state.clone(),
            signers: reward_set
                .signers
                .as_ref()
                .map(|signers| signers.iter().map(Self::signer_entry_to_payload).collect()),
            pox_ustx_threshold: reward_set.pox_ustx_threshold,
        }
    }
}

impl EventObserver {
    pub fn send_payload(&self, payload: &serde_json::Value, path: &str) {
        let body = match serde_json::to_vec(&payload) {
            Ok(body) => body,
            Err(err) => {
                error!("Event dispatcher: serialization failed  - {:?}", err);
                return;
            }
        };

        let url = {
            let joined_components = match path.starts_with('/') {
                true => format!("{}{}", &self.endpoint, path),
                false => format!("{}/{}", &self.endpoint, path),
            };
            let url = format!("http://{}", joined_components);
            Url::parse(&url)
                .unwrap_or_else(|_| panic!("Event dispatcher: unable to parse {} as a URL", url))
        };

        let backoff = Duration::from_millis((1.0 * 1_000.0) as u64);

        loop {
            let body = body.clone();
            let mut req = Request::new(Method::Post, url.clone());
            req.append_header("Content-Type", "application/json");
            req.set_body(body);

            let response = async_std::task::block_on(async {
                let stream = match TcpStream::connect(self.endpoint.clone()).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        warn!("Event dispatcher: connection failed  - {:?}", err);
                        return None;
                    }
                };

                match client::connect(stream, req).await {
                    Ok(response) => Some(response),
                    Err(err) => {
                        warn!("Event dispatcher: rpc invocation failed  - {:?}", err);
                        return None;
                    }
                }
            });

            if let Some(response) = response {
                if response.status().is_success() {
                    debug!(
                        "Event dispatcher: Successful POST"; "url" => %url
                    );
                    break;
                } else {
                    error!(
                        "Event dispatcher: Failed POST"; "url" => %url, "err" => ?response
                    );
                }
            }
            sleep(backoff);
        }
    }

    fn make_new_mempool_txs_payload(transactions: Vec<StacksTransaction>) -> serde_json::Value {
        let raw_txs = transactions
            .into_iter()
            .map(|tx| {
                serde_json::Value::String(format!("0x{}", &bytes_to_hex(&tx.serialize_to_vec())))
            })
            .collect();

        serde_json::Value::Array(raw_txs)
    }

    fn make_new_burn_block_payload(
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        slot_holders: Vec<PoxAddress>,
    ) -> serde_json::Value {
        let reward_recipients = rewards
            .into_iter()
            .map(|(pox_addr, amt)| {
                json!({
                    "recipient": pox_addr.to_b58(),
                    "amt": amt,
                })
            })
            .collect();

        let reward_slot_holders = slot_holders
            .into_iter()
            .map(|pox_addr| json!(pox_addr.to_b58()))
            .collect();

        json!({
            "burn_block_hash": format!("0x{}", burn_block),
            "burn_block_height": burn_block_height,
            "reward_recipients": serde_json::Value::Array(reward_recipients),
            "reward_slot_holders": serde_json::Value::Array(reward_slot_holders),
            "burn_amount": burns
        })
    }

    /// Returns tuple of (txid, success, raw_result, raw_tx, contract_interface_json)
    fn generate_payload_info_for_receipt(receipt: &StacksTransactionReceipt) -> ReceiptPayloadInfo {
        let tx = &receipt.transaction;

        let success = match (receipt.post_condition_aborted, &receipt.result) {
            (false, Value::Response(response_data)) => {
                if response_data.committed {
                    STATUS_RESP_TRUE
                } else {
                    STATUS_RESP_NOT_COMMITTED
                }
            }
            (true, Value::Response(_)) => STATUS_RESP_POST_CONDITION,
            _ => {
                if let TransactionOrigin::Stacks(inner_tx) = &tx {
                    if let TransactionPayload::PoisonMicroblock(..) = &inner_tx.payload {
                        STATUS_RESP_TRUE
                    } else {
                        unreachable!() // Transaction results should otherwise always be a Value::Response type
                    }
                } else {
                    unreachable!() // Transaction results should always be a Value::Response type
                }
            }
        };

        let (txid, raw_tx, burnchain_op_json) = match tx {
            TransactionOrigin::Burn(op) => (
                op.txid().to_string(),
                "00".to_string(),
                BlockstackOperationType::blockstack_op_to_json(&op),
            ),
            TransactionOrigin::Stacks(ref tx) => {
                let txid = tx.txid().to_string();
                let bytes = tx.serialize_to_vec();
                (txid, bytes_to_hex(&bytes), json!(null))
            }
        };

        let raw_result = {
            let bytes = receipt
                .result
                .serialize_to_vec()
                .expect("FATAL: failed to serialize transaction receipt");
            bytes_to_hex(&bytes)
        };
        let contract_interface_json = {
            match &receipt.contract_analysis {
                Some(analysis) => json!(build_contract_interface(analysis)
                    .expect("FATAL: failed to serialize contract publish receipt")),
                None => json!(null),
            }
        };
        ReceiptPayloadInfo {
            txid,
            success,
            raw_result,
            raw_tx,
            contract_interface_json,
            burnchain_op_json,
        }
    }

    /// Returns json payload to send for new block or microblock event
    fn make_new_block_txs_payload(
        receipt: &StacksTransactionReceipt,
        tx_index: u32,
    ) -> serde_json::Value {
        let receipt_payload_info = EventObserver::generate_payload_info_for_receipt(receipt);

        json!({
            "txid": format!("0x{}", &receipt_payload_info.txid),
            "tx_index": tx_index,
            "status": receipt_payload_info.success,
            "raw_result": format!("0x{}", &receipt_payload_info.raw_result),
            "raw_tx": format!("0x{}", &receipt_payload_info.raw_tx),
            "contract_abi": receipt_payload_info.contract_interface_json,
            "burnchain_op": receipt_payload_info.burnchain_op_json,
            "execution_cost": receipt.execution_cost,
            "microblock_sequence": receipt.microblock_header.as_ref().map(|x| x.sequence),
            "microblock_hash": receipt.microblock_header.as_ref().map(|x| format!("0x{}", x.block_hash())),
            "microblock_parent_hash": receipt.microblock_header.as_ref().map(|x| format!("0x{}", x.prev_block)),
        })
    }

    fn make_new_attachment_payload(
        attachment: &(AttachmentInstance, Attachment),
    ) -> serde_json::Value {
        json!({
            "attachment_index": attachment.0.attachment_index,
            "index_block_hash": format!("0x{}", attachment.0.index_block_hash),
            "block_height": attachment.0.stacks_block_height,
            "content_hash": format!("0x{}", attachment.0.content_hash),
            "contract_id": format!("{}", attachment.0.contract_id),
            "metadata": format!("0x{}", attachment.0.metadata),
            "tx_id": format!("0x{}", attachment.0.tx_id),
            "content": format!("0x{}", bytes_to_hex(&attachment.1.content)),
        })
    }

    fn send_new_attachments(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_ATTACHMENT_PROCESSED);
    }

    fn send_new_mempool_txs(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MEMPOOL_TX_SUBMIT);
    }

    /// Serializes new microblocks data into a JSON payload and sends it off to the correct path
    fn send_new_microblocks(
        &self,
        parent_index_block_hash: StacksBlockId,
        filtered_events: Vec<(usize, &(bool, Txid, &StacksTransactionEvent))>,
        serialized_txs: &Vec<serde_json::Value>,
        burn_block_hash: BurnchainHeaderHash,
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
            "parent_index_block_hash": format!("0x{}", parent_index_block_hash),
            "events": serialized_events,
            "transactions": serialized_txs,
            "burn_block_hash": format!("0x{}", burn_block_hash),
            "burn_block_height": burn_block_height,
            "burn_block_timestamp": burn_block_timestamp,
        });

        self.send_payload(&payload, PATH_MICROBLOCK_SUBMIT);
    }

    fn send_dropped_mempool_txs(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MEMPOOL_TX_DROP);
    }

    fn send_mined_block(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MINED_BLOCK);
    }

    fn send_mined_microblock(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MINED_MICROBLOCK);
    }

    fn send_mined_nakamoto_block(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MINED_NAKAMOTO_BLOCK);
    }

    fn send_stackerdb_chunks(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_STACKERDB_CHUNKS);
    }

    fn send_new_burn_block(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_BURN_BLOCK_SUBMIT);
    }

    fn make_new_block_processed_payload(
        &self,
        filtered_events: Vec<(usize, &(bool, Txid, &StacksTransactionEvent))>,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent_index_hash: &StacksBlockId,
        winner_txid: &Txid,
        mature_rewards: &serde_json::Value,
        parent_burn_block_hash: BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec_opt: &Option<BitVec<4000>>,
    ) -> serde_json::Value {
        // Serialize events to JSON
        let serialized_events: Vec<serde_json::Value> = filtered_events
            .iter()
            .map(|(event_index, (committed, txid, event))| {
                event
                    .json_serialize(*event_index, txid, *committed)
                    .unwrap()
            })
            .collect();

        let mut tx_index: u32 = 0;
        let mut serialized_txs = vec![];
        for receipt in receipts.iter() {
            let payload = EventObserver::make_new_block_txs_payload(receipt, tx_index);
            serialized_txs.push(payload);
            tx_index += 1;
        }

        let signer_bitvec_value = signer_bitvec_opt
            .as_ref()
            .map(|bitvec| serde_json::to_value(bitvec).unwrap_or_default())
            .unwrap_or_default();

        let (reward_set_value, cycle_number_value) = match &reward_set_data {
            Some(data) => (
                serde_json::to_value(&RewardSetEventPayload::from_reward_set(&data.reward_set))
                    .unwrap_or_default(),
                serde_json::to_value(data.cycle_number).unwrap_or_default(),
            ),
            None => (serde_json::Value::Null, serde_json::Value::Null),
        };

        // Wrap events
        let mut payload = json!({
            "block_hash": format!("0x{}", block.block_hash),
            "block_height": metadata.stacks_block_height,
            "burn_block_hash": format!("0x{}", metadata.burn_header_hash),
            "burn_block_height": metadata.burn_header_height,
            "miner_txid": format!("0x{}", winner_txid),
            "burn_block_time": metadata.burn_header_timestamp,
            "index_block_hash": format!("0x{}", metadata.index_block_hash()),
            "parent_block_hash": format!("0x{}", block.parent_block_hash),
            "parent_index_block_hash": format!("0x{}", parent_index_hash),
            "parent_microblock": format!("0x{}", block.parent_microblock_hash),
            "parent_microblock_sequence": block.parent_microblock_sequence,
            "matured_miner_rewards": mature_rewards.clone(),
            "events": serialized_events,
            "transactions": serialized_txs,
            "parent_burn_block_hash":  format!("0x{}", parent_burn_block_hash),
            "parent_burn_block_height": parent_burn_block_height,
            "parent_burn_block_timestamp": parent_burn_block_timestamp,
            "anchored_cost": anchored_consumed,
            "confirmed_microblocks_cost": mblock_confirmed_consumed,
            "pox_v1_unlock_height": pox_constants.v1_unlock_height,
            "pox_v2_unlock_height": pox_constants.v2_unlock_height,
            "pox_v3_unlock_height": pox_constants.v3_unlock_height,
            "signer_bitvec": signer_bitvec_value,
            "reward_set": reward_set_value,
            "cycle_number": cycle_number_value,
        });

        let as_object_mut = payload.as_object_mut().unwrap();

        if let StacksBlockHeaderTypes::Nakamoto(ref header) = &metadata.anchored_header {
            as_object_mut.insert(
                "signer_signature_hash".into(),
                format!("0x{}", header.signer_signature_hash()).into(),
            );
            as_object_mut.insert(
                "signer_signature".into(),
                format!("0x{}", header.signer_signature_hash()).into(),
            );
            as_object_mut.insert(
                "miner_signature".into(),
                format!("0x{}", &header.miner_signature).into(),
            );
            as_object_mut.insert(
                "signer_signature".into(),
                format!("0x{}", &header.signer_signature).into(),
            );
        }

        payload
    }
}

#[derive(Clone)]
pub struct EventDispatcher {
    registered_observers: Vec<EventObserver>,
    contract_events_observers_lookup: HashMap<(QualifiedContractIdentifier, String), HashSet<u16>>,
    assets_observers_lookup: HashMap<AssetIdentifier, HashSet<u16>>,
    burn_block_observers_lookup: HashSet<u16>,
    mempool_observers_lookup: HashSet<u16>,
    microblock_observers_lookup: HashSet<u16>,
    stx_observers_lookup: HashSet<u16>,
    any_event_observers_lookup: HashSet<u16>,
    miner_observers_lookup: HashSet<u16>,
    mined_microblocks_observers_lookup: HashSet<u16>,
    stackerdb_observers_lookup: HashSet<u16>,
    block_proposal_observers_lookup: HashSet<u16>,
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
            observer.send_payload(&response, PATH_PROPOSAL_RESPONSE);
        }
    }
}

impl MemPoolEventDispatcher for EventDispatcher {
    fn mempool_txs_dropped(&self, txids: Vec<Txid>, reason: MemPoolDropReason) {
        if !txids.is_empty() {
            self.process_dropped_mempool_txs(txids, reason)
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
        winner_txid: Txid,
        mature_rewards: &[MinerReward],
        mature_rewards_info: Option<&MinerRewardInfo>,
        parent_burn_block_hash: BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec: &Option<BitVec<4000>>,
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
        );
    }

    fn announce_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        recipient_info: Vec<PoxAddress>,
    ) {
        self.process_burn_block(
            burn_block,
            burn_block_height,
            rewards,
            burns,
            recipient_info,
        )
    }
}

impl EventDispatcher {
    pub fn new() -> EventDispatcher {
        EventDispatcher {
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
        }
    }

    pub fn process_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        recipient_info: Vec<PoxAddress>,
    ) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.burn_block_observers_lookup, true);
        if interested_observers.len() < 1 {
            return;
        }

        let payload = EventObserver::make_new_burn_block_payload(
            burn_block,
            burn_block_height,
            rewards,
            burns,
            recipient_info,
        );

        for observer in interested_observers.iter() {
            observer.send_new_burn_block(&payload);
        }
    }

    /// Iterates through tx receipts, and then the events corresponding to each receipt to
    /// generate a dispatch matrix & event vector.
    ///
    /// # Returns
    /// - dispatch_matrix: a vector where each index corresponds to the hashset of event indexes
    ///     that each respective event observer is subscribed to
    /// - events: a vector of all events from all the tx receipts
    fn create_dispatch_matrix_and_event_vector<'a>(
        &self,
        receipts: &'a Vec<StacksTransactionReceipt>,
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
                events.push((!receipt.post_condition_aborted, tx_hash, event));
                for o_i in &self.any_event_observers_lookup {
                    dispatch_matrix[*o_i as usize].insert(i);
                }
                i += 1;
            }
        }

        (dispatch_matrix, events)
    }

    pub fn process_chain_tip(
        &self,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent_index_hash: &StacksBlockId,
        winner_txid: Txid,
        mature_rewards: &[MinerReward],
        mature_rewards_info: Option<&MinerRewardInfo>,
        parent_burn_block_hash: BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec: &Option<BitVec<4000>>,
    ) {
        let all_receipts = receipts.to_owned();
        let (dispatch_matrix, events) = self.create_dispatch_matrix_and_event_vector(&all_receipts);

        if dispatch_matrix.len() > 0 {
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

            for (observer_id, filtered_events_ids) in dispatch_matrix.iter().enumerate() {
                let filtered_events: Vec<_> = filtered_events_ids
                    .iter()
                    .map(|event_id| (*event_id, &events[*event_id]))
                    .collect();

                let payload = self.registered_observers[observer_id]
                    .make_new_block_processed_payload(
                        filtered_events,
                        &block,
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
                    );

                // Send payload
                self.registered_observers[observer_id].send_payload(&payload, PATH_BLOCK_PROCESSED);
            }
        }
    }

    /// Creates a list of observers that are interested in the new microblocks event,
    /// creates a mapping from observers to the event ids that are relevant to each, and then
    /// sends the event to each interested observer.
    pub fn process_new_microblocks(
        &self,
        parent_index_block_hash: StacksBlockId,
        processed_unconfirmed_state: ProcessedUnconfirmedState,
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
        if interested_observers.len() < 1 {
            return;
        }
        let flattened_receipts = processed_unconfirmed_state
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
                let payload = EventObserver::make_new_block_txs_payload(receipt, tx_index);
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

            observer.send_new_microblocks(
                parent_index_block_hash,
                filtered_events,
                &serialized_txs,
                processed_unconfirmed_state.burn_block_hash,
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
                if lookup.contains(&lookup_ix) {
                    return Some(observer);
                } else if include_any && self.any_event_observers_lookup.contains(&lookup_ix) {
                    return Some(observer);
                } else {
                    return None;
                }
            })
            .collect()
    }

    pub fn process_new_mempool_txs(&self, txs: Vec<StacksTransaction>) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.mempool_observers_lookup, true);

        if interested_observers.len() < 1 {
            return;
        }

        let payload = EventObserver::make_new_mempool_txs_payload(txs);

        for observer in interested_observers.iter() {
            observer.send_new_mempool_txs(&payload);
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

        if interested_observers.len() < 1 {
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
            observer.send_mined_block(&payload);
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
        if interested_observers.len() < 1 {
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
            observer.send_mined_microblock(&payload);
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
        if interested_observers.len() < 1 {
            return;
        }

        let signer_bitvec = serde_json::to_value(block.header.signer_bitvec.clone())
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
            signer_signature_hash: block.header.signer_signature_hash(),
            signer_bitvec,
        })
        .unwrap();

        for observer in interested_observers.iter() {
            observer.send_mined_nakamoto_block(&payload);
        }
    }

    /// Forward newly-accepted StackerDB chunk metadata to downstream `stackerdb` observers.
    /// Infallible.
    pub fn process_new_stackerdb_chunks(
        &self,
        contract_id: QualifiedContractIdentifier,
        modified_slots: Vec<StackerDBChunkData>,
    ) {
        let interested_observers = self.filter_observers(&self.stackerdb_observers_lookup, false);

        let interested_receiver = STACKER_DB_CHANNEL.is_active(&contract_id);
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
                    "Failed to send StackerDB event to WSTS coordinator channel. Miner thread may have exited.";
                    "err" => ?send_err
                );
            }
        }

        for observer in interested_observers.iter() {
            observer.send_stackerdb_chunks(&payload);
        }
    }

    pub fn process_dropped_mempool_txs(&self, txs: Vec<Txid>, reason: MemPoolDropReason) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.mempool_observers_lookup, true);

        if interested_observers.len() < 1 {
            return;
        }

        let dropped_txids: Vec<_> = txs
            .into_iter()
            .map(|tx| serde_json::Value::String(format!("0x{}", &tx)))
            .collect();

        let payload = json!({
            "dropped_txids": serde_json::Value::Array(dropped_txids),
            "reason": reason.to_string(),
        });

        for observer in interested_observers.iter() {
            observer.send_dropped_mempool_txs(&payload);
        }
    }

    pub fn process_new_attachments(&self, attachments: &Vec<(AttachmentInstance, Attachment)>) {
        let interested_observers: Vec<_> = self.registered_observers.iter().enumerate().collect();
        if interested_observers.len() < 1 {
            return;
        }

        let mut serialized_attachments = vec![];
        for attachment in attachments.iter() {
            let payload = EventObserver::make_new_attachment_payload(attachment);
            serialized_attachments.push(payload);
        }

        for (_, observer) in interested_observers.iter() {
            observer.send_new_attachments(&json!(serialized_attachments));
        }
    }

    fn update_dispatch_matrix_if_observer_subscribed(
        &self,
        asset_identifier: &AssetIdentifier,
        event_index: usize,
        dispatch_matrix: &mut Vec<HashSet<usize>>,
    ) {
        if let Some(observer_indexes) = self.assets_observers_lookup.get(asset_identifier) {
            for o_i in observer_indexes {
                dispatch_matrix[*o_i as usize].insert(event_index);
            }
        }
    }

    pub fn register_observer(&mut self, conf: &EventObserverConfig) {
        info!("Registering event observer at: {}", conf.endpoint);
        let event_observer = EventObserver {
            endpoint: conf.endpoint.clone(),
        };

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

        self.registered_observers.push(event_observer);
    }
}

#[cfg(test)]
mod test {
    use clarity::vm::costs::ExecutionCost;
    use stacks::burnchains::{PoxConstants, Txid};
    use stacks::chainstate::stacks::db::StacksHeaderInfo;
    use stacks::chainstate::stacks::StacksBlock;
    use stacks_common::bitvec::BitVec;
    use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksBlockId};

    use crate::event_dispatcher::EventObserver;

    #[test]
    fn build_block_processed_event() {
        let observer = EventObserver {
            endpoint: "nowhere".to_string(),
        };

        let filtered_events = vec![];
        let block = StacksBlock::genesis_block();
        let metadata = StacksHeaderInfo::regtest_genesis();
        let receipts = vec![];
        let parent_index_hash = StacksBlockId([0; 32]);
        let winner_txid = Txid([0; 32]);
        let mature_rewards = serde_json::Value::Array(vec![]);
        let parent_burn_block_hash = BurnchainHeaderHash([0; 32]);
        let parent_burn_block_height = 0;
        let parent_burn_block_timestamp = 0;
        let anchored_consumed = ExecutionCost::zero();
        let mblock_confirmed_consumed = ExecutionCost::zero();
        let pox_constants = PoxConstants::testnet_default();
        let signer_bitvec = BitVec::zeros(2).expect("Failed to create BitVec with length 2");

        let payload = observer.make_new_block_processed_payload(
            filtered_events,
            &block.into(),
            &metadata,
            &receipts,
            &parent_index_hash,
            &winner_txid,
            &mature_rewards,
            parent_burn_block_hash,
            parent_burn_block_height,
            parent_burn_block_timestamp,
            &anchored_consumed,
            &mblock_confirmed_consumed,
            &pox_constants,
            &None,
            &Some(signer_bitvec.clone()),
        );
        assert_eq!(
            payload
                .get("pox_v1_unlock_height")
                .unwrap()
                .as_u64()
                .unwrap(),
            pox_constants.v1_unlock_height as u64
        );

        let expected_bitvec_str = serde_json::to_value(signer_bitvec)
            .unwrap_or_default()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            payload.get("signer_bitvec").unwrap().as_str().unwrap(),
            expected_bitvec_str
        );
    }
}
