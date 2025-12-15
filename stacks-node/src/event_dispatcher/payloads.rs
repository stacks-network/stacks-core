use clarity::vm::analysis::contract_interface_builder::{
    build_contract_interface, ContractInterface,
};
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::Value;
use serde_json::json;
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::burn::operations::{
    blockstack_op_extended_deserialize, blockstack_op_extended_serialize_opt,
    BlockstackOperationType,
};
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::boot::{
    NakamotoSignerEntry, PoxStartCycleInfo, RewardSet, RewardSetData,
};
use stacks::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksHeaderInfo};
use stacks::chainstate::stacks::events::{
    StacksBlockEventData, StacksTransactionEvent, StacksTransactionReceipt, TransactionOrigin,
};
use stacks::chainstate::stacks::miner::TransactionEvent;
use stacks::chainstate::stacks::{StacksTransaction, TransactionPayload};
use stacks::net::atlas::{Attachment, AttachmentInstance};
use stacks::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
use stacks::util::hash::{to_hex, to_hex_prefixed};
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::serde_serializers::{
    prefix_hex, prefix_hex_codec, prefix_opt_hex, prefix_string_0x,
};

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MinedNakamotoBlockEvent {
    pub target_burn_height: u64,
    pub parent_block_id: String,
    pub block_hash: String,
    pub block_id: String,
    pub stacks_height: u64,
    pub block_size: u64,
    pub cost: ExecutionCost,
    pub miner_signature: MessageSignature,
    pub miner_signature_hash: Sha512Trunc256Sum,
    pub signer_signature_hash: Sha512Trunc256Sum,
    pub tx_events: Vec<TransactionEvent>,
    pub signer_bitvec: String,
    pub signer_signature: Vec<MessageSignature>,
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

fn serialize_u128_as_string<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn serialize_pox_addresses<S>(value: &[PoxAddress], serializer: S) -> Result<S::Ok, S::Error>
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TransactionEventPayload<'a> {
    #[serde(with = "prefix_hex")]
    /// The transaction id
    pub txid: Txid,
    /// The transaction index
    pub tx_index: u32,
    /// The transaction status
    pub status: &'a str,
    #[serde(with = "prefix_hex_codec")]
    /// The raw transaction result
    pub raw_result: Value,
    /// The hex encoded raw transaction
    #[serde(with = "prefix_string_0x")]
    pub raw_tx: String,
    /// The contract interface
    pub contract_interface: Option<ContractInterface>,
    /// The burnchain op
    #[serde(
        serialize_with = "blockstack_op_extended_serialize_opt",
        deserialize_with = "blockstack_op_extended_deserialize"
    )]
    pub burnchain_op: Option<BlockstackOperationType>,
    /// The transaction execution cost
    pub execution_cost: ExecutionCost,
    /// The microblock sequence
    pub microblock_sequence: Option<u16>,
    #[serde(with = "prefix_opt_hex")]
    /// The microblock hash
    pub microblock_hash: Option<BlockHeaderHash>,
    #[serde(with = "prefix_opt_hex")]
    /// The microblock parent hash
    pub microblock_parent_hash: Option<BlockHeaderHash>,
    /// Error information if one occurred in the Clarity VM
    pub vm_error: Option<String>,
}

pub fn make_new_mempool_txs_payload(transactions: Vec<StacksTransaction>) -> serde_json::Value {
    let raw_txs = transactions
        .into_iter()
        .map(|tx| serde_json::Value::String(to_hex_prefixed(&tx.serialize_to_vec(), true)))
        .collect();

    serde_json::Value::Array(raw_txs)
}

pub fn make_new_burn_block_payload(
    burn_block: &BurnchainHeaderHash,
    burn_block_height: u64,
    rewards: Vec<(PoxAddress, u64)>,
    burns: u64,
    slot_holders: Vec<PoxAddress>,
    consensus_hash: &ConsensusHash,
    parent_burn_block_hash: &BurnchainHeaderHash,
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
        "burn_block_hash": format!("0x{burn_block}"),
        "burn_block_height": burn_block_height,
        "reward_recipients": serde_json::Value::Array(reward_recipients),
        "reward_slot_holders": serde_json::Value::Array(reward_slot_holders),
        "burn_amount": burns,
        "consensus_hash": format!("0x{consensus_hash}"),
        "parent_burn_block_hash": format!("0x{parent_burn_block_hash}"),
    })
}

const STATUS_RESP_TRUE: &str = "success";
const STATUS_RESP_NOT_COMMITTED: &str = "abort_by_response";
const STATUS_RESP_POST_CONDITION: &str = "abort_by_post_condition";

/// Returns transaction event payload to send for new block or microblock event
pub fn make_new_block_txs_payload(
    receipt: &StacksTransactionReceipt,
    tx_index: u32,
) -> TransactionEventPayload<'_> {
    let tx = &receipt.transaction;

    let status = match (receipt.post_condition_aborted, &receipt.result) {
        (false, Value::Response(response_data)) => {
            if response_data.committed {
                STATUS_RESP_TRUE
            } else {
                STATUS_RESP_NOT_COMMITTED
            }
        }
        (true, Value::Response(_)) => STATUS_RESP_POST_CONDITION,
        _ => {
            if !matches!(
                tx,
                TransactionOrigin::Stacks(StacksTransaction {
                    payload: TransactionPayload::PoisonMicroblock(_, _),
                    ..
                })
            ) {
                unreachable!("Unexpected transaction result type");
            }
            STATUS_RESP_TRUE
        }
    };

    let (txid, raw_tx, burnchain_op) = match tx {
        TransactionOrigin::Burn(op) => (op.txid(), "00".to_string(), Some(op.clone())),
        TransactionOrigin::Stacks(ref tx) => {
            let txid = tx.txid();
            let bytes = to_hex(&tx.serialize_to_vec());
            (txid, bytes, None)
        }
    };

    TransactionEventPayload {
        txid,
        tx_index,
        status,
        raw_result: receipt.result.clone(),
        raw_tx,
        contract_interface: receipt.contract_analysis.as_ref().map(|analysis| {
            build_contract_interface(analysis)
                .expect("FATAL: failed to serialize contract publish receipt")
        }),
        burnchain_op,
        execution_cost: receipt.execution_cost.clone(),
        microblock_sequence: receipt.microblock_header.as_ref().map(|x| x.sequence),
        microblock_hash: receipt.microblock_header.as_ref().map(|x| x.block_hash()),
        microblock_parent_hash: receipt
            .microblock_header
            .as_ref()
            .map(|x| x.prev_block.clone()),
        vm_error: receipt.vm_error.clone(),
    }
}

pub fn make_new_attachment_payload(
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
        "content": to_hex_prefixed(&attachment.1.content, true),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn make_new_block_processed_payload(
    filtered_events: Vec<(usize, &(bool, Txid, &StacksTransactionEvent))>,
    block: &StacksBlockEventData,
    metadata: &StacksHeaderInfo,
    receipts: &[StacksTransactionReceipt],
    parent_index_hash: &StacksBlockId,
    winner_txid: &Txid,
    mature_rewards: &serde_json::Value,
    parent_burn_block_hash: &BurnchainHeaderHash,
    parent_burn_block_height: u32,
    parent_burn_block_timestamp: u64,
    anchored_consumed: &ExecutionCost,
    mblock_confirmed_consumed: &ExecutionCost,
    pox_constants: &PoxConstants,
    reward_set_data: &Option<RewardSetData>,
    signer_bitvec_opt: &Option<BitVec<4000>>,
    block_timestamp: Option<u64>,
    coinbase_height: u64,
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

    let mut serialized_txs = vec![];
    for (tx_index, receipt) in receipts.iter().enumerate() {
        let payload = make_new_block_txs_payload(
            receipt,
            tx_index
                .try_into()
                .expect("BUG: more receipts than U32::MAX"),
        );
        serialized_txs.push(payload);
    }

    let signer_bitvec_value = signer_bitvec_opt
        .as_ref()
        .map(|bitvec| serde_json::to_value(bitvec).unwrap_or_default())
        .unwrap_or_default();

    let (reward_set_value, cycle_number_value) = match &reward_set_data {
        Some(data) => (
            serde_json::to_value(RewardSetEventPayload::from_reward_set(&data.reward_set))
                .unwrap_or_default(),
            serde_json::to_value(data.cycle_number).unwrap_or_default(),
        ),
        None => (serde_json::Value::Null, serde_json::Value::Null),
    };

    // Wrap events
    let mut payload = json!({
        "block_hash": format!("0x{}", block.block_hash),
        "block_height": metadata.stacks_block_height,
        "block_time": block_timestamp,
        "burn_block_hash": format!("0x{}", metadata.burn_header_hash),
        "burn_block_height": metadata.burn_header_height,
        "miner_txid": format!("0x{winner_txid}"),
        "burn_block_time": metadata.burn_header_timestamp,
        "index_block_hash": format!("0x{}", metadata.index_block_hash()),
        "parent_block_hash": format!("0x{}", block.parent_block_hash),
        "parent_index_block_hash": format!("0x{parent_index_hash}"),
        "parent_microblock": format!("0x{}", block.parent_microblock_hash),
        "parent_microblock_sequence": block.parent_microblock_sequence,
        "matured_miner_rewards": mature_rewards.clone(),
        "events": serialized_events,
        "transactions": serialized_txs,
        "parent_burn_block_hash":  format!("0x{parent_burn_block_hash}"),
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
        "tenure_height": coinbase_height,
        "consensus_hash": format!("0x{}", metadata.consensus_hash),
    });

    let as_object_mut = payload.as_object_mut().unwrap();

    if let StacksBlockHeaderTypes::Nakamoto(ref header) = &metadata.anchored_header {
        as_object_mut.insert(
            "signer_signature_hash".into(),
            format!("0x{}", header.signer_signature_hash()).into(),
        );
        as_object_mut.insert(
            "miner_signature".into(),
            format!("0x{}", &header.miner_signature).into(),
        );
        as_object_mut.insert(
            "signer_signature".into(),
            serde_json::to_value(&header.signer_signature).unwrap_or_default(),
        );
    }

    payload
}
