use burnchains::Txid;
use serde::de::Error as DeserError;
use serde::Deserialize;
use serde::Deserializer;
use util::HexError;
use vm::types::QualifiedContractIdentifier;
use vm::types::Value as ClarityValue;

use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::StacksBlockId;
use crate::vm::types::CharType;
use crate::vm::types::SequenceData;

use super::StacksEventBlock;
use super::SubnetStacksEvent;
use super::SubnetStacksEventType;

#[derive(PartialEq)]
pub enum TxEventType {
    ContractEvent,
    Other,
}

#[derive(Deserialize)]
pub struct ContractEvent {
    #[serde(deserialize_with = "deser_contract_identifier")]
    pub contract_identifier: QualifiedContractIdentifier,
    pub topic: String,
    #[serde(rename = "raw_value", deserialize_with = "deser_clarity_value")]
    pub value: ClarityValue,
}

#[derive(Deserialize)]
pub struct NewBlockTxEvent {
    #[serde(deserialize_with = "deser_txid")]
    pub txid: Txid,
    pub event_index: usize,
    pub committed: bool,
    #[serde(rename = "type", deserialize_with = "deser_tx_event_type")]
    pub event_type: TxEventType,
    #[serde(default)]
    pub contract_event: Option<ContractEvent>,
}

#[derive(Deserialize)]
pub struct NewBlock {
    pub block_height: u64,
    pub burn_block_time: u64,
    #[serde(deserialize_with = "deser_stacks_block_id")]
    pub index_block_hash: StacksBlockId,
    #[serde(deserialize_with = "deser_stacks_block_id")]
    pub parent_index_block_hash: StacksBlockId,
    pub events: Vec<NewBlockTxEvent>,
}

fn deser_clarity_value<'de, D>(deser: D) -> Result<ClarityValue, D::Error>
where
    D: Deserializer<'de>,
{
    let str_val = String::deserialize(deser)?;
    ClarityValue::try_deserialize_hex_untyped(&str_val).map_err(DeserError::custom)
}

fn deser_contract_identifier<'de, D>(deser: D) -> Result<QualifiedContractIdentifier, D::Error>
where
    D: Deserializer<'de>,
{
    let str_val = String::deserialize(deser)?;
    QualifiedContractIdentifier::parse(&str_val).map_err(DeserError::custom)
}

fn deser_txid<'de, D>(deser: D) -> Result<Txid, D::Error>
where
    D: Deserializer<'de>,
{
    let str_val = String::deserialize(deser)?;
    match str_val.get(2..) {
        Some(hex) => Txid::from_hex(hex).map_err(DeserError::custom),
        None => Err(DeserError::custom(HexError::BadLength(2))),
    }
}

fn deser_stacks_block_id<'de, D>(deser: D) -> Result<StacksBlockId, D::Error>
where
    D: Deserializer<'de>,
{
    let str_val = String::deserialize(deser)?;
    match str_val.get(2..) {
        Some(hex) => StacksBlockId::from_hex(hex).map_err(DeserError::custom),
        None => Err(DeserError::custom(HexError::BadLength(2))),
    }
}

fn deser_tx_event_type<'de, D>(deser: D) -> Result<TxEventType, D::Error>
where
    D: Deserializer<'de>,
{
    let str_val = String::deserialize(deser)?;
    match str_val.as_str() {
        "contract_event" => Ok(TxEventType::ContractEvent),
        _ => Ok(TxEventType::Other),
    }
}

impl SubnetStacksEvent {
    pub fn try_from_clar_value(
        v: ClarityValue,
        txid: Txid,
        in_block: &StacksBlockId,
    ) -> Result<SubnetStacksEvent, String> {
        let tuple = if let ClarityValue::Tuple(tuple) = v {
            Ok(tuple)
        } else {
            Err("Expected Clarity type to be tuple")
        }?;

        let event = tuple
            .get("event")
            .map_err(|_| "No 'event' field in Clarity tuple")?;
        let event = if let ClarityValue::Sequence(SequenceData::String(clar_str)) = event {
            Ok(clar_str.to_string())
        } else {
            Err("Expected 'event' type to be string")
        }?;

        match event.as_str() {
            "\"block-commit\"" => {
                let block_commit = tuple
                    .get("block-commit")
                    .map_err(|_| "No 'block-commit' field in Clarity tuple")?;
                let block_commit =
                    if let ClarityValue::Sequence(SequenceData::Buffer(buff_data)) = block_commit {
                        if u32::from(buff_data.len()) != 32 {
                            Err(format!(
                                "Expected 'block-commit' type to be length 32, found {}",
                                buff_data.len()
                            ))
                        } else {
                            let mut buff = [0; 32];
                            buff.copy_from_slice(&buff_data.data);
                            Ok(buff)
                        }
                    } else {
                        Err("Expected 'block-commit' type to be buffer".into())
                    }?;

                Ok(SubnetStacksEvent {
                    txid,
                    in_block: in_block.clone(),
                    opcode: 0,
                    event: SubnetStacksEventType::BlockCommit {
                        subnet_block_hash: BlockHeaderHash(block_commit),
                    },
                })
            }
            event_type => Err(format!("Unexpected 'event' string: {}", event_type)),
        }
    }
}

impl StacksEventBlock {
    pub fn from_new_block_event(
        subnets_contract: &QualifiedContractIdentifier,
        b: NewBlock,
    ) -> Self {
        let NewBlock {
            events,
            index_block_hash,
            parent_index_block_hash,
            block_height,
            ..
        } = b;

        let ops = events
            .into_iter()
            .filter_map(|e| {
                if !e.committed {
                    None
                } else if e.event_type != TxEventType::ContractEvent {
                    None
                } else {
                    let NewBlockTxEvent {
                        txid,
                        contract_event,
                        ..
                    } = e;

                    if let Some(contract_event) = contract_event {
                        if &contract_event.contract_identifier != subnets_contract {
                            None
                        } else {
                            match SubnetStacksEvent::try_from_clar_value(
                                contract_event.value,
                                txid,
                                &index_block_hash,
                            ) {
                                Ok(x) => Some(x),
                                Err(e) => {
                                    debug!(
                                        "StacksEventBlock parser skipped event because of {:?}",
                                        e
                                    );
                                    None
                                }
                            }
                        }
                    } else {
                        None
                    }
                }
            })
            .collect();

        StacksEventBlock {
            current_block: index_block_hash,
            parent_block: parent_index_block_hash,
            block_height,
            ops,
        }
    }
}
