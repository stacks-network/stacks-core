use std::convert::{TryInto, TryFrom};
use std::fmt::Formatter;

use burnchains::Txid;
use serde::de::Error as DeserError;
use serde::Deserialize;
use serde::Deserializer;
use util::HexError;
use vm::types::Value as ClarityValue;
use vm::types::{QualifiedContractIdentifier, TraitIdentifier};

use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::StacksBlockId;
use crate::vm::types::CharType;
use crate::vm::types::SequenceData;
use crate::vm::representations::ClarityName;

use super::StacksHyperBlock;
use super::StacksHyperOp;
use super::StacksHyperOpType;
use clarity::vm::types::PrincipalData;

/// Parsing struct for the transaction event types of the
/// `stacks-node` events API
#[derive(PartialEq, Clone, Debug)]
pub enum TxEventType {
    ContractEvent,
    Other,
}

/// Parsing struct for the contract_event field in transaction events
/// of the `stacks-node` events API
#[derive(Deserialize, Clone, Debug)]
pub struct ContractEvent {
    #[serde(deserialize_with = "deser_contract_identifier")]
    pub contract_identifier: QualifiedContractIdentifier,
    pub topic: String,
    #[serde(rename = "raw_value", deserialize_with = "deser_clarity_value")]
    pub value: ClarityValue,
}

/// Parsing struct for the transaction events of the `stacks-node`
/// events API
#[derive(Deserialize, Clone, Debug)]
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

/// Parsing struct for the new block events of the `stacks-node`
/// events API
#[derive(Deserialize, Clone)]
pub struct NewBlock {
    pub block_height: u64,
    pub burn_block_time: u64,
    #[serde(deserialize_with = "deser_stacks_block_id")]
    pub index_block_hash: StacksBlockId,
    #[serde(deserialize_with = "deser_stacks_block_id")]
    pub parent_index_block_hash: StacksBlockId,
    pub events: Vec<NewBlockTxEvent>,
}

impl std::fmt::Debug for NewBlock {
    /// Shortened debug string, for logging.
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "NewBlock(hash={:?}, parent_hash={:?}, block_height={}, num_events={})",
            &self.index_block_hash,
            &self.parent_index_block_hash,
            self.block_height,
            self.events.len()
        )
    }
}

/// Method for deserializing a ClarityValue from the `raw_value` field of contract
/// transaction events.
fn deser_clarity_value<'de, D>(deser: D) -> Result<ClarityValue, D::Error>
where
    D: Deserializer<'de>,
{
    let str_val = String::deserialize(deser)?;
    ClarityValue::try_deserialize_hex_untyped(&str_val).map_err(DeserError::custom)
}

/// Method for deserializing a contract identifier from `contract_identifier` fields in
/// transaction events.
fn deser_contract_identifier<'de, D>(deser: D) -> Result<QualifiedContractIdentifier, D::Error>
where
    D: Deserializer<'de>,
{
    let str_val = String::deserialize(deser)?;
    QualifiedContractIdentifier::parse(&str_val).map_err(DeserError::custom)
}

/// Method for deserializing a `Txid` from transaction events.
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

/// Method for deserializing a `StacksBlockId` from transaction events.
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

/// Method for deserializing a `TxEventType` from transaction events.
/// This module is currently only interested in `contract_event` types,
/// so all other events are parsed as `Other`.
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

impl StacksHyperOp {
    /// This method tries to parse a `StacksHyperOp` from a Clarity value: this should be a tuple
    /// emitted from the hyperchain contract in a statement like:
    /// `(print { event: "block-commit", block-commit: 0x123... })`
    ///
    /// If the provided value does not match that tuple, this method will return an error.
    pub fn try_from_clar_value(
        v: ClarityValue,
        txid: Txid,
        event_index: u32,
        in_block: &StacksBlockId,
    ) -> Result<Self, String> {
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

                Ok(Self {
                    txid,
                    event_index,
                    in_block: in_block.clone(),
                    opcode: 0,
                    event: StacksHyperOpType::BlockCommit {
                        subnet_block_hash: BlockHeaderHash(block_commit),
                    },
                })
            }
            "\"deposit-ft\"" => {
                // Parse 5 fields: ft-amount, ft-name, l1-contract-id, hc-contract-id, and sender
                let amount = tuple
                    .get("ft-amount")
                    .map_err(|_| "No 'ft-amount' field in Clarity tuple")?
                    .clone()
                    .expect_u128();
                let l1_contract_id = tuple
                    .get("l1-contract-id")
                    .map_err(|_| "No 'l1-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let l1_contract_id = if let PrincipalData::Contract(id) = l1_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'l1-contract-id' to be a contract principal")
                }?;
                let hc_contract_id = tuple
                    .get("hc-contract-id")
                    .map_err(|_| "No 'hc-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_contract_id = if let PrincipalData::Contract(id) = hc_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'hc-contract-id' to be a contract principal")
                }?;
                let name = tuple
                    .get("ft-name")
                    .map_err(|_| "No 'ft-name' field in Clarity tuple")?
                    .clone()
                    .expect_result()
                    .expect("Result should be ok")
                    .expect_ascii();
                let sender = tuple
                    .get("sender")
                    .map_err(|_| "No 'sender' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_function_name = tuple
                    .get("hc-function-name")
                    .map_err(|_| "No 'hc-function-name' field in Clarity tuple")?
                    .clone()
                    .expect_ascii();
                let hc_function_name = ClarityName::try_from(hc_function_name)
                    .map_err(|e| {
                        format!("Failed to parse Clarity name: {:?}", e)
                    })?;

                Ok(Self {
                    txid,
                    event_index,
                    in_block: in_block.clone(),
                    opcode: 1,
                    event: StacksHyperOpType::DepositFt {
                        l1_contract_id,
                        hc_contract_id,
                        hc_function_name,
                        name,
                        amount,
                        sender,
                    },
                })
            }
            "\"deposit-nft\"" => {
                // Parse 4 fields: nft-id, l1-contract-id, hc-contract-id, and sender
                let id = tuple
                    .get("nft-id")
                    .map_err(|_| "No 'nft-id' field in Clarity tuple")?
                    .clone()
                    .expect_u128();
                // check that this is a valid way of getting the ID of the L1 contract.
                let l1_contract_id = tuple
                    .get("l1-contract-id")
                    .map_err(|_| "No 'l1-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let l1_contract_id = if let PrincipalData::Contract(id) = l1_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'l1-contract-id' to be a contract principal")
                }?;
                let hc_contract_id = tuple
                    .get("hc-contract-id")
                    .map_err(|_| "No 'hc-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_contract_id = if let PrincipalData::Contract(id) = hc_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'hc-contract-id' to be a contract principal")
                }?;
                let sender = tuple
                    .get("sender")
                    .map_err(|_| "No 'sender' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_function_name = tuple
                    .get("hc-function-name")
                    .map_err(|_| "No 'hc-function-name' field in Clarity tuple")?
                    .clone()
                    .expect_ascii();
                let hc_function_name = ClarityName::try_from(hc_function_name)
                    .map_err(|e| {
                        format!("Failed to parse Clarity name: {:?}", e)
                    })?;

                Ok(Self {
                    txid,
                    event_index,
                    in_block: in_block.clone(),
                    opcode: 2,
                    event: StacksHyperOpType::DepositNft {
                        l1_contract_id,
                        hc_contract_id,
                        hc_function_name,
                        id,
                        sender,
                    },
                })
            }
            "\"withdraw-ft\"" => {
                // Parse 5 fields: ft-amount, ft-name, l1-contract-id, hc-contract-id, and recipient
                let amount = tuple
                    .get("ft-amount")
                    .map_err(|_| "No 'ft-amount' field in Clarity tuple")?
                    .clone()
                    .expect_u128();
                // check that this is a valid way of getting the ID of the L1 contract.
                let l1_contract_id = tuple
                    .get("l1-contract-id")
                    .map_err(|_| "No 'l1-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let l1_contract_id = if let PrincipalData::Contract(id) = l1_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'l1-contract-id' to be a contract principal")
                }?;
                let hc_contract_id = tuple
                    .get("hc-contract-id")
                    .map_err(|_| "No 'hc-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_contract_id = if let PrincipalData::Contract(id) = hc_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'hc-contract-id' to be a contract principal")
                }?;
                let name = tuple
                    .get("ft-name")
                    .map_err(|_| "No 'ft-name' field in Clarity tuple")?
                    .clone()
                    .expect_result()
                    .expect("Result should be ok")
                    .expect_ascii();
                let recipient = tuple
                    .get("recipient")
                    .map_err(|_| "No 'recipient' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_function_name = tuple
                    .get("hc-function-name")
                    .map_err(|_| "No 'hc-function-name' field in Clarity tuple")?
                    .clone()
                    .expect_ascii();
                let hc_function_name = ClarityName::try_from(hc_function_name)
                    .map_err(|e| {
                        format!("Failed to parse Clarity name: {:?}", e)
                    })?;

                Ok(Self {
                    txid,
                    event_index,
                    in_block: in_block.clone(),
                    opcode: 3,
                    event: StacksHyperOpType::WithdrawFt {
                        l1_contract_id,
                        hc_contract_id,
                        hc_function_name,
                        name,
                        amount,
                        recipient,
                    },
                })
            }
            "\"withdraw-nft\"" => {
                // Parse 4 fields: nft-id, l1-contract-id, hc-contract-id, and recipient
                let id = tuple
                    .get("nft-id")
                    .map_err(|_| "No 'nft-id' field in Clarity tuple")?
                    .clone()
                    .expect_u128();
                // check that this is a valid way of getting the ID of the L1 contract.
                let l1_contract_id = tuple
                    .get("l1-contract-id")
                    .map_err(|_| "No 'l1-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let l1_contract_id = if let PrincipalData::Contract(id) = l1_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'l1-contract-id' to be a contract principal")
                }?;
                let hc_contract_id = tuple
                    .get("hc-contract-id")
                    .map_err(|_| "No 'hc-contract-id' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_contract_id = if let PrincipalData::Contract(id) = hc_contract_id {
                    Ok(id)
                } else {
                    Err("Expected 'hc-contract-id' to be a contract principal")
                }?;
                let recipient = tuple
                    .get("recipient")
                    .map_err(|_| "No 'recipient' field in Clarity tuple")?
                    .clone()
                    .expect_principal();
                let hc_function_name = tuple
                    .get("hc-function-name")
                    .map_err(|_| "No 'hc-function-name' field in Clarity tuple")?
                    .clone()
                    .expect_ascii();
                let hc_function_name = ClarityName::try_from(hc_function_name)
                    .map_err(|e| {
                    format!("Failed to parse Clarity name: {:?}", e)
                })?;

                Ok(Self {
                    txid,
                    event_index,
                    in_block: in_block.clone(),
                    opcode: 4,
                    event: StacksHyperOpType::WithdrawNft {
                        l1_contract_id,
                        hc_contract_id,
                        hc_function_name,
                        id,
                        recipient,
                    },
                })
            }
            event_type => Err(format!("Unexpected 'event' string: {}", event_type)),
        }
    }
}

impl StacksHyperBlock {
    /// Process a `NewBlock` event from a layer-1 Stacks node, filter
    /// for the transaction events in the block that are relevant to
    /// the hyperchain and parse out the `StacksHyperOp`s from the
    /// block, producing a `StacksHyperBlock` struct.
    pub fn from_new_block_event(
        hyperchain_contract: &QualifiedContractIdentifier,
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
                        event_index,
                        ..
                    } = e;

                    let event_index: u32 = match event_index.try_into() {
                        Ok(x) => Some(x),
                        Err(_e) => {
                            warn!(
                                "StacksHyperBlock skipped event because event_index was not a u32"
                            );
                            None
                        }
                    }?;

                    if let Some(contract_event) = contract_event {
                        if &contract_event.contract_identifier != hyperchain_contract {
                            None
                        } else {
                            match StacksHyperOp::try_from_clar_value(
                                contract_event.value,
                                txid,
                                event_index,
                                &index_block_hash,
                            ) {
                                Ok(x) => Some(x),
                                Err(e) => {
                                    info!(
                                        "StacksHyperBlock parser skipped event because of {:?}",
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

        Self {
            current_block: index_block_hash,
            parent_block: parent_index_block_hash,
            block_height,
            ops,
        }
    }
}
