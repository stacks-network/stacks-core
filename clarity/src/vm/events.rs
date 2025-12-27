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

use serde_json::json;
use stacks_common::util::hash::to_hex_prefixed;

use super::types::serialization::SerializationError;
use crate::vm::types::{
    AssetIdentifier, BuffData, PrincipalData, QualifiedContractIdentifier, Value,
};

#[derive(Debug, Clone, PartialEq)]
pub enum StacksTransactionEvent {
    SmartContractEvent(SmartContractEventData),
    STXEvent(STXEventType),
    NFTEvent(NFTEventType),
    FTEvent(FTEventType),
    PostConditionEvent(PostConditionEventData),
}

impl StacksTransactionEvent {
    pub fn json_serialize(
        &self,
        event_index: usize,
        txid: &dyn std::fmt::Debug,
        committed: bool,
    ) -> Result<serde_json::Value, SerializationError> {
        let out = match self {
            StacksTransactionEvent::SmartContractEvent(event_data) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "contract_event",
                "contract_event": event_data.json_serialize()?
            }),
            StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "stx_transfer_event",
                "stx_transfer_event": event_data.json_serialize()
            }),
            StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "stx_mint_event",
                "stx_mint_event": event_data.json_serialize()
            }),
            StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "stx_burn_event",
                "stx_burn_event": event_data.json_serialize()
            }),
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "stx_lock_event",
                "stx_lock_event": event_data.json_serialize()
            }),
            StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "nft_transfer_event",
                "nft_transfer_event": event_data.json_serialize()?
            }),
            StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "nft_mint_event",
                "nft_mint_event": event_data.json_serialize()?
            }),
            StacksTransactionEvent::NFTEvent(NFTEventType::NFTBurnEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "nft_burn_event",
                "nft_burn_event": event_data.json_serialize()?
            }),
            StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "ft_transfer_event",
                "ft_transfer_event": event_data.json_serialize()
            }),
            StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "ft_mint_event",
                "ft_mint_event": event_data.json_serialize()
            }),
            StacksTransactionEvent::FTEvent(FTEventType::FTBurnEvent(event_data)) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "ft_burn_event",
                "ft_burn_event": event_data.json_serialize()
            }),
            StacksTransactionEvent::PostConditionEvent(event_data) => json!({
                "txid": format!("0x{txid:?}"),
                "event_index": event_index,
                "committed": committed,
                "type": "post_condition_event",
                "post_condition_event": event_data.json_serialize()?
            }),
        };
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum STXEventType {
    STXTransferEvent(STXTransferEventData),
    STXMintEvent(STXMintEventData),
    STXBurnEvent(STXBurnEventData),
    STXLockEvent(STXLockEventData),
}

#[derive(Debug, Clone, PartialEq)]
pub enum NFTEventType {
    NFTTransferEvent(NFTTransferEventData),
    NFTMintEvent(NFTMintEventData),
    NFTBurnEvent(NFTBurnEventData),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FTEventType {
    FTTransferEvent(FTTransferEventData),
    FTMintEvent(FTMintEventData),
    FTBurnEvent(FTBurnEventData),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct STXTransferEventData {
    pub sender: PrincipalData,
    pub recipient: PrincipalData,
    pub amount: u128,
    pub memo: BuffData,
}

impl STXTransferEventData {
    pub fn json_serialize(&self) -> serde_json::Value {
        json!({
            "sender": format!("{}",self.sender),
            "recipient": format!("{}",self.recipient),
            "amount": format!("{}", self.amount),
            "memo": format!("{}", self.memo),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct STXMintEventData {
    pub recipient: PrincipalData,
    pub amount: u128,
}

impl STXMintEventData {
    pub fn json_serialize(&self) -> serde_json::Value {
        json!({
            "recipient": format!("{}",self.recipient),
            "amount": format!("{}", self.amount),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct STXLockEventData {
    pub locked_amount: u128,
    pub unlock_height: u64,
    pub locked_address: PrincipalData,
    pub contract_identifier: QualifiedContractIdentifier,
}

impl STXLockEventData {
    pub fn json_serialize(&self) -> serde_json::Value {
        json!({
            "locked_amount": format!("{}",self.locked_amount),
            "unlock_height": format!("{}", self.unlock_height),
            "locked_address": format!("{}", self.locked_address),
            "contract_identifier": self.contract_identifier.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct STXBurnEventData {
    pub sender: PrincipalData,
    pub amount: u128,
}

impl STXBurnEventData {
    pub fn json_serialize(&self) -> serde_json::Value {
        json!({
            "sender": format!("{}", self.sender),
            "amount": format!("{}", self.amount),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NFTTransferEventData {
    pub asset_identifier: AssetIdentifier,
    pub sender: PrincipalData,
    pub recipient: PrincipalData,
    pub value: Value,
}

impl NFTTransferEventData {
    pub fn json_serialize(&self) -> Result<serde_json::Value, SerializationError> {
        let mut byte_serialization = Vec::new();
        self.value.serialize_write(&mut byte_serialization)?;
        let raw_value = to_hex_prefixed(byte_serialization.as_slice(), true);
        Ok(json!({
            "asset_identifier": format!("{}", self.asset_identifier),
            "sender": format!("{}",self.sender),
            "recipient": format!("{}",self.recipient),
            "value": self.value,
            "raw_value": raw_value,
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NFTMintEventData {
    pub asset_identifier: AssetIdentifier,
    pub recipient: PrincipalData,
    pub value: Value,
}

impl NFTMintEventData {
    pub fn json_serialize(&self) -> Result<serde_json::Value, SerializationError> {
        let mut byte_serialization = Vec::new();
        self.value.serialize_write(&mut byte_serialization)?;
        let raw_value = to_hex_prefixed(byte_serialization.as_slice(), true);
        Ok(json!({
            "asset_identifier": format!("{}", self.asset_identifier),
            "recipient": format!("{}",self.recipient),
            "value": self.value,
            "raw_value": raw_value,
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NFTBurnEventData {
    pub asset_identifier: AssetIdentifier,
    pub sender: PrincipalData,
    pub value: Value,
}

impl NFTBurnEventData {
    pub fn json_serialize(&self) -> Result<serde_json::Value, SerializationError> {
        let mut byte_serialization = Vec::new();
        self.value.serialize_write(&mut byte_serialization)?;
        let raw_value = to_hex_prefixed(byte_serialization.as_slice(), true);
        Ok(json!({
            "asset_identifier": format!("{}", self.asset_identifier),
            "sender": format!("{}",self.sender),
            "value": self.value,
            "raw_value": raw_value,
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FTTransferEventData {
    pub asset_identifier: AssetIdentifier,
    pub sender: PrincipalData,
    pub recipient: PrincipalData,
    pub amount: u128,
}

impl FTTransferEventData {
    pub fn json_serialize(&self) -> serde_json::Value {
        json!({
            "asset_identifier": format!("{}", self.asset_identifier),
            "sender": format!("{}",self.sender),
            "recipient": format!("{}",self.recipient),
            "amount": format!("{}", self.amount),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FTMintEventData {
    pub asset_identifier: AssetIdentifier,
    pub recipient: PrincipalData,
    pub amount: u128,
}

impl FTMintEventData {
    pub fn json_serialize(&self) -> serde_json::Value {
        json!({
            "asset_identifier": format!("{}", self.asset_identifier),
            "recipient": format!("{}",self.recipient),
            "amount": format!("{}", self.amount),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FTBurnEventData {
    pub asset_identifier: AssetIdentifier,
    pub sender: PrincipalData,
    pub amount: u128,
}

impl FTBurnEventData {
    pub fn json_serialize(&self) -> serde_json::Value {
        json!({
            "asset_identifier": format!("{}", self.asset_identifier),
            "sender": format!("{}",self.sender),
            "amount": format!("{}", self.amount),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SmartContractEventData {
    pub key: (QualifiedContractIdentifier, String),
    pub value: Value,
}

impl SmartContractEventData {
    pub fn json_serialize(&self) -> Result<serde_json::Value, SerializationError> {
        let mut byte_serialization = Vec::new();
        self.value.serialize_write(&mut byte_serialization)?;
        let raw_value = to_hex_prefixed(byte_serialization.as_slice(), true);
        Ok(json!({
            "contract_identifier": self.key.0.to_string(),
            "topic": self.key.1,
            "value": self.value,
            "raw_value": raw_value,
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PostConditionEventData {
    pub principal: PrincipalData,
    pub asset_id: Option<AssetIdentifier>,
    pub condition_code: u8,
    pub amount: Option<u128>,
    pub value: Option<Value>,
    pub expected: String, // Human readable expectation
    pub actual: String,   // Human readable actual value
}

impl PostConditionEventData {
    pub fn json_serialize(&self) -> Result<serde_json::Value, SerializationError> {
        let raw_value = if let Some(ref value) = self.value {
            let mut byte_serialization = Vec::new();
            value.serialize_write(&mut byte_serialization).map_err(|_| SerializationError::Other("failed to serialize value".to_string()))?;
            Some(to_hex_prefixed(byte_serialization.as_slice(), true))
        } else {
            None
        };

        Ok(json!({
            "principal": format!("{}", self.principal),
            "asset_id": self.asset_id.as_ref().map(|id| format!("{}", id)),
            "condition_code": self.condition_code,
            "amount": self.amount.map(|a| format!("{}", a)),
            "value": self.value,
            "raw_value": raw_value,
            "expected": self.expected,
            "actual": self.actual,
        }))
    }
}
