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
            "raw_value": raw_value,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::types::StandardPrincipalData;
    use crate::vm::{ClarityName, ContractName};

    fn test_principal() -> PrincipalData {
        PrincipalData::Standard(StandardPrincipalData::null_principal())
    }

    fn test_asset_id() -> AssetIdentifier {
        AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::null_principal(),
                ContractName::try_from("test-contract".to_string()).unwrap(),
            ),
            asset_name: ClarityName::try_from("test-nft".to_string()).unwrap(),
        }
    }

    #[test]
    fn nft_transfer_event_json_serialization() {
        let event = NFTTransferEventData {
            asset_identifier: test_asset_id(),
            sender: test_principal(),
            recipient: test_principal(),
            value: Value::UInt(42),
        };
        assert_eq!(
            event.json_serialize().unwrap(),
            json!({
                "asset_identifier": "S0000000000000000000002AA028H.test-contract::test-nft",
                "sender": "S0000000000000000000002AA028H",
                "recipient": "S0000000000000000000002AA028H",
                "raw_value": "0x010000000000000000000000000000002a",
            })
        );
    }

    #[test]
    fn nft_mint_event_json_serialization() {
        let event = NFTMintEventData {
            asset_identifier: test_asset_id(),
            recipient: test_principal(),
            value: Value::UInt(1),
        };
        assert_eq!(
            event.json_serialize().unwrap(),
            json!({
                "asset_identifier": "S0000000000000000000002AA028H.test-contract::test-nft",
                "recipient": "S0000000000000000000002AA028H",
                "raw_value": "0x0100000000000000000000000000000001",
            })
        );
    }

    #[test]
    fn nft_burn_event_json_serialization() {
        let event = NFTBurnEventData {
            asset_identifier: test_asset_id(),
            sender: test_principal(),
            value: Value::UInt(1),
        };
        assert_eq!(
            event.json_serialize().unwrap(),
            json!({
                "asset_identifier": "S0000000000000000000002AA028H.test-contract::test-nft",
                "sender": "S0000000000000000000002AA028H",
                "raw_value": "0x0100000000000000000000000000000001",
            })
        );
    }

    #[test]
    fn smart_contract_event_json_serialization() {
        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::null_principal(),
            ContractName::try_from("test-contract".to_string()).unwrap(),
        );
        let event = SmartContractEventData {
            key: (contract_id, "print".to_string()),
            value: Value::UInt(99),
        };
        assert_eq!(
            event.json_serialize().unwrap(),
            json!({
                "contract_identifier": "S0000000000000000000002AA028H.test-contract",
                "topic": "print",
                "raw_value": "0x0100000000000000000000000000000063",
            })
        );
    }
}
