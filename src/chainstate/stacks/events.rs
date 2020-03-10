use super::StacksAddress;
use vm::types::{
    Value,
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier,
    AssetIdentifier
};

#[derive(Debug, Clone, PartialEq)]
pub enum StacksTransactionEvent {
    SmartContractEvent(SmartContractEventData),
    STXEvent(STXEventType),
    NFTEvent(NFTEventType),
    FTEvent(FTEventType),
}

#[derive(Debug, Clone, PartialEq)]
pub enum STXEventType {
    STXTransferEvent(STXTransferEventData),
    STXMintEvent(STXMintEventData),
    STXBurnEvent(STXBurnEventData)
}

#[derive(Debug, Clone, PartialEq)]
pub enum NFTEventType {
    NFTTransferEvent(NFTTransferEventData),
    NFTMintEvent(NFTMintEventData),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FTEventType {
    FTTransferEvent(FTTransferEventData),
    FTMintEvent(FTMintEventData),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct STXTransferEventData {
    pub sender: PrincipalData,
    pub recipient: PrincipalData,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct STXMintEventData {
    pub recipient: PrincipalData,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct STXBurnEventData {
    pub sender: PrincipalData,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NFTTransferEventData {
    pub asset_identifier: AssetIdentifier,
    pub sender: PrincipalData,
    pub recipient: PrincipalData,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NFTMintEventData {
    pub asset_identifier: AssetIdentifier,
    pub recipient: PrincipalData,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FTTransferEventData {
    pub asset_identifier: AssetIdentifier,
    pub sender: PrincipalData,
    pub recipient: PrincipalData,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FTMintEventData {
    pub asset_identifier: AssetIdentifier,
    pub recipient: PrincipalData,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartContractEventData {
    pub key: (QualifiedContractIdentifier, String),
    pub value: Value,
}
