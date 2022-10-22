use crate::burnchains::Txid;
use crate::chainstate::stacks::StacksMicroblockHeader;
use crate::chainstate::stacks::StacksTransaction;
use crate::codec::StacksMessageCodec;
use crate::types::chainstate::StacksAddress;
use clarity::util::hash::to_hex;
use clarity::vm::analysis::ContractAnalysis;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{
    AssetIdentifier, PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value,
};

pub use clarity::vm::events::StacksTransactionEvent;

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionOrigin {
    Stacks(StacksTransaction),
    Burn(Txid),
    NetworkProtocol,
}

impl From<StacksTransaction> for TransactionOrigin {
    fn from(o: StacksTransaction) -> TransactionOrigin {
        TransactionOrigin::Stacks(o)
    }
}

impl TransactionOrigin {
    pub fn txid(&self) -> Txid {
        match self {
            TransactionOrigin::Burn(txid) => txid.clone(),
            TransactionOrigin::Stacks(tx) => tx.txid(),
            TransactionOrigin::NetworkProtocol => Txid([0; 32]),
        }
    }
    /// Serialize this origin type to a string that can be stored in
    ///  a database
    pub fn serialize_to_dbstring(&self) -> String {
        match self {
            TransactionOrigin::Burn(txid) => format!("BTC({})", txid),
            TransactionOrigin::Stacks(tx) => to_hex(&tx.serialize_to_vec()),
            TransactionOrigin::NetworkProtocol => "InternalNetworkBookkeeping".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransactionReceipt {
    pub transaction: TransactionOrigin,
    pub events: Vec<StacksTransactionEvent>,
    pub post_condition_aborted: bool,
    pub result: Value,
    pub stx_burned: u128,
    pub contract_analysis: Option<ContractAnalysis>,
    pub execution_cost: ExecutionCost,
    pub microblock_header: Option<StacksMicroblockHeader>,
    pub tx_index: u32,
    /// This is really a string-formatted CheckError (which can't be clone()'ed)
    pub vm_error: Option<String>,
}
