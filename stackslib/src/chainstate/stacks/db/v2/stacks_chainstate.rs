use clarity::vm::{
    ast::ASTRules, 
    tests::BurnStateDB
};
use stacks_common::types::chainstate::{TrieHash, ConsensusHash, BlockHeaderHash};

use crate::{
    chainstate::stacks::{
            Error, events::StacksTransactionReceipt, StacksTransaction
    }, 
    clarity_vm::clarity::ClarityTransactionConnection,
};

use super::super::{ClarityTx, StacksAccount};

pub trait StacksChainState {
    fn get_genesis_root_hash(&self) -> Result<TrieHash, Error>;

    /// Begin a transaction against the Clarity VM for initiating the genesis block
    ///  the genesis block is special cased because it must be evaluated _before_ the
    ///  cost contract is loaded in the boot code.
    fn genesis_block_begin(
        &mut self,
        burn_dbconn: &impl BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx;

    fn process_transaction_payload(
        clarity_tx: &mut ClarityTransactionConnection,
        tx: &StacksTransaction,
        origin_account: &StacksAccount,
        ast_rules: ASTRules,
    ) -> Result<StacksTransactionReceipt, Error>;
}