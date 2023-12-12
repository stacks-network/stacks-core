#![warn(unused_imports)]

use clarity::vm::{
    ast::ASTRules, 
    tests::BurnStateDB, database::v2::ClarityDbKvStore
};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash, ConsensusHash, BlockHeaderHash};

use crate::{
    chainstate::stacks::{
            events::StacksTransactionReceipt, StacksTransaction, index::{
            trie_db::TrieDb, marf::MARF
            }
    }, 
    clarity_vm::clarity::{
        ClarityInstance, ClarityTransactionConnection,
    },
};
use stacks_chainstate::StacksChainState;

use super::{
    ClarityTx, DBConfig, CHAINSTATE_VERSION, StacksAccount,
};

pub mod stacks_chainstate;
pub mod stacks_chainstate_db;
pub mod utils;
pub mod transactions;
pub mod blocks;
pub mod contracts;
pub mod boot;

#[derive(Debug)]
pub enum ChainStateError {}

pub type Result<T> = std::result::Result<T, ChainStateError>;

pub struct StacksChainStateImpl<KvDB>
where
    KvDB: TrieDb + ClarityDbKvStore
{
    conn: KvDB,
    is_mainnet: bool,
    chain_id: u32,
    clarity_state: ClarityInstance<KvDB>,
    state_index: MARF<StacksBlockId, KvDB>,
}

impl<KvDB> StacksChainStateImpl<KvDB> 
where
    KvDB: TrieDb + ClarityDbKvStore
{
    /// Retrieves this instance's configuration as a [`DBConfig`] struct.
    fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.is_mainnet,
            chain_id: self.chain_id,
            version: CHAINSTATE_VERSION.to_string(),
        }
    }
}

impl<KvDB> StacksChainState for StacksChainStateImpl<KvDB> 
where
    KvDB: TrieDb + ClarityDbKvStore
{
    fn get_genesis_root_hash(&self) -> Result<TrieHash> {
        Self::get_genesis_root_hash(self)
    }

    fn genesis_block_begin(
        &mut self,
        burn_dbconn: &impl BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx {
        Self::genesis_block_begin(
            self,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    fn process_transaction_payload(
        clarity_tx: &mut ClarityTransactionConnection,
        tx: &StacksTransaction,
        origin_account: &StacksAccount,
        ast_rules: ASTRules,
    ) -> Result<StacksTransactionReceipt> {
        Self::process_transaction_payload(clarity_tx, tx, origin_account, ast_rules)
    }
}