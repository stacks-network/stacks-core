


use clarity::vm::tests::BurnStateDB;
use stacks_common::types::chainstate::{TrieHash, ConsensusHash, BlockHeaderHash};

use crate::{
    chainstate::stacks::{
            Error, StacksBlockHeader, 
            index::{
                db::DbConnection, trie_db::TrieDb
            }
    }, 
    core::{
        FIRST_BURNCHAIN_CONSENSUS_HASH, 
        FIRST_STACKS_BLOCK_HASH
    },
};

use super::{
    super::ClarityTx,
    utils::ChainStateUtils,
    StacksChainStateImpl
};

impl<Conn> StacksChainStateImpl<Conn>
where
    Conn: DbConnection + TrieDb
{
    /// Retrieves the root hash of the genesis block.
    pub fn get_genesis_root_hash(&self) -> Result<TrieHash, Error> {
        let root_hash = self.clarity_state.with_marf(|marf| {
            let index_block_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash)
        })?;

        Ok(root_hash)
    }

    /// Begin a transaction against the Clarity VM for initiating the genesis block
    ///  the genesis block is special cased because it must be evaluated _before_ the
    ///  cost contract is loaded in the boot code.
    pub fn genesis_block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            ChainStateUtils::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }
}