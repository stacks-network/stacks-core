/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use chainstate::burn::{
    BlockSnapshot,
};

use chainstate::burn::db::burndb::{
    BurnDBTx, BurnDB,
};

use chainstate::burn::operations::{
    BlockstackOperation,
    BlockstackOperationType
};

use burnchains::{
    BurnchainHeaderHash, Burnchain, BurnchainBlockHeader, BurnchainStateTransition,
    Error as BurnchainError
};

use chainstate::stacks::index::{
    TrieHash, MarfTrieId, storage::TrieFileStorage,
    marf::MARF, MARFValue, Error as MARFError
};

use util::db::Error as DBError;

use address::AddressHashMode;

impl <'a> BurnDBTx <'a> {

    /// Uses the transaction's current fork identifier to get a block snapshot by
    ///   burnchain block header
    pub fn get_block_snapshot(&self, header: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, DBError> {
        BurnDB::get_block_snapshot(self, header)
    }

    pub fn get_index_value_by_burnheader(&self, burn_header_hash: &BurnchainHeaderHash, key: &str) -> Result<Option<String>, DBError> {
        self.get_indexed(burn_header_hash, key)
    }

    /// Get the abstracted burnchain header from an abstracted burnchain block, as well as its
    /// parent snapshot.
    /// the txs won't be considered; only the linkage to its parent.
    /// Returns the burnchain block header (with all fork information filled in), as well as the
    /// chain tip to which it will be attached.
    pub fn get_burnchain_block_attachment_info(&mut self, header: &BurnchainBlockHeader) ->  Result<BlockSnapshot, BurnchainError> {
        debug!("Get parent sortition snapshot for block {} {}", &header.block_height, &header.block_hash);

        BurnDB::get_block_snapshot(self, &header.parent_block_hash)?
            .ok_or_else(|| {
                warn!("Unknown block {:?}", header.parent_block_hash);
                BurnchainError::MissingParentBlock
            })
    }

    /// Given the extracted txs, and a block header, go process them into the next
    /// snapshot.  Unlike process_block_ops, this method applies safety checks against the given
    /// list of blockstack transactions.
    pub fn process_block_txs(&mut self, parent_snapshot: &BlockSnapshot, this_block_header: &BurnchainBlockHeader, burnchain: &Burnchain, blockstack_txs: Vec<BlockstackOperationType>) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        assert_eq!(parent_snapshot.block_height + 1, this_block_header.block_height);
        assert_eq!(parent_snapshot.burn_header_hash, this_block_header.parent_block_hash);

        let new_snapshot = self.process_block_ops(burnchain, &parent_snapshot, &this_block_header, blockstack_txs)?;
        Ok(new_snapshot)
    }

    /// Run a blockstack operation's "check()" method and return the result.
    fn check_transaction(&self, burnchain: &Burnchain, block_header: &BurnchainBlockHeader, blockstack_op: &BlockstackOperationType) -> Result<(), BurnchainError> {
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                op.check(burnchain, block_header, self)
                    .map_err(|e| {
                        warn!("REJECTED({}) leader key register {} at {},{}: {:?}", op.block_height, &op.txid, op.block_height, op.vtxindex, &e);
                        BurnchainError::OpError(e)
                    })
            },
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                op.check(burnchain, block_header, self)
                    .map_err(|e| {
                        warn!("REJECTED({}) leader block commit {} at {},{}: {:?}", op.block_height, &op.txid, op.block_height, op.vtxindex, &e);
                        BurnchainError::OpError(e)
                    })
            },
            BlockstackOperationType::UserBurnSupport(ref op) => {
                op.check(burnchain, block_header, self)
                    .map_err(|e| {
                        warn!("REJECTED({}) user burn support {} at {},{}: {:?}", op.block_height, &op.txid, op.block_height, op.vtxindex, &e);
                        BurnchainError::OpError(e)
                    })
            }
        }
    }

    /// Generate the list of blockstack operations that will be snapshotted -- a subset of the
    /// blockstack operations extracted from get_blockstack_transactions.
    /// Return the list of parsed blockstack operations whose check() method has returned true.
    fn check_block_ops(&self, burnchain: &Burnchain, block_header: &BurnchainBlockHeader, mut block_ops: Vec<BlockstackOperationType>) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        debug!("Check Blockstack transactions from block {} {}", block_header.block_height, &block_header.block_hash);

        // classify and check each transaction
        block_ops.retain(|blockstack_op| {
            self.check_transaction(burnchain, block_header, blockstack_op)
                .is_ok()
        });

        // block-wide check: no duplicate keys registered
        let ret_filtered = Burnchain::filter_block_VRF_dups(block_ops);
        assert!(Burnchain::ops_are_sorted(&ret_filtered));
    
        // block-wide check: at most one block-commit can consume a VRF key
        let ret_filtered = Burnchain::filter_block_commits_with_same_VRF_key(ret_filtered);
        assert!(Burnchain::ops_are_sorted(&ret_filtered));

        Ok(ret_filtered)
    }

    /// Check and then commit all blockstack operations to our chainstate.
    /// * pull out all the transactions that are blockstack ops
    /// * select the ones that are _valid_ 
    /// * do a cryptographic sortition to select the next Stacks block
    /// * commit all valid transactions
    /// * commit the results of the sortition
    /// Returns the BlockSnapshot created from this block.
    pub fn process_block_ops(&mut self, burnchain: &Burnchain, parent_snapshot: &BlockSnapshot, block_header: &BurnchainBlockHeader, blockstack_txs: Vec<BlockstackOperationType>) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        debug!("BEGIN({}) block ({},{})", block_header.block_height, block_header.block_hash, block_header.parent_block_hash);
        debug!("Append {} operation(s) from block {} {}", blockstack_txs.len(), block_header.block_height, &block_header.block_hash);

        // check each transaction, and filter out only the ones that are valid 
        let block_ops = self.check_block_ops(burnchain, block_header, blockstack_txs)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when checking block {} ({}): {:?}", block_header.block_height, &block_header.block_hash, e);
                e
            })?;

        // process them 
        let res = self.process_checked_block_ops(burnchain, parent_snapshot, block_header, &block_ops)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when snapshotting block {} ({}): {:?}", block_header.block_height, &block_header.block_hash, e);
                e
            })?;

        Ok(res)
    }

    /// Process all block's checked transactions 
    /// * make the burn distribution
    /// * insert the ones that went into the burn distribution
    /// * snapshot the block and run the sortition
    /// * return the snapshot (and sortition results)
    fn process_checked_block_ops(&mut self, burnchain: &Burnchain, parent_snapshot: &BlockSnapshot, block_header: &BurnchainBlockHeader, this_block_ops: &Vec<BlockstackOperationType>) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        let this_block_height = block_header.block_height;
        let this_block_hash = block_header.block_hash.clone();

        // make the burn distribution, and in doing so, identify the user burns that we'll keep
        let state_transition = BurnchainStateTransition::from_block_ops(&self.as_conn(), parent_snapshot, this_block_ops)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when converting {} blockstack operations in block {} ({}) to a burn distribution: {:?}", this_block_ops.len(), this_block_height, &this_block_hash, e);
                e
            })?;

        let txids = state_transition.accepted_ops.iter().map(|ref op| op.txid()).collect();
        
        // do the cryptographic sortition and pick the next winning block.
        let mut snapshot = BlockSnapshot::make_snapshot(&self.as_conn(), burnchain, parent_snapshot, block_header, &state_transition.burn_dist, &txids)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when taking snapshot at block {} ({}): {:?}", this_block_height, &this_block_hash, e);
                BurnchainError::DBError(e)
            })?;
        
        // store the snapshot
        let index_root = BurnDB::append_chain_tip_snapshot(self, parent_snapshot, &snapshot, &state_transition.accepted_ops, &state_transition.consumed_leader_keys)?;

        snapshot.index_root = index_root;

        debug!("OPS-HASH({}): {}", this_block_height, &snapshot.ops_hash);
        debug!("INDEX-ROOT({}): {}", this_block_height, &snapshot.index_root);
        debug!("SORTITION-HASH({}): {}", this_block_height, &snapshot.sortition_hash);
        debug!("CONSENSUS({}): {}", this_block_height, &snapshot.consensus_hash);
        Ok((snapshot, state_transition))
    }
}
