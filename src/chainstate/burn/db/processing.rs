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

use chainstate::burn::BlockSnapshot;

use chainstate::burn::db::sortdb::{PoxId, SortitionHandleTx, SortitionId};

use chainstate::coordinator::RewardCycleInfo;

use chainstate::burn::operations::{leader_block_commit::RewardSetInfo, BlockstackOperationType};

use burnchains::{
    Burnchain, BurnchainBlockHeader, BurnchainHeaderHash, BurnchainStateTransition,
    Error as BurnchainError,
};

use chainstate::stacks::index::{
    marf::MARF, storage::TrieFileStorage, Error as MARFError, MARFValue, MarfTrieId, TrieHash,
};

use util::db::Error as DBError;

use address::AddressHashMode;

impl<'a> SortitionHandleTx<'a> {
    /// Run a blockstack operation's "check()" method and return the result.
    fn check_transaction(
        &mut self,
        burnchain: &Burnchain,
        blockstack_op: &BlockstackOperationType,
        reward_info: Option<&RewardSetInfo>,
    ) -> Result<(), BurnchainError> {
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                op.check(burnchain, self).map_err(|e| {
                    warn!(
                        "REJECTED({}) leader key register {} at {},{}: {:?}",
                        op.block_height, &op.txid, op.block_height, op.vtxindex, &e
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                op.check(burnchain, self, reward_info).map_err(|e| {
                    warn!(
                        "REJECTED({}) leader block commit {} at {},{}: {:?}",
                        op.block_height, &op.txid, op.block_height, op.vtxindex, &e
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::UserBurnSupport(ref op) => {
                op.check(burnchain, self).map_err(|e| {
                    warn!(
                        "REJECTED({}) user burn support {} at {},{}: {:?}",
                        op.block_height, &op.txid, op.block_height, op.vtxindex, &e
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::StackStx(ref op) => op.check().map_err(|e| {
                warn!(
                    "REJECTED({}) stack stx op {} at {},{}: {:?}",
                    op.block_height, &op.txid, op.block_height, op.vtxindex, &e
                );
                BurnchainError::OpError(e)
            }),
            BlockstackOperationType::PreStackStx(_) => {
                // no check() required for PreStackStx
                Ok(())
            }
        }
    }

    /// Generate the list of blockstack operations that will be snapshotted -- a subset of the
    /// blockstack operations extracted from get_blockstack_transactions.
    /// Return the list of parsed blockstack operations whose check() method has returned true.
    fn check_block_ops(
        &mut self,
        burnchain: &Burnchain,
        mut block_ops: Vec<BlockstackOperationType>,
        reward_info: Option<&RewardSetInfo>,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        debug!(
            "Check Blockstack transactions from sortition_id: {}",
            &self.context.chain_tip
        );

        // classify and check each transaction
        block_ops.retain(|blockstack_op| {
            self.check_transaction(burnchain, blockstack_op, reward_info)
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

    /// Process all block's checked transactions
    /// * make the burn distribution
    /// * insert the ones that went into the burn distribution
    /// * snapshot the block and run the sortition
    /// * return the snapshot (and sortition results)
    fn process_checked_block_ops(
        &mut self,
        burnchain: &Burnchain,
        parent_snapshot: &BlockSnapshot,
        block_header: &BurnchainBlockHeader,
        this_block_ops: &Vec<BlockstackOperationType>,
        next_pox_info: Option<RewardCycleInfo>,
        parent_pox: PoxId,
        reward_info: Option<&RewardSetInfo>,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        let this_block_height = block_header.block_height;
        let this_block_hash = block_header.block_hash.clone();

        // make the burn distribution, and in doing so, identify the user burns that we'll keep
        let state_transition = BurnchainStateTransition::from_block_ops(self, parent_snapshot, this_block_ops, burnchain.pox_constants.sunset_end)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when converting {} blockstack operations in block {} ({}) to a burn distribution: {:?}", this_block_ops.len(), this_block_height, &this_block_hash, e);
                e
            })?;

        let total_burn = state_transition
            .accepted_ops
            .iter()
            .fold(Some(0u64), |acc, op| {
                if let Some(acc) = acc {
                    let bf = match op {
                        BlockstackOperationType::LeaderBlockCommit(ref op) => op.burn_fee,
                        BlockstackOperationType::UserBurnSupport(ref op) => op.burn_fee,
                        _ => 0,
                    };
                    acc.checked_add(bf)
                } else {
                    None
                }
            });

        let txids = state_transition
            .accepted_ops
            .iter()
            .map(|ref op| op.txid())
            .collect();

        let mut next_pox = parent_pox;
        if let Some(ref next_pox_info) = next_pox_info {
            if next_pox_info.is_reward_info_known() {
                info!(
                    "Begin reward-cycle sortition with present anchor block={:?}",
                    &next_pox_info.selected_anchor_block()
                );
                next_pox.extend_with_present_block();
            } else {
                info!(
                    "Begin reward-cycle sortition with absent anchor block={:?}",
                    &next_pox_info.selected_anchor_block()
                );
                next_pox.extend_with_not_present_block();
            }
        };

        let next_sortition_id = SortitionId::new(&this_block_hash, &next_pox);

        // do the cryptographic sortition and pick the next winning block.
        let mut snapshot = BlockSnapshot::make_snapshot(
            self,
            burnchain,
            &next_sortition_id,
            &next_pox,
            parent_snapshot,
            block_header,
            &state_transition.burn_dist,
            &txids,
            total_burn,
        )
        .map_err(|e| {
            error!(
                "TRANSACTION ABORTED when taking snapshot at block {} ({}): {:?}",
                this_block_height, &this_block_hash, e
            );
            BurnchainError::DBError(e)
        })?;

        // store the snapshot
        let index_root = self.append_chain_tip_snapshot(
            parent_snapshot,
            &snapshot,
            &state_transition.accepted_ops,
            next_pox_info,
            reward_info,
        )?;

        snapshot.index_root = index_root;

        debug!("OPS-HASH({}): {}", this_block_height, &snapshot.ops_hash);
        debug!(
            "INDEX-ROOT({}): {}",
            this_block_height, &snapshot.index_root
        );
        debug!(
            "SORTITION-HASH({}): {}",
            this_block_height, &snapshot.sortition_hash
        );
        debug!(
            "CONSENSUS({}): {}",
            this_block_height, &snapshot.consensus_hash
        );
        Ok((snapshot, state_transition))
    }

    /// Check and then commit all blockstack operations to our chainstate.
    /// * pull out all the transactions that are blockstack ops
    /// * select the ones that are _valid_
    /// * do a cryptographic sortition to select the next Stacks block
    /// * commit all valid transactions
    /// * commit the results of the sortition
    /// Returns the BlockSnapshot created from this block.
    pub fn process_block_ops(
        &mut self,
        burnchain: &Burnchain,
        parent_snapshot: &BlockSnapshot,
        block_header: &BurnchainBlockHeader,
        mut blockstack_txs: Vec<BlockstackOperationType>,
        next_pox_info: Option<RewardCycleInfo>,
        parent_pox: PoxId,
        reward_set_info: Option<&RewardSetInfo>,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        debug!(
            "BEGIN({}) block ({},{}) with sortition_id: {}",
            block_header.block_height,
            block_header.block_hash,
            block_header.parent_block_hash,
            &self.context.chain_tip
        );
        debug!(
            "Append {} operation(s) from block {} {}",
            blockstack_txs.len(),
            block_header.block_height,
            &block_header.block_hash
        );

        blockstack_txs.sort_by(|ref a, ref b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());

        // check each transaction, and filter out only the ones that are valid
        let block_ops = self
            .check_block_ops(burnchain, blockstack_txs, reward_set_info)
            .map_err(|e| {
                error!(
                    "TRANSACTION ABORTED when checking block {} ({}): {:?}",
                    block_header.block_height, &block_header.block_hash, e
                );
                e
            })?;

        // process them
        let res = self
            .process_checked_block_ops(
                burnchain,
                parent_snapshot,
                block_header,
                &block_ops,
                next_pox_info,
                parent_pox,
                reward_set_info,
            )
            .map_err(|e| {
                error!(
                    "TRANSACTION ABORTED when snapshotting block {} ({}): {:?}",
                    block_header.block_height, &block_header.block_hash, e
                );
                e
            })?;

        Ok(res)
    }

    /// Given the extracted txs, and a block header, go process them into the next
    /// snapshot.  Unlike process_block_ops, this method applies safety checks against the given
    /// list of blockstack transactions.
    pub fn process_block_txs(
        &mut self,
        parent_snapshot: &BlockSnapshot,
        this_block_header: &BurnchainBlockHeader,
        burnchain: &Burnchain,
        blockstack_txs: Vec<BlockstackOperationType>,
        next_pox_info: Option<RewardCycleInfo>,
        parent_pox: PoxId,
        reward_set_info: Option<&RewardSetInfo>,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        assert_eq!(
            parent_snapshot.block_height + 1,
            this_block_header.block_height
        );
        assert_eq!(
            parent_snapshot.burn_header_hash,
            this_block_header.parent_block_hash
        );

        let new_snapshot = self.process_block_ops(
            burnchain,
            &parent_snapshot,
            &this_block_header,
            blockstack_txs,
            next_pox_info,
            parent_pox,
            reward_set_info,
        )?;
        Ok(new_snapshot)
    }
}
