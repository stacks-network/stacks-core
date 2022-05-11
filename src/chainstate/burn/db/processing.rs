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

use crate::burnchains::{
    Burnchain, BurnchainBlockHeader, BurnchainStateTransition, Error as BurnchainError,
};
use crate::chainstate::burn::db::sortdb::{InitialMiningBonus, SortitionHandleTx};
use crate::chainstate::burn::operations::{
    leader_block_commit::{MissedBlockCommit, RewardSetInfo},
    BlockstackOperationType, Error as OpError,
};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::coordinator::RewardCycleInfo;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::{
    marf::MARF, storage::TrieFileStorage, Error as MARFError, MARFValue, MarfTrieId,
};
use crate::core::INITIAL_MINING_BONUS_WINDOW;
use crate::util_lib::db::Error as DBError;
use stacks_common::address::AddressHashMode;

use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::{BurnchainHeaderHash, SortitionId};

impl<'a> SortitionHandleTx<'a> {
    /// Run a blockstack operation's "check()" method and return the result.
    fn check_transaction(
        &mut self,
        burnchain: &Burnchain,
        blockstack_op: &BlockstackOperationType,
        reward_info: Option<&RewardSetInfo>,
    ) -> Result<(), BurnchainError> {
        match blockstack_op {
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                op.check(burnchain, self, reward_info).map_err(|e| {
                    warn!(
                        "REJECTED burnchain operation";
                        "op" => "leader_block_commit",
                        "l1_stacks_block_id" => %op.burn_header_hash,
                        "txid" => %op.txid,
                        "commited_block_hash" => %op.block_header_hash,
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::DepositStx(ref op) => {
                op.check(burnchain, self, reward_info).map_err(|e| {
                    warn!(
                        "REJECTED burnchain operation";
                        "op" => "deposit_stx",
                        "l1_stacks_block_id" => %op.burn_header_hash,
                        "txid" => %op.txid,
                        "amount" => %op.amount,
                        "sender" => %op.sender,
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::DepositFt(ref op) => {
                op.check(burnchain, self, reward_info).map_err(|e| {
                    warn!(
                        "REJECTED burnchain operation";
                        "op" => "deposit_ft",
                        "l1_stacks_block_id" => %op.burn_header_hash,
                        "txid" => %op.txid,
                        "l1_contract_id" => %op.l1_contract_id,
                        "hc_contract_id" => %op.hc_contract_id,
                        "name" => %op.name,
                        "amount" => %op.amount,
                        "sender" => %op.sender,
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::DepositNft(ref op) => {
                op.check(burnchain, self, reward_info).map_err(|e| {
                    warn!(
                        "REJECTED burnchain operation";
                        "op" => "deposit_nft",
                        "l1_stacks_block_id" => %op.burn_header_hash,
                        "txid" => %op.txid,
                        "l1_contract_id" => %op.l1_contract_id,
                        "hc_contract_id" => %op.hc_contract_id,
                        "id" => %op.id,
                        "sender" => %op.sender,
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::WithdrawFt(ref op) => {
                op.check(burnchain, self, reward_info).map_err(|e| {
                    warn!(
                        "REJECTED burnchain operation";
                        "op" => "withdraw_ft",
                        "l1_stacks_block_id" => %op.burn_header_hash,
                        "txid" => %op.txid,
                        "l1_contract_id" => %op.l1_contract_id,
                        "hc_contract_id" => %op.hc_contract_id,
                        "name" => %op.name,
                        "amount" => %op.amount,
                        "recipient" => %op.recipient,
                    );
                    BurnchainError::OpError(e)
                })
            }
            BlockstackOperationType::WithdrawNft(ref op) => {
                op.check(burnchain, self, reward_info).map_err(|e| {
                    warn!(
                        "REJECTED burnchain operation";
                        "op" => "withdraw_nft",
                        "l1_stacks_block_id" => %op.burn_header_hash,
                        "txid" => %op.txid,
                        "l1_contract_id" => %op.l1_contract_id,
                        "hc_contract_id" => %op.hc_contract_id,
                        "id" => %op.id,
                        "recipient" => %op.recipient,
                    );
                    BurnchainError::OpError(e)
                })
            }
        }
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
        _next_pox_info: Option<RewardCycleInfo>,
        reward_info: Option<&RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        let this_block_height = block_header.block_height;
        let this_block_hash = block_header.block_hash.clone();

        // make the burn distribution, and in doing so, identify the user burns that we'll keep
        let state_transition = BurnchainStateTransition::from_block_ops(self, burnchain, parent_snapshot, this_block_ops)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when converting {} blockstack operations in block {} ({}) to a burn distribution: {:?}", this_block_ops.len(), this_block_height, &this_block_hash, e);
                e
            })?;

        let total_burn = Some(1);

        let txids = state_transition
            .accepted_ops
            .iter()
            .map(|ref op| op.txid())
            .collect();

        // the SortitionId in Hyperchains is always equal to the identifying hash
        // of the L1 block (i.e., the burn block hash)
        let next_sortition_id = SortitionId(this_block_hash.0.clone());

        let block_commits: Vec<_> = this_block_ops
            .iter()
            .filter_map(|op| {
                if let BlockstackOperationType::LeaderBlockCommit(ref commit_op) = op {
                    Some(commit_op.clone())
                } else {
                    None
                }
            })
            .collect();

        // do the cryptographic sortition and pick the next winning block.
        let mut snapshot = BlockSnapshot::make_snapshot(
            self,
            burnchain,
            &next_sortition_id,
            parent_snapshot,
            &block_commits,
            block_header,
            &txids,
            total_burn,
            initial_mining_bonus_ustx,
        )
        .map_err(|e| {
            error!(
                "TRANSACTION ABORTED when taking snapshot at block {} ({}): {:?}",
                this_block_height, &next_sortition_id, e
            );
            BurnchainError::DBError(e)
        })?;

        // was this snapshot the first with mining?
        //  compute the initial block rewards.
        let initialize_bonus = if snapshot.sortition && parent_snapshot.total_burn == 0 {
            let blocks_without_winners =
                snapshot.block_height - burnchain.initial_reward_start_block;
            let mut total_reward = 0;
            for burn_block_height in burnchain.initial_reward_start_block..snapshot.block_height {
                total_reward += StacksChainState::get_coinbase_reward(
                    burn_block_height,
                    self.context.first_block_height,
                );
            }
            let per_block = total_reward / INITIAL_MINING_BONUS_WINDOW as u128;

            info!("First sortition winner chosen";
                  "blocks_without_winners" => blocks_without_winners,
                  "initial_mining_per_block_reward" => per_block,
                  "initial_mining_bonus_block_window" => INITIAL_MINING_BONUS_WINDOW);

            assert_eq!(snapshot.accumulated_coinbase_ustx, 0,
                       "First block should not have receive additional coinbase before initial reward calculation");
            snapshot.accumulated_coinbase_ustx = per_block;

            Some(InitialMiningBonus {
                total_reward,
                per_block,
            })
        } else {
            None
        };

        // store the snapshot
        let index_root = self.append_chain_tip_snapshot(
            parent_snapshot,
            &snapshot,
            &state_transition.accepted_ops,
            reward_info,
            initialize_bonus,
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
        reward_set_info: Option<&RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
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
        debug!(
            "Check Blockstack transactions from sortition_id: {}",
            &self.context.chain_tip
        );

        // classify and check each transaction
        blockstack_txs.retain(|blockstack_op| {
            self.check_transaction(burnchain, blockstack_op, reward_set_info)
                .is_ok()
        });

        // process them
        let res = self
            .process_checked_block_ops(
                burnchain,
                parent_snapshot,
                block_header,
                &blockstack_txs,
                next_pox_info,
                reward_set_info,
                initial_mining_bonus_ustx,
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
        reward_set_info: Option<&RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
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
            reward_set_info,
            initial_mining_bonus_ustx,
        )?;
        Ok(new_snapshot)
    }
}

#[cfg(test)]
mod tests {
    use crate::burnchains::bitcoin::{address::BitcoinAddress, BitcoinNetworkType};
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb::{tests::test_append_snapshot, SortitionDB};
    use crate::chainstate::burn::operations::{
        leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS, LeaderBlockCommitOp, LeaderKeyRegisterOp,
    };
    use crate::chainstate::burn::*;
    use crate::chainstate::stacks::address::StacksAddressExtensions;
    use crate::chainstate::stacks::index::TrieHashExtension;
    use crate::chainstate::stacks::StacksPublicKey;
    use crate::core::MICROSTACKS_PER_STACKS;
    use stacks_common::util::{hash::hex_bytes, vrf::VRFPublicKey};

    use crate::types::chainstate::{BlockHeaderHash, StacksAddress, VRFSeed};

    use super::*;

    #[test]
    fn test_initial_block_reward() {
        let first_burn_hash = BurnchainHeaderHash([0; 32]);

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash([0x22; 32]),
            txid: Txid::from_bytes_be(
                &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf")
                    .unwrap(),
            )
            .unwrap(),
            burn_header_hash: BurnchainHeaderHash([0x03; 32]),
        };

        let mut burnchain = Burnchain::default_unittest(100, &first_burn_hash);
        burnchain.initial_reward_start_block = 90;
        let mut db = SortitionDB::connect_test(100, &first_burn_hash).unwrap();

        let snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x01; 32]), &vec![]);

        let next_block_header = BurnchainBlockHeader {
            block_height: 102,
            block_hash: BurnchainHeaderHash([0x03; 32]),
            parent_block_hash: BurnchainHeaderHash([0x01; 32]),
            num_txs: 1,
            timestamp: 10,
        };

        {
            let mut ic = SortitionHandleTx::begin(&mut db, &snapshot.sortition_id).unwrap();

            let processed = ic
                .process_block_ops(
                    &burnchain,
                    &snapshot,
                    &next_block_header,
                    vec![BlockstackOperationType::LeaderBlockCommit(block_commit)],
                    None,
                    None,
                    0,
                )
                .unwrap();

            let reward_per_block = ic
                .get_initial_mining_bonus_per_block(&processed.0.sortition_id)
                .unwrap()
                .unwrap();
            let remaining = ic
                .get_initial_mining_bonus_remaining(&processed.0.sortition_id)
                .unwrap();
            assert_eq!(
                reward_per_block,
                1000 * (MICROSTACKS_PER_STACKS as u128) * (102 - 90)
                    / (INITIAL_MINING_BONUS_WINDOW as u128)
            );
            assert_eq!(
                remaining,
                reward_per_block * (INITIAL_MINING_BONUS_WINDOW as u128 - 1)
            );
        }
    }
}
