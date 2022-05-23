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

use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::burnchains::Address;
use crate::burnchains::Burnchain;
use crate::burnchains::BurnchainBlock;
use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::PublicKey;
use crate::chainstate::burn::db::sortdb::SortitionHandleTx;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp, UserBurnSupportOp,
};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::burn::{BurnchainHeaderHash, ConsensusHash, OpsHash, SortitionHash, Txid};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::core::*;
use crate::util_lib::db::Error as db_error;
use stacks_common::util::hash::Hash160;
use stacks_common::util::log;
use stacks_common::util::uint::BitArray;
use stacks_common::util::uint::Uint256;
use stacks_common::util::uint::Uint512;

use crate::chainstate::burn::ConsensusHashExtensions;
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::index::TrieHashExtension;
use crate::types::chainstate::StacksBlockId;
use crate::types::chainstate::{BlockHeaderHash, SortitionId, VRFSeed};
use stacks_common::types::chainstate::TrieHash;

impl BlockSnapshot {
    /// Create the sentinel block snapshot -- the first one
    pub fn initial(first_block_height: u64) -> BlockSnapshot {
        BlockSnapshot {
            block_height: first_block_height,
            burn_header_hash: BurnchainHeaderHash::sentinel(),
            burn_header_timestamp: 0,
            parent_burn_header_hash: BurnchainHeaderHash::sentinel(),
            consensus_hash: ConsensusHash([0u8; 20]),
            ops_hash: OpsHash([0u8; 32]),
            total_burn: 0,
            sortition: true,
            sortition_hash: SortitionHash::initial(),
            winning_block_txid: Txid([0u8; 32]),
            winning_stacks_block_hash: FIRST_STACKS_BLOCK_HASH.clone(),
            index_root: TrieHash::from_empty_data(),
            num_sortitions: 0,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: FIRST_STACKS_BLOCK_HASH.clone(),
            canonical_stacks_tip_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            sortition_id: SortitionId::sentinel(),
            parent_sortition_id: SortitionId::sentinel(),
            pox_valid: true,
            accumulated_coinbase_ustx: 0,
        }
    }

    pub fn is_initial(&self) -> bool {
        self.sortition_hash == SortitionHash::initial()
    }

    pub fn get_canonical_stacks_block_id(&self) -> StacksBlockId {
        StacksBlockId::new(&self.consensus_hash, &self.canonical_stacks_tip_hash)
    }

    /// Make the snapshot struct for the case where _no sortition_ takes place
    fn make_snapshot_no_sortition(
        sort_tx: &mut SortitionHandleTx,
        sortition_id: &SortitionId,
        parent_snapshot: &BlockSnapshot,
        block_header: &BurnchainBlockHeader,
        first_block_height: u64,
        burn_total: u64,
        sortition_hash: &SortitionHash,
        txids: &Vec<Txid>,
        accumulated_coinbase_ustx: u128,
    ) -> Result<BlockSnapshot, db_error> {
        let block_height = block_header.block_height;
        let block_hash = block_header.block_hash.clone();
        let parent_block_hash = block_header.parent_block_hash.clone();

        let non_winning_block_txid = Txid::from_bytes(&[0u8; 32]).unwrap();
        let non_winning_block_hash = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();

        let ops_hash = OpsHash::from_txids(txids);
        let ch = ConsensusHash::from_parent_block_data(
            sort_tx,
            &ops_hash,
            block_height - 1,
            first_block_height,
            &block_hash,
            burn_total,
        )?;

        debug!("SORTITION({}): NO BLOCK CHOSEN", block_height);

        Ok(BlockSnapshot {
            block_height: block_height,
            burn_header_hash: block_hash,
            burn_header_timestamp: block_header.timestamp,
            parent_burn_header_hash: parent_block_hash,
            consensus_hash: ch,
            ops_hash: ops_hash,
            total_burn: burn_total,
            sortition: false,
            sortition_hash: sortition_hash.clone(),
            winning_block_txid: non_winning_block_txid,
            winning_stacks_block_hash: non_winning_block_hash,
            index_root: TrieHash::from_empty_data(), // will be overwritten
            num_sortitions: parent_snapshot.num_sortitions,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            canonical_stacks_tip_height: parent_snapshot.canonical_stacks_tip_height,
            canonical_stacks_tip_hash: parent_snapshot.canonical_stacks_tip_hash.clone(),
            canonical_stacks_tip_consensus_hash: parent_snapshot
                .canonical_stacks_tip_consensus_hash
                .clone(),
            sortition_id: sortition_id.clone(),
            parent_sortition_id: parent_snapshot.sortition_id.clone(),
            pox_valid: true,
            accumulated_coinbase_ustx,
        })
    }

    /// Make a block snapshot from is block's data and the previous block.
    /// This process will:
    /// * calculate the new consensus hash
    /// * calculate the total burn so far
    /// * determine whether or not we can do a sortition, and if so,
    /// * carry out the sortition to select the next candidate block.
    ///
    /// All of this is rolled into the BlockSnapshot struct.
    ///
    /// Call this *after* you store all of the block's transactions to the burn db.
    pub fn make_snapshot(
        sort_tx: &mut SortitionHandleTx,
        burnchain: &Burnchain,
        my_sortition_id: &SortitionId,
        parent_snapshot: &BlockSnapshot,
        block_commits: &[LeaderBlockCommitOp],
        block_header: &BurnchainBlockHeader,
        txids: &Vec<Txid>,
        _block_burn_total: Option<u64>,
        initial_mining_bonus_ustx: u128,
    ) -> Result<BlockSnapshot, db_error> {
        assert_eq!(
            parent_snapshot.burn_header_hash,
            block_header.parent_block_hash
        );
        assert_eq!(parent_snapshot.block_height + 1, block_header.block_height);

        let block_height = block_header.block_height;
        let block_hash = block_header.block_hash.clone();
        let parent_block_hash = block_header.parent_block_hash.clone();
        let first_block_height = burnchain.first_block_height;

        let last_sortition_hash = parent_snapshot.sortition_hash.clone();
        let last_burn_total = parent_snapshot.total_burn;

        let accumulated_coinbase_ustx = if parent_snapshot.total_burn == 0 {
            0
        } else if parent_snapshot.sortition {
            initial_mining_bonus_ustx
        } else {
            let missed_coinbase = StacksChainState::get_coinbase_reward(
                parent_snapshot.block_height,
                first_block_height,
            );
            parent_snapshot
                .accumulated_coinbase_ustx
                .saturating_add(missed_coinbase)
                .saturating_add(initial_mining_bonus_ustx)
        };

        // next sortition hash
        let next_sortition_hash = last_sortition_hash.mix_burn_header(&block_hash);
        let mut make_snapshot_no_sortition = || {
            BlockSnapshot::make_snapshot_no_sortition(
                sort_tx,
                my_sortition_id,
                parent_snapshot,
                block_header,
                first_block_height,
                last_burn_total,
                &next_sortition_hash,
                &txids,
                accumulated_coinbase_ustx,
            )
        };

        if block_commits.len() == 0 {
            // no burns happened
            debug!(
                "No burns happened in block";
                "burn_block_height" => %block_height.to_string(),
                "burn_block_hash" => %block_hash.to_string(),
            );

            return make_snapshot_no_sortition();
        }

        // Try to pick a next block.
        let winning_block = &block_commits[0];

        let next_burn_total = 1;

        // no need to mix in VRF seeds in subnets
        let final_sortition_hash = next_sortition_hash;
        let next_ops_hash = OpsHash::from_txids(&txids);
        let next_ch = ConsensusHash::from_parent_block_data(
            sort_tx,
            &next_ops_hash,
            block_height - 1,
            first_block_height,
            &block_hash,
            next_burn_total,
        )?;

        debug!(
            "SORTITION({}): WINNER IS {:?} (from {:?})",
            block_height, &winning_block.block_header_hash, &winning_block.txid
        );

        Ok(BlockSnapshot {
            block_height,
            burn_header_hash: block_hash,
            burn_header_timestamp: block_header.timestamp,
            parent_burn_header_hash: parent_block_hash,
            consensus_hash: next_ch,
            ops_hash: next_ops_hash,
            total_burn: next_burn_total,
            sortition: true,
            sortition_hash: final_sortition_hash,
            winning_block_txid: winning_block.txid,
            winning_stacks_block_hash: winning_block.block_header_hash,
            index_root: TrieHash::from_empty_data(), // will be overwritten,
            num_sortitions: parent_snapshot.num_sortitions + 1,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            canonical_stacks_tip_height: parent_snapshot.canonical_stacks_tip_height,
            canonical_stacks_tip_hash: parent_snapshot.canonical_stacks_tip_hash.clone(),
            canonical_stacks_tip_consensus_hash: parent_snapshot
                .canonical_stacks_tip_consensus_hash
                .clone(),
            sortition_id: my_sortition_id.clone(),
            parent_sortition_id: parent_snapshot.sortition_id.clone(),
            pox_valid: true,
            accumulated_coinbase_ustx,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::burnchains::test::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::operations::*;
    use crate::chainstate::stacks::*;
    use stacks_common::address::*;
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::hash::hex_bytes;
    use stacks_common::util::vrf::VRFPrivateKey;
    use stacks_common::util::vrf::VRFPublicKey;

    use crate::types::chainstate::BlockHeaderHash;
    use crate::types::chainstate::BurnchainHeaderHash;
    use crate::types::chainstate::VRFSeed;

    use super::*;

    fn test_make_snapshot(
        sort_tx: &mut SortitionHandleTx,
        burnchain: &Burnchain,
        my_sortition_id: &SortitionId,
        parent_snapshot: &BlockSnapshot,
        block_header: &BurnchainBlockHeader,
        block_commits: &[LeaderBlockCommitOp],
        txids: &Vec<Txid>,
    ) -> Result<BlockSnapshot, db_error> {
        BlockSnapshot::make_snapshot(
            sort_tx,
            burnchain,
            my_sortition_id,
            parent_snapshot,
            block_commits,
            block_header,
            txids,
            Some(1),
            0,
        )
    }
}
