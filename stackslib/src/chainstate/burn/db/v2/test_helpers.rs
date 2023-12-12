use std::ops::Deref;

use crate::chainstate::stacks::index::trie_db::TrieDb;

use super::{SortitionDb, SortitionDbTransaction};

pub struct InMemorySortitionDb {

}

impl SortitionDbTransaction for InMemorySortitionDb {
    fn commit() -> super::Result<()> {
        todo!()
    }

    fn rollback() -> super::Result<()> {
        todo!()
    }

    fn get_chain_tip(&self) -> super::Result<stacks_common::types::chainstate::SortitionId> {
        todo!()
    }

    fn store_preprocessed_reward_set(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
        rc_info: &crate::chainstate::coordinator::RewardCycleInfo,
    ) -> super::Result<()> {
        todo!()
    }

    fn revalidate_snapshot_with_block(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
        canonical_stacks_ch: &stacks_common::types::chainstate::ConsensusHash,
        canonical_stacks_bhh: &stacks_common::types::chainstate::BlockHeaderHash,
        canonical_stacks_height: u64,
        stacks_block_accepted: Option<bool>,
    ) -> super::Result<()> {
        todo!()
    }

    fn invalidate_descendants_with_closures<F, G>(
        &self,
        burn_block: &stacks_common::types::chainstate::BurnchainHeaderHash,
        cls: F,
        after: G,
    ) -> super::Result<()>
    where
        Self: Sized,
        F: FnMut(&mut Self, &stacks_common::types::chainstate::BurnchainHeaderHash, &Vec<stacks_common::types::chainstate::BurnchainHeaderHash>) -> (),
        G: FnMut(&mut Self) -> () {
        todo!()
    }

    fn invalidate_descendants_of(
        &self,
        burn_block: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<()> {
        todo!()
    }

    fn evaluate_sortition<F: FnOnce(Option<crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo>) -> ()>(
        &self,
        burn_header: &crate::burnchains::BurnchainBlockHeader,
        ops: Vec<crate::chainstate::burn::operations::BlockstackOperationType>,
        burnchain: &crate::burnchains::Burnchain,
        from_tip: &stacks_common::types::chainstate::SortitionId,
        next_pox_info: Option<crate::chainstate::coordinator::RewardCycleInfo>,
        announce_to: F,
    ) -> super::Result<(crate::chainstate::burn::BlockSnapshot, crate::burnchains::BurnchainStateTransition)> {
        todo!()
    }

    fn append_chain_tip_snapshot(
        &self,
        parent_snapshot: &crate::chainstate::burn::BlockSnapshot,
        snapshot: &crate::chainstate::burn::BlockSnapshot,
        block_ops: &Vec<crate::chainstate::burn::operations::BlockstackOperationType>,
        missed_commits: &Vec<crate::chainstate::burn::operations::leader_block_commit::MissedBlockCommit>,
        next_pox_info: Option<crate::chainstate::coordinator::RewardCycleInfo>,
        reward_info: Option<&crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo>,
        initialize_bonus: Option<crate::chainstate::burn::db::sortdb::InitialMiningBonus>,
    ) -> super::Result<stacks_common::types::chainstate::TrieHash> {
        todo!()
    }

    fn store_transition_ops(
        &self,
        new_sortition: &stacks_common::types::chainstate::SortitionId,
        transition: &crate::burnchains::BurnchainStateTransition,
    ) -> super::Result<()> {
        todo!()
    }

    fn store_burnchain_transaction(
        &self,
        blockstack_op: &crate::chainstate::burn::operations::BlockstackOperationType,
        sort_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_leader_key(
        &self,
        leader_key: &crate::chainstate::burn::operations::LeaderKeyRegisterOp,
        sort_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_stack_stx(
        &self, 
        op: &crate::chainstate::burn::operations::StackStxOp
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_delegate_stx(
        &self, 
        op: &crate::chainstate::burn::operations::DelegateStxOp
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_peg_in_sbtc(
        &self, 
        op: &crate::chainstate::burn::operations::PegInOp
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_sbtc_peg_out_request(
        &self, 
        op: &crate::chainstate::burn::operations::PegOutRequestOp
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_sbtc_peg_out_fulfill(
        &self, 
        op: &crate::chainstate::burn::operations::PegOutFulfillOp
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_transfer_stx(
        &self, 
        op: &crate::chainstate::burn::operations::TransferStxOp
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_block_commit(
        &self,
        block_commit: &crate::chainstate::burn::operations::LeaderBlockCommitOp,
        sort_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_user_burn(
        &self,
        user_burn: &crate::chainstate::burn::operations::UserBurnSupportOp,
        sort_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_missed_block_commit(
        &self, 
        op: &crate::chainstate::burn::operations::leader_block_commit::MissedBlockCommit
    ) -> super::Result<()> {
        todo!()
    }

    fn insert_block_snapshot(
        &self,
        snapshot: &crate::chainstate::burn::BlockSnapshot,
        total_pox_payouts: (Vec<crate::chainstate::stacks::address::PoxAddress>, u128),
    ) -> super::Result<()> {
        todo!()
    }

    fn index_add_fork_info(
        &self,
        parent_snapshot: &mut crate::chainstate::burn::BlockSnapshot,
        snapshot: &crate::chainstate::burn::BlockSnapshot,
        block_ops: &[crate::chainstate::burn::operations::BlockstackOperationType],
        next_pox_info: Option<crate::chainstate::coordinator::RewardCycleInfo>,
        recipient_info: Option<&crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo>,
        initialize_bonus: Option<crate::chainstate::burn::db::sortdb::InitialMiningBonus>,
    ) -> super::Result<(stacks_common::types::chainstate::TrieHash, (Vec<crate::chainstate::stacks::address::PoxAddress>, u128))> {
        todo!()
    }

    fn update_new_block_arrivals(
        &self,
        tip: &crate::chainstate::burn::BlockSnapshot,
        best_chh: stacks_common::types::chainstate::ConsensusHash,
        best_bhh: stacks_common::types::chainstate::BlockHeaderHash,
        best_height: u64,
    ) -> super::Result<()> {
        todo!()
    }

    fn process_new_block_arrivals(
        &self,
        parent_tip: &mut crate::chainstate::burn::BlockSnapshot,
    ) -> super::Result<(Vec<String>, Vec<String>)> {
        todo!()
    }

    fn process_checked_block_ops(
        &self,
        burnchain: &crate::burnchains::Burnchain,
        parent_snapshot: &crate::chainstate::burn::BlockSnapshot,
        block_header: &crate::burnchains::BurnchainBlockHeader,
        this_block_ops: &Vec<crate::chainstate::burn::operations::BlockstackOperationType>,
        missed_commits: &Vec<crate::chainstate::burn::operations::leader_block_commit::MissedBlockCommit>,
        next_pox_info: Option<crate::chainstate::coordinator::RewardCycleInfo>,
        parent_pox: stacks_common::types::chainstate::PoxId,
        reward_info: Option<&crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
    ) -> super::Result<(crate::chainstate::burn::BlockSnapshot, crate::burnchains::BurnchainStateTransition)> {
        todo!()
    }

    fn process_block_ops(
        &self,
        burnchain: &crate::burnchains::Burnchain,
        parent_snapshot: &crate::chainstate::burn::BlockSnapshot,
        block_header: &crate::burnchains::BurnchainBlockHeader,
        blockstack_txs: Vec<crate::chainstate::burn::operations::BlockstackOperationType>,
        next_pox_info: Option<crate::chainstate::coordinator::RewardCycleInfo>,
        parent_pox: stacks_common::types::chainstate::PoxId,
        reward_set_info: Option<&crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
    ) -> super::Result<(crate::chainstate::burn::BlockSnapshot, crate::burnchains::BurnchainStateTransition)> {
        todo!()
    }

    fn process_block_txs(
        &mut self,
        parent_snapshot: &crate::chainstate::burn::BlockSnapshot,
        this_block_header: &crate::burnchains::BurnchainBlockHeader,
        burnchain: &crate::burnchains::Burnchain,
        blockstack_txs: Vec<crate::chainstate::burn::operations::BlockstackOperationType>,
        next_pox_info: Option<crate::chainstate::coordinator::RewardCycleInfo>,
        parent_pox: stacks_common::types::chainstate::PoxId,
        reward_set_info: Option<&crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
    ) -> super::Result<(crate::chainstate::burn::BlockSnapshot, crate::burnchains::BurnchainStateTransition)> {
        todo!()
    }
}

impl TrieDb for InMemorySortitionDb {
    fn create_tables_if_needed(&self) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn migrate_tables_if_needed<T: crate::chainstate::stacks::index::MarfTrieId>(&self) -> Result<u64, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_block_identifier<T: crate::chainstate::stacks::index::MarfTrieId>(&self, bhh: &T) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_mined_block_identifier<T: crate::chainstate::stacks::index::MarfTrieId>(&self, bhh: &T) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_confirmed_block_identifier<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_unconfirmed_block_identifier<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_block_hash<T: crate::chainstate::stacks::index::MarfTrieId>(&self, local_id: u32) -> Result<T, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn write_trie_blob<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn update_external_trie_blob<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn write_external_trie_blob<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
    ) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn write_trie_blob_to_mined<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn write_trie_blob_to_unconfirmed<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn open_trie_blob<'a>(conn: &'a rusqlite::Connection, block_id: u32) -> Result<rusqlite::blob::Blob<'a>, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn open_trie_blob_readonly<'a>(conn: &'a rusqlite::Connection, block_id: u32) -> Result<rusqlite::blob::Blob<'a>, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn read_node_hash_bytes<W: std::io::prelude::Write>(
        &self,
        w: &mut W,
        block_id: u32,
        ptr: &crate::chainstate::stacks::index::node::TriePtr,
    ) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn read_node_hash_bytes_by_bhh<W: std::io::prelude::Write, T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        w: &mut W,
        bhh: &T,
        ptr: &crate::chainstate::stacks::index::node::TriePtr,
    ) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn read_node_type(
        &self,
        block_id: u32,
        ptr: &crate::chainstate::stacks::index::node::TriePtr,
    ) -> Result<(crate::chainstate::stacks::index::node::TrieNodeType, stacks_common::types::chainstate::TrieHash), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn read_node_type_nohash(
        &self,
        block_id: u32,
        ptr: &crate::chainstate::stacks::index::node::TriePtr,
    ) -> Result<crate::chainstate::stacks::index::node::TrieNodeType, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_external_trie_offset_length(
        &self,
        block_id: u32,
    ) -> Result<(u64, u64), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_external_trie_offset_length_by_bhh<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<(u64, u64), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_external_blobs_length(&self) -> Result<u64, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn detect_partial_migration(&self) -> Result<bool, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn set_migrated(&self) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_node_hash_bytes(
        &self,
        block_id: u32,
        ptr: &crate::chainstate::stacks::index::node::TriePtr,
    ) -> Result<stacks_common::types::chainstate::TrieHash, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn get_node_hash_bytes_by_bhh<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
        bhh: &T,
        ptr: &crate::chainstate::stacks::index::node::TriePtr,
    ) -> Result<stacks_common::types::chainstate::TrieHash, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn tx_lock_bhh_for_extension<T: crate::chainstate::stacks::index::MarfTrieId>(
        tx: &rusqlite::Connection,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn lock_bhh_for_extension<T: crate::chainstate::stacks::index::MarfTrieId>(
        tx: &rusqlite::Transaction,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn count_blocks(&self) -> Result<u32, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool, crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn drop_lock<T: crate::chainstate::stacks::index::MarfTrieId>(&self, bhh: &T) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn drop_unconfirmed_trie<T: crate::chainstate::stacks::index::MarfTrieId>(&self, bhh: &T) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn clear_lock_data(&self) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    fn clear_tables(tx: &rusqlite::Transaction) -> Result<(), crate::chainstate::stacks::index::Error> {
        todo!()
    }

    #[cfg(test)]
    fn read_all_block_hashes_and_roots<T: crate::chainstate::stacks::index::MarfTrieId>(
        &self,
    ) -> Result<Vec<(stacks_common::types::chainstate::TrieHash, T)>, crate::chainstate::stacks::index::Error> {
        todo!()
    }
}


impl SortitionDb for InMemorySortitionDb {
    fn connect(
        path: &str,
        first_block_height: u64,
        first_burn_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
        epochs: &[crate::core::StacksEpoch],
        pox_constants: crate::burnchains::PoxConstants,
        readwrite: bool,
    ) -> super::Result<Self>
    where
        Self: Sized {
        todo!()
    }

    fn get_block_commit(
        &self,
        txid: &crate::burnchains::Txid,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<crate::chainstate::burn::operations::LeaderBlockCommitOp>> {
        todo!()
    }

    fn get_block_commit_parent_sortition_id(
        &self,
        txid: &crate::burnchains::Txid,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn get_all_snapshots(
        &self
    ) -> super::Result<Vec<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_all_snapshots_for_burn_block(
        &self,
        bhh: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Vec<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_consensus_hash_height(&self, ch: &stacks_common::types::chainstate::ConsensusHash) -> super::Result<Option<u64>> {
        todo!()
    }

    fn get_highest_block_height_from_path(
        &self, 
        path: &str
    ) -> super::Result<u64> {
        todo!()
    }

    fn get_ast_rules(
        &self, 
        height: u64
    ) -> super::Result<clarity::vm::ast::ASTRules> {
        todo!()
    }

    fn get_preprocessed_reward_set(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<crate::chainstate::coordinator::RewardCycleInfo>> {
        todo!()
    }

    fn find_sortition_tip_affirmation_map(
        &self,
        chain_tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<crate::burnchains::affirmation::AffirmationMap> {
        todo!()
    }

    fn get_stacks_header_hashes(
        &self,
        num_headers: u64,
        tip_consensus_hash: &stacks_common::types::chainstate::ConsensusHash,
        cache: &crate::chainstate::burn::db::sortdb::BlockHeaderCache,
    ) -> super::Result<Vec<(stacks_common::types::chainstate::ConsensusHash, Option<stacks_common::types::chainstate::BlockHeaderHash>)>> {
        todo!()
    }

    fn find_parent_snapshot_for_stacks_block(
        &self,
        consensus_hash: &stacks_common::types::chainstate::ConsensusHash,
        block_hash: &stacks_common::types::chainstate::BlockHeaderHash,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_reward_set_size_at(
        &self, 
        sortition_id: &stacks_common::types::chainstate::SortitionId
    ) -> super::Result<u16> {
        todo!()
    }

    fn get_reward_set_entry_at(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
        entry_ix: u16,
    ) -> super::Result<crate::chainstate::stacks::address::PoxAddress> {
        todo!()
    }

    fn get_reward_set_payouts_at(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<(Vec<crate::chainstate::stacks::address::PoxAddress>, u128)> {
        todo!()
    }

    fn get_sortition_id(
        &self,
        burnchain_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
        sortition_tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn is_sortition_processed(
        &self,
        burnchain_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Option<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn get_block_height(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<u32>> {
        todo!()
    }

    fn is_stacks_block_pox_anchor(
        &self,
        block: &stacks_common::types::chainstate::BlockHeaderHash,
        sortition_tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<stacks_common::types::chainstate::BlockHeaderHash>> {
        todo!()
    }

    fn find_snapshots_with_dirty_canonical_block_pointers(
        &self,
        canonical_stacks_height: u64,
    ) -> super::Result<Vec<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn get_prepare_end_for(
        &self,
        sortition_tip: &stacks_common::types::chainstate::SortitionId,
        anchor: &stacks_common::types::chainstate::BlockHeaderHash,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_pox_id(
        &self, 
        sortition_tip: &stacks_common::types::chainstate::SortitionId
    ) -> super::Result<stacks_common::types::chainstate::PoxId> {
        todo!()
    }

    fn get_sortition_result(
        &self,
        id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<(crate::chainstate::burn::BlockSnapshot, crate::burnchains::BurnchainStateTransitionOps)>> {
        todo!()
    }

    fn get_next_block_recipients(
        &mut self,
        burnchain: &crate::burnchains::Burnchain,
        parent_snapshot: &crate::chainstate::burn::BlockSnapshot,
        next_pox_info: Option<&crate::chainstate::coordinator::RewardCycleInfo>,
    ) -> super::Result<Option<crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo>> {
        todo!()
    }

    fn is_stacks_block_in_sortition_set(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
        block_to_check: &stacks_common::types::chainstate::BlockHeaderHash,
    ) -> super::Result<bool> {
        todo!()
    }

    fn latest_stacks_blocks_processed(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<u64> {
        todo!()
    }

    fn get_burnchain_view(
        &self,
        burnchain: &crate::burnchains::Burnchain,
        chain_tip: &crate::chainstate::burn::BlockSnapshot,
    ) -> super::Result<crate::burnchains::BurnchainView> {
        todo!()
    }

    fn get_canonical_burn_chain_tip(
        &self
    ) -> super::Result<crate::chainstate::burn::BlockSnapshot> {
        todo!()
    }

    fn get_highest_known_burn_chain_tip(
        &self
    ) -> super::Result<crate::chainstate::burn::BlockSnapshot> {
        todo!()
    }

    fn get_canonical_chain_tip_bhh(
        &self
    ) -> super::Result<stacks_common::types::chainstate::BurnchainHeaderHash> {
        todo!()
    }

    fn get_canonical_sortition_tip(
        &self
    ) -> super::Result<stacks_common::types::chainstate::SortitionId> {
        todo!()
    }

    fn get_stack_stx_ops(
        &self,
        burn_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::StackStxOp>> {
        todo!()
    }

    fn get_delegate_stx_ops(
        &self,
        burn_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::DelegateStxOp>> {
        todo!()
    }

    fn get_peg_in_ops(
        &self,
        burn_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::PegInOp>> {
        todo!()
    }

    fn get_peg_out_request_ops(
        &self,
        burn_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::PegOutRequestOp>> {
        todo!()
    }

    fn get_peg_out_fulfill_ops(
        &self,
        burn_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::PegOutFulfillOp>> {
        todo!()
    }

    fn get_transfer_stx_ops(
        &self,
        burn_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::TransferStxOp>> {
        todo!()
    }

    fn get_parent_burnchain_header_hash(
        &self,
        burnchain_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
    ) -> super::Result<Option<stacks_common::types::chainstate::BurnchainHeaderHash>> {
        todo!()
    }

    fn get_ancestor_burnchain_header_hashes(
        &self,
        burn_header_hash: &stacks_common::types::chainstate::BurnchainHeaderHash,
        count: u64,
    ) -> super::Result<Vec<stacks_common::types::chainstate::BurnchainHeaderHash>> {
        todo!()
    }

    fn get_canonical_stacks_chain_tip_hash(
        &self
    ) -> super::Result<(stacks_common::types::chainstate::ConsensusHash, stacks_common::types::chainstate::BlockHeaderHash)> {
        todo!()
    }

    fn get_max_arrival_index(
        &self
    ) -> super::Result<u64> {
        todo!()
    }

    fn get_snapshot_by_arrival_index(
        &self,
        arrival_index: u64,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_burnchain_header_hash_by_consensus(
        &self,
        consensus_hash: &stacks_common::types::chainstate::ConsensusHash,
    ) -> super::Result<Option<stacks_common::types::chainstate::BurnchainHeaderHash>> {
        todo!()
    }

    fn get_sortition_id_by_consensus(
        &self,
        consensus_hash: &stacks_common::types::chainstate::ConsensusHash,
    ) -> super::Result<Option<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn get_block_snapshot_consensus(
        &self,
        consensus_hash: &stacks_common::types::chainstate::ConsensusHash,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_block_snapshot(
        &self,
        sortition_id: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_first_block_snapshot(
        &self
    ) -> super::Result<crate::chainstate::burn::BlockSnapshot> {
        todo!()
    }

    fn is_pox_active(
        &self,
        burnchain: &crate::burnchains::Burnchain,
        block: &crate::chainstate::burn::BlockSnapshot,
    ) -> super::Result<bool> {
        todo!()
    }

    fn get_block_burn_amount(
        &self,
        block_snapshot: &crate::chainstate::burn::BlockSnapshot,
    ) -> super::Result<u64> {
        todo!()
    }

    fn get_user_burns_by_block(
        &self,
        sortition: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::UserBurnSupportOp>> {
        todo!()
    }

    fn get_block_commits_by_block(
        &self,
        sortition: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::LeaderBlockCommitOp>> {
        todo!()
    }

    fn get_missed_commits_by_intended(
        &self,
        sortition: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::leader_block_commit::MissedBlockCommit>> {
        todo!()
    }

    fn get_leader_keys_by_block(
        &self,
        sortition: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Vec<crate::chainstate::burn::operations::LeaderKeyRegisterOp>> {
        todo!()
    }

    fn get_block_winning_vtxindex(
        &self,
        sortition: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<u16>> {
        todo!()
    }

    fn get_ancestor_snapshot(
        &self,
        ancestor_block_height: u64,
        tip_block_hash: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_ancestor_snapshot_tx(
        &self,
        ancestor_block_height: u64,
        tip_block_hash: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_block_commit_parent(
        &self,
        block_height: u64,
        vtxindex: u32,
        tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<crate::chainstate::burn::operations::LeaderBlockCommitOp>> {
        todo!()
    }

    fn get_block_commit_of_sortition(
        &self,
        sortition: &stacks_common::types::chainstate::SortitionId,
        block_height: u64,
        vtxindex: u32,
    ) -> super::Result<Option<crate::chainstate::burn::operations::LeaderBlockCommitOp>> {
        todo!()
    }

    fn get_leader_key_at(
        &self,
        key_block_height: u64,
        key_vtxindex: u32,
        tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<crate::chainstate::burn::operations::LeaderKeyRegisterOp>> {
        todo!()
    }

    fn get_block_commit_for_stacks_block(
        &self,
        consensus_hash: &stacks_common::types::chainstate::ConsensusHash,
        block_hash: &stacks_common::types::chainstate::BlockHeaderHash,
    ) -> super::Result<Option<crate::chainstate::burn::operations::LeaderBlockCommitOp>> {
        todo!()
    }

    fn get_block_snapshot_for_winning_stacks_block(
        &self,
        tip: &stacks_common::types::chainstate::SortitionId,
        block_hash: &stacks_common::types::chainstate::BlockHeaderHash,
    ) -> super::Result<Option<crate::chainstate::burn::BlockSnapshot>> {
        todo!()
    }

    fn get_stacks_epoch(
        &self,
        burn_block_height: u64,
    ) -> super::Result<Option<crate::core::StacksEpoch>> {
        todo!()
    }

    fn get_sortition_ids_at_height(
        &self,
        height: u64,
    ) -> super::Result<Vec<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn get_stacks_epochs(
        &self
    ) -> super::Result<Vec<crate::core::StacksEpoch>> {
        todo!()
    }

    fn get_stacks_epoch_by_epoch_id(
        &self,
        epoch_id: &stacks_common::types::StacksEpochId,
    ) -> super::Result<Option<crate::core::StacksEpoch>> {
        todo!()
    }

    fn get_last_epoch_2_05_reward_cycle(
        &self
    ) -> super::Result<u64> {
        todo!()
    }

    fn get_last_snapshot_with_sortition_tx(
        &self,
        burn_block_height: u64,
        chain_tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<crate::chainstate::burn::BlockSnapshot> {
        todo!()
    }

    fn get_initial_mining_bonus_remaining(
        &self,
        chain_tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<u128> {
        todo!()
    }

    fn get_initial_mining_bonus_per_block(
        &self,
        chain_tip: &stacks_common::types::chainstate::SortitionId,
    ) -> super::Result<Option<u128>> {
        todo!()
    }

    fn get_num_pox_payouts(
        &self, 
        burn_block_height: u64
    ) -> super::Result<usize> {
        todo!()
    }

    fn get_pox_payout_per_output(
        &self, 
        block_ops: &[crate::chainstate::burn::operations::BlockstackOperationType]
    ) -> super::Result<u128> {
        todo!()
    }

    fn find_new_block_arrivals(
        &self,
        tip: &crate::chainstate::burn::BlockSnapshot,
    ) -> super::Result<(stacks_common::types::chainstate::ConsensusHash, stacks_common::types::chainstate::BlockHeaderHash, u64)> {
        todo!()
    }

    fn get_consensus_at(
        &self,
        block_height: u64,
    ) -> super::Result<Option<stacks_common::types::chainstate::ConsensusHash>> {
        todo!()
    }

    fn get_last_snapshot_with_sortition(
        &self,
        burn_block_height: u64,
    ) -> super::Result<crate::chainstate::burn::BlockSnapshot> {
        todo!()
    }

    fn transaction(&mut self) -> super::Result<super::SortitionDbTransactionImpl<Self>> {
        todo!()
    }
}