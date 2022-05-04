use std::collections::BTreeMap;

use crate::{neon_node::find_last_stacks_block_this_produced, rand::RngCore};
use stacks::{
    burnchains::Txid,
    chainstate::{
        burn::{
            db::sortdb::{SortitionDB, SortitionHandleTx},
            BlockSnapshot, ConsensusHash, OpsHash, SortitionHash,
        },
        stacks::index::TrieHashExtension,
    },
    core::{StacksEpoch, StacksEpochId, PEER_VERSION_EPOCH_1_0, STACKS_EPOCH_MAX},
    types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, SortitionId, TrieHash},
    util::{get_epoch_time_secs, hash::to_hex},
    vm::costs::ExecutionCost,
};

pub fn random_sortdb_test_dir() -> String {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    format!("/tmp/stacks-node-tests/sortdb/test-{}", to_hex(&buf))
}

/// Make a BlockSnapshot with many dummy values for test.
fn make_test_block_snapshot(height: u64, hash_byte: u8, parent_hash_byte: u8) -> BlockSnapshot {
    BlockSnapshot {
        accumulated_coinbase_ustx: 0,
        pox_valid: true,
        block_height: height,
        burn_header_timestamp: get_epoch_time_secs(),
        burn_header_hash: BurnchainHeaderHash([hash_byte; 32]),
        sortition_id: SortitionId([hash_byte; 32]),
        parent_sortition_id: SortitionId([parent_hash_byte; 32]),
        parent_burn_header_hash: BurnchainHeaderHash([parent_hash_byte; 32]),
        consensus_hash: ConsensusHash([hash_byte; 20]),
        ops_hash: OpsHash([0; 32]),
        total_burn: 0u64,
        sortition: true,
        sortition_hash: SortitionHash::initial(),
        winning_block_txid: Txid([0; 32]),
        winning_stacks_block_hash: BlockHeaderHash([0; 32]),
        index_root: TrieHash::from_empty_data(),
        num_sortitions: height,
        stacks_block_accepted: false,
        stacks_block_height: 0,
        arrival_index: 0,
        canonical_stacks_tip_height: 0,
        canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
        canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
    }
}

/// Add a link in the SortitionDB between a node with hash based on `hash_byte` and a node with hash based on `parent_hash_byte`.
fn add_sortition_link(
    db: &mut SortitionDB,
    height: u64,
    hash_byte: u8,
    parent_height: u64,
    parent_hash_byte: u8,
    grandparent_hash_byte: u8,
) {
    let mut ic = SortitionHandleTx::begin(db, &SortitionId([1; 32])).unwrap();
    let _ = ic
        .append_chain_tip_snapshot(
            &make_test_block_snapshot(parent_height, parent_hash_byte, grandparent_hash_byte),
            &make_test_block_snapshot(height, hash_byte, parent_hash_byte),
            &vec![],
            None,
            None,
        )
        .expect("append failed.");
    ic.commit().unwrap();
}

// Make a SortitionDB with the following implied tree.
//     / 2  -> 3 -> 4
//   1
//     \ 5
fn make_sortition_db_for_fork_tests() -> SortitionDB {
    let mut db = SortitionDB::connect(
        &random_sortdb_test_dir(),
        1,
        &BurnchainHeaderHash([1; 32]),
        get_epoch_time_secs(),
        &[StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        }],
        true,
    )
    .unwrap();

    add_sortition_link(&mut db, 2, 2, 1, 1, 0);
    add_sortition_link(&mut db, 3, 3, 2, 2, 1);
    add_sortition_link(&mut db, 4, 4, 3, 3, 2);
    add_sortition_link(&mut db, 2, 5, 1, 1, 0);
    db
}

#[test]
fn test_no_forks_empty_map() {
    // Empty map means we find nothing.
    let db = make_sortition_db_for_fork_tests();
    let empty_map: BTreeMap<(u64, BurnchainHeaderHash), BlockHeaderHash> = BTreeMap::new();
    let result = find_last_stacks_block_this_produced(&db, &empty_map);
    assert_eq!(None, result);
}

#[test]
fn test_no_forks_non_canonical_path() {
    // We have an item in the map but it's not on the canonical branch.
    let db = make_sortition_db_for_fork_tests();
    let mut map: BTreeMap<(u64, BurnchainHeaderHash), BlockHeaderHash> = BTreeMap::new();
    map.insert((2, BurnchainHeaderHash([5; 32])), BlockHeaderHash([5; 32]));
    let result = find_last_stacks_block_this_produced(&db, &map);
    assert_eq!(None, result);
}

#[test]
fn test_no_forks_ancestor_canonical_branch() {
    let db = make_sortition_db_for_fork_tests();
    // Item is on the canonical branch, so we find it.

    {
        let mut map: BTreeMap<(u64, BurnchainHeaderHash), BlockHeaderHash> = BTreeMap::new();
        map.insert((2, BurnchainHeaderHash([2; 32])), BlockHeaderHash([2; 32]));
        let result = find_last_stacks_block_this_produced(&db, &map);
        assert_eq!(Some(&BlockHeaderHash([2; 32])), result);
    }

    // Multiple items on the canonical branch, so pick higher one.
    {
        let mut map: BTreeMap<(u64, BurnchainHeaderHash), BlockHeaderHash> = BTreeMap::new();
        map.insert((1, BurnchainHeaderHash([1; 32])), BlockHeaderHash([1; 32]));
        map.insert((2, BurnchainHeaderHash([2; 32])), BlockHeaderHash([2; 32]));
        let result = find_last_stacks_block_this_produced(&db, &map);
        assert_eq!(Some(&BlockHeaderHash([2; 32])), result);
    }

    // Multiple items on the canonical branch, so pick higher one.
    {
        let mut map: BTreeMap<(u64, BurnchainHeaderHash), BlockHeaderHash> = BTreeMap::new();
        map.insert((2, BurnchainHeaderHash([2; 32])), BlockHeaderHash([2; 32]));
        map.insert((4, BurnchainHeaderHash([4; 32])), BlockHeaderHash([4; 32]));

        let result = find_last_stacks_block_this_produced(&db, &map);
        assert_eq!(Some(&BlockHeaderHash([4; 32])), result);
    }
}

#[test]
fn test_no_forks_common_ancestor() {
    // First hit is from the fork.
    let db = make_sortition_db_for_fork_tests();
    let mut map: BTreeMap<(u64, BurnchainHeaderHash), BlockHeaderHash> = BTreeMap::new();
    map.insert((1, BurnchainHeaderHash([1; 32])), BlockHeaderHash([1; 32]));
    let result = find_last_stacks_block_this_produced(&db, &map);
    assert_eq!(Some(&BlockHeaderHash([1; 32])), result);
}
