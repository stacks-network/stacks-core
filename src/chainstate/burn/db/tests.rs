use std::sync::mpsc::sync_channel;
use std::thread;

use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::db_keys;
use crate::chainstate::burn::operations::{
    leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS, BlockstackOperationType, LeaderBlockCommitOp,
    LeaderKeyRegisterOp, UserBurnSupportOp,
};
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::index::TrieHashExtension;
use crate::chainstate::stacks::StacksPublicKey;
use crate::core::*;
use crate::util_lib::db::Error as db_error;
use rand::RngCore;
use stacks_common::address::AddressHashMode;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{hex_bytes, Hash160};
use stacks_common::util::vrf::*;

use crate::chainstate::burn::*;
use crate::util::hash::to_hex;
use crate::vm::costs::ExecutionCost;
use stacks_common::types::chainstate::*;

use super::sortdb::*;

#[test]
fn test_instantiate() {
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let _db = SortitionDB::connect_test(123, &first_burn_hash).unwrap();
}

fn random_sortdb_test_dir() -> String {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    format!("/tmp/stacks-node-tests/sortdb/test-{}", to_hex(&buf))
}

#[test]
fn test_v1_to_v2_migration() {
    let db_path_dir = random_sortdb_test_dir();
    let first_block_height = 123;
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    // create a v1 sortition DB
    let db = SortitionDB::connect_v1(
        &db_path_dir,
        first_block_height,
        &first_burn_hash,
        get_epoch_time_secs(),
        true,
    )
    .unwrap();
    let res = SortitionDB::get_stacks_epoch(db.conn(), first_block_height);
    assert!(res.is_err());
    assert!(format!("{:?}", res).contains("no such table: epochs"));

    assert!(SortitionDB::open(&db_path_dir, true).is_err());

    // create a v2 sortition DB at the same path as the v1 DB.
    // the schema migration should be successfully applied, and the epochs table should exist.
    let db = SortitionDB::connect(
        &db_path_dir,
        first_block_height,
        &first_burn_hash,
        get_epoch_time_secs(),
        &StacksEpoch::unit_test_2_05(first_block_height),
        true,
    )
    .unwrap();
    // assert that an epoch is returned
    SortitionDB::get_stacks_epoch(db.conn(), first_block_height)
        .expect("Database should not error querying epochs")
        .expect("Database should have an epoch entry");

    assert!(SortitionDB::open(&db_path_dir, true).is_ok());
}

#[test]
fn test_tx_begin_end() {
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let mut db = SortitionDB::connect_test(123, &first_burn_hash).unwrap();
    let tx = db.tx_begin().unwrap();
    tx.commit().unwrap();
}

pub fn test_append_snapshot(
    db: &mut SortitionDB,
    next_hash: BurnchainHeaderHash,
    block_ops: &Vec<BlockstackOperationType>,
) -> BlockSnapshot {
    let mut sn = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    let mut tx = SortitionHandleTx::begin(db, &sn.sortition_id).unwrap();

    let sn_parent = sn.clone();
    sn.parent_burn_header_hash = sn.burn_header_hash.clone();
    sn.parent_sortition_id = sn.sortition_id.clone();
    sn.burn_header_hash = next_hash;
    sn.block_height += 1;
    sn.num_sortitions += 1;
    sn.sortition_id = SortitionId::new(&sn.burn_header_hash);
    sn.consensus_hash = ConsensusHash(Hash160::from_data(&sn.consensus_hash.0).0);

    let index_root = tx
        .append_chain_tip_snapshot(&sn_parent, &sn, block_ops, None, None)
        .unwrap();
    sn.index_root = index_root;

    tx.commit().unwrap();

    sn
}

#[test]
fn test_insert_block_commit() {
    let block_height = 123;
    let vtxindex = 456;
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    let block_commit = LeaderBlockCommitOp {
        block_header_hash: BlockHeaderHash([0x22; 32]),

        txid: Txid::from_bytes_be(
            &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap(),
        )
        .unwrap(),
        burn_header_hash: BurnchainHeaderHash([0x03; 32]),
    };

    let mut db = SortitionDB::connect_test(block_height, &first_burn_hash).unwrap();

    let snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x01; 32]), &vec![]);

    // test get_consumed_leader_keys()
    {
        let mut ic = SortitionHandleTx::begin(&mut db, &snapshot.sortition_id).unwrap();
        let keys = ic
            .get_consumed_leader_keys(&snapshot, &vec![block_commit.clone()])
            .unwrap();
        assert_eq!(keys, vec![]);
    }

    let snapshot_consumed = test_append_snapshot(
        &mut db,
        BurnchainHeaderHash([0x03; 32]),
        &vec![BlockstackOperationType::LeaderBlockCommit(
            block_commit.clone(),
        )],
    );

    {
        let res_block_commits =
            SortitionDB::get_block_commits_by_block(db.conn(), &snapshot_consumed.sortition_id)
                .unwrap();
        assert_eq!(res_block_commits.len(), 1);
        assert_eq!(res_block_commits[0], block_commit);
    }

    // advance and get parent
    let empty_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x05; 32]), &vec![]);

    // test get_block_commit()
    {
        let handle = db.index_handle(&empty_snapshot.sortition_id);
        let commit = handle.get_block_commit_by_txid(&block_commit.txid).unwrap();
        assert!(commit.is_some());
        assert_eq!(commit.unwrap(), block_commit);

        let bad_txid = Txid::from_bytes_be(
            &hex_bytes("4c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap(),
        )
        .unwrap();
        let commit = handle.get_block_commit_by_txid(&bad_txid).unwrap();
        assert!(commit.is_none());
    }

    // test get_consumed_leader_keys() (should be doable at any subsequent index root)
    {
        let mut ic = SortitionHandleTx::begin(&mut db, &snapshot.sortition_id).unwrap();
        let keys = ic
            .get_consumed_leader_keys(&empty_snapshot, &vec![block_commit.clone()])
            .unwrap();
        assert_eq!(keys, vec![]);
    }

    // make a fork between the leader key and block commit, and verify that the key is
    // unconsumed
    let fork_snapshot = {
        let mut sn = SortitionDB::get_block_snapshot(db.conn(), &snapshot.sortition_id)
            .unwrap()
            .unwrap();
        let next_hash = BurnchainHeaderHash([0x13; 32]);
        let mut tx = SortitionHandleTx::begin(&mut db, &sn.sortition_id).unwrap();

        let sn_parent = sn.clone();
        sn.parent_burn_header_hash = sn.burn_header_hash.clone();
        sn.sortition_id = SortitionId(next_hash.0.clone());
        sn.parent_sortition_id = sn_parent.sortition_id.clone();
        sn.burn_header_hash = next_hash;
        sn.block_height += 1;
        sn.num_sortitions += 1;
        sn.consensus_hash = ConsensusHash([0x23; 20]);

        let index_root = tx
            .append_chain_tip_snapshot(&sn_parent, &sn, &vec![], None, None)
            .unwrap();
        sn.index_root = index_root;

        tx.commit().unwrap();

        sn
    };
}

#[test]
fn is_fresh_consensus_hash() {
    let consensus_hash_lifetime = 24;
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "10000000000000000000000000000000000000000000000000000000000000ff",
    )
    .unwrap();
    let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();
    {
        let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
        for i in 0..255 {
            let sortition_id = SortitionId([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, i as u8,
            ]);
            let parent_sortition_id = if i == 0 {
                last_snapshot.sortition_id.clone()
            } else {
                SortitionId([
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    i - 1 as u8,
                ])
            };

            let mut tx = SortitionHandleTx::begin(&mut db, &parent_sortition_id).unwrap();
            let snapshot_row = BlockSnapshot {
                accumulated_coinbase_ustx: 0,
                pox_valid: true,
                block_height: i as u64 + 1,
                burn_header_timestamp: get_epoch_time_secs(),
                burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, i as u8,
                ])
                .unwrap(),
                sortition_id,
                parent_sortition_id,
                parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                    (if i == 0 { 0x10 } else { 0 }) as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (if i == 0 { 0xff } else { i - 1 }) as u8,
                ])
                .unwrap(),
                consensus_hash: ConsensusHash::from_bytes(&[
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (i + 1) as u8,
                ])
                .unwrap(),
                ops_hash: OpsHash::from_bytes(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, i as u8,
                ])
                .unwrap(),
                total_burn: i as u64,
                sortition: true,
                sortition_hash: SortitionHash::initial(),
                winning_block_txid: Txid::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                winning_stacks_block_hash: BlockHeaderHash::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                index_root: TrieHash::from_empty_data(),
                num_sortitions: i as u64 + 1,
                stacks_block_accepted: false,
                stacks_block_height: 0,
                arrival_index: 0,
                canonical_stacks_tip_height: 0,
                canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
            };
            let index_root = tx
                .append_chain_tip_snapshot(&last_snapshot, &snapshot_row, &vec![], None, None)
                .unwrap();
            last_snapshot = snapshot_row;
            last_snapshot.index_root = index_root;
            tx.commit().unwrap();
        }
    }

    let tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

    let ch_fresh =
        ConsensusHash::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255])
            .unwrap();
    let ch_oldest_fresh = ConsensusHash::from_bytes(&[
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        (255 - consensus_hash_lifetime) as u8,
    ])
    .unwrap();
    let ch_newest_stale = ConsensusHash::from_bytes(&[
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        (255 - consensus_hash_lifetime - 1) as u8,
    ])
    .unwrap();
    let ch_missing =
        ConsensusHash::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255])
            .unwrap();

    let mut ic = SortitionHandleTx::begin(&mut db, &tip.sortition_id).unwrap();
    let fresh_check = ic
        .is_fresh_consensus_hash(consensus_hash_lifetime, &ch_fresh)
        .unwrap();

    assert!(fresh_check);

    let oldest_fresh_check = ic
        .is_fresh_consensus_hash(consensus_hash_lifetime, &ch_oldest_fresh)
        .unwrap();

    assert!(oldest_fresh_check);

    let newest_stale_check = ic
        .is_fresh_consensus_hash(consensus_hash_lifetime, &ch_newest_stale)
        .unwrap();

    assert!(!newest_stale_check);

    let missing_check = ic
        .is_fresh_consensus_hash(consensus_hash_lifetime, &ch_missing)
        .unwrap();

    assert!(!missing_check);
}

#[test]
fn get_consensus_at() {
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "10000000000000000000000000000000000000000000000000000000000000ff",
    )
    .unwrap();
    let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();
    {
        let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
        for i in 0..256u64 {
            let sortition_id = SortitionId([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, i as u8,
            ]);
            let parent_sortition_id = if i == 0 {
                last_snapshot.sortition_id.clone()
            } else {
                SortitionId([
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (i - 1) as u8,
                ])
            };

            let mut tx = SortitionHandleTx::begin(&mut db, &parent_sortition_id).unwrap();
            let snapshot_row = BlockSnapshot {
                accumulated_coinbase_ustx: 0,
                pox_valid: true,
                block_height: i as u64 + 1,
                burn_header_timestamp: get_epoch_time_secs(),
                burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, i as u8,
                ])
                .unwrap(),
                sortition_id,
                parent_sortition_id,
                parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                    (if i == 0 { 0x10 } else { 0 }) as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (if i == 0 { 0xff } else { i - 1 }) as u8,
                ])
                .unwrap(),
                consensus_hash: ConsensusHash::from_bytes(&[
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ((i + 1) / 256) as u8,
                    (i + 1) as u8,
                ])
                .unwrap(),
                ops_hash: OpsHash::from_bytes(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, i as u8,
                ])
                .unwrap(),
                total_burn: i as u64,
                sortition: true,
                sortition_hash: SortitionHash::initial(),
                winning_block_txid: Txid::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                winning_stacks_block_hash: BlockHeaderHash::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                index_root: TrieHash::from_empty_data(),
                num_sortitions: i as u64 + 1,
                stacks_block_accepted: false,
                stacks_block_height: 0,
                arrival_index: 0,
                canonical_stacks_tip_height: 0,
                canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
            };
            let index_root = tx
                .append_chain_tip_snapshot(&last_snapshot, &snapshot_row, &vec![], None, None)
                .unwrap();
            last_snapshot = snapshot_row;
            last_snapshot.index_root = index_root;
            // should succeed within the tx
            let ch = tx.get_consensus_at(i as u64 + 1).unwrap().unwrap();
            assert_eq!(ch, last_snapshot.consensus_hash);

            tx.commit().unwrap();
        }
    }

    let tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

    for i in 0..256 {
        // should succeed within the conn
        let ic = db.index_handle(&tip.sortition_id);
        let expected_ch = ConsensusHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8,
        ])
        .unwrap();
        let ch = ic.get_consensus_at(i).unwrap().unwrap();
        assert_eq!(ch, expected_ch);
    }
}

#[test]
fn get_last_snapshot_with_sortition() {
    let block_height = 123;
    let total_burn_sortition = 100;
    let total_burn_no_sortition = 200;
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    let mut first_snapshot = BlockSnapshot {
        accumulated_coinbase_ustx: 0,
        pox_valid: true,
        block_height: block_height - 2,
        burn_header_timestamp: get_epoch_time_secs(),
        burn_header_hash: first_burn_hash.clone(),
        sortition_id: SortitionId(first_burn_hash.0.clone()),
        parent_sortition_id: SortitionId(first_burn_hash.0.clone()),
        parent_burn_header_hash: BurnchainHeaderHash([0xff; 32]),
        consensus_hash: ConsensusHash::from_hex("0000000000000000000000000000000000000000")
            .unwrap(),
        ops_hash: OpsHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        total_burn: 0,
        sortition: true,
        sortition_hash: SortitionHash::initial(),
        winning_block_txid: Txid::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        winning_stacks_block_hash: BlockHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        index_root: TrieHash([0u8; 32]),
        num_sortitions: 0,
        stacks_block_accepted: false,
        stacks_block_height: 0,
        arrival_index: 0,
        canonical_stacks_tip_height: 0,
        canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
        canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
    };

    let mut snapshot_with_sortition = BlockSnapshot {
        accumulated_coinbase_ustx: 0,
        pox_valid: true,
        block_height: block_height,
        burn_header_timestamp: get_epoch_time_secs(),
        burn_header_hash: BurnchainHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ])
        .unwrap(),
        sortition_id: SortitionId([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]),
        parent_sortition_id: SortitionId([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]),
        parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap(),
        consensus_hash: ConsensusHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])
        .unwrap(),
        ops_hash: OpsHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap(),
        total_burn: total_burn_sortition,
        sortition: true,
        sortition_hash: SortitionHash::initial(),
        winning_block_txid: Txid::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap(),
        winning_stacks_block_hash: BlockHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap(),
        index_root: TrieHash([1u8; 32]),
        num_sortitions: 1,
        stacks_block_accepted: false,
        stacks_block_height: 0,
        arrival_index: 0,
        canonical_stacks_tip_height: 0,
        canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
        canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
    };

    let snapshot_without_sortition = BlockSnapshot {
        accumulated_coinbase_ustx: 0,
        pox_valid: true,
        block_height: block_height - 1,
        burn_header_timestamp: get_epoch_time_secs(),
        burn_header_hash: BurnchainHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap(),
        sortition_id: SortitionId([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]),
        parent_sortition_id: SortitionId([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]),
        parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap(),
        consensus_hash: ConsensusHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ])
        .unwrap(),
        ops_hash: OpsHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ])
        .unwrap(),
        total_burn: total_burn_no_sortition,
        sortition: false,
        sortition_hash: SortitionHash::initial(),
        winning_block_txid: Txid::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap(),
        winning_stacks_block_hash: BlockHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap(),
        index_root: TrieHash([2u8; 32]),
        num_sortitions: 0,
        stacks_block_accepted: false,
        stacks_block_height: 0,
        arrival_index: 0,
        canonical_stacks_tip_height: 0,
        canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
        canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
    };

    let mut db = SortitionDB::connect_test(block_height - 2, &first_burn_hash).unwrap();

    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

    let initial_snapshot = {
        let ic = db.index_handle(&chain_tip.sortition_id);
        ic.get_last_snapshot_with_sortition(block_height - 2)
            .unwrap()
    };

    first_snapshot.index_root = initial_snapshot.index_root.clone();
    first_snapshot.burn_header_timestamp = initial_snapshot.burn_header_timestamp;
    assert_eq!(initial_snapshot, first_snapshot);

    {
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        let mut tx = SortitionHandleTx::begin(&mut db, &chain_tip.sortition_id).unwrap();

        tx.append_chain_tip_snapshot(&chain_tip, &snapshot_without_sortition, &vec![], None, None)
            .unwrap();
        tx.commit().unwrap();
    }

    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

    let mut next_snapshot = {
        let ic = db.index_handle(&chain_tip.sortition_id);
        ic.get_last_snapshot_with_sortition(block_height - 1)
            .unwrap()
    };

    next_snapshot.index_root = initial_snapshot.index_root.clone();
    next_snapshot.burn_header_timestamp = initial_snapshot.burn_header_timestamp;
    assert_eq!(initial_snapshot, next_snapshot);

    {
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        let mut tx = SortitionHandleTx::begin(&mut db, &chain_tip.sortition_id).unwrap();

        tx.append_chain_tip_snapshot(&chain_tip, &snapshot_with_sortition, &vec![], None, None)
            .unwrap();
        tx.commit().unwrap();
    }

    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

    let next_snapshot_2 = {
        let ic = db.index_handle(&chain_tip.sortition_id);
        ic.get_last_snapshot_with_sortition(block_height).unwrap()
    };

    snapshot_with_sortition.index_root = next_snapshot_2.index_root.clone();
    snapshot_with_sortition.burn_header_timestamp = next_snapshot_2.burn_header_timestamp;
    assert_eq!(snapshot_with_sortition, next_snapshot_2);
}

/// Verify that the snapshots in a fork are well-formed -- i.e. the block heights are
/// sequential and the parent block hash of the ith block is equal to the block hash of the
/// (i-1)th block.
fn verify_fork_integrity(db: &mut SortitionDB, tip: &SortitionId) {
    let mut child = SortitionDB::get_block_snapshot(db.conn(), tip)
        .unwrap()
        .unwrap();

    let initial = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();

    test_debug!(
        "Verify from {},hash={},parent={} back to {},hash={},parent={}",
        child.block_height,
        child.burn_header_hash,
        child.parent_burn_header_hash,
        initial.block_height,
        initial.burn_header_hash,
        initial.parent_burn_header_hash
    );

    while child.block_height > initial.block_height {
        let parent = {
            let ic = db.index_conn();
            SortitionDB::get_ancestor_snapshot(&ic, child.block_height - 1, &child.sortition_id)
                .unwrap()
                .unwrap()
        };

        test_debug!(
            "Verify {} == {} - 1 and hash={},parent_hash={} == parent={}",
            parent.block_height,
            child.block_height,
            child.burn_header_hash,
            parent.burn_header_hash,
            child.parent_burn_header_hash
        );

        assert_eq!(parent.block_height, child.block_height - 1);
        assert_eq!(parent.burn_header_hash, child.parent_burn_header_hash);

        child = parent.clone();
    }

    assert_eq!(child, initial);
}

#[test]
fn test_chain_reorg() {
    // Create a set of forks that looks like this:
    // 0-1-2-3-4-5-6-7-8-9 (fork 0)
    //  \
    //   1-2-3-4-5-6-7-8-9 (fork 1)
    //    \
    //     2-3-4-5-6-7-8-9 (fork 2)
    //      \
    //       3-4-5-6-7-8-9 (fork 3)
    //
    //    ...etc...
    //
    // Then, append a block to fork 9, and confirm that it switches places with fork 0.
    // Append 2 blocks to fork 8, and confirm that it switches places with fork 0.
    // Append 3 blocks to fork 7, and confirm that it switches places with fork 0.
    // ... etc.
    //
    let first_burn_hash = BurnchainHeaderHash([0x00; 32]);
    let first_block_height = 100;

    let mut db = SortitionDB::connect_test(first_block_height, &first_burn_hash).unwrap();

    // make an initial fork
    let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();

    for i in 0..10 {
        let mut next_snapshot = last_snapshot.clone();

        next_snapshot.block_height += 1;
        next_snapshot.num_sortitions += 1;
        next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
        next_snapshot.burn_header_hash = BurnchainHeaderHash([
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            i + 1,
        ]);
        next_snapshot.sortition_id = SortitionId([
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            i + 1,
        ]);
        next_snapshot.parent_sortition_id = last_snapshot.sortition_id.clone();
        next_snapshot.consensus_hash = ConsensusHash([
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            i + 1,
        ]);

        let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
        tx.append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], None, None)
            .unwrap();
        tx.commit().unwrap();

        last_snapshot = next_snapshot.clone();
    }

    test_debug!("----- make forks -----");

    // make other forks
    for i in 0..9 {
        let parent_block_hash = if i == 0 {
            [0u8; 32]
        } else {
            let mut tmp = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (i + 1) as u8,
            ];
            tmp[i - 1] = 1;
            tmp
        };

        let parent_block = SortitionId(parent_block_hash);
        test_debug!(
            "----- build fork off of parent {} (i = {}) -----",
            &parent_block,
            i
        );

        let mut last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &parent_block)
            .unwrap()
            .unwrap();

        let initial_block_height = last_snapshot.block_height;
        let initial_num_sortitions = last_snapshot.num_sortitions;

        let mut next_snapshot = last_snapshot.clone();

        for j in (i + 1)..10 {
            let mut block_hash = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (j + 1) as u8,
            ];
            block_hash[i] = (j - i) as u8;

            next_snapshot.block_height = initial_block_height + (j - i) as u64;
            next_snapshot.num_sortitions = initial_num_sortitions + (j - i) as u64;
            next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
            next_snapshot.sortition_id = SortitionId(block_hash.clone());
            next_snapshot.parent_sortition_id = last_snapshot.sortition_id.clone();
            next_snapshot.burn_header_hash = BurnchainHeaderHash(block_hash);
            next_snapshot.consensus_hash = ConsensusHash([
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                j as u8,
                (i + 1) as u8,
            ]);

            let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
            let next_index_root = tx
                .append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], None, None)
                .unwrap();
            tx.commit().unwrap();

            next_snapshot.index_root = next_index_root;
            last_snapshot = next_snapshot.clone();
        }

        test_debug!(
            "----- made fork {} (i = {}) -----",
            &next_snapshot.burn_header_hash,
            i
        );
    }

    test_debug!("----- grow forks -----");

    let mut all_chain_tips = vec![];

    // grow each fork so it overtakes the currently-canonical fork
    for i in 0..9 {
        let mut last_block_hash = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 10,
        ];
        last_block_hash[i] = (9 - i) as u8;
        let last_block = SortitionId(last_block_hash);

        test_debug!("----- grow fork {} (i = {}) -----", &last_block, i);

        let mut last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &last_block)
            .unwrap()
            .unwrap();

        let initial_block_height = last_snapshot.block_height;
        let mut next_snapshot = last_snapshot.clone();

        // grow the fork up to the length of the previous fork
        for j in 0..((i + 1) as u64) {
            next_snapshot = last_snapshot.clone();

            let mut next_block_hash_vec = last_snapshot.burn_header_hash.as_bytes().to_vec();
            next_block_hash_vec[0] += 1;
            let mut next_block_hash = [0u8; 32];
            next_block_hash.copy_from_slice(&next_block_hash_vec[..]);

            next_snapshot.block_height = last_snapshot.block_height + 1;
            next_snapshot.num_sortitions = last_snapshot.num_sortitions + 1;
            next_snapshot.parent_burn_header_hash = last_snapshot.burn_header_hash.clone();
            next_snapshot.sortition_id = SortitionId(next_block_hash.clone());
            next_snapshot.parent_sortition_id = last_snapshot.sortition_id.clone();
            next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);
            next_snapshot.consensus_hash = ConsensusHash([
                2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                j as u8,
                (i + 1) as u8,
            ]);

            let next_index_root = {
                let mut tx =
                    SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
                let next_index_root = tx
                    .append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], None, None)
                    .unwrap();
                tx.commit().unwrap();
                next_index_root
            };

            last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &next_snapshot.sortition_id)
                .unwrap()
                .unwrap();
        }

        // make the fork exceed the canonical chain tip
        next_snapshot = last_snapshot.clone();

        let mut next_block_hash_vec = last_snapshot.burn_header_hash.as_bytes().to_vec();
        next_block_hash_vec[0] = 0xff;
        let mut next_block_hash = [0u8; 32];
        next_block_hash.copy_from_slice(&next_block_hash_vec[..]);

        next_snapshot.block_height += 1;
        next_snapshot.num_sortitions += 1;
        next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
        next_snapshot.sortition_id = SortitionId(next_block_hash.clone());
        next_snapshot.parent_sortition_id = last_snapshot.sortition_id.clone();
        next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);
        next_snapshot.consensus_hash =
            ConsensusHash(Hash160::from_data(&next_snapshot.consensus_hash.0).0);

        let next_index_root = {
            let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
            let next_index_root = tx
                .append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], None, None)
                .unwrap();
            tx.commit().unwrap();
            next_index_root
        };

        next_snapshot.index_root = next_index_root;

        let mut expected_tip = next_snapshot.clone();
        expected_tip.index_root = next_index_root;

        let canonical_tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        assert_eq!(canonical_tip, expected_tip);

        verify_fork_integrity(&mut db, &canonical_tip.sortition_id);
        all_chain_tips.push(canonical_tip.sortition_id.clone());
    }

    for tip_header_hash in all_chain_tips.iter() {
        verify_fork_integrity(&mut db, tip_header_hash);
    }
}

#[test]
fn test_get_stacks_header_hashes() {
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "10000000000000000000000000000000000000000000000000000000000000ff",
    )
    .unwrap();
    let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();
    {
        let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
        let mut total_burn = 0;
        let mut total_sortitions = 0;
        for i in 0..256 {
            let snapshot_row = if i % 3 == 0 {
                BlockSnapshot {
                    accumulated_coinbase_ustx: 0,
                    pox_valid: true,
                    block_height: i + 1,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    sortition_id: SortitionId([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ]),
                    parent_sortition_id: last_snapshot.sortition_id.clone(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                        (if i == 0 { 0x10 } else { 0 }) as u8,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (if i == 0 { 0xff } else { i - 1 }) as u8,
                    ])
                    .unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    ops_hash: OpsHash::from_bytes(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    total_burn: total_burn,
                    sortition: false,
                    sortition_hash: SortitionHash([(i as u8); 32]),
                    winning_block_txid: Txid([(i as u8); 32]),
                    winning_stacks_block_hash: BlockHeaderHash([0u8; 32]),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: total_sortitions,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
                }
            } else {
                total_burn += 1;
                total_sortitions += 1;
                BlockSnapshot {
                    accumulated_coinbase_ustx: 0,
                    pox_valid: true,
                    block_height: i + 1,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    sortition_id: SortitionId([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ]),
                    parent_sortition_id: last_snapshot.sortition_id.clone(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[
                        (if i == 0 { 0x10 } else { 0 }) as u8,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (if i == 0 { 0xff } else { i - 1 }) as u8,
                    ])
                    .unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    ops_hash: OpsHash::from_bytes(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    total_burn: total_burn,
                    sortition: true,
                    sortition_hash: SortitionHash([(i as u8); 32]),
                    winning_block_txid: Txid([(i as u8); 32]),
                    winning_stacks_block_hash: BlockHeaderHash([(i as u8); 32]),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: total_sortitions,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
                }
            };

            // NOTE: we don't care about VRF keys or block commits here

            let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();

            let index_root = tx
                .append_chain_tip_snapshot(&last_snapshot, &snapshot_row, &vec![], None, None)
                .unwrap();
            last_snapshot = snapshot_row;
            last_snapshot.index_root = index_root;

            // should succeed within the tx
            let ch = tx
                .get_consensus_at(i + 1)
                .unwrap()
                .unwrap_or(ConsensusHash::empty());
            assert_eq!(ch, last_snapshot.consensus_hash);

            tx.commit().unwrap();
        }
    }

    let canonical_tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    let mut cache = BlockHeaderCache::new();

    {
        let ic = db.index_conn();
        let hashes = ic
            .get_stacks_header_hashes(256, &canonical_tip.consensus_hash, &cache)
            .unwrap();
        SortitionDB::merge_block_header_cache(&mut cache, &hashes);

        assert_eq!(hashes.len(), 256);
        for i in 0..256 {
            let (ref consensus_hash, ref block_hash_opt) = &hashes[i];
            if i % 3 == 0 {
                assert!(block_hash_opt.is_none());
            } else {
                assert!(block_hash_opt.is_some());
                let block_hash = block_hash_opt.unwrap();
                assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
            }
            assert_eq!(
                *consensus_hash,
                ConsensusHash::from_bytes(&[
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8
                ])
                .unwrap()
            );

            if i > 0 {
                assert!(cache.contains_key(consensus_hash));
                assert_eq!(cache.get(consensus_hash).unwrap().0, *block_hash_opt);
            }
        }
    }

    {
        let ic = db.index_conn();
        let hashes = ic
            .get_stacks_header_hashes(
                256,
                &canonical_tip.consensus_hash,
                &mut BlockHeaderCache::new(),
            )
            .unwrap();
        SortitionDB::merge_block_header_cache(&mut cache, &hashes);

        let cached_hashes = ic
            .get_stacks_header_hashes(256, &canonical_tip.consensus_hash, &cache)
            .unwrap();

        assert_eq!(hashes.len(), 256);
        assert_eq!(cached_hashes.len(), 256);
        for i in 0..256 {
            assert_eq!(cached_hashes[i], hashes[i]);
            let (ref consensus_hash, ref block_hash_opt) = &hashes[i];
            if i % 3 == 0 {
                assert!(block_hash_opt.is_none());
            } else {
                assert!(block_hash_opt.is_some());
                let block_hash = block_hash_opt.unwrap();
                assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
            }
            assert_eq!(
                *consensus_hash,
                ConsensusHash::from_bytes(&[
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8
                ])
                .unwrap()
            );

            if i > 0 {
                assert!(cache.contains_key(consensus_hash));
                assert_eq!(cache.get(consensus_hash).unwrap().0, *block_hash_opt);
            }
        }
    }

    {
        let ic = db.index_conn();
        let hashes = ic
            .get_stacks_header_hashes(
                192,
                &canonical_tip.consensus_hash,
                &mut BlockHeaderCache::new(),
            )
            .unwrap();
        SortitionDB::merge_block_header_cache(&mut cache, &hashes);

        let cached_hashes = ic
            .get_stacks_header_hashes(192, &canonical_tip.consensus_hash, &cache)
            .unwrap();

        assert_eq!(hashes.len(), 192);
        assert_eq!(cached_hashes.len(), 192);
        for i in 64..256 {
            assert_eq!(cached_hashes[i - 64], hashes[i - 64]);
            let (ref consensus_hash, ref block_hash_opt) = &hashes[i - 64];
            if i % 3 == 0 {
                assert!(block_hash_opt.is_none());
            } else {
                assert!(block_hash_opt.is_some());
                let block_hash = block_hash_opt.unwrap();
                assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
            }
            assert_eq!(
                *consensus_hash,
                ConsensusHash::from_bytes(&[
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8
                ])
                .unwrap()
            );

            assert!(cache.contains_key(consensus_hash));
            assert_eq!(cache.get(consensus_hash).unwrap().0, *block_hash_opt);
        }
    }

    {
        let ic = db.index_conn();
        let hashes = ic
            .get_stacks_header_hashes(
                257,
                &canonical_tip.consensus_hash,
                &mut BlockHeaderCache::new(),
            )
            .unwrap();
        SortitionDB::merge_block_header_cache(&mut cache, &hashes);

        let cached_hashes = ic
            .get_stacks_header_hashes(257, &canonical_tip.consensus_hash, &cache)
            .unwrap();

        assert_eq!(hashes.len(), 256);
        assert_eq!(cached_hashes.len(), 256);
        for i in 0..256 {
            assert_eq!(cached_hashes[i], hashes[i]);
            let (ref consensus_hash, ref block_hash_opt) = &hashes[i];
            if i % 3 == 0 {
                assert!(block_hash_opt.is_none());
            } else {
                assert!(block_hash_opt.is_some());
                let block_hash = block_hash_opt.unwrap();
                assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
            }
            assert_eq!(
                *consensus_hash,
                ConsensusHash::from_bytes(&[
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8
                ])
                .unwrap()
            );

            if i > 0 {
                assert!(cache.contains_key(consensus_hash));
                assert_eq!(cache.get(consensus_hash).unwrap().0, *block_hash_opt);
            }
        }
    }

    {
        let ic = db.index_conn();
        let err = ic
            .get_stacks_header_hashes(256, &ConsensusHash([0x03; 20]), &BlockHeaderCache::new())
            .unwrap_err();
        match err {
            db_error::NotFoundError => {}
            _ => {
                eprintln!("Got wrong error: {:?}", &err);
                assert!(false);
                unreachable!();
            }
        }

        let err = ic
            .get_stacks_header_hashes(256, &ConsensusHash([0x03; 20]), &cache)
            .unwrap_err();
        match err {
            db_error::NotFoundError => {}
            _ => {
                eprintln!("Got wrong error: {:?}", &err);
                assert!(false);
                unreachable!();
            }
        }
    }
}

fn make_fork_run(
    db: &mut SortitionDB,
    start_snapshot: &BlockSnapshot,
    length: u64,
    bit_pattern: u8,
) -> () {
    let mut last_snapshot = start_snapshot.clone();
    for i in last_snapshot.block_height..(last_snapshot.block_height + length) {
        let snapshot = BlockSnapshot {
            accumulated_coinbase_ustx: 0,
            pox_valid: true,
            block_height: last_snapshot.block_height + 1,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: BurnchainHeaderHash([(i as u8) | bit_pattern; 32]),
            sortition_id: SortitionId([(i as u8) | bit_pattern; 32]),
            parent_sortition_id: last_snapshot.sortition_id.clone(),
            parent_burn_header_hash: last_snapshot.burn_header_hash.clone(),
            consensus_hash: ConsensusHash([((i + 1) as u8) | bit_pattern; 20]),
            ops_hash: OpsHash([(i as u8) | bit_pattern; 32]),
            total_burn: 0,
            sortition: true,
            sortition_hash: SortitionHash([(i as u8) | bit_pattern; 32]),
            winning_block_txid: Txid([(i as u8) | bit_pattern; 32]),
            winning_stacks_block_hash: BlockHeaderHash([(i as u8) | bit_pattern; 32]),
            index_root: TrieHash([0u8; 32]),
            num_sortitions: last_snapshot.num_sortitions + 1,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
            canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
        };
        {
            let mut tx = SortitionHandleTx::begin(db, &last_snapshot.sortition_id).unwrap();
            let _index_root = tx
                .append_chain_tip_snapshot(&last_snapshot, &snapshot, &vec![], None, None)
                .unwrap();
            tx.commit().unwrap();
        }
        last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &snapshot.sortition_id)
            .unwrap()
            .unwrap();
    }
}

#[test]
fn test_set_stacks_block_accepted() {
    let first_burn_hash = BurnchainHeaderHash::from_hex(
        "10000000000000000000000000000000000000000000000000000000000000ff",
    )
    .unwrap();
    let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();

    let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();

    // seed a single fork
    make_fork_run(&mut db, &last_snapshot, 5, 0);

    // set some blocks as processed
    for i in 0..5 {
        let consensus_hash = ConsensusHash([(i + 1) as u8; 20]);
        let parent_stacks_block_hash = if i == 0 {
            FIRST_STACKS_BLOCK_HASH.clone()
        } else {
            BlockHeaderHash([(i - 1) as u8; 32])
        };

        let stacks_block_hash = BlockHeaderHash([i as u8; 32]);
        let height = i;

        {
            let mut tx = db.tx_begin_at_tip();
            tx.set_stacks_block_accepted(
                &consensus_hash,
                &parent_stacks_block_hash,
                &stacks_block_hash,
                height,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // chain tip is memoized to the current burn chain tip
        let (block_consensus_hash, block_bhh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
        assert_eq!(block_consensus_hash, consensus_hash);
        assert_eq!(block_bhh, stacks_block_hash);
    }

    // materialize all block arrivals in the MARF
    last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x04; 32]))
        .unwrap()
        .unwrap();
    make_fork_run(&mut db, &last_snapshot, 1, 0);

    // verify that all Stacks block in this fork can be looked up from this chain tip
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    {
        let ic = db.index_conn();
        for i in 0..5 {
            let parent_stacks_block_hash = BlockHeaderHash([i as u8; 32]);
            let parent_key = db_keys::stacks_block_index(&parent_stacks_block_hash);

            test_debug!(
                "Look up '{}' off of {}",
                &parent_key,
                &last_snapshot.burn_header_hash
            );
            let value_opt = ic
                .get_indexed(&last_snapshot.sortition_id, &parent_key)
                .unwrap();
            assert!(value_opt.is_some());
            assert_eq!(value_opt.unwrap(), format!("{}", i));
        }
    }

    // make a burn fork off of the 5th block
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    make_fork_run(&mut db, &last_snapshot, 5, 0x80);

    // chain tip is _still_ memoized to the last materialized chain tip
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x8a; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 4);
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x04; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x05; 20])
    );

    // accept blocks 5 and 7 in one fork, and 6, 8, 9 in another.
    // Stacks fork 1,2,3,4,5,7 will be the longest fork.
    // Stacks fork 1,2,3,4 will overtake it when blocks 6,8,9 are processed.
    let mut parent_stacks_block_hash = BlockHeaderHash([0x04; 32]);
    for (i, height) in [5, 7].iter().zip([5, 6].iter()) {
        let consensus_hash = ConsensusHash([((i + 1) | 0x80) as u8; 20]);
        let stacks_block_hash = BlockHeaderHash([(i | 0x80) as u8; 32]);

        {
            let mut tx = db.tx_begin_at_tip();
            tx.set_stacks_block_accepted(
                &consensus_hash,
                &parent_stacks_block_hash,
                &stacks_block_hash,
                *height,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // chain tip is memoized to the current burn chain tip, since it's the longest stacks fork
        let (block_consensus_hash, block_bhh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
        assert_eq!(block_consensus_hash, consensus_hash);
        assert_eq!(block_bhh, stacks_block_hash);

        parent_stacks_block_hash = stacks_block_hash;
    }

    // chain tip is _still_ memoized to the last materialized chain tip (i.e. stacks block 7)
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x8a; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x88; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x87; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 6);

    // when the blocks for burn blocks 6 and 8 arrive, the canonical fork is still at stacks
    // block 7.  The two stacks forks will be:
    // * 1,2,3,4,5,7
    // * 1,2,3,4,6,8
    parent_stacks_block_hash = BlockHeaderHash([4u8; 32]);
    for (i, height) in [6, 8].iter().zip([5, 6].iter()) {
        let consensus_hash = ConsensusHash([((i + 1) | 0x80) as u8; 20]);
        let stacks_block_hash = BlockHeaderHash([(i | 0x80) as u8; 32]);

        {
            let mut tx = db.tx_begin_at_tip();
            tx.set_stacks_block_accepted(
                &consensus_hash,
                &parent_stacks_block_hash,
                &stacks_block_hash,
                *height,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // chain tip is memoized to the current burn chain tip, since it's the longest stacks fork
        let (block_consensus_hash, block_bhh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
        assert_eq!(
            block_consensus_hash,
            last_snapshot.canonical_stacks_tip_consensus_hash
        );
        assert_eq!(block_bhh, last_snapshot.canonical_stacks_tip_hash);

        parent_stacks_block_hash = stacks_block_hash;
    }

    // when the block for burn block 9 arrives, the canonical stacks fork will be
    // 1,2,3,4,6,8,9.  It overtakes 1,2,3,4,5,7
    for (i, height) in [9].iter().zip([7].iter()) {
        let consensus_hash = ConsensusHash([((i + 1) | 0x80) as u8; 20]);
        let stacks_block_hash = BlockHeaderHash([(i | 0x80) as u8; 32]);

        {
            let mut tx = db.tx_begin_at_tip();
            tx.set_stacks_block_accepted(
                &consensus_hash,
                &parent_stacks_block_hash,
                &stacks_block_hash,
                *height,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // we've overtaken the longest fork with a different longest fork on this burn chain fork
        let (block_consensus_hash, block_bhh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
        assert_eq!(block_consensus_hash, consensus_hash);
        assert_eq!(block_bhh, stacks_block_hash);
    }

    // canonical stacks chain tip is now stacks block 9
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x8a; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x8a; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x89; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 7);

    // fork the burn chain at 0x4, producing a longer burnchain fork.  There are now two
    // burnchain forks, where the first one has two stacks forks:
    // stx:      1,    2,    3,    4,          6,          8,    9
    // stx:      1,    2,    3,    4,    5,          7,
    // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
    //
    // stx:      1,    2,    3,    4
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
    last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x04; 32]))
        .unwrap()
        .unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x04; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x05; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x04; 32])
    );

    make_fork_run(&mut db, &last_snapshot, 7, 0x40);

    // canonical stacks chain tip is now stacks block 4, since the burn chain fork ending on
    // 0x4b has overtaken the burn chain fork ending on 0x8a
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x4b; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x05; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x04; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 4);

    // set the stacks block at 0x4b as accepted as the 5th block
    {
        let mut tx = db.tx_begin_at_tip();
        tx.set_stacks_block_accepted(
            &ConsensusHash([0x4c; 20]),
            &BlockHeaderHash([0x04; 32]),
            &BlockHeaderHash([0x4b; 32]),
            5,
        )
        .unwrap();
        tx.commit().unwrap();
    }

    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x4b; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x4c; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x4b; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);

    // fork the burn chain at 0x48, producing a shorter burnchain fork.  There are now three
    // burnchain forks:
    // stx:      1,    2,    3,    4,          6,          8,    9
    // stx:      1,    2,    3,    4,    5,          7,
    // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
    //
    // stx:      1,    2,    3,    4,                                        5
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
    //
    // stx:      1,    2,    3,    4,
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a
    last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x48; 32]))
        .unwrap()
        .unwrap();
    make_fork_run(&mut db, &last_snapshot, 2, 0x20);

    last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x2a; 32]))
        .unwrap()
        .unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x2a; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x05; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x04; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 4);

    // doesn't affect canonical chain tip
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x4b; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x4c; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x4b; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);

    // set the stacks block at 0x29 and 0x2a as accepted as the 5th and 6th blocks
    {
        let mut tx = db.tx_handle_begin(&SortitionId([0x2a; 32])).unwrap();
        tx.set_stacks_block_accepted(
            &ConsensusHash([0x2a; 20]),
            &BlockHeaderHash([0x04; 32]),
            &BlockHeaderHash([0x29; 32]),
            5,
        )
        .unwrap();
        tx.set_stacks_block_accepted(
            &ConsensusHash([0x2b; 20]),
            &BlockHeaderHash([0x29; 32]),
            &BlockHeaderHash([0x2a; 32]),
            6,
        )
        .unwrap();
        tx.commit().unwrap();
    }

    // new state of the world:
    // burnchain forks:
    // stx:      1,    2,    3,    4,          6,          8,    9
    // stx:      1,    2,    3,    4,    5,          7,
    // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
    //
    // stx:      1,    2,    3,    4,                                        5
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
    //
    // stx:      1,    2,    3,    4,                            5,    6
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a

    // canonical stacks chain off of non-canonical burn chain fork 0x2a should have been updated
    last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x2a; 32]))
        .unwrap()
        .unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x2a; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x2b; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x2a; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 6);

    // insertion on the non-canonical tip doesn't affect canonical chain tip
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x4b; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x4c; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x4b; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);

    // insert stacks blocks #6, #7, #8, #9 off of the burn chain tip starting at 0x4b (i.e. the
    // canonical burn chain tip), on blocks 0x45, 0x46, and 0x47
    {
        let mut tx = db.tx_begin_at_tip();
        tx.set_stacks_block_accepted(
            &ConsensusHash([0x46; 20]),
            &BlockHeaderHash([0x04; 32]),
            &BlockHeaderHash([0x45; 32]),
            5,
        )
        .unwrap();
        tx.set_stacks_block_accepted(
            &ConsensusHash([0x47; 20]),
            &BlockHeaderHash([0x45; 32]),
            &BlockHeaderHash([0x46; 32]),
            6,
        )
        .unwrap();
        tx.set_stacks_block_accepted(
            &ConsensusHash([0x48; 20]),
            &BlockHeaderHash([0x46; 32]),
            &BlockHeaderHash([0x47; 32]),
            7,
        )
        .unwrap();
        tx.set_stacks_block_accepted(
            &ConsensusHash([0x49; 20]),
            &BlockHeaderHash([0x47; 32]),
            &BlockHeaderHash([0x48; 32]),
            8,
        )
        .unwrap();
        tx.commit().unwrap();
    }

    // new state of the world:
    // burnchain forks:
    // stx:      1,    2,    3,    4,          6,          8,    9
    // stx:      1,    2,    3,    4,    5,          7,
    // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
    //
    // stx:      1,    2,    3,    4,    6,    7,    8,   9
    // stx:      1,    2,    3,    4,                                        5
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
    //
    // stx:      1,    2,    3,    4,                            5,    6
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a

    // new stacks tip is the 9th block added on burn chain tipped by 0x4b
    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x4b; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x49; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x48; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 8);

    // LIMITATION: the burn chain tipped at 0x2a will _not_ be updated, since it is not the
    // canonical burn chain tip.
    last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x2a; 32]))
        .unwrap()
        .unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x2a; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x2b; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x2a; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 6);

    // BUT, when the burn chain tipped by 0x2a overtakes the one tipped by 0x4b, then all blocks
    // will show up.
    make_fork_run(&mut db, &last_snapshot, 2, 0x20);

    // new state of the world:
    // burnchain forks:
    // stx:      1,    2,    3,    4,          6,          8,    9
    // stx:      1,    2,    3,    4,    5,          7,
    // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
    //
    // stx:      1,    2,    3,    4,    6,    7,    8,    9
    // stx:      1,    2,    3,    4,                                        5
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
    //
    // stx:      1,    2,    3,    4,    7,    8,    9,   10
    // stx:      1,    2,    3,    4,                            5,    6
    // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a, 0x2b, 0x2c

    last_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    assert_eq!(
        last_snapshot.burn_header_hash,
        BurnchainHeaderHash([0x2c; 32])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_consensus_hash,
        ConsensusHash([0x49; 20])
    );
    assert_eq!(
        last_snapshot.canonical_stacks_tip_hash,
        BlockHeaderHash([0x48; 32])
    );
    assert_eq!(last_snapshot.canonical_stacks_tip_height, 8);
}

#[test]
fn test_epoch_switch() {
    let db_path_dir = random_sortdb_test_dir();

    let mut db = SortitionDB::connect(
        &db_path_dir,
        3,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: 8,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 8,
                end_height: 12,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 12,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ],
        true,
    )
    .unwrap();

    let mut cur_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
    // In this loop, we will advance the height, and check if the stacks epoch id is advancing as expected.
    for i in 0..20 {
        debug!("Get epoch for block height {}", cur_snapshot.block_height);
        let cur_epoch = SortitionDB::get_stacks_epoch(db.conn(), cur_snapshot.block_height)
            .unwrap()
            .unwrap();

        if cur_snapshot.block_height < 8 {
            assert_eq!(cur_epoch.epoch_id, StacksEpochId::Epoch10);
        } else if cur_snapshot.block_height < 12 {
            assert_eq!(cur_epoch.epoch_id, StacksEpochId::Epoch20);
        } else {
            assert_eq!(cur_epoch.epoch_id, StacksEpochId::Epoch2_05);
        }

        cur_snapshot =
            test_append_snapshot(&mut db, BurnchainHeaderHash([((i + 1) as u8); 32]), &vec![]);
    }
}

#[test]
#[should_panic]
fn test_bad_epochs_discontinuous() {
    let db_path_dir = random_sortdb_test_dir();

    let db = SortitionDB::connect(
        &db_path_dir,
        3,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: 8,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 9,
                end_height: 12,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            }, // discontinuity
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 12,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ],
        true,
    )
    .unwrap();
}

#[test]
#[should_panic]
fn test_bad_epochs_overlapping() {
    let db_path_dir = random_sortdb_test_dir();

    let db = SortitionDB::connect(
        &db_path_dir,
        3,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: 8,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 7,
                end_height: 12,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            }, // overlap
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 12,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ],
        true,
    )
    .unwrap();
}

#[test]
#[should_panic]
fn test_bad_epochs_missing_past() {
    let db_path_dir = random_sortdb_test_dir();

    let db = SortitionDB::connect(
        &db_path_dir,
        3,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 1,
                end_height: 8,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            }, // should start at 0
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 8,
                end_height: 12,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 12,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ],
        true,
    )
    .unwrap();
}

#[test]
#[should_panic]
fn test_bad_epochs_missing_future() {
    let db_path_dir = random_sortdb_test_dir();

    let db = SortitionDB::connect(
        &db_path_dir,
        3,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: 8,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 8,
                end_height: 12,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 12,
                end_height: 20,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            }, // missing future
        ],
        true,
    )
    .unwrap();
}

#[test]
#[should_panic]
fn test_bad_epochs_invalid() {
    let db_path_dir = random_sortdb_test_dir();

    let db = SortitionDB::connect(
        &db_path_dir,
        3,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: 8,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 8,
                end_height: 7,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            }, // invalid range
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 8,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ],
        true,
    )
    .unwrap();
}
