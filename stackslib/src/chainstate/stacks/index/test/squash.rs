// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::io::{Cursor, Seek};
use std::path::PathBuf;

use stacks_common::types::chainstate::{StacksBlockId, TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE};
use tempfile::tempdir;

use super::marf::setup_marf;
use crate::chainstate::stacks::index::bits::get_node_byte_len;
use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection, SquashStats, MARF, OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{
    is_u64_ptr, set_backptr, TrieNode as _, TrieNode16, TrieNode256, TrieNode4, TrieNode48,
    TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::squash::{
    compute_blob_offsets, compute_blob_offsets_inner, deserialize_node, remap_ptrs_to_blob_offsets,
    serialize_node, stream_squash_blob, NodeStore,
};
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::{trie_sql, ClarityMarfTrieId, Error, MARFValue, TrieLeaf};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn squash_helper(src_path: &str, dst_dir: &std::path::Path, height: u32) -> (PathBuf, SquashStats) {
    std::fs::create_dir_all(dst_dir).unwrap();
    let dst_db_path = dst_dir.join("index.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let stats = MARF::<StacksBlockId>::squash_to_path(
        src_path,
        dst_db_path.to_str().unwrap(),
        open_opts,
        height,
        "test",
    )
    .unwrap();
    (dst_db_path, stats)
}

const STRESS_SQUASH_BLOCKS: usize = 128;
const STRESS_SQUASH_KEYS_PER_BLOCK: usize = 8;
const STRESS_SQUASH_HEIGHT: u32 = 96;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_squash_to_path_outputs_data() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let (dst_db_path, stats) = squash_helper(
        src_db_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        1,
    );

    assert!(stats.node_count > 0);
    assert!(dst_db_path.exists());
    assert!(PathBuf::from(format!("{}.blobs", dst_db_path.display())).exists());

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut dst =
        MARF::<StacksBlockId>::from_path(dst_db_path.to_str().unwrap(), open_opts).unwrap();
    let k1 = dst.get(&blocks[1], "k1").unwrap().unwrap();
    assert_eq!(k1, MARFValue::from_value("v1_at_1"));
    let own_height = dst.get(&blocks[1], OWN_BLOCK_HEIGHT_KEY).unwrap().unwrap();
    assert_eq!(own_height, MARFValue::from(1u32));
}

#[test]
fn test_squash_info_detected_on_open() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let _ = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let (dst_db_path, _) = squash_helper(
        src_db_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        1,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(dst_db_path.to_str().unwrap(), open_opts).unwrap();
    let tip =
        trie_sql::get_latest_confirmed_block_hash::<StacksBlockId>(squashed.sqlite_conn()).unwrap();

    // Verify squash metadata was detected from the SQL table on open.
    let (is_squashed, info_root, info_height) = squashed
        .with_conn(|conn| -> Result<(bool, TrieHash, u32), Error> {
            let info = conn.squash_info().expect("missing squash info");
            Ok((
                conn.is_squashed(),
                info.archival_marf_root_hash,
                info.height,
            ))
        })
        .unwrap();

    // Cross-check with the SQL table directly.
    let (sql_root, _sql_squash_root, sql_height) =
        trie_sql::read_squash_info(squashed.sqlite_conn())
            .unwrap()
            .expect("SQL squash info missing");

    assert!(is_squashed);
    assert_eq!(info_root, sql_root);
    assert_eq!(info_height, sql_height);
    assert_eq!(info_height, 1);
}

#[test]
fn test_squash_info_absent_on_archival_open() {
    let (mut marf, _blocks, _expected_keys) = setup_marf(":memory:", 2, 1);

    let (is_squashed, has_info) = marf
        .with_conn(|conn| -> Result<(bool, bool), Error> {
            Ok((conn.is_squashed(), conn.squash_info().is_some()))
        })
        .unwrap();

    assert!(!is_squashed);
    assert!(!has_info);
}

#[test]
fn test_squashed_marf_can_extend_past_snapshot_height() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let (dst_db_path, _) = squash_helper(
        src_db_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        1,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(dst_db_path.to_str().unwrap(), open_opts).unwrap();

    let b2 = blocks[1].clone();
    let b3 = StacksBlockId::from_bytes(&[3u8; 32]).unwrap();
    let b4 = StacksBlockId::from_bytes(&[4u8; 32]).unwrap();

    squashed.begin(&b2, &b3).unwrap();
    squashed.insert("k3", MARFValue::from_value("v4")).unwrap();
    squashed.commit().unwrap();

    squashed.begin(&b3, &b4).unwrap();
    squashed.insert("k4", MARFValue::from_value("v5")).unwrap();
    squashed.commit().unwrap();

    let v4 = squashed.get(&b4, "k4").unwrap().unwrap();
    assert_eq!(v4, MARFValue::from_value("v5"));
    let own_height = squashed.get(&b4, OWN_BLOCK_HEIGHT_KEY).unwrap().unwrap();
    assert_eq!(own_height, MARFValue::from(3u32));
}

/// Verify that `get_root_hash_at` and `get_block_height_of` return correct
/// per-height values for blocks *inside* the squashed range.  Without the
/// squash-aware overrides these would return the shared blob's root hash
/// (wrong) and the squash height H (wrong) for every historical block.
#[test]
fn test_squashed_historical_root_hash_and_height() {
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let (mut archival, blocks, _) = setup_marf(archival_path.to_str().unwrap(), 5, 1);

    // Collect archival root hashes and heights for blocks inside range.
    let archival_roots: Vec<TrieHash> = (0..=4)
        .map(|i| archival.get_root_hash_at(&blocks[i]).unwrap())
        .collect();

    // Squash at height 4 (blocks 0..=4 are in the squashed range).
    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        4,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    // (a) get_root_hash_at must return the archival per-height root, not
    //     the shared squash blob root.
    for i in 0..=4 {
        let sq_root = squashed.get_root_hash_at(&blocks[i]).unwrap();
        assert_eq!(
            archival_roots[i], sq_root,
            "root hash mismatch at height {i} (inside squashed range)"
        );
    }

    // (b) get_block_height_of must return the correct per-block height,
    //     not the squash height (4) for all of them.
    for i in 0..=4usize {
        let h = squashed
            .get_block_height_of(&blocks[i], &blocks[4])
            .unwrap()
            .expect("height should be Some");
        assert_eq!(
            h, i as u32,
            "height mismatch for block at index {i}: expected {i}, got {h}"
        );
    }

    // (c) The archival roots should not all be identical (sanity).
    assert_ne!(archival_roots[0], archival_roots[4]);
}

/// Verify that `test_squash_info_detected_on_open` also asserts the
/// squash_root_node_hash from the SQL table.
#[test]
fn test_squash_info_sql_squash_root_asserted() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let _ = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let (dst_db_path, _) = squash_helper(
        src_db_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        1,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(dst_db_path.to_str().unwrap(), open_opts).unwrap();

    let (_, sql_squash_root, _) = trie_sql::read_squash_info(squashed.sqlite_conn())
        .unwrap()
        .expect("SQL squash info missing");

    let cached_root = squashed
        .with_conn(|conn| -> Result<TrieHash, Error> {
            Ok(conn.squash_info().unwrap().squash_root_node_hash)
        })
        .unwrap();

    // sql_squash_root may be None if not yet computed (squash_to_path sets
    // it after blob commit).  If present, it must match the cached value.
    if let Some(sql_root) = sql_squash_root {
        assert_eq!(sql_root, cached_root, "cached vs SQL squash root mismatch");
    }
    // Either way, the cached root must not be the zero hash (squash_to_path
    // computes and stores it).
    assert_ne!(
        cached_root,
        TrieHash::from_data(&[]),
        "squash root node hash should be populated after squash"
    );
}

#[test]
fn test_large_marf_squash_extend_root_hash_matches_archival() {
    // Squash a 10-block MARF at height 8, then extend both the archival
    // and squashed MARFs with the same data at heights 9 and 10.
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let (mut archival, blocks, _expected_keys) = setup_marf(archival_path.to_str().unwrap(), 10, 1);

    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        8,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let b_new_9 = StacksBlockId::from_bytes(&[101u8; 32]).unwrap();
    let b_new_10 = StacksBlockId::from_bytes(&[102u8; 32]).unwrap();

    // --- Extend archival ---
    archival.begin(&blocks[8], &b_new_9).unwrap();
    archival
        .insert("k_new_9", MARFValue::from_value("val9"))
        .unwrap();
    archival.commit().unwrap();

    archival.begin(&b_new_9, &b_new_10).unwrap();
    archival
        .insert("k_new_10", MARFValue::from_value("val10"))
        .unwrap();
    archival.commit().unwrap();

    // --- Extend squashed ---
    squashed.begin(&blocks[8], &b_new_9).unwrap();
    squashed
        .insert("k_new_9", MARFValue::from_value("val9"))
        .unwrap();
    squashed.commit().unwrap();

    squashed.begin(&b_new_9, &b_new_10).unwrap();
    squashed
        .insert("k_new_10", MARFValue::from_value("val10"))
        .unwrap();
    squashed.commit().unwrap();

    // (a) Data inserted at the extended heights is readable.
    assert_eq!(
        squashed.get(&b_new_9, "k_new_9").unwrap().unwrap(),
        MARFValue::from_value("val9")
    );
    assert_eq!(
        squashed.get(&b_new_10, "k_new_10").unwrap().unwrap(),
        MARFValue::from_value("val10")
    );
    assert_eq!(
        squashed.get(&b_new_10, "k1").unwrap().unwrap(),
        MARFValue::from_value("v1_at_8")
    );

    // (b) MARF root hashes at the extended heights must match.
    let archival_root_9 = archival.get_root_hash_at(&b_new_9).unwrap();
    let squashed_root_9 = squashed.get_root_hash_at(&b_new_9).unwrap();
    assert_eq!(
        archival_root_9, squashed_root_9,
        "Root hash mismatch at height 9"
    );

    let archival_root_10 = archival.get_root_hash_at(&b_new_10).unwrap();
    let squashed_root_10 = squashed.get_root_hash_at(&b_new_10).unwrap();
    assert_eq!(
        archival_root_10, squashed_root_10,
        "Root hash mismatch at height 10"
    );

    assert_ne!(archival_root_9, TrieHash([0u8; 32]), "root at 9 is zero");
    assert_ne!(archival_root_10, TrieHash([0u8; 32]), "root at 10 is zero");
    assert_ne!(
        archival_root_9, archival_root_10,
        "roots at 9 and 10 should differ"
    );

    let own_h = squashed
        .get(&b_new_10, OWN_BLOCK_HEIGHT_KEY)
        .unwrap()
        .unwrap();
    assert_eq!(own_h, MARFValue::from(10u32));
}

/// Squash a larger MARF at a deep height, then extend both MARFs through 10 additional
/// heights and verify hash equality at EVERY extended height.
#[test]
fn test_multi_height_extension_hash_equality() {
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let (mut archival, blocks, _expected_keys) = setup_marf(
        archival_path.to_str().unwrap(),
        STRESS_SQUASH_BLOCKS,
        STRESS_SQUASH_KEYS_PER_BLOCK,
    );

    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        STRESS_SQUASH_HEIGHT,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let mut prev_block = blocks[STRESS_SQUASH_HEIGHT as usize].clone();
    let mut new_blocks: Vec<StacksBlockId> = Vec::new();
    for i in 0..10u8 {
        let new_bh = StacksBlockId::from_bytes(&[200 + i; 32]).unwrap();
        let key = format!("ext_k{i}");
        let val = format!("ext_v{i}");

        archival.begin(&prev_block, &new_bh).unwrap();
        archival.insert(&key, MARFValue::from_value(&val)).unwrap();
        archival.commit().unwrap();

        squashed.begin(&prev_block, &new_bh).unwrap();
        squashed.insert(&key, MARFValue::from_value(&val)).unwrap();
        squashed.commit().unwrap();

        new_blocks.push(new_bh.clone());
        prev_block = new_bh;
    }

    for (i, bh) in new_blocks.iter().enumerate() {
        let arch_root = archival.get_root_hash_at(bh).unwrap();
        let sq_root = squashed.get_root_hash_at(bh).unwrap();
        assert_eq!(
            arch_root,
            sq_root,
            "Root hash mismatch at extended height {}",
            i + STRESS_SQUASH_HEIGHT as usize + 1
        );
        assert_ne!(
            arch_root,
            TrieHash([0u8; 32]),
            "root at {} is zero",
            i + STRESS_SQUASH_HEIGHT as usize + 1
        );
    }

    let last = new_blocks.last().unwrap();
    assert_eq!(
        squashed.get(last, "k1").unwrap().unwrap(),
        MARFValue::from_value(&format!("v1_at_{STRESS_SQUASH_HEIGHT}")),
    );
    assert_eq!(
        squashed.get(last, "ext_k9").unwrap().unwrap(),
        MARFValue::from_value("ext_v9"),
    );
}

/// Test that extending a squashed MARF with blocks that write MANY keys
/// per block produces the same root hashes as the archival MARF.
#[test]
fn test_dense_writes_after_squash_hash_equality() {
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let (mut archival, blocks, _expected_keys) = setup_marf(
        archival_path.to_str().unwrap(),
        STRESS_SQUASH_BLOCKS,
        STRESS_SQUASH_KEYS_PER_BLOCK,
    );

    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        STRESS_SQUASH_HEIGHT,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    // Extend with blocks that write MANY keys each - simulating a block
    // with many contract calls (like mainnet block 201697 with 42 txs).
    let keys_per_extension_block = 200;
    let extension_blocks = 20;

    let mut prev_block = blocks[STRESS_SQUASH_HEIGHT as usize].clone();
    let mut new_blocks: Vec<StacksBlockId> = Vec::new();

    for blk in 0..extension_blocks {
        let new_bh = StacksBlockId::from_bytes(&[200 + blk as u8; 32]).unwrap();

        archival.begin(&prev_block, &new_bh).unwrap();
        squashed.begin(&prev_block, &new_bh).unwrap();

        for k in 0..keys_per_extension_block {
            let key = format!("dense_blk{blk}_k{k}");
            let val = format!("dense_blk{blk}_v{k}");
            archival.insert(&key, MARFValue::from_value(&val)).unwrap();
            squashed.insert(&key, MARFValue::from_value(&val)).unwrap();
        }

        // Also overwrite some keys from the archival history to force
        // COW copies of deeper trie nodes.
        for k in 0..STRESS_SQUASH_KEYS_PER_BLOCK {
            let key = format!("k{k}");
            let val = format!("overwritten_blk{blk}");
            archival.insert(&key, MARFValue::from_value(&val)).unwrap();
            squashed.insert(&key, MARFValue::from_value(&val)).unwrap();
        }

        // Simulate at-block: read a key from a historical block mid-transaction.
        // This exercises the open_block/restore cycle on the squashed blob.
        if blk > 0 {
            let historical_block = &new_blocks[blk - 1];
            let _arch_val = archival.get(historical_block, "dense_blk0_k0").unwrap();
            let _sq_val = squashed.get(historical_block, "dense_blk0_k0").unwrap();
            assert_eq!(_arch_val, _sq_val, "at-block read mismatch at blk {blk}");

            // Also read from a pre-squash block
            let old_block = &blocks[STRESS_SQUASH_HEIGHT as usize / 2];
            let _arch_val2 = archival.get(old_block, "k0").unwrap();
            let _sq_val2 = squashed.get(old_block, "k0").unwrap();
            assert_eq!(
                _arch_val2, _sq_val2,
                "at-block pre-squash read mismatch at blk {blk}"
            );
        }

        archival.commit().unwrap();
        squashed.commit().unwrap();

        new_blocks.push(new_bh.clone());
        prev_block = new_bh;
    }

    for (i, bh) in new_blocks.iter().enumerate() {
        let arch_root = archival.get_root_hash_at(bh).unwrap();
        let sq_root = squashed.get_root_hash_at(bh).unwrap();
        assert_eq!(
            arch_root, sq_root,
            "Root hash mismatch at dense extension block {} (wrote {} keys + {} overwrites)",
            i, keys_per_extension_block, STRESS_SQUASH_KEYS_PER_BLOCK
        );
    }
}

/// Verify that reading a key at a pre-squash block on a squashed MARF
/// returns the squash-tip's value, not the value that existed at that block.
/// This documents the known limitation of the single-blob design: historical
/// reads within the squash range return tip-era values for keys that changed.
#[test]
fn test_squash_historical_read_returns_tip_value() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    // 64 blocks, 4 keys per block, squash at height 48
    let (mut archival, blocks, _) = setup_marf(src_path.to_str().unwrap(), 64, 4);

    let squash_height: u32 = 48;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let tip_block = &blocks[squash_height as usize];

    // `k1` is written at EVERY block with value `v1_at_{height}`.
    // At block 10, the archival should return "v1_at_10".
    // The squash should return "v1_at_{squash_height}" because
    // all blocks share the squash-tip's blob.
    let early_block = &blocks[10];

    let arch_val = archival.get(early_block, "k1").unwrap();
    let sq_val = squashed.get(early_block, "k1").unwrap();
    let tip_val = squashed.get(tip_block, "k1").unwrap();

    // Archival correctly returns the value at block 10
    assert_eq!(
        arch_val,
        Some(MARFValue::from_value("v1_at_10")),
        "archival should return the historical value"
    );

    // Squash returns the TIP value, not the block-10 value.
    // This is the documented limitation of the single-blob squash.
    assert_eq!(
        sq_val, tip_val,
        "squashed historical read should return tip value, not historical value"
    );
    assert_ne!(
        sq_val, arch_val,
        "squashed historical read should differ from archival for keys that changed"
    );
}

/// Same as above but for `common_some_*` keys that only change on some blocks.
/// At blocks where the key was NOT updated, the archival returns the last-written
/// value before that block. The squash returns the tip value regardless.
#[test]
fn test_squash_historical_read_intermittent_key() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (mut archival, blocks, _) = setup_marf(src_path.to_str().unwrap(), 64, 4);

    let squash_height: u32 = 48;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let tip_block = &blocks[squash_height as usize];

    // common_some_0 is written at heights where (height + 0) % 3 == 0,
    // i.e. heights 0, 3, 6, 9, 12, ... with value "common_some_0_at_{h}".
    // Read at block 10 - last write was at height 9.
    let early_block = &blocks[10];

    let arch_val = archival.get(early_block, "common_some_0").unwrap();
    let sq_val = squashed.get(early_block, "common_some_0").unwrap();
    let tip_val = squashed.get(tip_block, "common_some_0").unwrap();

    // Archival returns the value from the last write at/before height 10
    assert_eq!(
        arch_val,
        Some(MARFValue::from_value("common_some_0_at_9")),
        "archival should return value from height 9"
    );

    // Squash returns the tip value
    assert_eq!(
        sq_val, tip_val,
        "squashed should return tip value for intermittent key"
    );
    assert_ne!(
        sq_val, arch_val,
        "squashed historical read should differ from archival"
    );
}

/// Extend a squashed MARF through enough blocks to exercise deep backpointer
/// chains and node promotions, then verify hash equality with the archival.
/// Uses 256 blocks, 32 keys/block at squash height 192 (leaving 64 extension blocks).
#[test]
fn test_deep_extension_hash_equality() {
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let num_blocks: usize = 256;
    let keys_per_block: usize = 32;
    let squash_height: u32 = 192;
    let extension_blocks: usize = 20;

    let (mut archival, blocks, _) =
        setup_marf(archival_path.to_str().unwrap(), num_blocks, keys_per_block);

    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let mut prev_block = blocks[squash_height as usize].clone();
    let mut new_blocks: Vec<StacksBlockId> = Vec::new();

    for blk in 0..extension_blocks {
        let new_bh = {
            let mut bytes = [0u8; 32];
            bytes[0] = 0xee;
            bytes[24..28].copy_from_slice(&(blk as u32).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        };

        archival.begin(&prev_block, &new_bh).unwrap();
        squashed.begin(&prev_block, &new_bh).unwrap();

        // Write many new keys (forces node promotions in the trie)
        for k in 0..(keys_per_block * 4) {
            let key = format!("ext_blk{blk}_k{k}");
            let val = format!("ext_blk{blk}_v{k}");
            archival.insert(&key, MARFValue::from_value(&val)).unwrap();
            squashed.insert(&key, MARFValue::from_value(&val)).unwrap();
        }

        // Overwrite keys from across the squash range (deep COW walks)
        for k in 0..keys_per_block {
            let key_index = 2 + (squash_height as usize / 2) * keys_per_block + k;
            let key = format!("k{key_index}");
            let val = format!("deep_overwrite_blk{blk}");
            archival.insert(&key, MARFValue::from_value(&val)).unwrap();
            squashed.insert(&key, MARFValue::from_value(&val)).unwrap();
        }

        // Also overwrite common keys (causes COW of root-adjacent nodes)
        for c in 0..10 {
            let key = format!("common_all_{c}");
            let val = format!("common_all_{c}_ext_{blk}");
            archival.insert(&key, MARFValue::from_value(&val)).unwrap();
            squashed.insert(&key, MARFValue::from_value(&val)).unwrap();
        }

        archival.commit().unwrap();
        squashed.commit().unwrap();

        new_blocks.push(new_bh.clone());
        prev_block = new_bh;
    }

    for (i, bh) in new_blocks.iter().enumerate() {
        let arch_root = archival.get_root_hash_at(bh).unwrap();
        let sq_root = squashed.get_root_hash_at(bh).unwrap();
        assert_eq!(
            arch_root,
            sq_root,
            "Root hash mismatch at deep extension block {i} (256 blocks, \
             32 keys/block, squash at 192, {} new keys + {} overwrites per ext block)",
            keys_per_block * 4,
            keys_per_block + 10
        );
    }
}

/// Verify that all historical marf_data entries share the same
/// external_offset (i.e. point to the single shared trie storage).
#[test]
fn test_marf_data_entries_share_blob_offset() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (_, blocks, _expected_keys) = setup_marf(src_path.to_str().unwrap(), 10, 1);

    let (dst_path, _) = squash_helper(src_path.to_str().unwrap(), &dir.path().join("squashed"), 8);

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let squashed = MARF::<StacksBlockId>::from_path(dst_path.to_str().unwrap(), open_opts).unwrap();
    let conn = squashed.sqlite_conn();

    let tip_id = trie_sql::get_block_identifier(conn, &blocks[8]).unwrap();
    let (tip_offset, tip_length) = trie_sql::get_external_trie_offset_length(conn, tip_id).unwrap();
    assert!(tip_length > 0, "blob length should be non-zero");

    for i in 0..8 {
        let blk_id = trie_sql::get_block_identifier(conn, &blocks[i]).unwrap();
        let (offset, length) = trie_sql::get_external_trie_offset_length(conn, blk_id).unwrap();
        assert_eq!(offset, tip_offset, "block {i} offset mismatch");
        assert_eq!(length, tip_length, "block {i} length mismatch");
    }
}

/// Verify that walk_cow correctly follows annotated back_block values
/// when copying nodes from a squashed blob into a new block.
#[test]
fn test_walk_cow_preserves_backpointer_identity() {
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let (mut archival, blocks, _expected_keys) = setup_marf(archival_path.to_str().unwrap(), 10, 1);

    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        8,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let b_new = StacksBlockId::from_bytes(&[250u8; 32]).unwrap();
    squashed.begin(&blocks[8], &b_new).unwrap();
    squashed
        .insert("k1", MARFValue::from_value("v1_at_10"))
        .unwrap();
    squashed
        .insert("new_key", MARFValue::from_value("new_val"))
        .unwrap();
    squashed.commit().unwrap();

    for key in ["k2", "k5", "k9"] {
        let result = squashed.get(&b_new, &key).unwrap();
        assert!(result.is_some(), "missing key {key} after extend");
    }

    assert_eq!(
        squashed.get(&b_new, "k1").unwrap().unwrap(),
        MARFValue::from_value("v1_at_10"),
    );

    assert_eq!(
        squashed.get(&b_new, "new_key").unwrap().unwrap(),
        MARFValue::from_value("new_val"),
    );

    archival.begin(&blocks[8], &b_new).unwrap();
    archival
        .insert("k1", MARFValue::from_value("v1_at_10"))
        .unwrap();
    archival
        .insert("new_key", MARFValue::from_value("new_val"))
        .unwrap();
    archival.commit().unwrap();

    let arch_root = archival.get_root_hash_at(&b_new).unwrap();
    let sq_root = squashed.get_root_hash_at(&b_new).unwrap();
    assert_eq!(arch_root, sq_root, "Root hash mismatch after walk_cow");
}

#[test]
fn test_squash_internal_blobs_extend_with_compression() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("sort.sqlite");

    let squash_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false);
    let mut src =
        MARF::<StacksBlockId>::from_path(src_db_path.to_str().unwrap(), squash_opts.clone())
            .unwrap();

    let b1 = StacksBlockId::from_bytes(&[1u8; 32]).unwrap();
    let b2 = StacksBlockId::from_bytes(&[2u8; 32]).unwrap();
    let b3 = StacksBlockId::from_bytes(&[3u8; 32]).unwrap();

    src.begin(&StacksBlockId::sentinel(), &b1).unwrap();
    for i in 0u8..32 {
        src.insert(
            &format!("k{i:02}"),
            MARFValue::from_value(&format!("v1-{i:02}")),
        )
        .unwrap();
    }
    src.commit().unwrap();

    src.begin(&b1, &b2).unwrap();
    for i in 0u8..32 {
        src.insert(
            &format!("k{i:02}"),
            MARFValue::from_value(&format!("v2-{i:02}")),
        )
        .unwrap();
    }
    src.commit().unwrap();
    drop(src);

    let dst_dir = dir.path().join("squashed-compressed");
    std::fs::create_dir_all(&dst_dir).unwrap();
    let dst_db_path = dst_dir.join("sort.sqlite");

    MARF::<StacksBlockId>::squash_to_path(
        src_db_path.to_str().unwrap(),
        dst_db_path.to_str().unwrap(),
        squash_opts,
        1,
        "test",
    )
    .unwrap();

    let compressed_opts =
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true).with_compression(true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(dst_db_path.to_str().unwrap(), compressed_opts).unwrap();

    squashed.begin(&b2, &b3).unwrap();
    squashed
        .insert("k_extra", MARFValue::from_value("v3-extra"))
        .unwrap();
    squashed.commit().unwrap();

    let value = squashed.get(&b3, "k_extra").unwrap().unwrap();
    assert_eq!(value, MARFValue::from_value("v3-extra"));
}

// ---------------------------------------------------------------------------
// Targeted unit tests for the disk-backed squash mechanisms
// ---------------------------------------------------------------------------

/// Helper: build a leaf node for tests.
fn make_test_leaf(path: &[u8], value_byte: u8) -> TrieNodeType {
    let mut data = [0u8; 40];
    data[0] = value_byte;
    TrieNodeType::Leaf(TrieLeaf {
        path: path.to_vec(),
        data: MARFValue(data),
    })
}

/// Helper: build a Node4 with the given child pointers.
fn make_test_node4(path: &[u8], ptrs: [TriePtr; 4]) -> TrieNodeType {
    TrieNodeType::Node4(TrieNode4 {
        path: path.to_vec(),
        ptrs,
        cowptr: None,
        patches: vec![],
    })
}

#[test]
fn test_node_store_roundtrip_all_variants() {
    let dir = tempdir().unwrap();
    let dir_str = dir.path().to_str().unwrap();

    let mut store = NodeStore::new(dir_str).unwrap();

    // Leaf
    let leaf = make_test_leaf(&[1, 2, 3], 0xAA);
    let leaf_hash = TrieHash::from_data(&[1]);
    store.push(&leaf, leaf_hash, 10).unwrap();

    // Node4
    let n4 = make_test_node4(
        &[4, 5],
        [
            TriePtr::new(1, b'a', 100),
            TriePtr::default(),
            TriePtr::default(),
            TriePtr::default(),
        ],
    );
    let n4_hash = TrieHash::from_data(&[2]);
    store.push(&n4, n4_hash, 20).unwrap();

    // Node16
    let mut ptrs16 = [TriePtr::default(); 16];
    ptrs16[0] = TriePtr::new(2, b'b', 200);
    let n16 = TrieNodeType::Node16(TrieNode16 {
        path: vec![6, 7, 8],
        ptrs: ptrs16,
        cowptr: None,
        patches: vec![],
    });
    let n16_hash = TrieHash::from_data(&[3]);
    store.push(&n16, n16_hash, 30).unwrap();

    // Node48
    let mut indexes48 = [-1i8; 256];
    indexes48[b'c' as usize] = 0;
    let mut ptrs48 = [TriePtr::default(); 48];
    ptrs48[0] = TriePtr::new(3, b'c', 300);
    let n48 = TrieNodeType::Node48(Box::new(TrieNode48 {
        path: vec![9, 10],
        indexes: indexes48,
        ptrs: ptrs48,
        cowptr: None,
        patches: vec![],
    }));
    let n48_hash = TrieHash::from_data(&[4]);
    store.push(&n48, n48_hash, 40).unwrap();

    // Node256
    let mut ptrs256 = [TriePtr::default(); 256];
    ptrs256[b'd' as usize] = TriePtr::new(4, b'd', 400);
    let n256 = TrieNodeType::Node256(Box::new(TrieNode256 {
        path: vec![11],
        ptrs: ptrs256,
        cowptr: None,
        patches: vec![],
    }));
    let n256_hash = TrieHash::from_data(&[5]);
    store.push(&n256, n256_hash, 50).unwrap();

    store.finish_writing().unwrap();
    assert_eq!(store.len(), 5);

    // Read back and verify
    let mut reader = store.open_reader().unwrap();

    // Leaf round-trip
    let rt_leaf = store.read_node_with(&mut reader, 0).unwrap();
    assert!(rt_leaf.is_leaf());
    assert_eq!(rt_leaf.path_bytes(), &[1, 2, 3]);
    assert_eq!(store.hash(0), leaf_hash);
    assert_eq!(store.block_id(0), 10);

    // Node4 round-trip
    let rt_n4 = store.read_node_with(&mut reader, 1).unwrap();
    assert_eq!(rt_n4.ptrs()[0].chr(), b'a');
    assert_eq!(rt_n4.ptrs()[0].ptr(), 100);

    // Node16 round-trip
    let rt_n16 = store.read_node_with(&mut reader, 2).unwrap();
    assert_eq!(rt_n16.ptrs()[0].chr(), b'b');
    assert_eq!(rt_n16.ptrs()[0].ptr(), 200);

    // Node48 round-trip
    let rt_n48 = store.read_node_with(&mut reader, 3).unwrap();
    assert_eq!(rt_n48.ptrs()[0].chr(), b'c');
    assert_eq!(rt_n48.ptrs()[0].ptr(), 300);

    // Node256 round-trip
    let rt_n256 = store.read_node_with(&mut reader, 4).unwrap();
    assert_eq!(rt_n256.ptrs()[b'd' as usize].chr(), b'd');
    assert_eq!(rt_n256.ptrs()[b'd' as usize].ptr(), 400);
}

#[test]
fn test_node_store_spill_file_cleaned_on_drop() {
    let dir = tempdir().unwrap();
    let dir_str = dir.path().to_str().unwrap();

    let spill_path;
    {
        let mut store = NodeStore::new(dir_str).unwrap();
        spill_path = store.path.clone();

        let leaf = make_test_leaf(&[1], 0x01);
        store.push(&leaf, TrieHash::from_data(&[]), 0).unwrap();
        store.finish_writing().unwrap();

        // File should exist while store is alive
        assert!(spill_path.exists(), "spill file should exist before drop");
    }
    // After drop, file should be cleaned up
    assert!(
        !spill_path.exists(),
        "spill file should be removed after drop"
    );
}

#[test]
fn test_node_store_unique_temp_file_names() {
    let dir = tempdir().unwrap();
    let dir_str = dir.path().to_str().unwrap();

    let store1 = NodeStore::new(dir_str).unwrap();
    // Ensure different nanos by adding a tiny sleep
    std::thread::sleep(std::time::Duration::from_millis(1));
    let store2 = NodeStore::new(dir_str).unwrap();

    assert_ne!(
        store1.path, store2.path,
        "concurrent NodeStores should have different temp file paths"
    );
}

#[test]
fn test_serialize_deserialize_node_roundtrip() {
    // Test the raw serialize/deserialize functions independently of NodeStore
    let nodes: Vec<TrieNodeType> = vec![
        make_test_leaf(&[1, 2, 3, 4], 0xFF),
        make_test_node4(
            &[10, 20],
            [
                TriePtr::new(1, b'x', 42),
                TriePtr::new(1, b'y', 99),
                TriePtr::default(),
                TriePtr::default(),
            ],
        ),
    ];

    for original in &nodes {
        let mut buf = Vec::new();
        serialize_node(&mut buf, original).unwrap();

        let mut cursor = Cursor::new(&buf);
        let roundtripped = deserialize_node(&mut cursor).unwrap();

        assert_eq!(original.path_bytes(), roundtripped.path_bytes());
        assert_eq!(original.ptrs().len(), roundtripped.ptrs().len());
        for (a, b) in original.ptrs().iter().zip(roundtripped.ptrs().iter()) {
            assert_eq!(a.id(), b.id());
            assert_eq!(a.chr(), b.chr());
            assert_eq!(a.ptr(), b.ptr());
            assert_eq!(a.back_block(), b.back_block());
        }
    }
}

/// Build a branching trie with mixed node types and verify that
/// `compute_blob_offsets` + `stream_squash_blob` agree on sizes.
///
/// Trie layout (indices 0–6):
///   0: Node16 (root) -> children 1, 2
///   1: Node4           -> children 3, 4
///   2: Node4           -> child 5
///   3: Leaf
///   4: Leaf
///   5: Node4           -> child 6
///   6: Leaf
#[test]
fn test_blob_offsets_with_mixed_node_types() {
    let dir = tempdir().unwrap();
    let dir_str = dir.path().to_str().unwrap();
    let mut store = NodeStore::new(dir_str).unwrap();
    let h = TrieHash([0; 32]);

    // Index 0: Node16 root with two forward children.
    let mut root_ptrs = [TriePtr::default(); 16];
    root_ptrs[0] = TriePtr::new(TrieNodeID::Node4 as u8, b'a', 1);
    root_ptrs[1] = TriePtr::new(TrieNodeID::Node4 as u8, b'b', 2);
    let root = TrieNodeType::Node16(TrieNode16 {
        path: vec![0],
        ptrs: root_ptrs,
        cowptr: None,
        patches: vec![],
    });
    store.push(&root, h, 0).unwrap();

    // Index 1: Node4 with two forward children.
    store
        .push(
            &make_test_node4(
                &[1],
                [
                    TriePtr::new(TrieNodeID::Leaf as u8, b'c', 3),
                    TriePtr::new(TrieNodeID::Leaf as u8, b'd', 4),
                    TriePtr::default(),
                    TriePtr::default(),
                ],
            ),
            h,
            0,
        )
        .unwrap();

    // Index 2: Node4 with one forward child.
    store
        .push(
            &make_test_node4(
                &[2],
                [
                    TriePtr::new(TrieNodeID::Node4 as u8, b'e', 5),
                    TriePtr::default(),
                    TriePtr::default(),
                    TriePtr::default(),
                ],
            ),
            h,
            0,
        )
        .unwrap();

    // Index 3: Leaf
    store.push(&make_test_leaf(&[3, 4], 0xAA), h, 0).unwrap();
    // Index 4: Leaf
    store.push(&make_test_leaf(&[5, 6], 0xBB), h, 0).unwrap();

    // Index 5: Node4 with one forward child (deeper subtree).
    store
        .push(
            &make_test_node4(
                &[7],
                [
                    TriePtr::new(TrieNodeID::Leaf as u8, b'f', 6),
                    TriePtr::default(),
                    TriePtr::default(),
                    TriePtr::default(),
                ],
            ),
            h,
            0,
        )
        .unwrap();

    // Index 6: Leaf
    store.push(&make_test_leaf(&[8, 9], 0xCC), h, 0).unwrap();

    store.finish_writing().unwrap();

    let (blob_offsets, total_size) = compute_blob_offsets(&mut store).unwrap();
    assert_eq!(blob_offsets.len(), 7);

    // Offsets must be strictly increasing (each node has non-zero size).
    for w in blob_offsets.windows(2) {
        assert!(w[1] > w[0], "offsets must be strictly increasing");
    }

    // stream_squash_blob must write exactly total_size bytes.
    let parent_hash = StacksBlockId::sentinel();
    let mut output = Cursor::new(Vec::new());
    let bytes_written =
        stream_squash_blob(&mut store, &parent_hash, &blob_offsets, &mut output).unwrap();
    assert_eq!(bytes_written, total_size);

    // Verify blob header.
    let blob = output.into_inner();
    assert_eq!(&blob[..32], parent_hash.as_bytes());
    assert_eq!(
        &blob[BLOCK_HEADER_HASH_ENCODED_SIZE..BLOCK_HEADER_HASH_ENCODED_SIZE + 4],
        &0u32.to_le_bytes()
    );
}

/// Verify that writing the blob at a non-zero sink offset doesn't corrupt
/// the output. bytes_written equals total_size and the prefix is untouched.
#[test]
fn test_stream_squash_blob_at_nonzero_offset() {
    let dir = tempdir().unwrap();
    let dir_str = dir.path().to_str().unwrap();
    let mut store = NodeStore::new(dir_str).unwrap();

    let leaf = make_test_leaf(&[1, 2], 0xBB);
    let root = make_test_node4(
        &[0],
        [
            TriePtr::new(1, b'a', 1),
            TriePtr::default(),
            TriePtr::default(),
            TriePtr::default(),
        ],
    );
    store.push(&root, TrieHash::from_data(&[0xAA]), 0).unwrap();
    store.push(&leaf, TrieHash::from_data(&[0xBB]), 0).unwrap();
    store.finish_writing().unwrap();

    let parent_hash = StacksBlockId::sentinel();
    let (blob_offsets, total_size) = compute_blob_offsets(&mut store).unwrap();

    // Write to a sink that already has 1000 bytes of garbage prefix.
    let prefix_len: u64 = 1000;
    let mut buf = vec![0xFFu8; prefix_len as usize];
    let mut output = Cursor::new(&mut buf);
    output.seek(std::io::SeekFrom::End(0)).unwrap();

    let bytes_written =
        stream_squash_blob(&mut store, &parent_hash, &blob_offsets, &mut output).unwrap();
    assert_eq!(bytes_written, total_size);

    let total_buf = output.into_inner();
    assert_eq!(total_buf.len() as u64, prefix_len + total_size);
    assert!(total_buf[..prefix_len as usize].iter().all(|&b| b == 0xFF));
}

/// Test `remap_ptrs_to_blob_offsets` directly: verify it replaces forward
/// child pointers with their blob offsets, leaves back/empty pointers
/// untouched, and returns CorruptionError for out-of-bounds indices.
#[test]
fn test_remap_ptrs_to_blob_offsets() {
    // Build a Node4 with a mix of pointer types:
    //   slot 0: forward ptr to child index 1
    //   slot 1: back ptr (should be left untouched)
    //   slot 2: empty (should be left untouched)
    //   slot 3: forward ptr to child index 2
    let back_id = set_backptr(TrieNodeID::Node4 as u8);
    let mut node = make_test_node4(
        &[0],
        [
            TriePtr::new(TrieNodeID::Leaf as u8, b'a', 1),
            TriePtr {
                id: back_id,
                chr: b'x',
                ptr: 999,
                back_block: 5,
            },
            TriePtr::default(),
            TriePtr::new(TrieNodeID::Leaf as u8, b'b', 2),
        ],
    );

    let offsets: Vec<u64> = vec![100, 200, 300];
    remap_ptrs_to_blob_offsets(&mut node, &offsets).unwrap();

    let ptrs = node.ptrs();
    // Forward ptrs remapped to blob offsets.
    assert_eq!(ptrs[0].ptr(), 200); // child_idx 1 -> offset 200
    assert_eq!(ptrs[3].ptr(), 300); // child_idx 2 -> offset 300
                                    // Back ptr untouched.
    assert_eq!(ptrs[1].ptr(), 999);
    assert_eq!(ptrs[1].back_block(), 5);
    // Empty ptr untouched.
    assert_eq!(ptrs[2].ptr(), 0);

    // Leaves are a no-op.
    let mut leaf = make_test_leaf(&[1], 0xAA);
    remap_ptrs_to_blob_offsets(&mut leaf, &offsets).unwrap();

    // Out-of-bounds child index returns CorruptionError.
    let mut bad_node = make_test_node4(
        &[0],
        [
            TriePtr::new(TrieNodeID::Leaf as u8, b'a', 99), // index 99 > offsets.len()
            TriePtr::default(),
            TriePtr::default(),
            TriePtr::default(),
        ],
    );
    assert!(remap_ptrs_to_blob_offsets(&mut bad_node, &offsets).is_err());
}

/// Verify that `remap_ptrs_to_blob_offsets` with offsets > u32::MAX causes
/// the node's serialized size to grow (u32 -> u64 pointer encoding), which
/// is the mechanism that drives the fixpoint in `compute_blob_offsets`.
#[test]
fn test_remap_ptrs_u64_encoding_widens_node() {
    let mut node = make_test_node4(
        &[0],
        [
            TriePtr::new(TrieNodeID::Leaf as u8, b'a', 0), // child_idx 0
            TriePtr::new(TrieNodeID::Leaf as u8, b'b', 1), // child_idx 1
            TriePtr::default(),
            TriePtr::default(),
        ],
    );

    let size_before = get_node_byte_len(&node);

    // One offset below u32::MAX, one above -> mixed encoding.
    let offsets: Vec<u64> = vec![1000, u64::from(u32::MAX) + 1];
    remap_ptrs_to_blob_offsets(&mut node, &offsets).unwrap();

    let size_after = get_node_byte_len(&node);

    // Exactly one pointer widened from u32 (4 bytes) to u64 (8 bytes) -> +4 bytes.
    assert_eq!(
        size_after - size_before,
        4,
        "one u64 pointer should add exactly 4 bytes"
    );

    // The ptr that stayed below u32::MAX should still use u32 encoding.
    assert_eq!(node.ptrs()[0].ptr(), 1000);
    assert!(!is_u64_ptr(node.ptrs()[0].encoded_id()));

    // The ptr that crossed u32::MAX should use u64 encoding.
    assert_eq!(node.ptrs()[1].ptr(), u64::from(u32::MAX) + 1);
    assert!(is_u64_ptr(node.ptrs()[1].encoded_id()));
}

#[test]
fn test_squash_rejects_compress_true() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let _ = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let dst_dir = dir.path().join("squashed");
    std::fs::create_dir_all(&dst_dir).unwrap();
    let dst_db_path = dst_dir.join("index.sqlite");

    let mut open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    open_opts.compress = true;

    let result = MARF::<StacksBlockId>::squash_to_path(
        src_db_path.to_str().unwrap(),
        dst_db_path.to_str().unwrap(),
        open_opts,
        1,
        "test",
    );
    assert!(result.is_err(), "compress=true should be rejected");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("compress=true"),
        "error should mention compress=true: {err_msg}"
    );
}

/// Exercise the fixpoint loop inside `compute_blob_offsets_inner` by
/// passing `early_exit_threshold = 0`, which forces the loop to run
/// even though the blob is small.  The results must be identical to the
/// normal (early-exit) path because no pointers actually widen.
#[test]
fn test_compute_blob_offsets_fixpoint_loop() {
    let dir = tempdir().unwrap();
    let dir_str = dir.path().to_str().unwrap();
    let mut store = NodeStore::new(dir_str).unwrap();
    let h = TrieHash([0; 32]);

    // Build a small trie: root (Node4) -> inner (Node4) -> leaf.
    // Both interior nodes have forward pointers.
    let root = make_test_node4(
        &[0],
        [
            TriePtr::new(TrieNodeID::Node4 as u8, b'a', 1),
            TriePtr::default(),
            TriePtr::default(),
            TriePtr::default(),
        ],
    );
    store.push(&root, h, 0).unwrap();

    let inner = make_test_node4(
        &[1],
        [
            TriePtr::new(TrieNodeID::Leaf as u8, b'b', 2),
            TriePtr::default(),
            TriePtr::default(),
            TriePtr::default(),
        ],
    );
    store.push(&inner, h, 0).unwrap();

    store.push(&make_test_leaf(&[2, 3], 0xAA), h, 0).unwrap();
    store.finish_writing().unwrap();

    // Normal call. early exit, no fixpoint loop.
    let (offsets_normal, total_normal) = compute_blob_offsets(&mut store).unwrap();

    // Forced fixpoint. threshold = 0 means the loop always runs.
    let (offsets_forced, total_forced) = compute_blob_offsets_inner(&mut store, 0).unwrap();

    // Results must be identical (no actual pointer widening for small blobs).
    assert_eq!(offsets_normal, offsets_forced);
    assert_eq!(total_normal, total_forced);

    // Verify stream_squash_blob agrees on total size.
    let parent_hash = StacksBlockId::sentinel();
    let mut output = Cursor::new(Vec::new());
    let bytes_written =
        stream_squash_blob(&mut store, &parent_hash, &offsets_forced, &mut output).unwrap();
    assert_eq!(bytes_written, total_forced);
}

/// Build a synthetic >4 GiB squash blob so at least one real remapped child
/// pointer crosses `u32::MAX` and is emitted with the u64-width encoding bit.
#[test]
#[ignore = "synthetic large-offset regression"]
fn compute_blob_offsets_large_offset_sets_u64_ptr_bit() {
    let dir = tempdir().expect("create temp dir");
    let dir_str = dir.path().to_str().unwrap();
    let path = dir
        .path()
        .join("compute_blob_offsets_large_offset_sets_u64_ptr_bit.bin");

    let mut store = NodeStore::new(dir_str).expect("create node store");
    let template = TrieNodeType::Node256(Box::new(TrieNode256::new(&[])));
    let per_node_size = u64::try_from(get_node_byte_len(&template)).expect("infallible");
    let required_nodes = u64::from(u32::MAX) / per_node_size + 2;
    let hash = TrieHash([0; 32]);
    for i in 0..required_nodes {
        let mut node = TrieNode256::new(&[]);
        if i + 1 < required_nodes {
            assert!(node.insert(&TriePtr::new(TrieNodeID::Node256 as u8, 0x00, i + 1)));
        }
        store
            .push(&TrieNodeType::Node256(Box::new(node)), hash, 0)
            .expect("push trie node");
    }
    store.finish_writing().expect("finish node store");

    let (blob_offsets, total_size) = compute_blob_offsets(&mut store).expect("compute offsets");
    assert!(total_size > u64::from(u32::MAX));

    let parent_hash = StacksBlockId([0x55; 32]);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("create temp squash blob");
    let bytes_written = stream_squash_blob(&mut store, &parent_hash, &blob_offsets, &mut file)
        .expect("stream squash blob");
    assert_eq!(bytes_written, total_size);
    let second_last_node_start = total_size
        .checked_sub(per_node_size + (per_node_size + 4))
        .expect("second-last node should exist");
    file.seek(std::io::SeekFrom::Start(
        second_last_node_start
            + u64::try_from(stacks_common::types::chainstate::TRIEHASH_ENCODED_SIZE + 1)
                .expect("infallible"),
    ))
    .expect("seek to second-last child ptr id");
    let mut encoded_id = [0u8; 1];
    std::io::Read::read_exact(&mut file, &mut encoded_id)
        .expect("read encoded second-last child ptr id");
    assert!(is_u64_ptr(encoded_id[0]));
}

/// Extending a squashed MARF must correctly serialize patch nodes even when
/// the squash tip has many inline (forward-ptr) children that become
/// backpointers in the new block.
///
/// This test uses `insert_raw` with controlled `TrieHash` paths to build a
/// deterministic wide Node256 root (64 children in distinct chr() slots).
/// After squashing and extending with a single-key modification, the root is
/// COW'd as a patch: 1 forward child + 63 inherited backpointers.
///
/// The test verifies:
/// 1. The `assert!(node_forward.eq(diff_forward))` in `dump_compressed_consume`
///    does not panic - the forward-ptr sequence filtering is correct.
/// 2. The root of b3's blob is actually stored as a `TrieNodeID::Patch`,
///    proving the patch path was exercised (not silently skipped).
/// 3. Both archival and squashed MARFs produce identical data when extended
///    with the same operations.
///
/// Regression test for the `assert_eq!(num_new_nodes, patch_node.ptr_diff.len())`
/// panic that occurred when extending squashed mainnet MARFs.
#[test]
fn test_squash_extend_many_keys_patch_backptr_regression() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("src.sqlite");

    // Compression MUST be enabled for the patch path in dump_compressed_consume.
    let open_opts =
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false).with_compression(true);

    // Build a controlled trie path for each first-byte value.
    // 64 distinct first bytes guarantees a Node256 root (>48 children).
    let make_path = |first_byte: u8| -> TrieHash {
        let mut bytes = [0u8; 32];
        bytes[0] = first_byte;
        TrieHash(bytes)
    };
    let make_leaf = |val: u8| -> TrieLeaf {
        let mut data = [0u8; 40];
        data[0] = val;
        TrieLeaf {
            path: vec![],
            data: MARFValue(data),
        }
    };
    let num_keys: u8 = 64;

    let b1 = StacksBlockId::from_bytes(&[1u8; 32]).unwrap();
    let b2 = StacksBlockId::from_bytes(&[2u8; 32]).unwrap();
    let b3 = StacksBlockId::from_bytes(&[3u8; 32]).unwrap();

    // --- Build archival source MARF ---
    let mut src =
        MARF::<StacksBlockId>::from_path(src_db_path.to_str().unwrap(), open_opts.clone()).unwrap();

    src.begin(&StacksBlockId::sentinel(), &b1).unwrap();
    for i in 0..num_keys {
        src.insert_raw(make_path(i), make_leaf(i)).unwrap();
    }
    src.commit().unwrap();

    src.begin(&b1, &b2).unwrap();
    for i in 0..num_keys {
        src.insert_raw(make_path(i), make_leaf(i.wrapping_add(100)))
            .unwrap();
    }
    src.commit().unwrap();

    // Extend archival to b3: modify ONE key so the root is COW'd with
    // 1 changed child + (num_keys - 1) inherited backpointers.
    src.begin(&b2, &b3).unwrap();
    src.insert_raw(make_path(0), make_leaf(255)).unwrap();
    src.commit().unwrap();

    // Collect archival values at b3 for later comparison.
    let archival_val_0 = src
        .with_conn(|c| MARF::get_by_hash(c, &b3, &make_path(0)))
        .unwrap();
    let archival_val_1 = src
        .with_conn(|c| MARF::get_by_hash(c, &b3, &make_path(1)))
        .unwrap();
    let archival_val_63 = src
        .with_conn(|c| MARF::get_by_hash(c, &b3, &make_path(num_keys - 1)))
        .unwrap();
    drop(src);

    // --- Squash at height 1 (= b2) ---
    let dst_dir = dir.path().join("squashed");
    std::fs::create_dir_all(&dst_dir).unwrap();
    let dst_db_path = dst_dir.join("dst.sqlite");

    // squash_to_path requires compress=false; compression is for the extend step.
    let squash_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false);
    MARF::<StacksBlockId>::squash_to_path(
        src_db_path.to_str().unwrap(),
        dst_db_path.to_str().unwrap(),
        squash_opts,
        1,
        "test",
    )
    .unwrap();

    // --- Extend squashed MARF to b3 with compression enabled ---
    // Compression enables the patch-node path in dump_compressed_consume.
    let squashed_opts =
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true).with_compression(true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(dst_db_path.to_str().unwrap(), squashed_opts.clone())
            .unwrap();

    squashed.begin(&b2, &b3).unwrap();
    squashed.insert_raw(make_path(0), make_leaf(255)).unwrap();
    // The commit exercises dump_compressed_consume with a COW'd Node256
    // root where most children are backpointers. The forward-ptr sequence
    // assertion must pass for this to succeed.
    squashed.commit().unwrap();

    // --- Verify patch node was actually emitted ---
    // b3's blob is in the .blobs file. The root node starts at
    // blob_offset + HEADER (36 bytes). Its type ID byte is at +68.
    // TrieNodeID::Patch = 6 proves patch encoding was used, not Normal.
    let b3_block_id = trie_sql::get_block_identifier(squashed.sqlite_conn(), &b3).unwrap();
    let (b3_blob_offset, b3_blob_length) =
        trie_sql::get_external_trie_offset_length(squashed.sqlite_conn(), b3_block_id).unwrap();
    assert!(b3_blob_length > 0, "b3 blob should have non-zero length");

    let blobs_path = format!("{}.blobs", dst_db_path.display());
    let mut blobs_file = std::fs::File::open(&blobs_path).unwrap();
    // Root node type ID is at: blob_offset + 32 (parent hash) + 4 (identifier) + 32 (node hash)
    let root_type_offset = b3_blob_offset + (BLOCK_HEADER_HASH_ENCODED_SIZE as u64) + 4 + 32;
    blobs_file
        .seek(std::io::SeekFrom::Start(root_type_offset))
        .unwrap();
    let mut type_byte = [0u8; 1];
    std::io::Read::read_exact(&mut blobs_file, &mut type_byte).unwrap();
    assert_eq!(
        type_byte[0],
        TrieNodeID::Patch as u8,
        "Root of b3 should be stored as a Patch node (type {}), got type {}. \
         This means dump_compressed_consume fell back to Normal serialization.",
        TrieNodeID::Patch as u8,
        type_byte[0]
    );

    // --- Verify data matches archival MARF ---
    let squashed_val_0 = squashed
        .with_conn(|c| MARF::get_by_hash(c, &b3, &make_path(0)))
        .unwrap();
    let squashed_val_1 = squashed
        .with_conn(|c| MARF::get_by_hash(c, &b3, &make_path(1)))
        .unwrap();
    let squashed_val_63 = squashed
        .with_conn(|c| MARF::get_by_hash(c, &b3, &make_path(num_keys - 1)))
        .unwrap();

    assert_eq!(archival_val_0, squashed_val_0, "modified key mismatch");
    assert_eq!(archival_val_1, squashed_val_1, "inherited key mismatch");
    assert_eq!(
        archival_val_63, squashed_val_63,
        "last inherited key mismatch"
    );

    // Pre-squash data still readable through the squash tip.
    let val_at_b2 = squashed
        .with_conn(|c| MARF::get_by_hash(c, &b2, &make_path(1)))
        .unwrap();
    assert!(val_at_b2.is_some(), "data at b2 should still be readable");
}
