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

use stacks_common::types::chainstate::{StacksBlockId, TrieHash, TRIEHASH_ENCODED_SIZE};
use tempfile::tempdir;

use super::marf::setup_marf;
use crate::chainstate::stacks::index::bits::{
    get_node_byte_len, get_node_hash, read_nodetype, resolve_inline_child_offsets,
};
use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection, SquashStats, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF,
    OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{
    is_u64_ptr, set_backptr, TrieNode as _, TrieNode16, TrieNode256, TrieNode4, TrieNode48,
    TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::squash::{
    compute_node_hash, deserialize_node, serialize_node, stream_squash_blob, NodeStore,
};
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::{
    blob_layout, trie_sql, ClarityMarfTrieId, Error, MARFValue, TrieLeaf, TrieMerkleProof,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn squash_helper(
    src_path: &str,
    dst_dir: &std::path::Path,
    tip: &StacksBlockId,
    height: u32,
) -> (PathBuf, SquashStats) {
    std::fs::create_dir_all(dst_dir).unwrap();
    let dst_db_path = dst_dir.join("index.sqlite");
    let src_open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let stats = MARF::squash_to_path(
        src_path,
        dst_db_path.to_str().unwrap(),
        src_open_opts,
        tip,
        height,
        "test",
    )
    .unwrap();
    (dst_db_path, stats)
}

/// Build an archival MARF in `dir` and squash it at `squash_height`.
/// Returns the open archival MARF, the open squashed MARF, and the block list
/// from the archival source. Used by the hash-equivalence tests so they don't
/// have to repeat the same five-line scaffolding.
fn build_archival_and_squashed_marfs(
    dir: &tempfile::TempDir,
    num_blocks: usize,
    keys_per_block: usize,
    squash_height: u32,
) -> (MARF<StacksBlockId>, MARF<StacksBlockId>, Vec<StacksBlockId>) {
    let archival_path = dir.path().join("archival.sqlite");
    let (archival, blocks, _) =
        setup_marf(archival_path.to_str().unwrap(), num_blocks, keys_per_block);

    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    (archival, squashed, blocks)
}

/// Assert that the archival and squashed MARFs report identical root hashes
/// at every block in `blocks` and that no root is the zero hash.
fn assert_roots_match_at(
    archival: &mut MARF<StacksBlockId>,
    squashed: &mut MARF<StacksBlockId>,
    blocks: &[StacksBlockId],
    context: &str,
) {
    for (i, bh) in blocks.iter().enumerate() {
        let arch = archival.get_root_hash_at(bh).unwrap();
        let sq = squashed.get_root_hash_at(bh).unwrap();
        assert_eq!(arch, sq, "{context}: root hash mismatch at block #{i}");
        assert_ne!(arch, TrieHash::ZERO, "{context}: root #{i} is zero");
    }
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
        blocks.last().unwrap(),
        1,
    );

    assert_eq!(stats.node_count, 29);
    assert!(dst_db_path.exists());
    assert!(PathBuf::from(format!("{}.blobs", dst_db_path.display())).exists());

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut dst = MARF::from_path(dst_db_path.to_str().unwrap(), open_opts).unwrap();
    let k1 = dst.get(&blocks[1], "k1").unwrap().unwrap();
    assert_eq!(k1, MARFValue::from_value("v1_at_1"));
    let own_height = dst.get(&blocks[1], OWN_BLOCK_HEIGHT_KEY).unwrap().unwrap();
    assert_eq!(own_height, MARFValue::from(1u32));
}

#[test]
fn test_squash_info_detected_on_open() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let (dst_db_path, _) = squash_helper(
        src_db_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
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
                info.squash_height,
            ))
        })
        .unwrap();

    // Cross-check with the SQL table directly.
    let sql_info = trie_sql::read_squash_info(squashed.sqlite_conn())
        .unwrap()
        .expect("SQL squash info missing");

    assert!(is_squashed);
    assert_eq!(info_root, sql_info.archival_marf_root_hash);
    assert_eq!(info_height, sql_info.squash_height);
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
        blocks.last().unwrap(),
        1,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(dst_db_path.to_str().unwrap(), open_opts).unwrap();

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

/// The read guard short-circuits reads of the in-RAM block being extended (always above the
/// squash height, so never in `marf_squashed_blocks`). Verify a squashed MARF can be extended
/// past the snapshot and the new block read back, while a pre-squash read is still rejected.
#[test]
fn test_squash_uncommitted_extension_read_allowed() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_path.to_str().unwrap(), 64, 4);

    let squash_height: u32 = 48;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    // Extend past the squash tip; committing reads the uncommitted block via the short-circuit.
    let parent = blocks[squash_height as usize].clone();
    let new_block = StacksBlockId::from_bytes(&[0xab; 32]).unwrap();
    squashed.begin(&parent, &new_block).unwrap();
    squashed
        .insert("k_post_squash", MARFValue::from_value("v_post_squash"))
        .unwrap();
    squashed.commit().unwrap();

    // The post-squash block is above the squash height, so the read is allowed.
    assert_eq!(
        squashed.get(&new_block, "k_post_squash").unwrap(),
        Some(MARFValue::from_value("v_post_squash")),
    );

    // The guard still rejects a genuine pre-squash historical read.
    match squashed.get(&blocks[10], "k1") {
        Err(Error::HistoricalReadInSquashedRange {
            block_height,
            squash_height: sh,
        }) => {
            assert_eq!(block_height, 10);
            assert_eq!(sh, squash_height);
        }
        other => panic!("expected HistoricalReadInSquashedRange, got {other:?}"),
    }
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

    // The archival roots should not all be identical (sanity).
    assert_ne!(archival_roots[0], archival_roots[4]);

    // Squash at height 4 (blocks 0..=4 are in the squashed range).
    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        4,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

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
}

/// Verify that `test_squash_info_detected_on_open` also asserts the
/// squash_root_node_hash from the SQL table.
#[test]
fn test_squash_info_sql_squash_root_asserted() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let (dst_db_path, _) = squash_helper(
        src_db_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        1,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed =
        MARF::<StacksBlockId>::from_path(dst_db_path.to_str().unwrap(), open_opts).unwrap();

    let sql_info = trie_sql::read_squash_info(squashed.sqlite_conn())
        .unwrap()
        .expect("SQL squash info missing");

    let cached_root = squashed
        .with_conn(|conn| -> Result<TrieHash, Error> {
            Ok(conn.squash_info().unwrap().squash_root_node_hash)
        })
        .unwrap();

    assert_eq!(
        sql_info.squash_root_node_hash, cached_root,
        "cached vs SQL squash root mismatch"
    );

    assert_ne!(
        cached_root,
        TrieHash::EMPTY,
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
        blocks.last().unwrap(),
        8,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

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

    assert_ne!(archival_root_9, TrieHash::ZERO, "root at 9 is zero");
    assert_ne!(archival_root_10, TrieHash::ZERO, "root at 10 is zero");
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
    let (mut archival, mut squashed, blocks) = build_archival_and_squashed_marfs(
        &dir,
        STRESS_SQUASH_BLOCKS,
        STRESS_SQUASH_KEYS_PER_BLOCK,
        STRESS_SQUASH_HEIGHT,
    );

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

    assert_roots_match_at(
        &mut archival,
        &mut squashed,
        &new_blocks,
        "multi-height extension",
    );

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
        blocks.last().unwrap(),
        STRESS_SQUASH_HEIGHT,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

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

        // Simulate at-block: read a key from a post-squash block mid-transaction.
        // This exercises the open_block/restore cycle on the squashed blob.
        if blk > 0 {
            let historical_block = &new_blocks[blk - 1];
            let _arch_val = archival.get(historical_block, "dense_blk0_k0").unwrap();
            let _sq_val = squashed.get(historical_block, "dense_blk0_k0").unwrap();
            assert_eq!(_arch_val, _sq_val, "at-block read mismatch at blk {blk}");

            // Reading at a pre-squash block must be rejected on the squashed
            // MARF. The archival side keeps working.
            let old_block = &blocks[STRESS_SQUASH_HEIGHT as usize / 2];
            let _arch_val2 = archival.get(old_block, "k0").unwrap();
            match squashed.get(old_block, "k0") {
                Err(Error::HistoricalReadInSquashedRange { .. }) => {}
                other => {
                    panic!("expected HistoricalReadInSquashedRange at blk {blk}, got {other:?}")
                }
            }
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

/// Reading a key at a pre-squash block on a squashed MARF must be rejected
/// explicitly. The squashed MARF only retains the canonical state at the
/// squash height; per-block historical reads cannot be served and the API
/// returns `HistoricalReadInSquashedRange` instead of plausible bad data.
/// Reads at the squash tip and at post-squash blocks remain valid.
#[test]
fn test_squash_historical_read_rejected() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    // 64 blocks, 4 keys per block, squash at height 48
    let (mut archival, blocks, _) = setup_marf(src_path.to_str().unwrap(), 64, 4);

    let squash_height: u32 = 48;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let tip_block = &blocks[squash_height as usize];
    let early_block = &blocks[10];

    // Archival still serves historical reads correctly.
    let arch_val = archival.get(early_block, "k1").unwrap();
    assert_eq!(
        arch_val,
        Some(MARFValue::from_value("v1_at_10")),
        "archival should return the historical value"
    );

    // Squashed MARF must reject the historical read.
    match squashed.get(early_block, "k1") {
        Err(Error::HistoricalReadInSquashedRange {
            block_height,
            squash_height: sh,
        }) => {
            assert_eq!(block_height, 10);
            assert_eq!(sh, squash_height);
        }
        other => panic!("expected HistoricalReadInSquashedRange, got {other:?}"),
    }

    // Reading at the squash tip is still valid.
    let tip_val = squashed.get(tip_block, "k1").unwrap();
    assert_eq!(tip_val, Some(MARFValue::from_value("v1_at_48")));
}

/// Reads at any block strictly below the squash height are rejected, even
/// for keys that aren't written at every block. This complements
/// `test_squash_historical_read_rejected` to make sure the guard doesn't
/// depend on which key is being read - only on the block's height relative
/// to the squash height.
#[test]
fn test_squash_historical_read_intermittent_key_rejected() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (mut archival, blocks, _) = setup_marf(src_path.to_str().unwrap(), 64, 4);

    let squash_height: u32 = 48;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let early_block = &blocks[10];

    // Archival still resolves intermittent keys to the last-written value at/before block 10.
    let arch_val = archival.get(early_block, "common_some_0").unwrap();
    assert_eq!(
        arch_val,
        Some(MARFValue::from_value("common_some_0_at_9")),
        "archival should return value from height 9"
    );

    // Squashed MARF rejects the read regardless of the key.
    match squashed.get(early_block, "common_some_0") {
        Err(Error::HistoricalReadInSquashedRange {
            block_height,
            squash_height: sh,
        }) => {
            assert_eq!(block_height, 10);
            assert_eq!(sh, squash_height);
        }
        other => panic!("expected HistoricalReadInSquashedRange, got {other:?}"),
    }
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
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

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

    let (dst_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        8,
    );

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
        blocks.last().unwrap(),
        8,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

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

    let src_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false);
    let mut src = MARF::from_path(src_db_path.to_str().unwrap(), src_opts.clone()).unwrap();

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

    MARF::squash_to_path(
        src_db_path.to_str().unwrap(),
        dst_db_path.to_str().unwrap(),
        src_opts,
        &b2,
        1,
        "test",
    )
    .unwrap();

    let compressed_opts =
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true).with_compression(true);
    let mut squashed = MARF::from_path(dst_db_path.to_str().unwrap(), compressed_opts).unwrap();

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

/// `compute_node_hash` must agree with `bits::get_node_hash` for any
/// backptr-free node. If they ever diverge, every root-hash equivalence test
/// would still pass on the squash output alone — this dedicated test catches
/// such drift directly.
#[test]
fn test_compute_node_hash_matches_bits_get_node_hash() {
    let child_hashes = [
        TrieHash([1; 32]),
        TrieHash([2; 32]),
        TrieHash([3; 32]),
        TrieHash::EMPTY,
    ];

    // Leaf: no children
    let leaf = TrieLeaf {
        path: vec![0xab, 0xcd],
        data: MARFValue([7u8; 40]),
    };
    let leaf_via_bits = get_node_hash(&leaf, &[], &mut ());
    let leaf_via_squash = compute_node_hash(&TrieNodeType::Leaf(leaf), &[]);
    assert_eq!(leaf_via_bits, leaf_via_squash, "TrieLeaf hash drift");

    // Node4 with three inline children and one empty slot.
    let node4 = TrieNode4 {
        path: vec![1, 2, 3],
        ptrs: [
            TriePtr::new(TrieNodeID::Leaf as u8, b'a', 100),
            TriePtr::new(TrieNodeID::Leaf as u8, b'b', 200),
            TriePtr::new(TrieNodeID::Leaf as u8, b'c', 300),
            TriePtr::default(),
        ],
        cowptr: None,
        patches: vec![],
    };
    let node4_via_bits = get_node_hash(&node4, &child_hashes, &mut ());
    let node4_via_squash = compute_node_hash(&TrieNodeType::Node4(node4), &child_hashes);
    assert_eq!(node4_via_bits, node4_via_squash, "TrieNode4 hash drift");
}

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

    store.flush().unwrap();
    assert_eq!(store.len(), 5);

    // Leaf round-trip
    let rt_leaf = store.read_node(0).unwrap();
    assert!(rt_leaf.is_leaf());
    assert_eq!(rt_leaf.path_bytes(), &[1, 2, 3]);
    assert_eq!(*store.get_hash(0), leaf_hash);
    assert_eq!(store.block_id(0), 10);

    // Node4 round-trip
    let rt_n4 = store.read_node(1).unwrap();
    assert_eq!(rt_n4.ptrs()[0].chr(), b'a');
    assert_eq!(rt_n4.ptrs()[0].ptr(), 100);

    // Node16 round-trip
    let rt_n16 = store.read_node(2).unwrap();
    assert_eq!(rt_n16.ptrs()[0].chr(), b'b');
    assert_eq!(rt_n16.ptrs()[0].ptr(), 200);

    // Node48 round-trip
    let rt_n48 = store.read_node(3).unwrap();
    assert_eq!(rt_n48.ptrs()[0].chr(), b'c');
    assert_eq!(rt_n48.ptrs()[0].ptr(), 300);

    // Node256 round-trip
    let rt_n256 = store.read_node(4).unwrap();
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
        store.push(&leaf, TrieHash::EMPTY, 0).unwrap();
        store.flush().unwrap();

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
/// `stream_squash_blob` writes a readable child-before-parent blob.
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
fn test_stream_squash_blob_mixed_node_types() {
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

    store.flush().unwrap();

    let parent_hash = StacksBlockId::sentinel();
    let mut output = Cursor::new(Vec::new());
    let bytes_written = stream_squash_blob(&mut store, &parent_hash, &mut output).unwrap();

    // Verify blob header.
    let blob = output.into_inner();
    assert_eq!(blob.len() as u64, bytes_written);
    assert_eq!(
        &blob[..blob_layout::RESERVED_FIELD_OFFSET],
        parent_hash.as_bytes()
    );
    assert_eq!(
        &blob[blob_layout::RESERVED_FIELD_OFFSET
            ..blob_layout::RESERVED_FIELD_OFFSET + blob_layout::RESERVED_FIELD_LEN],
        &0u32.to_le_bytes()
    );

    // Verify the root was written at the canonical root position and its child
    // pointers target readable descendants.
    let header_size = blob_layout::ROOT_NODE_OFFSET as u64;
    let mut cursor = Cursor::new(blob.as_slice());
    let root_ptr = TriePtr::new(TrieNodeID::Node16 as u8, 0, header_size);
    let (root_node, _) = read_nodetype(&mut cursor, &root_ptr).unwrap();
    assert_eq!(root_node.ptrs()[0].id(), TrieNodeID::Node4 as u8);
    assert_eq!(root_node.ptrs()[1].id(), TrieNodeID::Node4 as u8);
    assert!(root_node.ptrs()[0].ptr() > header_size);
    assert!(root_node.ptrs()[1].ptr() > header_size);

    let first_child_ptr = root_node.ptrs()[0];
    let (first_child, _) = read_nodetype(&mut cursor, &first_child_ptr).unwrap();
    assert_eq!(first_child.ptrs()[0].id(), TrieNodeID::Leaf as u8);
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
    store.flush().unwrap();

    let parent_hash = StacksBlockId::sentinel();

    // Write to a sink that already has 1000 bytes of garbage prefix.
    let prefix_len: u64 = 1000;
    let mut buf = vec![0xFFu8; prefix_len as usize];
    let mut output = Cursor::new(&mut buf);
    output.seek(std::io::SeekFrom::End(0)).unwrap();

    let bytes_written = stream_squash_blob(&mut store, &parent_hash, &mut output).unwrap();

    let total_buf = output.into_inner();
    assert_eq!(total_buf.len() as u64, prefix_len + bytes_written);
    assert!(total_buf[..prefix_len as usize].iter().all(|&b| b == 0xFF));
    assert_eq!(
        &total_buf[prefix_len as usize..prefix_len as usize + 32],
        parent_hash.as_bytes()
    );
}

/// Test `resolve_inline_child_offsets` directly: verify it replaces forward
/// child pointers with their blob offsets, leaves back/empty pointers
/// untouched, and returns CorruptionError for out-of-bounds indices.
#[test]
fn test_resolve_inline_child_offsets() {
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
    resolve_inline_child_offsets(node.ptrs_mut(), &offsets).unwrap();

    let ptrs = node.ptrs();
    // Forward ptrs remapped to blob offsets.
    assert_eq!(ptrs[0].ptr(), 200); // child_idx 1 -> offset 200
    assert_eq!(ptrs[3].ptr(), 300); // child_idx 2 -> offset 300
                                    // Back ptr untouched.
    assert_eq!(ptrs[1].ptr(), 999);
    assert_eq!(ptrs[1].back_block(), 5);
    // Empty ptr untouched.
    assert_eq!(ptrs[2].ptr(), 0);

    // Empty pointer slices are a no-op.
    let mut empty: [TriePtr; 0] = [];
    resolve_inline_child_offsets(&mut empty, &offsets).unwrap();

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
    assert!(resolve_inline_child_offsets(bad_node.ptrs_mut(), &offsets).is_err());
}

/// Verify that `resolve_inline_child_offsets` with offsets > u32::MAX causes
/// the node's serialized size to grow (u32 -> u64 pointer encoding).
#[test]
fn test_resolve_inline_child_offsets_u64_encoding_widens_node() {
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
    resolve_inline_child_offsets(node.ptrs_mut(), &offsets).unwrap();

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
fn test_squash_rejects_proof_generation() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_path.to_str().unwrap(), 4, 1);

    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        2,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    // Squash-aware proofs are out of scope for this PR. The squashed MARF
    // must reject both `get_with_proof` entry points so callers don't get
    // proofs that commit to the wrong (H-state) leaf for historical blocks.
    let tip = &blocks[2];
    match squashed.get_with_proof(tip, "k1") {
        Err(Error::UnsupportedOnSquashedMarf(op)) => assert_eq!(op, "get_with_proof"),
        other => panic!("expected UnsupportedOnSquashedMarf, got {other:?}"),
    }

    let path = TrieHash::from_data(b"k1");
    match squashed.get_with_proof_from_hash(tip, &path) {
        Err(Error::UnsupportedOnSquashedMarf(op)) => {
            assert_eq!(op, "get_with_proof_from_hash")
        }
        other => panic!("expected UnsupportedOnSquashedMarf, got {other:?}"),
    }
}

/// `MARF::get_with_proof` rejects squashed MARFs, but a caller holding a
/// `TrieStorageConnection` could previously bypass that by calling
/// `TrieMerkleProof::from_path` (or `from_entry` / `from_raw_entry`, which
/// delegate to it). Direct invocation must also be rejected so squashed
/// MARFs cannot produce silently-wrong proofs by any code path.
#[test]
fn test_trie_merkle_proof_from_path_rejects_squashed_marf() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_path.to_str().unwrap(), 4, 1);

    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        2,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let tip = blocks[2].clone();
    let value = MARFValue::from_value("v1_at_2");
    let path = TrieHash::from_key("k1");

    let result = squashed.with_conn(|conn| TrieMerkleProof::from_path(conn, &path, &value, &tip));
    match result {
        Err(Error::UnsupportedOnSquashedMarf(op)) => {
            assert_eq!(op, "TrieMerkleProof::from_path");
        }
        other => panic!("expected UnsupportedOnSquashedMarf, got {other:?}"),
    }
}

/// `get_block_at_height` is chain metadata - the answer is in
/// `marf_squashed_blocks` even when the caller is standing on a pre-squash
/// block. Without the squash-aware short-circuit the lookup would route
/// through `MARF::get_path` and trip the historical-read guard.
#[test]
fn test_get_block_at_height_works_for_pre_squash_caller() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_path.to_str().unwrap(), 16, 1);

    let squash_height: u32 = 12;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    // Stand on a pre-squash block and ask for an even earlier height. The
    // answer must come from `marf_squashed_blocks`, not from a trie metadata
    // read that would be rejected.
    let standing_block = &blocks[8];
    let resolved = squashed
        .get_bhh_at_height(standing_block, 4)
        .unwrap()
        .expect("squashed MARF must resolve metadata height -> block");
    assert_eq!(resolved, blocks[4]);

    // Asking for a height equal to the standing block returns that block.
    let same = squashed
        .get_bhh_at_height(standing_block, 8)
        .unwrap()
        .expect("height == current_block_height short-circuits");
    assert_eq!(same, blocks[8]);

    // Asking for a height strictly greater than the standing block returns
    // None (the future is unknown from that vantage point).
    assert!(squashed
        .get_bhh_at_height(standing_block, 9)
        .unwrap()
        .is_none());

    // Standing on the squash tip still resolves earlier heights via the
    // side-table.
    let tip = &blocks[squash_height as usize];
    let resolved_tip = squashed.get_bhh_at_height(tip, 0).unwrap().unwrap();
    assert_eq!(resolved_tip, blocks[0]);
}

#[test]
fn test_get_block_height_of_same_pre_squash_block() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_path.to_str().unwrap(), 16, 1);

    let squash_height: u32 = 12;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let standing_block = &blocks[8];
    let height = squashed
        .get_block_height_of(standing_block, standing_block)
        .unwrap();

    assert_eq!(height, Some(8));
}

/// Sanity: a complete squashed MARF opens and resolves the squash tip's own
/// height to `squash_height` (the tip flows through the trie read path, not
/// the side-table fallback).
#[test]
fn test_get_own_block_height_of_squash_tip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_path.to_str().unwrap(), 16, 1);

    let squash_height: u32 = 12;
    let (squashed_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        squash_height,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();

    let tip = &blocks[squash_height as usize];
    let height = squashed.get_block_height_of(tip, tip).unwrap();
    assert_eq!(height, Some(squash_height));
}

/// `squash_to_path` must follow the explicit `tip` argument, not the
/// highest `block_id` in `marf_data`. Build a forked MARF where the
/// canonical tip is inserted *before* the non-canonical fork, so picking by
/// insertion order would land on the wrong fork. Then squash with the
/// canonical tip and verify the resulting MARF reflects canonical state at
/// the squash height.
#[test]
fn test_squash_follows_explicit_tip_on_forked_marf() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut src = MARF::from_path(src_path.to_str().unwrap(), open_opts.clone()).unwrap();

    let g = StacksBlockId::from_bytes(&[0x01; 32]).unwrap();
    let canonical_tip = StacksBlockId::from_bytes(&[0x02; 32]).unwrap();
    let fork_tip = StacksBlockId::from_bytes(&[0x03; 32]).unwrap();

    // Genesis - height 0.
    src.begin(&StacksBlockId::sentinel(), &g).unwrap();
    src.insert("shared", MARFValue::from_value("genesis"))
        .unwrap();
    src.commit().unwrap();

    // Canonical fork at height 1 (inserted FIRST → lower block_id).
    src.begin(&g, &canonical_tip).unwrap();
    src.insert("contested", MARFValue::from_value("canonical_v1"))
        .unwrap();
    src.commit().unwrap();

    // Non-canonical fork at height 1 (inserted SECOND → higher block_id).
    // get_latest_confirmed_block_hash would pick this one.
    src.begin(&g, &fork_tip).unwrap();
    src.insert("contested", MARFValue::from_value("fork_v1"))
        .unwrap();
    src.commit().unwrap();

    drop(src);

    // Squash with the explicit canonical tip - must NOT pick the fork.
    let (dst_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        &canonical_tip,
        1,
    );

    let mut squashed = MARF::from_path(
        dst_path.to_str().unwrap(),
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true),
    )
    .unwrap();

    // The squash root must reflect canonical state, not the fork.
    let value = squashed
        .get(&canonical_tip, "contested")
        .unwrap()
        .expect("contested key must be present at canonical tip");
    assert_eq!(
        value,
        MARFValue::from_value("canonical_v1"),
        "squash followed the wrong fork (insertion-order tip selection regression)"
    );

    // The fork's tip should NOT be in the squashed range - its height (1)
    // would be ambiguous, so confirm it isn't recorded as the height-1 block.
    let h1 = squashed
        .get_bhh_at_height(&canonical_tip, 1)
        .unwrap()
        .expect("height 1 must resolve");
    assert_eq!(h1, canonical_tip);
    assert_ne!(h1, fork_tip);
}

/// Below-tip `commit_to` blocks should squash using their real hashes.
#[test]
fn test_squash_handles_commit_to_renamed_blocks_below_tip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut src = MARF::from_path(src_path.to_str().unwrap(), open_opts.clone()).unwrap();

    let dummy = StacksBlockId::from_bytes(&[0xee; 32]).unwrap();
    let reals: Vec<StacksBlockId> = (1u8..=5)
        .map(|i| StacksBlockId::from_bytes(&[i; 32]).unwrap())
        .collect();

    src.begin(&StacksBlockId::sentinel(), &dummy).unwrap();
    src.insert("k0", MARFValue::from_value("v0")).unwrap();
    src.commit_to(&reals[0]).unwrap();

    for i in 1..reals.len() {
        src.begin(&reals[i - 1], &dummy).unwrap();
        let key = format!("k{i}");
        let val = format!("v{i}");
        src.insert(&key, MARFValue::from_value(&val)).unwrap();
        src.commit_to(&reals[i]).unwrap();
    }
    drop(src);

    let (dst_path, stats) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        &reals[4],
        3,
    );

    let mut squashed = MARF::from_path(
        dst_path.to_str().unwrap(),
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true),
    )
    .unwrap();

    for h in 0..=3u32 {
        let bh = squashed
            .get_bhh_at_height(&reals[3], h)
            .unwrap()
            .unwrap_or_else(|| panic!("missing block at height {h}"));
        assert_eq!(bh, reals[h as usize], "height {h} resolved to wrong block");
    }
    assert_eq!(stats.squash_height, 3);
    assert_eq!(stats.historical_placeholder_count, 3);
}

/// Tip-height `commit_to` squashes must tolerate the stale dummy height key.
#[test]
fn test_squash_handles_commit_to_renamed_blocks_at_tip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("index.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut src = MARF::from_path(src_path.to_str().unwrap(), open_opts.clone()).unwrap();

    let dummy = StacksBlockId::from_bytes(&[0xee; 32]).unwrap();
    let reals: Vec<StacksBlockId> = (1u8..=3)
        .map(|i| StacksBlockId::from_bytes(&[i; 32]).unwrap())
        .collect();

    src.begin(&StacksBlockId::sentinel(), &dummy).unwrap();
    src.insert("k0", MARFValue::from_value("v0")).unwrap();
    src.commit_to(&reals[0]).unwrap();

    for i in 1..reals.len() {
        src.begin(&reals[i - 1], &dummy).unwrap();
        let key = format!("k{i}");
        let val = format!("v{i}");
        src.insert(&key, MARFValue::from_value(&val)).unwrap();
        src.commit_to(&reals[i]).unwrap();
    }
    drop(src);

    let (dst_path, stats) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        &reals[2],
        2,
    );

    let mut squashed = MARF::from_path(
        dst_path.to_str().unwrap(),
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true),
    )
    .unwrap();
    for h in 0..=2u32 {
        let bh = squashed
            .get_bhh_at_height(&reals[2], h)
            .unwrap()
            .unwrap_or_else(|| panic!("missing block at height {h}"));
        assert_eq!(bh, reals[h as usize], "height {h} resolved to wrong block");
    }
    assert_eq!(stats.squash_height, 2);
}

/// Re-squash walks new blocks and reads old heights from the side table.
#[test]
fn test_resquash_after_squash_succeeds() {
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let (mut archival, blocks, _) = setup_marf(archival_path.to_str().unwrap(), 3, 1);

    let squashed_dir = dir.path().join("squashed");
    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &squashed_dir,
        blocks.last().unwrap(),
        2,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts).unwrap();
    let post: Vec<StacksBlockId> = (0u8..3)
        .map(|i| StacksBlockId::from_bytes(&[0x80 + i; 32]).unwrap())
        .collect();

    squashed.begin(&blocks[2], &post[0]).unwrap();
    squashed
        .insert("k_post0", MARFValue::from_value("v_post0"))
        .unwrap();
    squashed.commit().unwrap();
    squashed.begin(&post[0], &post[1]).unwrap();
    squashed
        .insert("k_post1", MARFValue::from_value("v_post1"))
        .unwrap();
    squashed.commit().unwrap();
    squashed.begin(&post[1], &post[2]).unwrap();
    squashed
        .insert("k_post2", MARFValue::from_value("v_post2"))
        .unwrap();
    squashed.commit().unwrap();
    drop(squashed);

    archival.begin(&blocks[2], &post[0]).unwrap();
    archival
        .insert("k_post0", MARFValue::from_value("v_post0"))
        .unwrap();
    archival.commit().unwrap();
    archival.begin(&post[0], &post[1]).unwrap();
    archival
        .insert("k_post1", MARFValue::from_value("v_post1"))
        .unwrap();
    archival.commit().unwrap();
    archival.begin(&post[1], &post[2]).unwrap();
    archival
        .insert("k_post2", MARFValue::from_value("v_post2"))
        .unwrap();
    archival.commit().unwrap();
    drop(archival);

    let resquashed_dir = dir.path().join("resquashed");
    let (resquashed_path, resquash_stats) = squash_helper(
        squashed_path.to_str().unwrap(),
        &resquashed_dir,
        &post[2],
        4,
    );
    assert_eq!(resquash_stats.squash_height, 4);

    let mut resquashed = MARF::from_path(
        resquashed_path.to_str().unwrap(),
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true),
    )
    .unwrap();
    let expected: Vec<StacksBlockId> = (0..=4)
        .map(|h| {
            if h <= 2 {
                blocks[h as usize].clone()
            } else {
                post[(h - 3) as usize].clone()
            }
        })
        .collect();
    for h in 0..=4u32 {
        let bh = resquashed
            .get_bhh_at_height(&post[1], h)
            .unwrap()
            .unwrap_or_else(|| panic!("missing block at height {h}"));
        assert_eq!(bh, expected[h as usize], "height {h} mismatch");
    }
}

/// Re-squash must advance beyond the source squash height.
#[test]
fn test_resquash_rejects_height_at_or_below_existing_squash() {
    let dir = tempdir().unwrap();
    let archival_path = dir.path().join("archival.sqlite");
    let (_archival, blocks, _) = setup_marf(archival_path.to_str().unwrap(), 3, 1);

    let squashed_dir = dir.path().join("squashed");
    let (squashed_path, _) = squash_helper(
        archival_path.to_str().unwrap(),
        &squashed_dir,
        blocks.last().unwrap(),
        2,
    );

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut squashed = MARF::from_path(squashed_path.to_str().unwrap(), open_opts.clone()).unwrap();
    let post = StacksBlockId::from_bytes(&[0x80; 32]).unwrap();
    squashed.begin(&blocks[2], &post).unwrap();
    squashed
        .insert("k_post", MARFValue::from_value("v_post"))
        .unwrap();
    squashed.commit().unwrap();
    drop(squashed);

    for bad_height in [1u32, 2u32] {
        let resquashed_dir = dir.path().join(format!("bad_{bad_height}"));
        std::fs::create_dir_all(&resquashed_dir).unwrap();
        let dst_db_path = resquashed_dir.join("index.sqlite");
        let dst_blobs_path = resquashed_dir.join("index.sqlite.blobs");
        let result = MARF::squash_to_path(
            squashed_path.to_str().unwrap(),
            dst_db_path.to_str().unwrap(),
            open_opts.clone(),
            &post,
            bad_height,
            "test",
        );
        match result {
            Err(Error::CorruptionError(msg)) => {
                assert!(
                    msg.contains("already squashed"),
                    "unexpected error for bad_height={bad_height}: {msg}"
                );
            }
            other => panic!("expected CorruptionError for bad_height={bad_height}, got {other:?}"),
        }
        assert!(
            !dst_db_path.exists(),
            "destination DB must not be created when source rejects (bad_height={bad_height})"
        );
        assert!(
            !dst_blobs_path.exists(),
            "destination .blobs must not be created when source rejects (bad_height={bad_height})"
        );
    }
}

/// Parent walk should match the trie height index for a `commit_to` chain.
#[test]
fn test_parent_walk_matches_height_index_lookups() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let mut src = MARF::from_path(src_path.to_str().unwrap(), open_opts.clone()).unwrap();

    let dummy = StacksBlockId::from_bytes(&[0xee; 32]).unwrap();
    let reals: Vec<StacksBlockId> = (1u8..=5)
        .map(|i| StacksBlockId::from_bytes(&[i; 32]).unwrap())
        .collect();
    src.begin(&StacksBlockId::sentinel(), &dummy).unwrap();
    src.insert("k0", MARFValue::from_value("v0")).unwrap();
    src.commit_to(&reals[0]).unwrap();
    for i in 1..reals.len() {
        src.begin(&reals[i - 1], &dummy).unwrap();
        src.insert(&format!("k{i}"), MARFValue::from_value(&format!("v{i}")))
            .unwrap();
        src.commit_to(&reals[i]).unwrap();
    }

    let squash_height = 3u32;
    let tip = &reals[4];

    let mut expected: Vec<(u32, StacksBlockId, TrieHash)> = Vec::new();
    for h in 0..=squash_height {
        let h_key = format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{h}");
        let bh = src
            .with_conn(|conn| MARF::<StacksBlockId>::get_by_key(conn, tip, &h_key))
            .unwrap()
            .map(StacksBlockId::from)
            .unwrap_or_else(|| panic!("missing ::h mapping for h={h}"));
        let rh = src.get_root_hash_at(&bh).unwrap();
        expected.push((h, bh, rh));
    }
    drop(src);

    let (dst_db_path, _) = squash_helper(
        src_path.to_str().unwrap(),
        &dir.path().join("squashed"),
        tip,
        squash_height,
    );

    let conn = rusqlite::Connection::open(&dst_db_path).unwrap();
    let actual = trie_sql::bulk_read_squashed_blocks::<StacksBlockId>(&conn).unwrap();
    assert_eq!(
        expected, actual,
        "parent walk diverged from MARF height-index lookups for the same chain"
    );
}

#[test]
fn test_squash_rejects_existing_destination() {
    let dir = tempdir().unwrap();
    let src_db_path = dir.path().join("index.sqlite");
    let (_, blocks, _) = setup_marf(src_db_path.to_str().unwrap(), 2, 1);

    let dst_db_path = dir.path().join("dst.sqlite");
    // Pre-create an empty file at the destination path: the guard must trip.
    std::fs::write(&dst_db_path, b"").unwrap();

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let result = MARF::squash_to_path(
        src_db_path.to_str().unwrap(),
        dst_db_path.to_str().unwrap(),
        open_opts.clone(),
        blocks.last().unwrap(),
        1,
        "test",
    );
    match result {
        Err(Error::DestinationExists(path)) => assert_eq!(path, dst_db_path.to_str().unwrap()),
        other => panic!("expected DestinationExists for the .sqlite collision, got {other:?}"),
    }

    // Same check for an existing .blobs sibling without the .sqlite file.
    std::fs::remove_file(&dst_db_path).unwrap();
    let dst_blobs_path = dir.path().join("dst.sqlite.blobs");
    std::fs::write(&dst_blobs_path, b"").unwrap();

    let result = MARF::squash_to_path(
        src_db_path.to_str().unwrap(),
        dst_db_path.to_str().unwrap(),
        open_opts,
        blocks.last().unwrap(),
        1,
        "test",
    );
    match result {
        Err(Error::DestinationExists(path)) => assert_eq!(path, dst_blobs_path.to_str().unwrap()),
        other => panic!("expected DestinationExists for the .blobs collision, got {other:?}"),
    }
}

/// `stream_squash_blob` relies on NodeStore's root-first DFS preorder. If a
/// parent appears after its child in the temp store, reverse iteration would
/// try to write the parent before the child's offset is known. Make sure this
/// invariant fails loudly instead of writing a bogus offset 0 pointer.
#[test]
fn test_stream_squash_blob_rejects_non_preorder_nodes() {
    let dir = tempdir().unwrap();
    let dir_str = dir.path().to_str().unwrap();
    let mut store = NodeStore::new(dir_str).unwrap();
    let h = TrieHash([0; 32]);

    // Invalid order for the child-before-parent writer:
    //   0: root -> parent at index 2
    //   1: leaf
    //   2: parent -> leaf at index 1
    // A valid root-first DFS preorder would have placed index 2 before index 1.
    let root = make_test_node4(
        &[0],
        [
            TriePtr::new(TrieNodeID::Node4 as u8, b'a', 2),
            TriePtr::default(),
            TriePtr::default(),
            TriePtr::default(),
        ],
    );
    store.push(&root, h, 0).unwrap();
    store.push(&make_test_leaf(&[2, 3], 0xAA), h, 0).unwrap();

    let inner = make_test_node4(
        &[1],
        [
            TriePtr::new(TrieNodeID::Leaf as u8, b'b', 1),
            TriePtr::default(),
            TriePtr::default(),
            TriePtr::default(),
        ],
    );
    store.push(&inner, h, 0).unwrap();
    store.flush().unwrap();

    let parent_hash = StacksBlockId::sentinel();
    let mut output = Cursor::new(Vec::new());
    let err = stream_squash_blob(&mut store, &parent_hash, &mut output).unwrap_err();
    assert!(
        format!("{err}").contains("has not been written"),
        "expected unwritten child offset error, got {err}"
    );
}

/// Build a synthetic >4 GiB squash blob so the root's first child pointer
/// crosses `u32::MAX` and is emitted with the u64-width encoding bit.
#[test]
#[ignore = "synthetic large-offset regression"]
fn stream_squash_blob_large_offset_sets_u64_ptr_bit() {
    let dir = tempdir().expect("create temp dir");
    let dir_str = dir.path().to_str().unwrap();
    let path = dir
        .path()
        .join("stream_squash_blob_large_offset_sets_u64_ptr_bit.bin");

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
    store.flush().expect("flush node store");

    let parent_hash = StacksBlockId([0x55; 32]);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("create temp squash blob");
    let bytes_written =
        stream_squash_blob(&mut store, &parent_hash, &mut file).expect("stream squash blob");
    assert!(bytes_written > u64::from(u32::MAX));

    let header_size = blob_layout::ROOT_NODE_OFFSET as u64;
    let root_ptr = TriePtr::new(TrieNodeID::Node256 as u8, 0, header_size);
    let (root_node, _) = read_nodetype(&mut file, &root_ptr).expect("read root node");
    let child_ptr = root_node.ptrs()[0];
    assert!(child_ptr.ptr() > u64::from(u32::MAX));
    assert!(is_u64_ptr(child_ptr.encoded_id()));
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
    let mut src = MARF::from_path(src_db_path.to_str().unwrap(), open_opts.clone()).unwrap();

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

    MARF::squash_to_path(
        src_db_path.to_str().unwrap(),
        dst_db_path.to_str().unwrap(),
        open_opts.clone(),
        &b2,
        1,
        "test",
    )
    .unwrap();

    // --- Extend squashed MARF to b3 with compression enabled ---
    // Compression enables the patch-node path in dump_compressed_consume.
    let squashed_opts =
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true).with_compression(true);
    let mut squashed =
        MARF::from_path(dst_db_path.to_str().unwrap(), squashed_opts.clone()).unwrap();

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
    // Root node type ID sits one root-hash past the start of the root node.
    let root_type_offset =
        b3_blob_offset + blob_layout::ROOT_NODE_OFFSET as u64 + TRIEHASH_ENCODED_SIZE as u64;
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
