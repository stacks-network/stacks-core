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

//! Burnchain DB (burnchain.sqlite) copy tests.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::{params, Connection};
use stacks_common::types::chainstate::BurnchainHeaderHash;
use tempfile::tempdir;

use super::super::burnchain::{
    assert_source_tables_classified, burnchain_copy_specs, copy_burnchain_db, COPIED_TABLES,
};
use crate::burnchains::db::BurnchainDB;
use crate::burnchains::{Burnchain, PoxConstants};
use crate::chainstate::burn::db::sortdb::tests::test_append_snapshot;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::index::Error;
use crate::core::{StacksEpoch, StacksEpochExtension};

/// Drift guard: a freshly built production burnchain schema must be fully
/// classified, so a future migration can't silently drop a table from the copy.
#[test]
fn test_no_unclassified_burnchain_tables() {
    let dir = tempdir().unwrap();
    let conn = create_burnchain_db(&dir.path().join("src.sqlite"));
    assert_source_tables_classified(&conn)
        .expect("fresh production burnchain schema must be fully classified");
}

/// A source table the copy lists don't classify is rejected before any
/// destination is produced — the runtime complement to the drift test.
#[test]
fn test_unclassified_source_table_is_rejected() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let sort_path = create_squashed_sortition(dir.path(), &[]);

    let src = create_burnchain_db(&src_path);
    src.execute_batch("CREATE TABLE surprise_table (x INTEGER)")
        .unwrap();
    drop(src);

    let err = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .expect_err("unclassified source table should error");
    match err {
        Error::CorruptionError(msg) => assert!(
            msg.contains("surprise_table"),
            "error should name the unknown table, got: {msg}"
        ),
        other => panic!("expected CorruptionError, got {other:?}"),
    }
    assert!(
        !dst_path.exists(),
        "destination must not be produced when the source schema is rejected"
    );
}

/// Every cloned table (`COPIED_TABLES`) must have a row-copy spec and vice versa,
/// else it would be cloned but never populated (present-but-empty).
#[test]
fn test_copy_specs_match_copied_tables() {
    let copied: HashSet<&str> = COPIED_TABLES.iter().copied().collect();

    let specs: Vec<&str> = burnchain_copy_specs().iter().map(|s| s.table).collect();
    let spec_set: HashSet<&str> = specs.iter().copied().collect();
    assert_eq!(specs.len(), spec_set.len(), "duplicate spec tables");
    assert_eq!(spec_set, copied);
}

/// Create a burnchain.sqlite source via the production initializer
/// ([`BurnchainDB::connect`]), so the fixture always carries the current
/// schema instead of replaying migrations by hand. `connect` also seeds
/// the regtest first-block header.
fn create_burnchain_db(path: &Path) -> Connection {
    let burnchain = Burnchain::regtest(":memory:");
    let _db = BurnchainDB::connect(path.to_str().unwrap(), &burnchain, true)
        .expect("burnchain DB init failed");
    Connection::open(path).unwrap()
}

/// Burn header hash of the squashed-sortition fixture's genesis snapshot.
const GENESIS_BHH: BurnchainHeaderHash = BurnchainHeaderHash([0u8; 32]);

/// A distinct burn header hash for fixture block `i`.
fn fixture_bhh(i: u8) -> BurnchainHeaderHash {
    BurnchainHeaderHash([i; 32])
}

/// Create a squashed-sortition stand-in through production write paths
/// ([`SortitionDB::connect`] + [`test_append_snapshot`]), so the fixture
/// cannot drift from what production actually writes: a real sortition DB
/// whose canonical chain is the genesis snapshot ([`GENESIS_BHH`] at height
/// 0) followed by `hashes` at heights 1... Returns its sqlite path.
fn create_squashed_sortition(dir: &Path, hashes: &[BurnchainHeaderHash]) -> std::path::PathBuf {
    let db_dir = dir.join("sortition");
    let mut db = SortitionDB::connect(
        db_dir.to_str().unwrap(),
        0,
        &GENESIS_BHH,
        0,
        &StacksEpoch::unit_test_3_4(0),
        PoxConstants::test_default(),
        None,
        true,
        None,
    )
    .expect("sortition DB init failed");
    for hash in hashes {
        test_append_snapshot(&mut db, hash.clone(), &[]);
    }
    db_dir.join("marf.sqlite")
}

/// End-to-end burnchain copy: canonical headers, ops, and commit
/// metadata are copied verbatim; fork rows are dropped.
#[test]
fn test_burnchain_db_copy() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_burnchain.sqlite");
    let dst_path = dir.path().join("dst_burnchain.sqlite");

    // Canonical hashes at heights 0, 1, 2.
    let canonical = [GENESIS_BHH, fixture_bhh(1), fixture_bhh(2)];
    let sort_path = create_squashed_sortition(dir.path(), &canonical[1..]);
    let hash_1 = fixture_bhh(1).to_string();

    let src = create_burnchain_db(&src_path);
    // Insert canonical block headers.
    for (h, hash) in canonical.iter().enumerate() {
        BurnchainDB::test_insert_block_header_row(
            &src,
            h as u64,
            &hash.to_string(),
            &format!("parent_{hash}"),
        )
        .unwrap();
    }
    // Insert a non-canonical block at height 1.
    BurnchainDB::test_insert_block_header_row(&src, 1, "fork_hash_1", "parent_fork").unwrap();
    // Ops for canonical and non-canonical.
    BurnchainDB::test_insert_block_ops_row(&src, &hash_1, "op1", "tx1").unwrap();
    BurnchainDB::test_insert_block_ops_row(&src, "fork_hash_1", "op_fork", "tx_fork").unwrap();
    // block_commit_metadata for canonical.
    BurnchainDB::test_insert_block_commit_metadata_row(&src, &hash_1, "tx1", 1, None).unwrap();
    // block_commit_metadata for non-canonical.
    BurnchainDB::test_insert_block_commit_metadata_row(&src, "fork_hash_1", "tx_fork", 1, None)
        .unwrap();
    drop(src);

    let stats = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        2,
    )
    .unwrap();

    assert_eq!(stats.block_headers_rows, 3); // 3 canonical
    assert_eq!(stats.block_ops_rows, 1); // only fixture_bhh(1)'s op
    assert_eq!(stats.block_commit_metadata_rows, 1); // only canonical

    // Copied rows carry their full source content, and the fork rows are
    // absent by key.
    let dst = Connection::open(&dst_path).unwrap();
    let header: (u64, String, String, u64, u64) = dst
        .query_row(
            "SELECT block_height, block_hash, parent_block_hash, num_txs, timestamp \
             FROM burnchain_db_block_headers WHERE block_hash = ?1",
            params![hash_1],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        header,
        (1, hash_1.clone(), format!("parent_{hash_1}"), 0, 0)
    );
    let op: (String, String, String) = dst
        .query_row(
            "SELECT block_hash, op, txid FROM burnchain_db_block_ops",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(op, (hash_1.clone(), "op1".into(), "tx1".into()));
    let commit: (String, String, u64, u64) = dst
        .query_row(
            "SELECT burn_block_hash, txid, block_height, vtxindex FROM block_commit_metadata",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(commit, (hash_1.clone(), "tx1".into(), 1, 0));
    let version: u64 = dst
        .query_row(
            "SELECT MAX(CAST(version AS INTEGER)) FROM db_config",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        version,
        u64::from(BurnchainDB::SCHEMA_VERSION),
        "db_config copied verbatim"
    );
    let fork_rows: i64 = dst
        .query_row(
            "SELECT (SELECT COUNT(*) FROM burnchain_db_block_headers WHERE block_hash = 'fork_hash_1') \
             + (SELECT COUNT(*) FROM burnchain_db_block_ops WHERE block_hash = 'fork_hash_1') \
             + (SELECT COUNT(*) FROM block_commit_metadata WHERE burn_block_hash = 'fork_hash_1')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fork_rows, 0, "fork rows must be absent by key");
}

/// The copy writes into a NEW destination only: a pre-existing
/// `burnchain.sqlite` (e.g. left over from a prior failed squash) is an
/// error, never appended to or overwritten.
#[test]
fn test_burnchain_db_existing_destination_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let sort_path = create_squashed_sortition(dir.path(), &[fixture_bhh(1)]);
    let src = create_burnchain_db(&src_path);
    drop(src);

    // A stale destination left over from a prior run must not be touched.
    std::fs::write(&dst_path, b"stale data").unwrap();

    let err = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .expect_err("existing destination should error");
    assert!(
        matches!(err, Error::DestinationExists(_)),
        "expected DestinationExists, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&dst_path).unwrap(),
        b"stale data",
        "existing destination must be left untouched"
    );
}

/// Two headers at the same height: only the one whose hash is in the
/// squashed sortition snapshots is copied.
#[test]
fn test_burnchain_db_excludes_non_canonical_fork() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    // Only fixture_bhh(0xa1) is canonical at height 1.
    let hash_a = fixture_bhh(0xa1);
    let sort_path = create_squashed_sortition(dir.path(), &[hash_a.clone()]);

    let src = create_burnchain_db(&src_path);
    BurnchainDB::test_insert_block_header_row(&src, 0, &GENESIS_BHH.to_string(), "none").unwrap();
    BurnchainDB::test_insert_block_header_row(
        &src,
        1,
        &hash_a.to_string(),
        &GENESIS_BHH.to_string(),
    )
    .unwrap();
    BurnchainDB::test_insert_block_header_row(&src, 1, "hash_b", "parent_b").unwrap();
    drop(src);

    let stats = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    assert_eq!(stats.block_headers_rows, 2); // genesis + hash_a, not hash_b

    // Verify hash_b is not in destination.
    let dst = Connection::open(&dst_path).unwrap();
    let count: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM burnchain_db_block_headers WHERE block_hash = 'hash_b'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

/// Block ops follow their header's canonicality: ops of a fork header
/// are dropped.
#[test]
fn test_burnchain_db_block_ops_follow_canonical_headers() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    // Only the genesis snapshot is canonical.
    let sort_path = create_squashed_sortition(dir.path(), &[]);

    let src = create_burnchain_db(&src_path);
    BurnchainDB::test_insert_block_header_row(&src, 0, &GENESIS_BHH.to_string(), "none").unwrap();
    BurnchainDB::test_insert_block_header_row(&src, 0, "fork", "none").unwrap();
    BurnchainDB::test_insert_block_ops_row(&src, &GENESIS_BHH.to_string(), "op_c", "tx_c").unwrap();
    BurnchainDB::test_insert_block_ops_row(&src, "fork", "op_f", "tx_f").unwrap();
    drop(src);

    let stats = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(stats.block_ops_rows, 1);

    let dst = Connection::open(&dst_path).unwrap();
    let op: String = dst
        .query_row("SELECT op FROM burnchain_db_block_ops", [], |r| r.get(0))
        .unwrap();
    assert_eq!(op, "op_c");
}

/// `anchor_blocks` and `overrides` are restricted to reward cycles
/// referenced by the copied commit metadata.
#[test]
fn test_burnchain_db_anchor_blocks_filtered() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let h1 = fixture_bhh(1);
    let sort_path = create_squashed_sortition(dir.path(), &[h1.clone()]);

    let src = create_burnchain_db(&src_path);
    BurnchainDB::test_insert_block_header_row(&src, 0, &GENESIS_BHH.to_string(), "none").unwrap();
    BurnchainDB::test_insert_block_header_row(&src, 1, &h1.to_string(), &GENESIS_BHH.to_string())
        .unwrap();
    // Anchor block for cycle 1 (referenced by canonical commit).
    BurnchainDB::test_insert_anchor_block_row(&src, 1).unwrap();
    // Anchor block for cycle 99 (not referenced by any canonical commit).
    BurnchainDB::test_insert_anchor_block_row(&src, 99).unwrap();
    // Canonical commit referencing anchor block cycle 1.
    BurnchainDB::test_insert_block_commit_metadata_row(&src, &h1.to_string(), "tx_a", 1, Some(1))
        .unwrap();
    // Override for cycle 1 (should be copied) and cycle 99 (should not).
    BurnchainDB::test_insert_override_row(&src, 1, "map_1").unwrap();
    BurnchainDB::test_insert_override_row(&src, 99, "map_99").unwrap();
    drop(src);

    let stats = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    assert_eq!(stats.anchor_blocks_rows, 1);

    let dst = Connection::open(&dst_path).unwrap();
    let cycle: i64 = dst
        .query_row("SELECT reward_cycle FROM anchor_blocks", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cycle, 1);
    // `overrides` is schema-only: the table exists in the dst, but no rows are
    // copied -- not even for a canonical reward cycle.
    let override_rows: i64 = dst
        .query_row("SELECT COUNT(*) FROM overrides", [], |r| r.get(0))
        .unwrap();
    assert_eq!(override_rows, 0, "overrides must not be row-copied");
    let anchor99: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM anchor_blocks WHERE reward_cycle = 99",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(anchor99, 0, "unreferenced anchor block must not be copied");
}

/// A missing source burnchain.sqlite is an error, and the read-only
/// ATTACH must not create the source file as a side effect.
#[test]
fn test_burnchain_db_missing_source_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let sort_path = create_squashed_sortition(dir.path(), &[]);

    let result = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    );
    assert!(result.is_err(), "missing source should error");
    assert!(
        !src_path.exists(),
        "missing source must not be created by ATTACH"
    );
}

/// A sortition tip height that disagrees with the caller's expected burn
/// height is corruption: the copy must abort.
#[test]
fn test_burnchain_db_sortition_tip_mismatch_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    // Sortition tip is at height 5.
    let hashes: Vec<_> = (1..=5).map(fixture_bhh).collect();
    let sort_path = create_squashed_sortition(dir.path(), &hashes);

    let src = create_burnchain_db(&src_path);
    BurnchainDB::test_insert_block_header_row(&src, 0, &GENESIS_BHH.to_string(), "none").unwrap();
    drop(src);

    // Pass expected_burn_height=10, but sortition tip is 5.
    let result = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        10,
    );
    assert!(result.is_err(), "should fail on sortition tip mismatch");
}

/// The copy creates missing parent directories for the destination path.
#[test]
fn test_burnchain_db_fresh_output_dir() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    // Nested non-existent directory.
    let dst_path = dir
        .path()
        .join("deep")
        .join("nested")
        .join("burnchain.sqlite");

    let sort_path = create_squashed_sortition(dir.path(), &[]);

    let src = create_burnchain_db(&src_path);
    BurnchainDB::test_insert_block_header_row(&src, 0, &GENESIS_BHH.to_string(), "none").unwrap();
    drop(src);

    let stats = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(stats.block_headers_rows, 1);
    assert!(dst_path.exists());
}

/// A canonical burn hash absent from the source headers is corruption:
/// the copy must abort.
#[test]
fn test_burnchain_db_copy_fails_when_source_missing_canonical_hash() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    // Sortition says heights 0, 1, 2 are canonical.
    let sort_path = create_squashed_sortition(dir.path(), &[fixture_bhh(1), fixture_bhh(2)]);

    // But source burnchain.sqlite only has heights 0 and 1 - 2 is missing.
    let src = create_burnchain_db(&src_path);
    BurnchainDB::test_insert_block_header_row(&src, 0, &GENESIS_BHH.to_string(), "none").unwrap();
    BurnchainDB::test_insert_block_header_row(
        &src,
        1,
        &fixture_bhh(1).to_string(),
        &GENESIS_BHH.to_string(),
    )
    .unwrap();
    drop(src);

    let result = copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        2,
    );
    assert!(
        result.is_err(),
        "should fail when source is missing a canonical burn hash"
    );
}
