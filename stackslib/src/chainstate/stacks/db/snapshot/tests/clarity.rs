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

//! Clarity MARF squash + side-table (`data_table`, `metadata_table`)
//! copy tests.

use std::path::PathBuf;

use clarity::vm::database::clarity_store::make_contract_hash_key;
use clarity::vm::database::{ClarityBackingStore, MetadataRow, SqliteConnection};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::Sha512Trunc256Sum;
use tempfile::tempdir;

use super::super::clarity::assert_source_tables_classified;
use super::super::copy_clarity_side_tables;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::{ClarityMarfTrieId as _, Error, MARFValue};
use crate::clarity_vm::clarity::ClarityMarfStoreTransaction as _;
use crate::clarity_vm::database::marf::MarfedKV;

/// Build a Clarity MARF with N blocks of data and a single contract.
/// Returns the block hashes for each height.
fn build_clarity_marf(
    dir: &std::path::Path,
    num_blocks: u8,
    contract_name: &str,
    value_suffix: &str,
) -> Vec<StacksBlockId> {
    let mut kv = MarfedKV::open(dir.to_str().unwrap(), None, None).unwrap();

    let blocks: Vec<StacksBlockId> = (1..=num_blocks)
        .map(|i| StacksBlockId::from_bytes(&[i; 32]).unwrap())
        .collect();

    // Height 0
    {
        let mut store = kv.begin(&StacksBlockId::sentinel(), &blocks[0]);

        // data_table entries (via put_all_data)
        let contract_id =
            clarity::vm::types::QualifiedContractIdentifier::local(contract_name).unwrap();
        let contract_key = make_contract_hash_key(&contract_id);
        let contract_hash =
            Sha512Trunc256Sum::from_data(format!("{contract_name}{value_suffix}").as_bytes());
        let contract_commitment = store.make_contract_commitment(contract_hash);

        store
            .put_all_data(vec![
                (
                    "clarity_key_1".into(),
                    format!("clarity_val_1{value_suffix}"),
                ),
                (
                    "clarity_key_2".into(),
                    format!("clarity_val_2{value_suffix}"),
                ),
                (contract_key, contract_commitment),
            ])
            .unwrap();

        // metadata_table entries (via insert_metadata)
        store
            .insert_metadata(&contract_id, "source", "contract source code v0")
            .unwrap();

        // Insert metadata with keys that contain "::" (similar to
        // `vm-metadata::N::VAR` keys produced by ClarityDB::make_metadata_key).
        store
            .insert_metadata(&contract_id, "vm-metadata::9", "meta_value_9")
            .unwrap();
        store
            .insert_metadata(&contract_id, "vm-metadata::10::sub", "meta_value_10_sub")
            .unwrap();

        store.commit_to_processed_block(&blocks[0]).unwrap();
    }

    // Heights 1..N-1
    for i in 1..blocks.len() {
        let mut store = kv.begin(&blocks[i - 1], &blocks[i]);

        let key = format!("clarity_key_{}", i + 2);
        let val = format!("clarity_val_{}{value_suffix}", i + 2);
        store.put_all_data(vec![(key, val)]).unwrap();

        // Update an existing key to exercise overwrites.
        store
            .put_all_data(vec![(
                "clarity_key_1".into(),
                format!("clarity_val_1_at_{i}{value_suffix}"),
            )])
            .unwrap();

        store.commit_to_processed_block(&blocks[i]).unwrap();
    }

    drop(kv);
    blocks
}

fn clarity_marf_db_path(dir: &std::path::Path) -> PathBuf {
    dir.join("marf.sqlite")
}

/// Squash a Clarity MARF and copy side tables.  Returns the squashed db path.
fn squash_clarity_marf(
    src_dir: &std::path::Path,
    dst_dir: &std::path::Path,
    tip: &StacksBlockId,
    height: u32,
) -> PathBuf {
    std::fs::create_dir_all(dst_dir).unwrap();
    let src_db = clarity_marf_db_path(src_dir);
    let dst_db = dst_dir.join("marf.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    MARF::<StacksBlockId>::squash_to_path(
        src_db.to_str().unwrap(),
        dst_db.to_str().unwrap(),
        open_opts,
        tip,
        height,
        "test",
    )
    .unwrap();

    // Copy Clarity side tables.
    let stats =
        copy_clarity_side_tables(src_db.to_str().unwrap(), dst_db.to_str().unwrap()).unwrap();
    assert!(stats.data_table_rows > 0, "Expected data_table rows > 0");

    // The destination holds exactly the copied row counts.
    let dst_conn = rusqlite::Connection::open(&dst_db).unwrap();
    let (data_rows, meta_rows): (u64, u64) = dst_conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM data_table), (SELECT COUNT(*) FROM metadata_table)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (data_rows, meta_rows),
        (stats.data_table_rows, stats.metadata_table_rows)
    );

    dst_db
}

/// `SqliteConnection::check_schema` accepts the squashed Clarity DB
/// (tables and index recreated by the copy).
#[test]
fn test_squashed_clarity_marf_check_schema_passes() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 3, "test-contract", "");

    let squashed_db = squash_clarity_marf(
        &src_dir,
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        2,
    );

    // check_schema must pass on the squashed DB.
    let conn = rusqlite::Connection::open(&squashed_db).unwrap();
    SqliteConnection::check_schema(&conn)
        .expect("check_schema should pass on squashed Clarity MARF");
}

/// Clarity data reads through `MarfedKV` work on the squashed MARF,
/// including a key overwritten at the squash height and one written only
/// at height 0.
#[test]
fn test_squashed_clarity_marf_data_reads_work() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");

    let squashed_db = squash_clarity_marf(
        &src_dir,
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        3,
    );

    // Open the squashed MARF via MarfedKV.
    let squashed_dir = dir.path().join("squashed");
    let mut kv = MarfedKV::open(squashed_dir.to_str().unwrap(), Some(&blocks[3]), None).unwrap();

    // Verify trie reads + data_table lookups work.
    {
        let mut store = kv.begin_read_only(Some(&blocks[3]));

        // The latest value for clarity_key_1 should be the overwrite
        // from the last block.
        let val = store.get_data("clarity_key_1").unwrap();
        assert!(val.is_some(), "clarity_key_1 should be readable");
        assert_eq!(val.unwrap(), "clarity_val_1_at_3");

        // clarity_key_2 was written at height 0 and never overwritten.
        let val2 = store.get_data("clarity_key_2").unwrap();
        assert!(val2.is_some(), "clarity_key_2 should be readable");
        assert_eq!(val2.unwrap(), "clarity_val_2");
    }

    // Stale overwritten values are pruned from the content-addressed
    // data_table: only the tip value of clarity_key_1 survives.
    let conn = rusqlite::Connection::open(&squashed_db).unwrap();
    let stale: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM data_table \
             WHERE value LIKE 'clarity_val_1%' AND value != 'clarity_val_1_at_3'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stale, 0, "overwritten values must be pruned");
}

/// Contract metadata reads through `MarfedKV` work on the squashed MARF
/// (the lookup resolves the deployment block via the copied trie).
#[test]
fn test_squashed_clarity_marf_metadata_reads_work() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");

    squash_clarity_marf(
        &src_dir,
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        3,
    );

    // Open the squashed MARF via MarfedKV.
    let squashed_dir = dir.path().join("squashed");
    let mut kv = MarfedKV::open(squashed_dir.to_str().unwrap(), Some(&blocks[3]), None).unwrap();

    // Verify sqlite_get_metadata path works. Metadata was inserted at
    // height 0 with blockhash = blocks[0]. The lookup resolves the
    // deployment block via get_contract_hash -> get_block_at_height.
    {
        let mut store = kv.begin_read_only(Some(&blocks[3]));
        let contract_id =
            clarity::vm::types::QualifiedContractIdentifier::local("test-contract").unwrap();

        let md = store.get_metadata(&contract_id, "source").unwrap();
        assert!(md.is_some(), "metadata should be present");
        assert_eq!(md.unwrap(), "contract source code v0");
    }
}

/// Metadata rows for a (well-formed) contract absent from the squashed trie
/// are not copied.
#[test]
fn test_metadata_exclusions() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");

    // A rogue but well-formed row in src: a contract with no trie commitment.
    let src_conn = rusqlite::Connection::open(clarity_marf_db_path(&src_dir)).unwrap();
    SqliteConnection::insert_metadata_row(
        &src_conn,
        &MetadataRow {
            key: "clr-meta::ST000000000000000000002AMW42H.ghost::source",
            block_id: &blocks[0].to_hex(),
            value: "ghost",
        },
    )
    .unwrap();
    drop(src_conn);

    let squashed_db = squash_clarity_marf(
        &src_dir,
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        3,
    );

    let conn = rusqlite::Connection::open(&squashed_db).unwrap();
    let mut rogue = 0;
    SqliteConnection::visit_metadata_keys(&conn, |key| -> Result<(), rusqlite::Error> {
        if key.contains("ghost") {
            rogue += 1;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(rogue, 0, "unrequired metadata must not be copied");
}

/// A `metadata_table` row whose key is not in the `clr-meta::` format is a
/// corruption signal: the copy must fail loudly rather than silently drop it.
#[test]
fn test_malformed_metadata_key_is_corruption() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");

    let src_conn = rusqlite::Connection::open(clarity_marf_db_path(&src_dir)).unwrap();
    SqliteConnection::insert_metadata_row(
        &src_conn,
        &MetadataRow {
            key: "not-a-metadata-key",
            block_id: &blocks[0].to_hex(),
            value: "junk",
        },
    )
    .unwrap();
    drop(src_conn);

    // Squash, then attempt the side-table copy directly so we can assert it errors
    // (the squash_clarity_marf helper unwraps the copy).
    let squashed_dir = dir.path().join("squashed");
    std::fs::create_dir_all(&squashed_dir).unwrap();
    let src_db = clarity_marf_db_path(&src_dir);
    let dst_db = squashed_dir.join("marf.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    MARF::<StacksBlockId>::squash_to_path(
        src_db.to_str().unwrap(),
        dst_db.to_str().unwrap(),
        open_opts,
        blocks.last().unwrap(),
        3,
        "test",
    )
    .unwrap();

    let err = copy_clarity_side_tables(src_db.to_str().unwrap(), dst_db.to_str().unwrap())
        .expect_err("malformed metadata key must fail the copy");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("clr-meta"),
        "expected a clr-meta format corruption error, got: {msg}"
    );
}

/// Extending the squashed MARF and the archival MARF from the squash
/// height with the same block yields identical root hashes.
#[test]
fn test_squashed_clarity_marf_extend_hash_equality() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 5, "test-contract", "");

    // Squash at height 3, copy side tables.
    let squashed_db = squash_clarity_marf(
        &src_dir,
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        3,
    );

    // Open both MARFs at the raw MARF level for hash comparison.
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let src_db = clarity_marf_db_path(&src_dir);
    let mut archival =
        MARF::<StacksBlockId>::from_path(src_db.to_str().unwrap(), open_opts.clone()).unwrap();
    let mut squashed =
        MARF::<StacksBlockId>::from_path(squashed_db.to_str().unwrap(), open_opts).unwrap();

    // Extend both from blocks[3] with the same new block.
    let b_ext = StacksBlockId::from_bytes(&[201u8; 32]).unwrap();

    archival.begin(&blocks[3], &b_ext).unwrap();
    archival
        .insert("ext_key", MARFValue::from_value("ext_val"))
        .unwrap();
    archival.commit().unwrap();

    squashed.begin(&blocks[3], &b_ext).unwrap();
    squashed
        .insert("ext_key", MARFValue::from_value("ext_val"))
        .unwrap();
    squashed.commit().unwrap();

    let arch_root = archival.get_root_hash_at(&b_ext).unwrap();
    let sq_root = squashed.get_root_hash_at(&b_ext).unwrap();
    assert_eq!(
        arch_root, sq_root,
        "Root hash mismatch after extending squashed Clarity MARF"
    );
    assert_ne!(
        arch_root,
        TrieHash([0u8; 32]),
        "root hash should be non-zero"
    );
}

/// Side tables copied from the wrong source MARF leave trie value hashes
/// dangling: data and metadata reads must fail, not return wrong data.
#[test]
fn test_mismatched_clarity_db_causes_data_read_failure() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let other_dir = dir.path().join("other");

    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");
    let _other_blocks = build_clarity_marf(&other_dir, 4, "other-contract", "_other");

    // Squash the source MARF, but copy side tables from the OTHER MARF.
    let squashed_dir = dir.path().join("squashed");
    std::fs::create_dir_all(&squashed_dir).unwrap();
    let src_db = clarity_marf_db_path(&src_dir);
    let dst_db = squashed_dir.join("marf.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    MARF::<StacksBlockId>::squash_to_path(
        src_db.to_str().unwrap(),
        dst_db.to_str().unwrap(),
        open_opts,
        blocks.last().unwrap(),
        3,
        "test",
    )
    .unwrap();

    let other_db = clarity_marf_db_path(&other_dir);
    copy_clarity_side_tables(other_db.to_str().unwrap(), dst_db.to_str().unwrap()).unwrap();

    // Open and attempt to read data via Clarity store.
    let mut kv = MarfedKV::open(squashed_dir.to_str().unwrap(), Some(&blocks[3]), None).unwrap();
    let mut store = kv.begin_read_only(Some(&blocks[3]));

    // Data lookup should error because the value hash isn't in the copied data_table.
    let result = store.get_data("clarity_key_1");
    assert!(
        result.is_err(),
        "expected get_data to fail with mismatched side tables"
    );

    // Metadata lookup should fail because the contract commitment hash
    // is missing from the copied data_table.
    let contract_id =
        clarity::vm::types::QualifiedContractIdentifier::local("test-contract").unwrap();
    let md = store.get_metadata(&contract_id, "source");
    assert!(
        md.is_err(),
        "expected get_metadata to fail with mismatched side tables"
    );
}

/// Metadata keys containing `::` split on the first separator only: the
/// copy keeps them, and they remain readable after the squash.
#[test]
fn test_copy_clarity_side_tables_with_double_colon_metadata_keys() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    // build_clarity_marf now inserts metadata keys with "::" in them
    // (e.g. "vm-metadata::9", "vm-metadata::10::sub").
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");
    assert!(!blocks.is_empty());

    squash_clarity_marf(
        &src_dir,
        &dir.path().join("squashed"),
        blocks.last().unwrap(),
        3,
    );

    // Verify the metadata with "::" keys is readable.
    let squashed_dir = dir.path().join("squashed");
    let mut kv = MarfedKV::open(squashed_dir.to_str().unwrap(), Some(&blocks[3]), None).unwrap();
    {
        let mut store = kv.begin_read_only(Some(&blocks[3]));
        let contract_id =
            clarity::vm::types::QualifiedContractIdentifier::local("test-contract").unwrap();

        let md = store.get_metadata(&contract_id, "vm-metadata::9").unwrap();
        assert!(md.is_some(), "vm-metadata::9 should be present");
        assert_eq!(md.unwrap(), "meta_value_9");

        let md2 = store
            .get_metadata(&contract_id, "vm-metadata::10::sub")
            .unwrap();
        assert!(md2.is_some(), "vm-metadata::10::sub should be present");
        assert_eq!(md2.unwrap(), "meta_value_10_sub");
    }
}

/// Drift guard for the Clarity MARF DB: every table must be either copied by
/// `copy_clarity_side_tables` (data_table, metadata_table) or owned by the MARF
/// trie itself (recreated by `MARF::squash_to_path`). Runs the exact production
/// guard against a freshly-built schema, so the test and the runtime check
/// cannot drift apart.
#[test]
fn test_no_unclassified_clarity_source_tables() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    build_clarity_marf(&src_dir, 2, "test-contract", "");
    let conn = rusqlite::Connection::open(clarity_marf_db_path(&src_dir)).unwrap();

    assert_source_tables_classified(&conn)
        .expect("fresh production Clarity schema must be fully classified");
}

/// A source table the copy lists don't classify is rejected before any
/// destination is produced — the runtime complement to the drift test.
#[test]
fn test_unclassified_source_table_is_rejected() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    build_clarity_marf(&src_dir, 2, "test-contract", "");
    let src_db = clarity_marf_db_path(&src_dir);

    let conn = rusqlite::Connection::open(&src_db).unwrap();
    conn.execute_batch("CREATE TABLE surprise_table (x INTEGER)")
        .unwrap();
    drop(conn);

    let dst_db = dir.path().join("squashed").join("marf.sqlite");
    let err = copy_clarity_side_tables(src_db.to_str().unwrap(), dst_db.to_str().unwrap())
        .expect_err("unclassified source table must be rejected");
    match err {
        Error::CorruptionError(msg) => assert!(
            msg.contains("surprise_table"),
            "error should name the offending table, got: {msg}"
        ),
        other => panic!("expected CorruptionError, got {other:?}"),
    }
    assert!(
        !dst_db.exists(),
        "no destination should be produced when the source is rejected"
    );
}
