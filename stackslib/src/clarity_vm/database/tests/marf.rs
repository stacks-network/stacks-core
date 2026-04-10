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

use std::path::PathBuf;

use clarity::vm::database::clarity_store::make_contract_hash_key;
use clarity::vm::database::{ClarityBackingStore, SqliteConnection};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::Sha512Trunc256Sum;
use tempfile::tempdir;

use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue};
use crate::clarity_vm::clarity::ClarityMarfStoreTransaction;
use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::snapshot::{
    copy_clarity_side_tables, validate_clarity_side_tables,
};

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
        height,
        "test",
    )
    .unwrap();

    // Copy Clarity side tables.
    let stats =
        copy_clarity_side_tables(src_db.to_str().unwrap(), dst_db.to_str().unwrap()).unwrap();
    assert!(stats.data_table_rows > 0, "Expected data_table rows > 0");

    dst_db
}

#[test]
fn test_copy_clarity_side_tables_round_trip() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let _blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");

    let squashed_db = squash_clarity_marf(&src_dir, &dir.path().join("squashed"), 3);

    // Validate side tables.
    let validation = validate_clarity_side_tables(
        clarity_marf_db_path(&src_dir).to_str().unwrap(),
        squashed_db.to_str().unwrap(),
    )
    .unwrap();

    assert!(
        validation.required_data_keys_present,
        "missing required data_table keys"
    );
    assert!(
        validation.required_metadata_present,
        "missing required metadata rows"
    );
    assert_eq!(validation.sample_contracts_missing_in_trie, 0);
    assert_eq!(validation.sample_contracts_missing_in_data_table, 0);
    assert_eq!(validation.missing_required_data_table_keys, 0);
    assert_eq!(validation.missing_required_metadata_rows, 0);
}

#[test]
fn test_squashed_clarity_marf_check_schema_passes() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let _blocks = build_clarity_marf(&src_dir, 3, "test-contract", "");

    let squashed_db = squash_clarity_marf(&src_dir, &dir.path().join("squashed"), 2);

    // check_schema must pass on the squashed DB.
    let conn = rusqlite::Connection::open(&squashed_db).unwrap();
    SqliteConnection::check_schema(&conn)
        .expect("check_schema should pass on squashed Clarity MARF");
}

#[test]
fn test_squashed_clarity_marf_data_reads_work() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");

    let squashed_db = squash_clarity_marf(&src_dir, &dir.path().join("squashed"), 3);

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
}

#[test]
fn test_squashed_clarity_marf_metadata_reads_work() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");

    let squashed_db = squash_clarity_marf(&src_dir, &dir.path().join("squashed"), 3);

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

#[test]
fn test_squashed_clarity_marf_extend_hash_equality() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let blocks = build_clarity_marf(&src_dir, 5, "test-contract", "");

    // Squash at height 3, copy side tables.
    let squashed_db = squash_clarity_marf(&src_dir, &dir.path().join("squashed"), 3);

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

#[test]
fn test_validate_clarity_side_tables_detects_mismatch() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let other_dir = dir.path().join("other");

    let _blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");
    let _other_blocks = build_clarity_marf(&other_dir, 4, "other-contract", "_other");

    // Squash source, but copy side tables from other.
    let squashed_dir = dir.path().join("squashed");
    std::fs::create_dir_all(&squashed_dir).unwrap();
    let src_db = clarity_marf_db_path(&src_dir);
    let dst_db = squashed_dir.join("marf.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    MARF::<StacksBlockId>::squash_to_path(
        src_db.to_str().unwrap(),
        dst_db.to_str().unwrap(),
        open_opts,
        3,
        "test",
    )
    .unwrap();

    let other_db = clarity_marf_db_path(&other_dir);
    copy_clarity_side_tables(other_db.to_str().unwrap(), dst_db.to_str().unwrap()).unwrap();

    let validation =
        validate_clarity_side_tables(src_db.to_str().unwrap(), dst_db.to_str().unwrap()).unwrap();

    assert!(
        validation.missing_required_data_table_keys > 0
            || validation.missing_required_metadata_rows > 0,
        "expected validation to detect mismatch between trie and data_table"
    );
}

#[test]
fn test_copy_clarity_side_tables_with_double_colon_metadata_keys() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    // build_clarity_marf now inserts metadata keys with "::" in them
    // (e.g. "vm-metadata::9", "vm-metadata::10::sub").
    let blocks = build_clarity_marf(&src_dir, 4, "test-contract", "");
    assert!(!blocks.is_empty());

    let squashed_db = squash_clarity_marf(&src_dir, &dir.path().join("squashed"), 3);

    // Validate side tables - this would previously fail with a
    // CorruptionError("Failed to parse contract identifier ...").
    let validation = validate_clarity_side_tables(
        clarity_marf_db_path(&src_dir).to_str().unwrap(),
        squashed_db.to_str().unwrap(),
    )
    .unwrap();

    assert!(
        validation.required_data_keys_present,
        "missing required data_table keys"
    );
    assert!(
        validation.required_metadata_present,
        "missing required metadata rows"
    );
    assert_eq!(validation.sample_contracts_missing_in_trie, 0);
    assert_eq!(validation.sample_contracts_missing_in_data_table, 0);
    assert_eq!(validation.missing_required_data_table_keys, 0);
    assert_eq!(validation.missing_required_metadata_rows, 0);

    // Also verify the metadata with "::" keys is readable.
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
