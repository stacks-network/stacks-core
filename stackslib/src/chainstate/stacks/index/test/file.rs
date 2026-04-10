// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::fs;

use rusqlite::{Connection, OpenFlags};

use super::*;
use crate::chainstate::stacks::index::file::*;
use crate::chainstate::stacks::index::*;
use crate::util_lib::db::*;

fn db_path(test_name: &str) -> String {
    let path = format!("/tmp/{}.sqlite", test_name);
    path
}

fn setup_db(test_name: &str) -> Connection {
    let path = db_path(test_name);
    if fs::metadata(&path).is_ok() {
        fs::remove_file(&path).unwrap();
    }

    let mut db = sqlite_open(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        true,
    )
    .unwrap();
    trie_sql::create_tables_if_needed(&mut db).unwrap();
    db
}

#[test]
fn test_load_store_trie_blob() {
    let mut db = setup_db("test_load_store_trie_blob");
    let mut blobs = TrieFile::from_db_path(&db_path("test_load_store_trie_blob"), false).unwrap();
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db, false).unwrap();

    blobs
        .store_trie_blob::<BlockHeaderHash>(&db, &BlockHeaderHash([0x01; 32]), &[1, 2, 3, 4, 5])
        .unwrap();
    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &db,
            &BlockHeaderHash([0x02; 32]),
            &[10, 20, 30, 40, 50],
        )
        .unwrap();

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x01; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap(), 0);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![1, 2, 3, 4, 5]);

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x02; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap(), 5);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![10, 20, 30, 40, 50]);
}

#[test]
fn test_migrate_tables_readonly_succeeds_when_current() {
    let mut db = setup_db("test_migrate_tables_readonly_ok");
    // First migrate in writable mode to bring schema to current version
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db, false).unwrap();
    // Now a read-only migration check should succeed
    let version = trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db, true).unwrap();
    assert_eq!(version, trie_sql::SQL_MARF_SCHEMA_VERSION);
}

#[test]
fn test_migrate_tables_readonly_fails_when_outdated() {
    let path = db_path("test_migrate_tables_readonly_fail");
    if fs::metadata(&path).is_ok() {
        fs::remove_file(&path).unwrap();
    }
    let mut db = sqlite_open(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        true,
    )
    .unwrap();
    trie_sql::create_tables_if_needed(&mut db).unwrap();
    // Don't migrate - schema is at version 1.
    // A read-only open should fail because the schema is outdated.
    let err = trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db, true).unwrap_err();
    assert!(
        matches!(&err, crate::chainstate::stacks::index::Error::CorruptionError(msg) if msg.contains("not compatible with read-only")),
        "instead got: {err}"
    );
}

#[test]
fn test_migrate_existing_trie_blobs() {
    let test_file = "/tmp/test_migrate_existing_trie_blobs.sqlite";
    let test_blobs_file = "/tmp/test_migrate_existing_trie_blobs.sqlite.blobs";
    if fs::metadata(&test_file).is_ok() {
        fs::remove_file(&test_file).unwrap();
    }
    if fs::metadata(&test_blobs_file).is_ok() {
        fs::remove_file(&test_blobs_file).unwrap();
    }

    let (data, last_block_header, root_header_map) = {
        let marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false);

        let f = TrieFileStorage::open(test_file, marf_opts).unwrap();
        let mut marf = MARF::from_storage(f);

        // make data to insert
        let data = make_test_insert_data(128, 128);
        let mut last_block_header = BlockHeaderHash::sentinel();
        for (i, block_data) in data.iter().enumerate() {
            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

            let block_header = BlockHeaderHash(block_hash_bytes);
            marf.begin(&last_block_header, &block_header).unwrap();

            for (key, value) in block_data.iter() {
                let path = TrieHash::from_key(key);
                let leaf = TrieLeaf::from_value(&[], value.clone());
                marf.insert_raw(path, leaf).unwrap();
            }
            marf.commit().unwrap();
            last_block_header = block_header;
        }

        let root_header_map =
            trie_sql::read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
                .unwrap();
        (data, last_block_header, root_header_map)
    };

    // migrate
    let mut marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    marf_opts.force_db_migrate = true;

    let f = TrieFileStorage::open(test_file, marf_opts).unwrap();
    let mut marf = MARF::from_storage(f);

    // blobs file exists
    assert!(fs::metadata(&test_blobs_file).is_ok());

    // verify that the new blob structure is well-formed
    let blob_root_header_map = {
        let mut blobs = TrieFile::from_db_path(test_file, false).unwrap();
        let blob_root_header_map = blobs
            .read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
            .unwrap();
        blob_root_header_map
    };

    assert_eq!(blob_root_header_map.len(), root_header_map.len());
    for (e1, e2) in blob_root_header_map.iter().zip(root_header_map.iter()) {
        assert_eq!(e1, e2);
    }

    // verify that we can read everything from the blobs
    for (i, block_data) in data.iter().enumerate() {
        for (key, value) in block_data.iter() {
            let path = TrieHash::from_key(key);
            let marf_leaf = TrieLeaf::from_value(&[], value.clone());

            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            assert_eq!(leaf.data.to_vec(), marf_leaf.data.to_vec());
        }
    }
}

#[test]
fn test_bulk_read_block_entries_rejects_negative_external_offset() {
    let mut db = setup_db("test_bulk_read_block_entries_rejects_negative_external_offset");
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db, false).unwrap();

    let block_hash = BlockHeaderHash([0x11; 32]);
    db.execute(
        "INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) \
         VALUES (?1, ?2, 0, ?3, ?4)",
        rusqlite::params![block_hash.to_string(), Vec::<u8>::new(), -1i64, 0i64],
    )
    .unwrap();

    let err = trie_sql::bulk_read_block_entries::<BlockHeaderHash>(&db).unwrap_err();
    assert!(
        matches!(err, crate::chainstate::stacks::index::Error::OverflowError),
        "instead got: {err:?}"
    );
}

#[test]
fn test_update_squash_root_node_hash_requires_existing_row() {
    let db = setup_db("test_update_squash_root_node_hash_requires_existing_row");
    let hash = TrieHash::from_data(b"squash-root");

    let err = trie_sql::update_squash_root_node_hash(&db, &hash).unwrap_err();
    assert!(
        matches!(
            err,
            crate::chainstate::stacks::index::Error::CorruptionError(ref msg)
                if msg.contains("no marf_squash_info row exists")
        ),
        "instead got: {err:?}"
    );
}
