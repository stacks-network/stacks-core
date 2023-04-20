// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use crate::chainstate::stacks::index::cache::*;
use crate::chainstate::stacks::index::file::*;
use crate::chainstate::stacks::index::marf::*;
use crate::chainstate::stacks::index::storage::*;
use crate::chainstate::stacks::index::*;
use crate::chainstate::stacks::index::test::cache::make_test_insert_data;
use crate::util_lib::db::*;
use rusqlite::Connection;
use rusqlite::OpenFlags;
use std::fs;
use stacks_common::types::chainstate::{MARFOpenOpts, BlobCompressionType, TrieHashCalculationMode, TrieCachingStrategy};

use super::*;

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
fn test_load_store_trie_blob_no_compression() {
    let mut db = setup_db("test_load_store_trie_blob_no_compression");
    let compression_type = BlobCompressionType::None;
    let mut blobs = TrieFile2::from_db_path(&db_path("test_load_store_trie_blob_no_compression"), false, compression_type).unwrap();
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();

    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &compression_type, 
            &db, 
            &BlockHeaderHash([0x01; 32]), 
            &[1, 2, 3, 4, 5]
        )
        .unwrap();
    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &compression_type,
            &db,
            &BlockHeaderHash([0x02; 32]),
            &[10, 20, 30, 40, 50],
        )
        .unwrap();

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x01; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap().offset, 0);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![1, 2, 3, 4, 5]);

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x02; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap().offset, 5);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![10, 20, 30, 40, 50]);
}

#[test]
fn test_load_store_trie_blob_lz4_compression() {
    let mut db = setup_db("test_load_store_trie_blob_lz4_compression");
    let compression_type = BlobCompressionType::LZ4;
    let mut blobs = TrieFile2::from_db_path(
        &db_path("test_load_store_trie_blob_lz4_compression"), 
        false, 
        compression_type
    ).unwrap();

    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();

    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &compression_type,
            &db,
            &BlockHeaderHash([0x01; 32]),
            &[1, 2, 3, 4, 5]
        )
        .unwrap();

    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &compression_type,
            &db,
            &BlockHeaderHash([0x02; 32]),
            &[10, 20, 30, 40, 50],
        )
        .unwrap();

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x01; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap().offset, 0);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![1, 2, 3, 4, 5]);

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x02; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap().offset, 10);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![10, 20, 30, 40, 50]);
}

#[test]
fn test_load_store_trie_blob_zstd_compression() {
    let mut db = setup_db("test_load_store_trie_blob_zstd_compression");
    let compression_type = BlobCompressionType::ZStd(0);
    let mut blobs = TrieFile2::from_db_path(&db_path("test_load_store_trie_blob_zstd_compression"), false, compression_type).unwrap();
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();

    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &compression_type, 
            &db, 
            &BlockHeaderHash([0x01; 32]), 
            &[1, 2, 3, 4, 5]
        )
        .unwrap();
    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &compression_type,
            &db,
            &BlockHeaderHash([0x02; 32]),
            &[10, 20, 30, 40, 50],
        )
        .unwrap();

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x01; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap().offset, 0);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![1, 2, 3, 4, 5]);

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x02; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap().offset, 14);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![10, 20, 30, 40, 50]);
}

#[test]
fn test_migrate_db_trie_blobs_no_compression() {
    test_migrate_existing_trie_blobs(false, BlobCompressionType::None, BlobCompressionType::None)
}

#[test]
fn test_migrate_db_trie_blobs_lz4_compression() {
    test_migrate_existing_trie_blobs(false, BlobCompressionType::None, BlobCompressionType::LZ4)
}

#[test]
fn test_migrate_db_trie_blobs_zstd_compression() {
    test_migrate_existing_trie_blobs(false, BlobCompressionType::None, BlobCompressionType::ZStd(0))
}

#[test]
fn test_migrate_external_trie_blobs_lz4_to_zstd_compression() {
    test_migrate_existing_trie_blobs(true, BlobCompressionType::LZ4, BlobCompressionType::ZStd(0))
}

#[test]
fn test_migrate_external_trie_blobs_nocomp_to_lz4_compression() {
    test_migrate_existing_trie_blobs(true, BlobCompressionType::None, BlobCompressionType::LZ4)
}

fn test_migrate_existing_trie_blobs(external_blobs: bool, source_compression_type: BlobCompressionType, dest_compression_type: BlobCompressionType) {
    let test_dir = format!("/tmp/test_migrate_existing_trie_blobs_external_{}_{}_to_{}", external_blobs, source_compression_type, dest_compression_type);
    let test_file = format!("{}/marf.sqlite", &test_dir);
    let test_blobs_file = format!("{}/marf.sqlite.blobs", &test_dir);

    if !fs::metadata(&test_dir).is_ok() {
        fs::create_dir(&test_dir).unwrap();
    }

    if fs::metadata(&test_file).is_ok() {
        fs::remove_file(&test_file).unwrap();
    }

    if fs::metadata(&test_blobs_file).is_ok() {
        fs::remove_file(&test_blobs_file).unwrap();
    }

    let (
        data, 
        last_block_header, 
        root_header_map
    ) = {
        let marf_opts = MARFOpenOpts::new(
            TrieHashCalculationMode::Deferred, 
            TrieCachingStrategy::Noop, 
            external_blobs, 
            source_compression_type);

        let f = TrieFileStorage::open(&test_file, marf_opts).unwrap();
        let mut marf = MARF::from_storage(f);

        // make data to insert
        info!("Preparing test data and filling MARF...");
        let data = make_test_insert_data(100, 256);
        let mut last_block_header = BlockHeaderHash::sentinel();

        for (i, block_data) in data.iter().enumerate() {
            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

            let block_header = BlockHeaderHash(block_hash_bytes);
            marf.begin(&last_block_header, &block_header).unwrap();

            for (key, value) in block_data.iter() {
                marf.insert(key, value.clone()).unwrap();
            }
            marf.commit().unwrap();
            last_block_header = block_header;
        }

        if external_blobs {
            let mut file = TrieFile2::from_db_path(&test_file, false, source_compression_type).unwrap();
            
            let root_header_map = 
                file.read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
                .unwrap();
            (data, last_block_header, root_header_map)
        } else {
            let root_header_map =
                trie_sql::read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
                .unwrap();
            (data, last_block_header, root_header_map)
        }
    };

    // migrate
    info!("Performing the migration...");
    let mut marf_opts = MARFOpenOpts::new(
        TrieHashCalculationMode::Deferred, 
        TrieCachingStrategy::Noop, 
        true, 
        dest_compression_type);
    marf_opts.force_db_migrate = !external_blobs;

    info!("Opening trie file (migration expected)...");
    let mut f = TrieFileStorage::open(&test_file, marf_opts.clone()).unwrap();
    info!("Re-opening trie file (no migration should be needed)...");
    f = TrieFileStorage::open(&test_file, marf_opts.clone()).unwrap();
    let mut marf = MARF::from_storage(f);

    // blobs file exists
    assert!(fs::metadata(&test_blobs_file).is_ok());

    // verify that the new blob structure is well-formed
    let blob_root_header_map = {
        let mut blobs = TrieFile2::from_db_path(&test_file, false, dest_compression_type).unwrap();
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
            let path = TriePath::from_key(key);
            let marf_leaf = TrieLeaf::from_value(&vec![], value.clone());

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
