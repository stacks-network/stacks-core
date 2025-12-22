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

use std::time::SystemTime;
use std::{cmp, fs};

use stacks_common::util::hash::Sha512Trunc256Sum;

use super::*;
use crate::chainstate::stacks::index::*;

/// Deterministic random keys to insert
pub fn make_test_insert_data(
    num_inserts_per_block: u64,
    num_blocks: u64,
) -> Vec<Vec<(String, MARFValue)>> {
    let mut data = vec![0u8; 32];
    let mut ret = vec![];

    for blk in 0..num_blocks {
        let mut block_data = vec![];
        test_debug!("Make block {}", blk);
        for val in 0..num_inserts_per_block {
            let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
            data.copy_from_slice(&path_bytes[0..32]);

            let path = to_hex(&path_bytes);

            let value_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
            data.copy_from_slice(&value_bytes[0..32]);

            let mut value_bytes_slice = [0u8; 40];
            value_bytes_slice[0..32].copy_from_slice(&value_bytes);

            let value = MARFValue(value_bytes_slice);
            block_data.push((path, value));
        }
        ret.push(block_data);
    }
    ret
}

fn test_marf_with_cache(
    test_name: &str,
    cache_strategy: &str,
    hash_strategy: TrieHashCalculationMode,
    data: &[Vec<(String, MARFValue)>],
    batch_size: Option<usize>,
) -> TrieHash {
    inner_test_marf_with_cache(
        test_name,
        cache_strategy,
        hash_strategy,
        data,
        batch_size,
        false,
    )
}

fn test_marf_with_cache_compressed(
    test_name: &str,
    cache_strategy: &str,
    hash_strategy: TrieHashCalculationMode,
    data: &[Vec<(String, MARFValue)>],
    batch_size: Option<usize>,
) -> TrieHash {
    inner_test_marf_with_cache(
        &format!("{}.compressed", test_name),
        cache_strategy,
        hash_strategy,
        data,
        batch_size,
        true,
    )
}

fn inner_test_marf_with_cache(
    test_name: &str,
    cache_strategy: &str,
    hash_strategy: TrieHashCalculationMode,
    data: &[Vec<(String, MARFValue)>],
    batch_size: Option<usize>,
    compress: bool,
) -> TrieHash {
    let test_file = if test_name == ":memory:" {
        test_name.to_string()
    } else {
        let test_dir = format!("/tmp/stacks-marf-tests/{}", test_name);
        if fs::metadata(&test_dir).is_ok() {
            fs::remove_dir_all(&test_dir).unwrap();
        }
        fs::create_dir_all(&test_dir).unwrap();

        let test_file = format!(
            "{}/marf-cache-{}-{:?}.sqlite",
            &test_dir, cache_strategy, hash_strategy
        );
        test_file
    };

    let mut marf_opts = MARFOpenOpts::new(hash_strategy, cache_strategy, true);
    marf_opts.compress = compress;

    let f = TrieFileStorage::open(&test_file, marf_opts).unwrap();
    let mut marf = MARF::from_storage(f);
    let mut last_block_header = BlockHeaderHash::sentinel();
    let batch_size = batch_size.unwrap_or(0);

    for (i, block_data) in data.iter().enumerate() {
        info!("Write block {}", i);
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

        let block_header = BlockHeaderHash(block_hash_bytes);
        marf.begin(&last_block_header, &block_header).unwrap();

        if batch_size > 0 {
            for b in (0..block_data.len()).step_by(batch_size) {
                let batch = &block_data[b..cmp::min(block_data.len(), b + batch_size)];
                let keys: Vec<_> = batch.iter().map(|(k, _)| k.clone()).collect();
                let values = batch.iter().map(|(_, v)| v.clone()).collect();
                marf.insert_batch(&keys, values).unwrap();
            }
        } else {
            for (key, value) in block_data.iter() {
                let path = TrieHash::from_key(key);
                let leaf = TrieLeaf::from_value(&[], value.clone());
                marf.insert_raw(path, leaf).unwrap();
            }
        }

        marf.commit().unwrap();
        last_block_header = block_header.clone();

        let proof_block_data = data.get(i / 2).unwrap();
        info!("Prove block {}", i / 2);
        for (key, value) in proof_block_data.iter() {
            let path = TrieHash::from_key(key);
            info!("Prove {} = {}", &key, &to_hex(value.as_bytes()));
            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &block_header,
                TrieHash::from_key(key).as_bytes(),
                value.as_bytes(),
                None,
            );
        }
    }

    let write_bench = marf.borrow_storage_backend().get_benchmarks();
    marf.borrow_storage_backend().reset_benchmarks();
    eprintln!("MARF bench writes: {:#?}", &write_bench);

    debug!("---------");
    debug!("MARF gets");
    debug!("---------");

    let mut total_read_time = 0;
    let mut root_hash = TrieHash([0u8; 32]);
    for (i, block_data) in data.iter().enumerate() {
        test_debug!("Read block {}", i);
        for (key, value) in block_data.iter() {
            let path = TrieHash::from_key(key);
            let marf_leaf = TrieLeaf::from_value(&[], value.clone());

            let read_time = SystemTime::now();
            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            let read_time = read_time.elapsed().unwrap().as_nanos();
            total_read_time += read_time;

            assert_eq!(leaf.data.to_vec(), marf_leaf.data.to_vec());
        }
    }

    let read_bench = marf.borrow_storage_backend().get_benchmarks();
    eprintln!(
        "MARF bench reads ({} total): {:#?}",
        total_read_time, &read_bench
    );

    let mut bench = write_bench;
    bench.add(&read_bench);

    eprintln!("MARF bench total: {:#?}", &bench);

    root_hash = marf.get_root_hash_at(&last_block_header).unwrap();
    eprintln!("root hash at {:?}: {:?}", &last_block_header, &root_hash);
    root_hash
}

#[test]
fn test_marf_node_compressed_1_insert() {
    let test_data = make_test_insert_data(1, 256);
    let compressed_root_hash = test_marf_with_cache_compressed(
        "test_marf_node_compressed_1_insert",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );
    eprintln!("Final root hash is {}", compressed_root_hash);

    let root_hash = test_marf_with_cache(
        "test_marf_node_compressed_1_insert",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );
    eprintln!("Final root hash is {}", root_hash);

    assert_eq!(root_hash, compressed_root_hash);
}

#[test]
fn test_marf_node_compressed_1_trie() {
    let test_data = make_test_insert_data(2048, 1);
    let root_hash = test_marf_with_cache(
        "test_marf_node_compressed_1_trie",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );
    eprintln!("Final root hash is {}", root_hash);

    let compressed_root_hash = test_marf_with_cache_compressed(
        "test_marf_node_compressed_1_trie",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );

    eprintln!("Final compressed root hash is {}", compressed_root_hash);

    assert_eq!(root_hash, compressed_root_hash);
}

#[test]
fn test_marf_node_compressed_8_inserts() {
    let test_data = make_test_insert_data(8, 256);
    let root_hash = test_marf_with_cache(
        "test_marf_node_compressed_1_insert",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );
    eprintln!("Final root hash is {}", root_hash);

    let compressed_root_hash = test_marf_with_cache_compressed(
        "test_marf_node_compressed_1_insert",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );
    eprintln!("Final root hash is {}", compressed_root_hash);

    assert_eq!(root_hash, compressed_root_hash);
}

#[test]
fn test_marf_node_compressed_8_inserts_different_batches() {
    let test_data = make_test_insert_data(8, 256);
    let root_hash = test_marf_with_cache(
        "test_marf_node_compressed_1_insert",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );
    eprintln!("Final root hash is {}", root_hash);

    let compressed_root_hash = test_marf_with_cache_compressed(
        "test_marf_node_compressed_1_insert",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(5),
    );
    eprintln!("Final root hash is {}", compressed_root_hash);

    assert_eq!(root_hash, compressed_root_hash);
}

/// Test that expanding a path into a leaf, node4, node16, node48, and then node256 repeatedly
/// will produce patch nodes which can be read
#[test]
fn test_marf_patch_expansion() {
    let hash_strategy = TrieHashCalculationMode::Deferred;
    let cache_strategy = "noop";
    let test_name = "test_marf_patch_expansion";

    let data: Vec<_> = (0u8..=255u8)
        .map(|i| {
            let mut path = [0u8; 32];
            path[31] = i;
            vec![(TrieHash(path), MARFValue::from(u32::from(i)))]
        })
        .collect();

    let test_dir = format!("/tmp/stacks-marf-tests/{}", test_name);
    if fs::metadata(&test_dir).is_ok() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let test_file = format!(
        "{}/marf-cache-{}-{:?}.sqlite",
        &test_dir, cache_strategy, hash_strategy
    );

    let marf_opts = MARFOpenOpts::new(hash_strategy, cache_strategy, true);
    let f = TrieFileStorage::open(&test_file, marf_opts).unwrap();
    let mut marf = MARF::from_storage(f);
    let mut last_block_header = BlockHeaderHash::sentinel();

    for (i, block_data) in data.iter().enumerate() {
        test_debug!("Write block {}", i);
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

        let block_header = BlockHeaderHash(block_hash_bytes);
        marf.begin(&last_block_header, &block_header).unwrap();

        for (path, value) in block_data.iter() {
            let leaf = TrieLeaf::from_value(&[], value.clone());
            marf.insert_raw(path.clone(), leaf).unwrap();
        }

        marf.commit().unwrap();
        last_block_header = block_header;
    }

    let write_bench = marf.borrow_storage_backend().get_benchmarks();
    marf.borrow_storage_backend().reset_benchmarks();
    eprintln!("MARF bench writes: {:#?}", &write_bench);

    debug!("---------");
    debug!("MARF gets");
    debug!("---------");

    let mut total_read_time = 0;
    let mut root_hash = TrieHash([0u8; 32]);
    for (i, block_data) in data.iter().enumerate() {
        test_debug!("Read block {}", i);
        for (path, value) in block_data.iter() {
            let marf_leaf = TrieLeaf::from_value(&[], value.clone());

            let read_time = SystemTime::now();
            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            let read_time = read_time.elapsed().unwrap().as_nanos();
            total_read_time += read_time;

            assert_eq!(leaf.data.to_vec(), marf_leaf.data.to_vec());
        }
    }

    let read_bench = marf.borrow_storage_backend().get_benchmarks();
    eprintln!(
        "MARF bench reads ({} total): {:#?}",
        total_read_time, &read_bench
    );

    let mut bench = write_bench;
    bench.add(&read_bench);

    eprintln!("MARF bench total: {:#?}", &bench);

    root_hash = marf.get_root_hash_at(&last_block_header).unwrap();
    eprintln!("root hash at {:?}: {:?}", &last_block_header, &root_hash);
}

#[test]
fn test_marf_node_compressed() {
    let test_data = make_test_insert_data(8, 256);
    let root_hash = test_marf_with_cache(
        "test_marf_node_compressed",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(8),
    );
    eprintln!("Final root hash is {}", root_hash);
}

#[test]
fn test_marf_node_cache_noop() {
    let test_data = make_test_insert_data(128, 128);
    let root_hash = test_marf_with_cache(
        "test_marf_node_cache_noop",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        None,
    );
    eprintln!("Final root hash is {}", root_hash);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(64),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(128),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(67),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(13),
    );
    assert_eq!(root_hash, root_hash_batched);
}

#[test]
fn test_marf_node_cache_noop_deferred() {
    let test_data = make_test_insert_data(128, 128);
    let root_hash = test_marf_with_cache(
        "test_marf_node_cache_noop_deferred",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        None,
    );
    eprintln!("Final root hash is {}", root_hash);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop_deferred",
        "noop",
        TrieHashCalculationMode::Deferred,
        &test_data,
        None,
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop_deferred",
        "noop",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(64),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop_deferred",
        "noop",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(128),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop_deferred",
        "noop",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(67),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_noop_deferred",
        "noop",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(13),
    );
    assert_eq!(root_hash, root_hash_batched);
}

#[test]
fn test_marf_node_cache_everything() {
    let test_data = make_test_insert_data(128, 128);
    let root_hash = test_marf_with_cache(
        "test_marf_node_cache_everything",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        None,
    );
    eprintln!("Final root hash is {}", root_hash);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything",
        "everything",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(64),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything",
        "everything",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(128),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything",
        "everything",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(67),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything",
        "everything",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(13),
    );
    assert_eq!(root_hash, root_hash_batched);
}

#[test]
fn test_marf_node_cache_everything_deferred() {
    let test_data = make_test_insert_data(128, 128);
    let root_hash = test_marf_with_cache(
        "test_marf_node_cache_everything_deferred",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        None,
    );
    eprintln!("Final root hash is {}", root_hash);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything_deferred",
        "everything",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(64),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything_deferred",
        "everything",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(128),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything_deferred",
        "everything",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(67),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_everything_deferred",
        "everything",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(13),
    );
    assert_eq!(root_hash, root_hash_batched);
}

#[test]
fn test_marf_node_cache_node256() {
    let test_data = make_test_insert_data(128, 128);
    let root_hash = test_marf_with_cache(
        "test_marf_node_cache_node256",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        None,
    );
    eprintln!("Final root hash is {}", root_hash);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256",
        "node256",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(64),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256",
        "node256",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(128),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256",
        "node256",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(67),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256",
        "node256",
        TrieHashCalculationMode::Immediate,
        &test_data,
        Some(13),
    );
    assert_eq!(root_hash, root_hash_batched);
}

#[test]
fn test_marf_node_cache_node256_deferred() {
    let test_data = make_test_insert_data(128, 128);
    let root_hash = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        None,
    );
    eprintln!("Final root hash is {}", root_hash);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(64),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(128),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(67),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(13),
    );
    assert_eq!(root_hash, root_hash_batched);
}

#[test]
fn test_marf_node_cache_node256_deferred_15500() {
    let test_data = make_test_insert_data(15500, 10);
    let root_hash = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred_15500",
        "noop",
        TrieHashCalculationMode::Immediate,
        &test_data,
        None,
    );
    eprintln!("Final root hash is {}", root_hash);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred_15500",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(64),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred_15500",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(128),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred_15500",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(67),
    );
    assert_eq!(root_hash, root_hash_batched);

    let root_hash_batched = test_marf_with_cache(
        "test_marf_node_cache_node256_deferred_15500",
        "node256",
        TrieHashCalculationMode::Deferred,
        &test_data,
        Some(13),
    );
    assert_eq!(root_hash, root_hash_batched);
}
