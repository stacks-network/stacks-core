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

//! MARF performance tests intended to be run manually for analysis.

use std::fs;

use clarity::types::chainstate::{BlockHeaderHash, TrieHash};
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::to_hex;

use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use crate::chainstate::stacks::index::storage::TrieFileStorage;
use crate::chainstate::stacks::index::test::{merkle_test_marf, opts};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue, TrieLeaf};

// insert a random sequence of 1024 * 1024 keys.  Every 4096 inserts, fork.
// Use file storage, and use batching.
// Used mainly for performance analysis.
#[test]
#[ignore]
fn marf_insert_random_1048576_4096_file_storage() {
    let path = "/tmp/rust_marf_insert_random_1048576_4096_file_storage".to_string();
    if fs::metadata(&path).is_ok() {
        fs::remove_dir_all(&path).unwrap();
    };
    let marf_opts = MARFOpenOpts::default();
    let f = TrieFileStorage::open(&path, marf_opts).unwrap();
    let mut m = MARF::from_storage(f);

    let mut block_header = BlockHeaderHash::sentinel();

    let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
    let mut start_time = get_epoch_time_ms();
    let mut end_time = 0;
    let mut block_start_time = start_time;
    let mut prev_block_header = block_header.clone();

    let mut i: u64 = 1;
    let num_iterations = 1024 * 1024;
    let block_size = 4096;

    while i <= num_iterations {
        let mut keys = vec![];
        let mut values = vec![];

        let i0 = (i & 0xff000000) >> 24;
        let i1 = (i & 0x00ff0000) >> 16;
        let i2 = (i & 0x0000ff00) >> 8;
        let i3 = i & 0x000000ff;

        prev_block_header = block_header.clone();
        block_header = BlockHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            i0 as u8, i1 as u8, i2 as u8, i3 as u8,
        ])
        .unwrap();

        for _ in 0..block_size {
            let i0 = (i & 0xff000000) >> 24;
            let i1 = (i & 0x00ff0000) >> 16;
            let i2 = (i & 0x0000ff00) >> 8;
            let i3 = i & 0x000000ff;

            let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
            seed = path.clone();

            let key = to_hex(&path);
            let value = to_hex(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8, i3 as u8,
            ]);

            keys.push(key);
            values.push(value);
            i += 1;
        }

        block_start_time = get_epoch_time_ms();
        m.begin(&prev_block_header, &block_header).unwrap();

        start_time = get_epoch_time_ms();

        let values = values
            .into_iter()
            .map(|x| MARFValue::from_value(&x))
            .collect();

        m.insert_batch(&keys, values).unwrap();
        end_time = get_epoch_time_ms();

        let flush_start_time = get_epoch_time_ms();
        m.commit().unwrap();
        let flush_end_time = get_epoch_time_ms();

        eprintln!(
            "Inserted {} in {} (1 insert = {} ms).  Processed {} keys in {} ms (flush = {} ms)",
            i,
            end_time - start_time,
            ((end_time - start_time) as f64) / (block_size as f64),
            block_size,
            flush_end_time - block_start_time,
            flush_end_time - flush_start_time
        );
    }

    i = 1;
    seed = TrieHash::from_data(&[]).as_bytes().to_vec();

    while i <= num_iterations {
        let mut keys = vec![];
        let mut values = vec![];

        for _ in 0..block_size {
            let i0 = (i & 0xff000000) >> 24;
            let i1 = (i & 0x00ff0000) >> 16;
            let i2 = (i & 0x0000ff00) >> 8;
            let i3 = i & 0x000000ff;

            let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
            seed = path.clone();

            let key = to_hex(&path);
            let value = to_hex(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8, i3 as u8,
            ]);

            keys.push(key);
            values.push(value);
            i += 1;
        }

        start_time = get_epoch_time_ms();

        for j in 0..block_size {
            let read_value = m.get(&block_header, &keys[j]).unwrap().unwrap();
            assert_eq!(read_value, MARFValue::from_value(&values[j]));
        }

        end_time = get_epoch_time_ms();

        eprintln!(
            "Got {} in {} (1 get = {} ms)",
            i,
            end_time - start_time,
            ((end_time - start_time) as f64) / (block_size as f64)
        );
    }
}

// Test reads specifically on existing test data.
#[test]
#[ignore]
fn marf_read_random_1048576_4096_file_storage() {
    let do_merkle_check = std::env::var("TEST_MARF_PERFS_MERKLE_PROOFS") == Ok("1".to_string());

    for marf_opts in opts::OPTS_ALL_NOOP.clone().into_iter() {
        test_debug!("With {:?}", &marf_opts);
        let path = "/tmp/rust_marf_insert_random_1048576_4096_file_storage".to_string();
        if fs::metadata(&path).is_err() {
            eprintln!("Run the marf_insert_random_1048576_4096_file_storage test first");
            return;
        };
        let marf_opts = MARFOpenOpts::default();
        let mut f_store = TrieFileStorage::new_memory(marf_opts).unwrap();
        let mut f = f_store.connection();

        let block_header = BlockHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0xf0, 0xff, 0xff,
        ])
        .unwrap();
        f.open_block(&block_header).unwrap();

        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut start_time = 0;

        start_time = get_epoch_time_ms();
        for i in 0..1048576 {
            // can read them all back
            let i0 = (i & 0xff0000) >> 12;
            let i1 = (i & 0x00ff00) >> 8;
            let i2 = i & 0x0000ff;

            let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
            seed = path.clone();

            let triepath = TrieHash::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &[],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8,
                ],
            );

            let read_value = MARF::get_path(
                &mut f,
                &block_header,
                &TrieHash::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());

            // can make a merkle proof to each one
            if do_merkle_check {
                merkle_test_marf(&mut f, &block_header, &path, &value.data.to_vec(), None);
            }
            if i % 128 == 0 {
                let end_time = get_epoch_time_ms();
                let (read_count, write_count) = f.stats();
                let (node_reads, backptr_reads, node_writes) = f.node_stats();
                let (leaf_reads, leaf_writes) = f.leaf_stats();
                debug!("Got {} in {} (1 get = {} ms).  Read = {}, Write = {}, Node Reads = {}, Node Writes = {}, Backptr Reads = {}, Leaf Reads = {}, Leaf Writes = {}",
                         i, end_time - start_time, ((end_time - start_time) as f64) / 128.0, read_count, write_count, node_reads, node_writes, backptr_reads, leaf_reads, leaf_writes);

                start_time = get_epoch_time_ms();
            }
        }
    }
}
