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

#![allow(unused_variables)]
#![allow(unused_assignments)]

use std::collections::HashMap;
use std::fs;

use clarity::types::chainstate::{BlockHeaderHash, TrieHash};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::to_hex;
use tempfile::tempdir;

use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY,
    BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF, OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{TrieNodeID, TrieNodeType, TriePtr};
use crate::chainstate::stacks::index::storage::{
    TrieFileStorage, TrieHashCalculationMode, TrieStorageConnection,
};
use crate::chainstate::stacks::index::test::{
    make_node4_path, make_node_path, merkle_test_marf, merkle_test_marf_key_value,
};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, Error, MARFValue, TrieLeaf};

#[test]
fn marf_insert_different_leaf_same_block_100() {
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        test_debug!("With {:?}", &marf_opts);
        let f = TrieFileStorage::new_memory(marf_opts).unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let path_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let path = TrieHash::from_bytes(&path_bytes).unwrap();

        for i in 0..100 {
            let value = TrieLeaf::new(&[], &[i as u8; 40]);
            marf.insert_raw(path, value).unwrap();
        }

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        let value = TrieLeaf::new(&[], &[99; 40]);
        let leaf = MARF::get_path(&mut marf.borrow_storage_backend(), &block_header, &path)
            .unwrap()
            .unwrap();

        assert_eq!(leaf.data.to_vec(), [99; 40].to_vec());
        assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

        if marf.borrow_storage_backend().hash_calculation_mode == TrieHashCalculationMode::Deferred
        {
            // materialize all hashes
            marf.commit().unwrap();
        }
        merkle_test_marf(
            &mut marf.borrow_storage_backend(),
            &block_header,
            &path_bytes,
            &[99; 40],
            None,
        );

        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = marf
                .borrow_storage_backend()
                .read_root_to_block_table()
                .unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

#[test]
fn marf_insert_different_leaf_different_path_different_block_100() {
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        test_debug!("With {:?}", &marf_opts);
        let f = TrieFileStorage::new_memory(marf_opts).unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        for i in 0..100 {
            debug!("insert {}", i);
            let block_header = BlockHeaderHash::from_bytes(&[i + 1; 32]).unwrap();
            let path_bytes = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, i,
            ];
            marf.commit().unwrap();
            marf.begin(&BlockHeaderHash::sentinel(), &block_header)
                .unwrap();
            let path = TrieHash::from_bytes(&path_bytes).unwrap();
            let value = TrieLeaf::new(&[], &[i; 40]);
            marf.insert_raw(path, value).unwrap();
        }

        let mut committed = false;
        if marf.borrow_storage_backend().hash_calculation_mode == TrieHashCalculationMode::Deferred
        {
            // materialize all hashes
            marf.commit().unwrap();
            committed = true;
        }

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        for i in 0..100 {
            let block_header = BlockHeaderHash::from_bytes(&[i + 1; 32]).unwrap();
            let path_bytes = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, i,
            ];
            let path = TrieHash::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&[], &[i; 40]);
            let leaf = MARF::get_path(&mut marf.borrow_storage_backend(), &block_header, &path)
                .unwrap()
                .unwrap();

            assert_eq!(leaf.data.to_vec(), [i; 40].to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &block_header,
                &path_bytes,
                &[i; 40],
                None,
            );
        }

        if !committed {
            marf.commit().unwrap();
        }

        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = marf
                .borrow_storage_backend()
                .read_root_to_block_table()
                .unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

#[test]
fn marf_insert_same_leaf_different_block_100() {
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        test_debug!("With {:?}", &marf_opts);
        let f = TrieFileStorage::new_memory(marf_opts).unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let path_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let path = TrieHash::from_bytes(&path_bytes).unwrap();

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1; 32]).unwrap();
            let value = TrieLeaf::new(&[], &[i; 40]);
            marf.commit().unwrap();
            marf.begin(&BlockHeaderHash::sentinel(), &next_block_header)
                .unwrap();
            let path = TrieHash::from_bytes(&path_bytes).unwrap();
            let value = TrieLeaf::new(&[], &[i; 40]);
            marf.insert_raw(path, value).unwrap();
        }

        let mut committed = false;
        if marf.borrow_storage_backend().hash_calculation_mode == TrieHashCalculationMode::Deferred
        {
            // materialize all hashes
            marf.commit().unwrap();
            committed = true;
        }

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1; 32]).unwrap();
            let value = TrieLeaf::new(&[], &[i; 40]);
            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            assert_eq!(leaf.data.to_vec(), [i; 40].to_vec());
            assert_eq!(
                marf.borrow_storage_backend().get_cur_block(),
                next_block_header
            );

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &path_bytes,
                &[i; 40],
                None,
            );
        }

        if !committed {
            marf.commit().unwrap();
        }

        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = marf
                .borrow_storage_backend()
                .read_root_to_block_table()
                .unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

#[test]
fn marf_insert_leaf_sequence_2() {
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        test_debug!("With {:?}", &marf_opts);
        let f = TrieFileStorage::new_memory(marf_opts).unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        for i in 0..2 {
            let path_bytes = [
                i, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TrieHash::from_bytes(&path_bytes).unwrap();
            let prior_block_header = BlockHeaderHash::from_bytes(&[i; 32]).unwrap();
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1; 32]).unwrap();
            marf.commit().unwrap();
            marf.begin(&prior_block_header, &next_block_header).unwrap();

            let value = TrieLeaf::new(&[], &[i; 40]);
            marf.insert_raw(path, value).unwrap();
        }

        marf.commit().unwrap();
        let last_block_header = BlockHeaderHash::from_bytes(&[2; 32]).unwrap();

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        for i in 0..2 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1; 32]).unwrap();
            let path_bytes = [
                i, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TrieHash::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&[], &[i; 40]);
            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            assert_eq!(leaf.data.to_vec(), [i; 40].to_vec());
            assert_eq!(
                marf.borrow_storage_backend().get_cur_block(),
                next_block_header
            );

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path_bytes,
                &[i; 40],
                None,
            );
        }
        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = marf
                .borrow_storage_backend()
                .read_root_to_block_table()
                .unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

#[test]
fn marf_insert_leaf_sequence_100() {
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        test_debug!("With {:?}", &marf_opts);
        let f = TrieFileStorage::new_memory(marf_opts).unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let mut last_block_header = block_header.clone();

        for i in 1..101 {
            let path_bytes = [
                i, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TrieHash::from_bytes(&path_bytes).unwrap();

            marf.commit().unwrap();
            let next_block_header = BlockHeaderHash::from_bytes(&[i; 32]).unwrap();
            marf.begin(&last_block_header, &next_block_header).unwrap();
            last_block_header = next_block_header;

            let value = TrieLeaf::new(&[], &[i; 40]);
            marf.insert_raw(path, value).unwrap();
        }
        marf.commit().unwrap();

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        let mut f = marf.borrow_storage_backend();

        for i in 1..101 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i; 32]).unwrap();
            let path_bytes = [
                i, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TrieHash::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&[], &[i; 40]);
            eprintln!("Finding value inserted at {}", &next_block_header);
            let leaf = MARF::get_path(&mut f, &last_block_header, &path)
                .unwrap()
                .unwrap();

            assert_eq!(leaf.data.to_vec(), [i; 40].to_vec());

            merkle_test_marf(&mut f, &last_block_header, &path_bytes, &[i; 40], None);
        }
        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = f.read_root_to_block_table().unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

#[test]
#[ignore]
fn marf_walk_cow_node4_20() {
    marf_walk_cow_test(
        |s| {
            // make a deep path
            let path_segments = vec![
                (vec![], 0),
                (vec![], 1),
                (vec![], 2),
                (vec![], 3),
                (vec![], 4),
                (vec![], 5),
                (vec![], 6),
                (vec![], 7),
                (vec![], 8),
                (vec![], 9),
                (vec![], 10),
                (vec![], 11),
                (vec![], 12),
                (vec![], 13),
                (vec![], 14),
                (vec![], 15),
                (vec![], 16),
                (vec![], 17),
                (vec![], 18),
                (vec![], 19),
                (vec![], 20),
                (vec![], 21),
                (vec![], 22),
                (vec![], 23),
                (vec![], 24),
                (vec![], 25),
                (vec![], 26),
                (vec![], 27),
                (vec![], 28),
                (vec![], 29),
                (vec![], 30),
                (vec![], 31),
            ];
            make_node4_path(s, &path_segments, [31u8; 40].to_vec())
        },
        |i, mut p| {
            p[i as usize] = 32;
            p
        },
    );
}

#[test]
#[ignore]
fn marf_walk_cow_node4_20_reversed() {
    marf_walk_cow_test(
        |s| {
            // make a deep path
            let path_segments = vec![
                (vec![], 0),
                (vec![], 1),
                (vec![], 2),
                (vec![], 3),
                (vec![], 4),
                (vec![], 5),
                (vec![], 6),
                (vec![], 7),
                (vec![], 8),
                (vec![], 9),
                (vec![], 10),
                (vec![], 11),
                (vec![], 12),
                (vec![], 13),
                (vec![], 14),
                (vec![], 15),
                (vec![], 16),
                (vec![], 17),
                (vec![], 18),
                (vec![], 19),
                (vec![], 20),
                (vec![], 21),
                (vec![], 22),
                (vec![], 23),
                (vec![], 24),
                (vec![], 25),
                (vec![], 26),
                (vec![], 27),
                (vec![], 28),
                (vec![], 29),
                (vec![], 30),
                (vec![], 31),
            ];
            make_node4_path(s, &path_segments, [31u8; 40].to_vec())
        },
        |i, mut p| {
            p[31 - i as usize] = 32;
            p
        },
    );
}

fn marf_walk_cow_4_test<F>(filename: &str, path_gen: F)
where
    F: Fn(u32, [u8; 32]) -> [u8; 32],
{
    for node_id in [
        TrieNodeID::Node4,
        TrieNodeID::Node16,
        TrieNodeID::Node48,
        TrieNodeID::Node256,
    ]
    .iter()
    {
        let path_segments = vec![
            (vec![], 4),
            (vec![0, 1, 2, 3, 5, 6, 7, 8], 9),
            (vec![10, 11, 12, 13], 14),
            (vec![15, 16, 17, 18], 19),
            (vec![20, 21, 22, 23], 24),
            (vec![25, 26, 27, 28], 29),
            (vec![30], 31),
        ];

        marf_walk_cow_test(
            |s| make_node_path(s, node_id.to_u8(), &path_segments, [31u8; 40].to_vec()),
            &path_gen,
        );
    }
}

fn marf_walk_cow_test<F, G>(path_init: G, path_gen: F)
where
    F: Fn(u32, [u8; 32]) -> [u8; 32],
    G: Fn(
        &mut TrieStorageConnection<BlockHeaderHash>,
    ) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>),
{
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        let mut f_store = TrieFileStorage::new_memory(marf_opts).unwrap();
        let path = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let mut last_block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();

        let (nodes, node_ptrs, hashes) = {
            let mut f = f_store.transaction().unwrap();
            MARF::format(&mut f, &last_block_header).unwrap();
            f.test_genesis_block.replace(last_block_header.clone());

            let r = path_init(&mut f);
            f.commit_tx();
            r
        };

        let mut marf = MARF::from_storage(f_store);

        for i in 1..31 {
            debug!("----------------");
            debug!("i = {}", i);
            debug!("----------------");

            // switch to the next block
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.commit().unwrap();
            marf.begin(&last_block_header, &next_block_header).unwrap();
            last_block_header = next_block_header.clone();
            // add a leaf at the end of the path

            let next_path = path_gen(i, path);

            let triepath = TrieHash::from_bytes(&next_path[..]).unwrap();
            let value = TrieLeaf::new(&[], &[i as u8; 40]);

            debug!("----------------");
            debug!("insert");
            debug!("----------------");
            marf.insert_raw(triepath, value.clone()).unwrap();

            // verify that this leaf exists in _this_ Trie
            debug!("----------------");
            debug!("get");
            debug!("----------------");
            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &TrieHash::from_bytes(&next_path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(
                marf.borrow_storage_backend().get_cur_block(),
                next_block_header
            );

            // can get all previous leaves from _this_ Trie
            for j in 1..(i + 1) {
                debug!("----------------");
                debug!("get-prev {} of {}", j, i);
                debug!("----------------");

                let prev_path = path_gen(j, path);

                let read_value = MARF::get_path(
                    &mut marf.borrow_storage_backend(),
                    &next_block_header,
                    &TrieHash::from_bytes(&prev_path[..]).unwrap(),
                )
                .unwrap()
                .unwrap();
                assert_eq!(read_value.data.to_vec(), [j as u8; 40].to_vec());

                // can only do this test if not in deferred mode, since the trie hashes won't
                // have been calculated until commit
                if marf.borrow_storage_backend().hash_calculation_mode
                    != TrieHashCalculationMode::Deferred
                {
                    debug!("---------------------------------------");
                    debug!(
                        "MARF verify {:?} {:?} from current block header (immediate) {:?}",
                        &prev_path, &[j as u8; 40], &next_block_header
                    );
                    debug!("----------------------------------------");
                    merkle_test_marf(
                        &mut marf.borrow_storage_backend(),
                        &next_block_header,
                        &prev_path,
                        &[j as u8; 40],
                        None,
                    );
                }
            }

            // now commit the marf, and test previous headers if we haven't already
            marf.commit().unwrap();
            if marf.borrow_storage_backend().hash_calculation_mode
                == TrieHashCalculationMode::Deferred
            {
                for j in 1..(i + 1) {
                    let prev_path = path_gen(j, path);
                    debug!("---------------------------------------");
                    debug!(
                        "MARF verify {:?} {:?} from current block header (deferred) {:?}",
                        &prev_path, &[j as u8; 40], &next_block_header
                    );
                    debug!("----------------------------------------");
                    merkle_test_marf(
                        &mut marf.borrow_storage_backend(),
                        &next_block_header,
                        &prev_path,
                        &[j as u8; 40],
                        None,
                    );
                }
            }

            marf.borrow_storage_backend()
                .open_block(&next_block_header)
                .unwrap();

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &next_path,
                &[i as u8; 40],
                None,
            );
        }

        // all leaves are reachable from the last block
        for i in 1..31 {
            // add a leaf at the end of the path
            let next_path = path_gen(i, path);

            let triepath = TrieHash::from_bytes(&next_path[..]).unwrap();
            let value = MARFValue([i as u8; 40]);

            assert_eq!(
                MARF::get_path(
                    &mut marf.borrow_storage_backend(),
                    &last_block_header,
                    &triepath
                )
                .unwrap()
                .unwrap()
                .data,
                value
            );

            debug!("---------------------------------------");
            debug!(
                "MARF verify {:?} {:?} from last block header {:?}",
                &next_path, &[i as u8; 40], &last_block_header
            );
            debug!("----------------------------------------");
            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &next_path,
                &[i as u8; 40],
                None,
            );
        }

        // root hashes are all the same
        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = marf
                .borrow_storage_backend()
                .read_root_to_block_table()
                .unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

#[test]
#[ignore]
fn marf_walk_cow_4() {
    marf_walk_cow_4_test("/tmp/rust_marf_walk_cow_node4_20", |i, mut p| {
        p[i as usize] = 32;
        p
    })
}

#[test]
#[ignore]
fn marf_walk_cow_4_reversed() {
    marf_walk_cow_4_test("/tmp/rust_marf_walk_cow_node4_20_reversed", |i, mut p| {
        p[31 - i as usize] = 32;
        p
    })
}

#[test]
fn marf_invalid_ancestor() {
    let marf_opts_1 = MARFOpenOpts::default();
    let marf_opts_2 = MARFOpenOpts::default();
    let f1 = TrieFileStorage::new_memory(marf_opts_1).unwrap();
    let f2 = TrieFileStorage::new_memory(marf_opts_2).unwrap();
    let mut m1 = MARF::from_storage(f1);
    let mut m2 = MARF::from_storage(f2);

    let mock_miner_hash = BlockHeaderHash([1; 32]);

    m1.begin(&BlockHeaderHash::sentinel(), &mock_miner_hash)
        .unwrap();
    m1.commit_to(&BlockHeaderHash([2; 32])).unwrap();
    m1.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
        .unwrap();
    m1.commit_to(&BlockHeaderHash([3; 32])).unwrap();
    m1.begin(&BlockHeaderHash([3; 32]), &mock_miner_hash)
        .unwrap();
    m1.drop_current();

    // m1 should be dirty...

    m2.begin(&BlockHeaderHash::sentinel(), &mock_miner_hash)
        .unwrap();
    m2.commit_to(&BlockHeaderHash([2; 32])).unwrap();
    m2.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
        .unwrap();
    m2.commit_to(&BlockHeaderHash([3; 32])).unwrap();
    m2.begin(&BlockHeaderHash([3; 32]), &mock_miner_hash)
        .unwrap();
    m2.commit_to(&BlockHeaderHash([4; 32])).unwrap();

    // m2 is clean...

    // now let's make a block whose parent is _2_ (not _3_)

    m1.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
        .unwrap();
    m2.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
        .unwrap();

    let hash_1 = m1.seal().unwrap();
    let hash_2 = m2.seal().unwrap();

    eprintln!("{} == {}", hash_1, hash_2);

    assert_eq!(hash_1, hash_2);
}

#[test]
fn marf_merkle_verify_backptrs() {
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        for node_id in [
            TrieNodeID::Node4,
            TrieNodeID::Node16,
            TrieNodeID::Node48,
            TrieNodeID::Node256,
        ]
        .iter()
        {
            let mut f_store = TrieFileStorage::new_memory(marf_opts.clone()).unwrap();

            let path_segments = vec![
                (vec![], 12),
                (
                    vec![
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                        24,
                    ],
                    25,
                ),
                (vec![26, 27, 28, 29, 30], 31),
            ];

            let path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];

            let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();

            let (nodes, node_ptrs, hashes) = {
                let mut f = f_store.transaction().unwrap();
                MARF::format(&mut f, &block_header_1).unwrap();
                f.test_genesis_block.replace(block_header_1.clone());

                let r =
                    make_node_path(&mut f, node_id.to_u8(), &path_segments, [31u8; 40].to_vec());
                f.commit_tx();

                r
            };

            let mut marf = MARF::from_storage(f_store);

            let block_header_2 = BlockHeaderHash::from_bytes(&[1u8; 32]).unwrap();
            let path_2 = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 32,
            ];

            debug!("----------------");
            debug!("Extend to {:?}", block_header_2);
            debug!("----------------");

            marf.commit().unwrap();
            marf.begin(&block_header_1, &block_header_2).unwrap();
            marf.insert_raw(
                TrieHash::from_bytes(&path_2[..]).unwrap(),
                TrieLeaf::new(&[], &[20; 40]),
            )
            .unwrap();

            let block_header_3 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
            let path_3 = vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 33,
            ];

            debug!("----------------");
            debug!("Extend to {:?}", block_header_3);
            debug!("----------------");

            marf.commit().unwrap();
            marf.begin(&block_header_2, &block_header_3).unwrap();
            marf.insert_raw(
                TrieHash::from_bytes(&path_3[..]).unwrap(),
                TrieLeaf::new(&[], &[21; 40]),
            )
            .unwrap();

            debug!("----------------");
            debug!(
                "Merkle verify {:?} from {:?}",
                &to_hex(&[21; 40]),
                block_header_3
            );
            debug!("----------------");

            // materialize all hashes
            marf.commit().unwrap();
            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &block_header_3,
                &path_3,
                &[21; 40],
                None,
            );
            if let Some(root_hashes) = last_root_hashes.take() {
                let next_root_hashes = marf
                    .borrow_storage_backend()
                    .read_root_to_block_table()
                    .unwrap();
                assert_eq!(root_hashes, next_root_hashes);
                last_root_hashes = Some(next_root_hashes);
            }
        }
    }
}

fn marf_insert<F>(mut path_gen: F, count: u32, check_merkle_proof: bool)
where
    F: FnMut(u32) -> ([u8; 32], Option<BlockHeaderHash>),
{
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        test_debug!("With {:?}", &marf_opts);
        let f = TrieFileStorage::new_memory(marf_opts).unwrap();
        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let mut root_table_cache = None;

        let mut blocks = vec![block_header.clone()];

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;

            let (path, next_block_header) = path_gen(i);

            let triepath = TrieHash::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &[],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
                ],
            );

            if let Some(next_block_header) = next_block_header {
                marf.commit().unwrap();
                marf.begin(&block_header, &next_block_header).unwrap();
                block_header = next_block_header;
                blocks.push(block_header.clone())
            }

            marf.insert_raw(triepath, value.clone()).unwrap();

            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &block_header,
                &TrieHash::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

            if check_merkle_proof
                && marf.borrow_storage_backend().hash_calculation_mode
                    != TrieHashCalculationMode::Deferred
            {
                // can only test if the hashes are materialized, which is not the case for
                // deferred mode
                root_table_cache = Some(merkle_test_marf(
                    &mut marf.borrow_storage_backend(),
                    &block_header,
                    &path,
                    &value.data.to_vec(),
                    root_table_cache,
                ));
            }
        }
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(
                MARF::get_block_height(&mut marf.borrow_storage_backend(), block, &block_header)
                    .unwrap(),
                Some(i as u32)
            );
            assert_eq!(
                MARF::get_block_at_height(
                    &mut marf.borrow_storage_backend(),
                    i as u32,
                    &block_header
                )
                .unwrap(),
                Some(block.clone())
            );
        }

        root_table_cache = None;
        let mut committed = false;

        if marf.borrow_storage_backend().hash_calculation_mode == TrieHashCalculationMode::Deferred
        {
            // materialize the hashes
            marf.commit().unwrap();
            committed = true;
        }

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;
            let (path, _next_block_header) = path_gen(i);

            let triepath = TrieHash::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &[],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
                ],
            );

            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &block_header,
                &TrieHash::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());

            // can make a merkle proof to each one
            if check_merkle_proof {
                root_table_cache = Some(merkle_test_marf(
                    &mut marf.borrow_storage_backend(),
                    &block_header,
                    &path,
                    &value.data.to_vec(),
                    root_table_cache,
                ));
            }
        }

        if !committed {
            marf.commit().unwrap();
        }
        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = marf
                .borrow_storage_backend()
                .read_root_to_block_table()
                .unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

// insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
// every 128 keys, make a new trie
#[test]
#[ignore]
fn marf_insert_4096_128_seq_low() {
    marf_insert(
        |i| {
            let path = [
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
                26,
                27,
                28,
                29,
                (i / 256) as u8,
                (i % 256) as u8,
            ];
            let block_header = if (i + 1) % 128 == 0 {
                // next block
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        },
        4096,
        true,
    );
}

// insert a range of 4096 consecutive keys (forcing node promotions) by varying the high-order bits.
// every 128 keys, make a new trie
#[test]
#[ignore]
fn marf_insert_4096_128_seq_high() {
    marf_insert(
        |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [
                i0 as u8, i1 as u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let block_header = if (i + 1) % 128 == 0 {
                // next block
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        },
        4096,
        true,
    );
}

// insert a leaf, open a new block, and attempt to split the leaf
// TODO: try also when the leaf to split dangles from an intermediate node, not off of the root
// (since we have a different backptr copy routine there)
#[test]
fn marf_split_leaf_path() {
    let path = "/tmp/rust_marf_split_leaf_path";
    let marf_opts = MARFOpenOpts::default();
    let f = TrieFileStorage::new_memory(marf_opts).unwrap();

    let mut marf = MARF::from_storage(f);
    let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();

    marf.begin(&BlockHeaderHash::sentinel(), &block_header)
        .unwrap();

    let path = [0u8; 32];
    let triepath = TrieHash::from_bytes(&path[..]).unwrap();
    let value = TrieLeaf::new(&[], &[0u8; 40]);

    debug!("----------------");
    debug!(
        "insert ({:?}, {:?}) in {:?}",
        &triepath, &value, &block_header
    );
    debug!("----------------");

    marf.insert_raw(triepath, value.clone()).unwrap();

    // insert a leaf along the same path but in a different block
    let block_header_2 = BlockHeaderHash::from_bytes(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .unwrap();
    let path_2 = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1,
    ];
    let triepath_2 = TrieHash::from_bytes(&path_2[..]).unwrap();
    let value_2 = TrieLeaf::new(&[], &[1u8; 40]);

    debug!("----------------");
    debug!(
        "insert ({:?}, {:?}) in {:?}",
        &triepath_2, &value_2, &block_header_2
    );
    debug!("----------------");

    marf.commit().unwrap();
    marf.begin(&block_header, &block_header_2).unwrap();
    marf.insert_raw(triepath_2, value_2.clone()).unwrap();

    debug!("----------------");
    debug!(
        "get ({:?}, {:?}) in {:?}",
        &triepath, &value, &block_header_2
    );
    debug!("----------------");

    let read_value = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &block_header_2,
        &triepath,
    )
    .unwrap()
    .unwrap();
    assert_eq!(read_value.data.to_vec(), value.data.to_vec());

    debug!("----------------");
    debug!(
        "get ({:?}, {:?}) in {:?}",
        &triepath_2, &value_2, &block_header_2
    );
    debug!("----------------");

    let read_value_2 = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &block_header_2,
        &triepath_2,
    )
    .unwrap()
    .unwrap();
    assert_eq!(read_value_2.data.to_vec(), value_2.data.to_vec());
}

// insert a random sequence of 65536 keys.  Every 2048 inserts, start a new block.
//   *these aren't forks* `insert_leaf` on a non-existent bhh creates a block extension in
//   walk_cow via `MARF::extend_trie`.

#[test]
#[ignore]
fn marf_insert_random_65536_2048() {
    let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
    marf_insert(
        |i| {
            let mut path = [0; 32];
            path.copy_from_slice(
                &TrieHash::from_data(if i == 0 { &[] } else { seed.as_slice() }).as_bytes()[0..32],
            );
            seed = path.to_vec();

            let block_header = if (i + 1) % 2048 == 0 {
                // next block
                Some(
                    BlockHeaderHash::from_bytes(&[
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        ((i + 1) / 2048) as u8,
                        ((i + 1) % 2048) as u8,
                    ])
                    .unwrap(),
                )
            } else {
                None
            };
            (path, block_header)
        },
        65536,
        false,
    );
}

// insert a random sequence of 1024 * 1024 * 10 keys.  Every 4096 inserts, fork.
// Use file storage, and use batching.
// Used mainly for performance analysis.
#[test]
fn marf_insert_random_10485760_4096_file_storage() {
    // this takes too long to run, so disable it by default
    if std::env::var("BLOCKSTACK_BIG_TEST") != Ok("1".to_string()) {
        debug!("Skipping this test because it will take too long.  Run with BLOCKSTACK_BIG_TEST=1 to activate.");
        return;
    }

    let path = "/tmp/rust_marf_insert_random_10485760_4096_file_storage".to_string();
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
    let num_iterations = 1024 * 1024 * 10;
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

// insert a random sequence of 4096 keys.  Every 128 inserts, fork.  Use batching.
// Do merkle tests each key/value inserted -- both immediately after the batch containing them
// is inserted, and once all inserts complete.
#[test]
#[ignore]
fn marf_insert_random_4096_128_merkle_proof() {
    let mut last_root_hashes = None;
    for marf_opts in MARFOpenOpts::all().into_iter() {
        let f = TrieFileStorage::new_memory(marf_opts).unwrap();

        let mut m = MARF::from_storage(f);

        let mut block_header = BlockHeaderHash::sentinel();

        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut prev_block_header = block_header.clone();

        let mut i = 1;
        while i <= 4096 {
            let mut keys = vec![];
            let mut values = vec![];

            let i0 = (i & 0xff0000) >> 12;
            let i1 = (i & 0x00ff00) >> 8;
            let i2 = i & 0x0000ff;

            prev_block_header = block_header.clone();
            block_header = BlockHeaderHash::from_bytes(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, i0 as u8, i1 as u8, i2 as u8,
            ])
            .unwrap();

            for _ in 0..128 {
                let i0 = (i & 0xff0000) >> 12;
                let i1 = (i & 0x00ff00) >> 8;
                let i2 = i & 0x0000ff;

                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let raw_value = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8,
                ]
                .to_vec();
                let value = to_hex(&raw_value);

                debug!("Insert ({:?}, {:?})", &key, &value);

                keys.push(key);
                values.push(value);
                i += 1;
            }

            m.begin(&prev_block_header, &block_header).unwrap();

            let marf_values = values.iter().map(|x| MARFValue::from_value(x)).collect();

            m.insert_batch(&keys, marf_values).unwrap();
            m.commit().unwrap();

            let mut block_table_cache = None;
            for j in 0..128 {
                debug!("Prove {:?} == {:?}", &keys[j], &values[j]);
                block_table_cache = Some(merkle_test_marf_key_value(
                    &mut m.borrow_storage_backend(),
                    &block_header,
                    &keys[j],
                    &values[j],
                    block_table_cache,
                ));
            }
        }

        i = 1;
        seed = TrieHash::from_data(&[]).as_bytes().to_vec();

        let mut block_table_cache = None;
        while i <= 4096 {
            let mut keys = vec![];
            let mut values = vec![];

            for _ in 0..128 {
                let i0 = (i & 0xff0000) >> 12;
                let i1 = (i & 0x00ff00) >> 8;
                let i2 = i & 0x0000ff;

                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let raw_value = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8,
                ]
                .to_vec();
                let value = to_hex(&raw_value);

                keys.push(key);
                values.push(value);

                i += 1;
            }

            for j in 0..128 {
                debug!("Get {:?}, should be {:?}", &keys[j], &values[j]);

                let read_value = m.get(&block_header, &keys[j]).unwrap().unwrap();
                assert_eq!(read_value, MARFValue::from_value(&values[j]));

                debug!("Get {:?}, should be {:?}", &keys[j], &values[j]);
                block_table_cache = Some(merkle_test_marf_key_value(
                    &mut m.borrow_storage_backend(),
                    &block_header,
                    &keys[j],
                    &values[j],
                    block_table_cache,
                ));
            }
        }

        if let Some(root_hashes) = last_root_hashes.take() {
            let next_root_hashes = m
                .borrow_storage_backend()
                .read_root_to_block_table()
                .unwrap();
            assert_eq!(root_hashes, next_root_hashes);
            last_root_hashes = Some(next_root_hashes);
        }
    }
}

// Test reads specifically on existing test data.
#[test]
fn marf_read_random_1048576_4096_file_storage() {
    // this takes too long to run, so disable it by default
    if std::env::var("BLOCKSTACK_BIG_TEST") != Ok("1".to_string()) {
        debug!("Skipping this test because it will take too long.  Run with BLOCKSTACK_BIG_TEST=1 to activate.");
        return;
    }

    let do_merkle_check = std::env::var("MARF_BIG_TEST_MERKLE_PROOFS") == Ok("1".to_string());

    for marf_opts in MARFOpenOpts::all().into_iter() {
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

// insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
// every 128 keys, make a new trie.
#[test]
fn marf_insert_128_32() {
    marf_insert(
        |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
            ];
            let block_header = if (i + 1) % 32 == 0 {
                // next block
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 32) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        },
        128,
        true,
    );
}

// insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
// every 128 keys, make a new trie.
#[test]
#[ignore]
fn marf_insert_4096_128() {
    marf_insert(
        |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
            ];
            let block_header = if (i + 1) % 128 == 0 {
                // next block
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        },
        4096,
        true,
    );
}

// insert a range of 256 consecutive keys (forcing node promotions) by varying the low-order bits.
// every 16 keys, make a new trie.
#[test]
fn marf_insert_256_16() {
    marf_insert(
        |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
            ];
            let block_header = if (i + 1) % 16 == 0 {
                // next block
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 16) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        },
        256,
        true,
    );
}

#[test]
#[ignore]
fn marf_insert_get_128_fork_256() {
    // create 256 forks organized as a binary tree, and insert 128 values into each one.
    // make sure we can read them all from each chain tip, and make sure we can generate merkle
    // proofs of each one's value.
    let path = ":memory:".to_string();

    let marf_opts = MARFOpenOpts::default();
    let mut m = MARF::from_path(&path, marf_opts).unwrap();
    let mut fork_headers = vec![];

    let mut pattern = 0u8;
    for c in 0..8 {
        let mut next_fork_row = vec![];
        for i in 0..(1 << c) {
            next_fork_row.push(BlockHeaderHash([pattern; 32]));
            pattern += 1;
        }
        fork_headers.push(next_fork_row);
    }

    m.begin(&BlockHeaderHash::sentinel(), &BlockHeaderHash([0u8; 32]))
        .unwrap();
    m.commit().unwrap();

    for i in 1..8 {
        let parent_row = &fork_headers[i - 1];
        for j in 0..parent_row.len() {
            let parent_hash = &parent_row[j];
            for k in (2 * j)..(2 * j + 2) {
                let child_hash = &fork_headers[i][k];

                debug!("Branch from {:?} to {:?}", parent_hash, child_hash);
                m.begin(parent_hash, child_hash).unwrap();

                let mut keys = vec![];
                let mut values = vec![];

                for l in 0..128 {
                    let raw_value = [
                        i as u8, j as u8, k as u8, l as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]
                    .to_vec();
                    let value = to_hex(&raw_value);
                    let key = format!("{}-{}-{}-{}", i, j, k, l);

                    keys.push(key);
                    values.push(value);
                }

                let values = values
                    .into_iter()
                    .map(|x| MARFValue::from_value(&x))
                    .collect();

                m.insert_batch(&keys, values).unwrap();
                m.commit().unwrap();
            }
        }
    }

    for (height, fork_row) in fork_headers.iter().enumerate() {
        for block in fork_row.iter() {
            assert_eq!(
                MARF::get_block_height(&mut m.borrow_storage_backend(), block, block).unwrap(),
                Some(height as u32)
            );
            assert_eq!(
                MARF::get_block_at_height(&mut m.borrow_storage_backend(), height as u32, block)
                    .unwrap(),
                Some(block.clone())
            );
        }
    }

    let mut expected_chain_tips = fork_headers[fork_headers.len() - 1].clone();
    expected_chain_tips.sort();

    let mut block_table = None;

    for k in 0..expected_chain_tips.len() {
        for l in 0..128 {
            let raw_value = [
                7u8,
                (k / 2) as u8,
                k as u8,
                l as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
            .to_vec();
            let expected_value = to_hex(&raw_value);
            let key = format!("{}-{}-{}-{}", 7, (k / 2), k, l);

            let marf_value = m.get(&expected_chain_tips[k], &key).unwrap().unwrap();
            assert_eq!(marf_value, MARFValue::from_value(&expected_value));

            block_table = Some(merkle_test_marf_key_value(
                &mut m.borrow_storage_backend(),
                &expected_chain_tips[k],
                &key,
                &expected_value,
                block_table,
            ));
        }
    }
}

#[test]
#[ignore]
fn marf_insert_flush_to_different_block() {
    let path = "/tmp/marf_insert_flush_to_different_block".to_string();
    let marf_opts = MARFOpenOpts::default();
    let f = TrieFileStorage::new_memory(marf_opts).unwrap();

    let target_block = BlockHeaderHash([1u8; 32]);

    let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
    let mut marf = MARF::from_storage(f);
    marf.begin(&BlockHeaderHash::sentinel(), &target_block)
        .unwrap();

    let mut root_table_cache = None;

    let mut blocks = vec![];
    let num_blocks_created = 8;
    let count = 256 * num_blocks_created;

    for i in 0..count {
        let i0 = i / 256;
        let i1 = i % 256;
        let path = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
        ];
        let next_block_header = if (i + 1) % 256 == 0 {
            // next block
            BlockHeaderHash::from_bytes(&[
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, i0 as u8, i1 as u8,
            ])
        } else {
            None
        };

        let triepath = TrieHash::from_bytes(&path[..]).unwrap();
        let value = TrieLeaf::new(
            &[],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
            ],
        );

        if let Some(next_block_header) = next_block_header {
            marf.commit_to(&block_header).unwrap();
            marf.begin(&block_header, &target_block).unwrap();
            blocks.push(block_header.clone());
            block_header = next_block_header;
        }

        marf.insert_raw(triepath, value.clone()).unwrap();

        // all I/O happens off the target block
        let read_value = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &target_block,
            &TrieHash::from_bytes(&path[..]).unwrap(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(read_value.data.to_vec(), value.data.to_vec());
        assert_eq!(marf.borrow_storage_backend().get_cur_block(), target_block);

        // can prove off of the target block (but only if we're not in deferred-hash mode,
        // since we haven't committed yet).
        if marf.borrow_storage_backend().hash_calculation_mode != TrieHashCalculationMode::Deferred
        {
            root_table_cache = Some(merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &target_block,
                &path,
                &value.data.to_vec(),
                root_table_cache,
            ));
        }
    }

    // would have been the next block
    let final_block_header = BlockHeaderHash::from_bytes(&[
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        (num_blocks_created - 1) as u8,
        0xff,
    ])
    .unwrap();
    marf.commit_to(&final_block_header).unwrap();

    let num_blocks = blocks.len();

    block_header = final_block_header.clone();
    blocks.push(block_header.clone());

    for (i, block) in blocks.iter().enumerate() {
        debug!("Verify block height and hash at {i} {block} from {block_header}");
        assert_eq!(
            MARF::get_block_height_miner_tip(
                &mut marf.borrow_storage_backend(),
                block,
                &block_header
            )
            .unwrap(),
            Some(i as u32)
        );

        // get_block_at_height should now always return the correct block_header
        assert_eq!(
            MARF::get_block_at_height(&mut marf.borrow_storage_backend(), i as u32, &block_header)
                .unwrap(),
            Some(block.clone())
        );
    }

    root_table_cache = None;

    for i in (0..count).rev() {
        let i0 = i / 256;
        let i1 = i % 256;
        let path = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
        ];

        let triepath = TrieHash::from_bytes(&path[..]).unwrap();
        let value = TrieLeaf::new(
            &[],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
            ],
        );

        // all but the final value are dangling off of block_header.
        // the last value is dangling off of target_block.

        let read_from_block = final_block_header.clone();

        // all I/O happens off the final block header
        debug!("{i}: Get {triepath} off of {read_from_block}");
        let read_value = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &read_from_block,
            &TrieHash::from_bytes(&path[..]).unwrap(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(read_value.data.to_vec(), value.data.to_vec());

        if i == 2046 {
            //    std::env::set_var("BLOCKSTACK_TRACE", "1");
        }
        // can make a merkle proof to each one using the final committed block header
        debug!("{i}: Check proof for {triepath} off of {read_from_block}");
        root_table_cache = Some(merkle_test_marf(
            &mut marf.borrow_storage_backend(),
            &read_from_block,
            &path,
            &value.data.to_vec(),
            root_table_cache,
        ));
    }
}

#[test]
fn test_marf_read_only() {
    let marf_opts = MARFOpenOpts::default();
    let f = TrieFileStorage::new_memory(marf_opts).unwrap();
    let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
    let marf = MARF::from_storage(f);
    let mut ro_marf = marf.reopen_readonly().unwrap();

    let path = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let triepath = TrieHash::from_bytes(&path[..]).unwrap();
    let leaf = TrieLeaf::new(
        &[],
        &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    let value = MARFValue::from(0x1234u32);

    // functions that require a transaction _cannot_ be called on a readonly marf, because
    //   both the storage function for initiating a tx _and_ sqlite will have errored before
    //   you could call the function.
    assert!(matches!(ro_marf.begin_tx(), Err(Error::ReadOnlyError)));
    assert!(matches!(
        ro_marf.insert("foo", value.clone()),
        Err(Error::ReadOnlyError)
    ));
    assert!(matches!(
        ro_marf.insert_raw(triepath, leaf),
        Err(Error::ReadOnlyError)
    ));
    assert!(matches!(
        ro_marf.insert_batch(&["foo".to_string()], vec![value.clone()]),
        Err(Error::ReadOnlyError)
    ));
    assert!(matches!(ro_marf.commit(), Err(Error::ReadOnlyError)));
    assert!(matches!(
        ro_marf.commit_mined(&BlockHeaderHash([0x22; 32])),
        Err(Error::ReadOnlyError)
    ));
    assert!(matches!(
        ro_marf.commit_to(&BlockHeaderHash([0x33; 32])),
        Err(Error::ReadOnlyError)
    ));
    assert!(matches!(
        ro_marf.begin(&BlockHeaderHash([0x22; 32]), &BlockHeaderHash([0x33; 32])),
        Err(Error::ReadOnlyError)
    ));
}

#[test]
fn test_marf_begin_from_sentinel_twice() {
    let marf_opts = MARFOpenOpts::default();
    let f = TrieFileStorage::new_memory(marf_opts).unwrap();
    let block_header_1 = BlockHeaderHash::from_bytes(&[1u8; 32]).unwrap();
    let block_header_2 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
    let mut marf = MARF::from_storage(f);

    let path_1 = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let triepath_1 = TrieHash::from_bytes(&path_1[..]).unwrap();

    let path_2 = [
        1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let triepath_2 = TrieHash::from_bytes(&path_2[..]).unwrap();

    let value_1 = TrieLeaf::new(&[], &[1u8; 40]);
    let value_2 = TrieLeaf::new(&[], &[2u8; 40]);

    marf.begin(&BlockHeaderHash::sentinel(), &block_header_1)
        .unwrap();
    marf.insert_raw(triepath_1, value_1).unwrap();
    marf.commit_to(&block_header_1).unwrap();

    marf.begin(&BlockHeaderHash::sentinel(), &block_header_2)
        .unwrap();
    marf.insert_raw(triepath_2, value_2).unwrap();
    marf.commit_to(&block_header_2).unwrap();

    let read_value_1 = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &block_header_1,
        &triepath_1,
    )
    .unwrap()
    .unwrap();
    eprintln!("read_value_1 from {block_header_1:?} is {read_value_1:?}");

    let read_value_2 = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &block_header_2,
        &triepath_2,
    )
    .unwrap()
    .unwrap();
    eprintln!("read_value_2 from {block_header_2:?} is {read_value_2:?}");

    // should fail
    let read_value_1 = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &block_header_2,
        &triepath_1,
    )
    .unwrap_err();
    assert!(matches!(read_value_1, Error::NotFoundError));
}

#[test]
fn test_marf_unconfirmed() {
    let marf_path = "/tmp/test_marf_unconfirmed";
    if std::fs::metadata(marf_path).is_ok() {
        std::fs::remove_file(marf_path).unwrap();
    }
    let marf_opts = MARFOpenOpts::default();
    let f = TrieFileStorage::<StacksBlockId>::open_unconfirmed(marf_path, marf_opts).unwrap();
    let mut marf = MARF::<StacksBlockId>::from_storage(f);

    let path_1 = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let triepath_1 = TrieHash::from_bytes(&path_1[..]).unwrap();
    let value_1 = TrieLeaf::new(&[], &[1u8; 40]);

    let path_2 = [
        1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let triepath_2 = TrieHash::from_bytes(&path_2[..]).unwrap();
    let value_2 = TrieLeaf::new(&[], &[2u8; 40]);

    let block_header = StacksBlockId([0x33u8; 32]);

    // set up a confirmed MARF
    {
        let marf_opts = MARFOpenOpts::default();
        let cf = TrieFileStorage::<StacksBlockId>::open(marf_path, marf_opts).unwrap();
        let mut confirmed_marf = MARF::<StacksBlockId>::from_storage(cf);
        confirmed_marf
            .begin(&StacksBlockId::sentinel(), &StacksBlockId([0x11; 32]))
            .unwrap();
        confirmed_marf.commit_to(&block_header).unwrap();
    }

    let unconfirmed_tip = marf.begin_unconfirmed(&block_header).unwrap();
    marf.insert_raw(triepath_1, value_1).unwrap();
    marf.commit().unwrap();

    // read succeeds
    let read_value_1 = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &unconfirmed_tip,
        &triepath_1,
    )
    .unwrap()
    .unwrap();
    eprintln!("read_value_1 from {unconfirmed_tip:?} is {read_value_1:?}");

    marf.begin_unconfirmed(&block_header).unwrap();
    marf.insert_raw(triepath_2, value_2).unwrap();
    marf.drop_current();

    // read still succeeds -- only current trie is dropped
    let read_value_1 = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &unconfirmed_tip,
        &triepath_1,
    )
    .unwrap()
    .unwrap();
    eprintln!("read_value_1 from {unconfirmed_tip:?} is {read_value_1:?}");

    // value 2 is dropped
    let e = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &unconfirmed_tip,
        &triepath_2,
    )
    .unwrap_err();
    assert!(matches!(e, Error::NotFoundError));

    marf.begin_unconfirmed(&block_header).unwrap();
    marf.drop_unconfirmed();

    // value 1 is dropped
    let e = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &unconfirmed_tip,
        &triepath_1,
    )
    .unwrap_err();
    assert!(matches!(e, Error::NotFoundError), "whoops: {e:?}");

    // value 2 is dropped
    let e = MARF::get_path(
        &mut marf.borrow_storage_backend(),
        &unconfirmed_tip,
        &triepath_2,
    )
    .unwrap_err();
    assert!(matches!(e, Error::NotFoundError));
}

// ---------------------------------------------------------------------------
// for_each_leaf tests
// ---------------------------------------------------------------------------

/// Verify that the expected MARF metadata keys are present in the leaf set
/// for a MARF with blocks at heights 0..=`height`.
///
/// Expected metadata keys at height H with (H+1) blocks:
/// - `OWN_BLOCK_HEIGHT_KEY` (1 key)
/// - `BLOCK_HEIGHT_TO_HASH_MAPPING_KEY::<h>` for h in 0..=H (H+1 keys)
/// - `BLOCK_HASH_TO_HEIGHT_MAPPING_KEY::<block_hash>` for each block (H+1 keys)
///
/// Total metadata keys = 1 + (H+1) + (H+1) = 2H + 3
fn assert_metadata_keys_present(
    seen: &HashMap<TrieHash, MARFValue>,
    height: u32,
    blocks: &[StacksBlockId],
) {
    // OWN_BLOCK_HEIGHT_KEY
    let own_height_hash = TrieHash::from_key(OWN_BLOCK_HEIGHT_KEY);
    assert!(
        seen.contains_key(&own_height_hash),
        "missing metadata key: {OWN_BLOCK_HEIGHT_KEY}"
    );
    assert_eq!(
        seen[&own_height_hash],
        MARFValue::from(height),
        "OWN_BLOCK_HEIGHT_KEY should equal {height}"
    );

    // BLOCK_HEIGHT_TO_HASH_MAPPING_KEY::<h> for each height 0..=H
    for h in 0..=height {
        let key = format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{h}");
        let hash = TrieHash::from_key(&key);
        assert!(seen.contains_key(&hash), "missing metadata key: {key}");
    }

    // BLOCK_HASH_TO_HEIGHT_MAPPING_KEY::<block_hash> for each block 0..=H
    for (i, bh) in blocks.iter().enumerate().take((height + 1) as usize) {
        let key = format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{bh}");
        let hash = TrieHash::from_key(&key);
        assert!(
            seen.contains_key(&hash),
            "missing metadata key for block {i}: {key}"
        );
    }
}

/// Create a small MARF with 2 blocks for `for_each_leaf` tests.
///
/// Block 0 (b1): inserts k1 = "v1".
/// Block 1 (b2): overwrites k1 = "v2", inserts k2 = "v3".
fn setup_for_each_leaf_marf(path: &str) -> (MARF<StacksBlockId>, StacksBlockId, StacksBlockId) {
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(path, open_opts).unwrap();

    let b1 = StacksBlockId::from_bytes(&[1u8; 32]).unwrap();
    let b2 = StacksBlockId::from_bytes(&[2u8; 32]).unwrap();

    marf.begin(&StacksBlockId::sentinel(), &b1).unwrap();
    marf.insert("k1", MARFValue::from_value("v1")).unwrap();
    marf.commit().unwrap();

    marf.begin(&b1, &b2).unwrap();
    marf.insert("k1", MARFValue::from_value("v2")).unwrap();
    marf.insert("k2", MARFValue::from_value("v3")).unwrap();
    marf.commit().unwrap();

    (marf, b1, b2)
}

/// Create a 10-block MARF (heights 0-9) for `for_each_leaf` tests.
///
/// k1 is updated at every block (exercises backpointers at every depth).
/// k2..k10 are each inserted at their respective blocks.
fn setup_for_each_leaf_large_marf(path: &str) -> (MARF<StacksBlockId>, Vec<StacksBlockId>) {
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(path, open_opts).unwrap();

    let blocks: Vec<StacksBlockId> = (1..=10u8)
        .map(|i| StacksBlockId::from_bytes(&[i; 32]).unwrap())
        .collect();

    // Block at height 0
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("k1", MARFValue::from_value("v1_at_0")).unwrap();
    marf.commit().unwrap();

    // Heights 1-9
    for i in 1..blocks.len() {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        let key = format!("k{}", i + 1);
        let val = format!("v{}_at_{}", i + 1, i);
        marf.insert(&key, MARFValue::from_value(&val)).unwrap();
        marf.insert("k1", MARFValue::from_value(&format!("v1_at_{i}")))
            .unwrap();
        marf.commit().unwrap();
    }

    (marf, blocks)
}

#[test]
fn test_for_each_leaf_yields_all_keys() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.sqlite");
    let (mut marf, b1, b2) = setup_for_each_leaf_marf(db_path.to_str().unwrap());

    // b2 is the tip (last committed block = height 1).
    let mut seen: HashMap<TrieHash, MARFValue> = HashMap::new();
    let leaf_count = marf
        .with_conn(|conn| {
            MARF::for_each_leaf(conn, &b2, |path, value| {
                seen.insert(path, value);
                Ok(())
            })
        })
        .unwrap();

    assert_eq!(leaf_count, seen.len() as u64);

    // User keys: k1 (overwritten) and k2.
    assert_eq!(
        seen.get(&TrieHash::from_key("k1")).cloned().unwrap(),
        MARFValue::from_value("v2")
    );
    assert_eq!(
        seen.get(&TrieHash::from_key("k2")).cloned().unwrap(),
        MARFValue::from_value("v3")
    );

    // Metadata keys: height 1 MARF with 2 blocks (b1, b2).
    // Expected: OWN_BLOCK_HEIGHT_KEY + 2 height-to-hash + 2 hash-to-height = 5 metadata.
    assert_metadata_keys_present(&seen, 1, &[b1, b2]);

    // Total: 2 user + 5 metadata = 7.
    assert_eq!(leaf_count, 7, "expected 7 leaves (2 user + 5 metadata)");
}

#[test]
fn test_for_each_leaf_resolves_backpointers() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.sqlite");
    let (mut marf, blocks) = setup_for_each_leaf_large_marf(db_path.to_str().unwrap());

    // blocks[9] is the tip (height 9). k2..k10 are reachable via backpointers.
    let block_at_tip = &blocks[9];

    let mut seen: HashMap<TrieHash, MARFValue> = HashMap::new();
    let leaf_count = marf
        .with_conn(|conn| {
            MARF::for_each_leaf(conn, block_at_tip, |path, value| {
                seen.insert(path, value);
                Ok(())
            })
        })
        .unwrap();

    assert_eq!(leaf_count, seen.len() as u64);

    // User keys: k1..k10.
    assert_eq!(
        seen.get(&TrieHash::from_key("k1")).cloned().unwrap(),
        MARFValue::from_value("v1_at_9"),
        "k1 should have latest value"
    );
    for i in 2..=10 {
        let key = format!("k{i}");
        assert!(
            seen.contains_key(&TrieHash::from_key(&key)),
            "missing key {key} from walk"
        );
    }

    // Metadata keys: height 9 MARF with 10 blocks.
    // Expected: OWN_BLOCK_HEIGHT_KEY + 10 height-to-hash + 10 hash-to-height = 21 metadata.
    assert_metadata_keys_present(&seen, 9, &blocks);

    // Total: 10 user + 21 metadata = 31.
    assert_eq!(leaf_count, 31, "expected 31 leaves (10 user + 21 metadata)");
}

#[test]
fn test_for_each_leaf_single_block() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(db_path.to_str().unwrap(), open_opts).unwrap();

    let b1 = StacksBlockId::from_bytes(&[1u8; 32]).unwrap();
    marf.begin(&StacksBlockId::sentinel(), &b1).unwrap();
    marf.insert("alpha", MARFValue::from_value("a1")).unwrap();
    marf.insert("beta", MARFValue::from_value("b1")).unwrap();
    marf.insert("gamma", MARFValue::from_value("g1")).unwrap();
    marf.commit().unwrap();

    let mut seen: HashMap<TrieHash, MARFValue> = HashMap::new();
    let leaf_count = marf
        .with_conn(|conn| {
            MARF::for_each_leaf(conn, &b1, |path, value| {
                seen.insert(path, value);
                Ok(())
            })
        })
        .unwrap();

    assert_eq!(leaf_count, seen.len() as u64);

    // User keys.
    assert_eq!(
        seen.get(&TrieHash::from_key("alpha")).cloned().unwrap(),
        MARFValue::from_value("a1")
    );
    assert_eq!(
        seen.get(&TrieHash::from_key("beta")).cloned().unwrap(),
        MARFValue::from_value("b1")
    );
    assert_eq!(
        seen.get(&TrieHash::from_key("gamma")).cloned().unwrap(),
        MARFValue::from_value("g1")
    );

    // Metadata keys: height 0, 1 block.
    // Expected: OWN_BLOCK_HEIGHT_KEY + 1 height-to-hash + 1 hash-to-height = 3 metadata.
    assert_metadata_keys_present(&seen, 0, &[b1]);

    // Total: 3 user + 3 metadata = 6.
    assert_eq!(leaf_count, 6, "expected 6 leaves (3 user + 3 metadata)");
}

#[test]
fn test_for_each_leaf_at_intermediate_height() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.sqlite");
    let (mut marf, blocks) = setup_for_each_leaf_large_marf(db_path.to_str().unwrap());

    // Walk at height 4 (blocks[4]), NOT the tip.
    let block_at_4 = &blocks[4];

    let mut seen: HashMap<TrieHash, MARFValue> = HashMap::new();
    let leaf_count = marf
        .with_conn(|conn| {
            MARF::for_each_leaf(conn, block_at_4, |path, value| {
                seen.insert(path, value);
                Ok(())
            })
        })
        .unwrap();

    // k1 should have its height-4 value.
    assert_eq!(
        seen.get(&TrieHash::from_key("k1")).cloned().unwrap(),
        MARFValue::from_value("v1_at_4"),
        "k1 should have value from height 4"
    );

    // k2..k5 should be present (inserted at heights 1-4).
    for i in 2..=5 {
        let key = format!("k{i}");
        assert!(
            seen.contains_key(&TrieHash::from_key(&key)),
            "expected key {key} at height 4"
        );
    }

    // k6..k10 should be absent (inserted at heights 5-9).
    for i in 6..=10 {
        let key = format!("k{i}");
        assert!(
            !seen.contains_key(&TrieHash::from_key(&key)),
            "key {key} should NOT be visible at height 4"
        );
    }

    // Metadata keys: height 4, 5 blocks (blocks[0..=4]).
    // Expected: OWN_BLOCK_HEIGHT_KEY + 5 height-to-hash + 5 hash-to-height = 11 metadata.
    assert_metadata_keys_present(&seen, 4, &blocks[..5]);

    // Total: 5 user (k1..k5) + 11 metadata = 16.
    assert_eq!(leaf_count, seen.len() as u64);
    assert_eq!(leaf_count, 16, "expected 16 leaves (5 user + 11 metadata)");
}

#[test]
fn test_for_each_leaf_callback_error_propagates() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.sqlite");
    let (mut marf, _b1, b2) = setup_for_each_leaf_marf(db_path.to_str().unwrap());

    let mut call_count = 0u64;
    let result = marf.with_conn(|conn| {
        MARF::for_each_leaf(conn, &b2, |_path, _value| {
            call_count += 1;
            if call_count >= 1 {
                return Err(Error::CorruptionError(
                    "test error from callback".to_string(),
                ));
            }
            Ok(())
        })
    });

    assert!(result.is_err(), "expected error from callback");
    match result.unwrap_err() {
        Error::CorruptionError(msg) => {
            assert_eq!(msg, "test error from callback");
        }
        other => panic!("unexpected error type: {other:?}"),
    }
    assert_eq!(
        call_count, 1,
        "callback should have been called exactly once"
    );
}
