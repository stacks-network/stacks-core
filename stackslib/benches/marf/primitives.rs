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

//! Allocation-focused micro-benchmark for trie node construction and index-bit codecs.

use std::hint::black_box;
use std::io::Cursor;
use std::sync::OnceLock;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use blockstack_lib::chainstate::stacks::index::node::{
    CursorError, TrieCursor, TrieNode as _, TrieNode16, TrieNode256, TrieNode4, TrieNode48,
    TrieNodeID, TrieNodeType, TriePtr, TRIEPTR_SIZE,
};
use blockstack_lib::chainstate::stacks::index::storage::{
    TrieFileStorage, TrieHashCalculationMode,
};
use blockstack_lib::chainstate::stacks::index::trie::Trie;
use blockstack_lib::chainstate::stacks::index::{
    bits, ClarityMarfTrieId as _, Error as IndexError, MARFValue, TrieLeaf,
};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash, TRIEHASH_ENCODED_SIZE};

use crate::common::record_case_with_rounds;
use crate::utils::{
    block_id, has_help_flag, missing_path_hash, parse_usize_env, path_from_seed, trie_insert,
    walk_to_insertion_point,
};
use crate::{OutputMode, Summary};

/// Default iterations per primitive case.
const DEFAULT_ITERS: usize = 200_000;
/// Default independent repetitions per case.
const DEFAULT_ROUNDS: usize = 1;

#[rustfmt::skip]
fn print_usage(args: &[String]) {
    if has_help_flag(args) {
        println!("primitives: Allocation profiling micro-benchmark for primitives (codec + trie/storage)");
        println!();
        println!("Environment Variables:");
        println!("  ITERS Iterations per measured case [default: {DEFAULT_ITERS}]");
        println!("              Higher values reduce timer noise but increase runtime linearly");
        println!("              Allocation counters are total counts/bytes across all iterations");
        println!("  ROUNDS      Independent repetitions per case [default: {DEFAULT_ROUNDS}]");
        println!("              Higher values improve stability estimates in summary totals");
        println!("  OUTPUT_FORMAT");
        println!("              Output mode [default: summary]");
        println!("              'summary': unified summary lines only");
        println!("              'raw': detailed per-case lines + unified summary lines");
        println!();
        println!("Output Lines:");
        println!("  summary     Unified summary lines emitted by marf bench main");
        return;
    }
}

/// Measure and append one primitive case to summary output.
fn record_case<F>(summary: &mut Summary, name: &str, mode: OutputMode, f: F)
where
    F: FnMut(),
{
    record_case_with_rounds(summary, name, mode, configured_rounds(), f);
}

/// Return validated `ROUNDS` benchmark setting, parsed once per process.
fn configured_rounds() -> usize {
    static ROUNDS: OnceLock<usize> = OnceLock::new();
    *ROUNDS.get_or_init(|| {
        let rounds = parse_usize_env("ROUNDS", DEFAULT_ROUNDS);
        assert!(rounds > 0, "ROUNDS must be > 0");
        rounds
    })
}

/// Return a deterministic full-length trie path byte array.
fn sample_path() -> [u8; TRIEHASH_ENCODED_SIZE] {
    std::array::from_fn(|i| i as u8)
}

/// Construct a node4 instance with populated child pointers.
fn make_node4(path: &[u8]) -> TrieNode4 {
    let mut node4 = TrieNode4::new(path);
    for i in 0..4u8 {
        node4.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1);
    }
    node4
}

/// Construct a node16 instance with populated child pointers.
fn make_node16(path: &[u8]) -> TrieNode16 {
    let mut node16 = TrieNode16::new(path);
    for i in 0..16u8 {
        node16.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1);
    }
    node16
}

/// Construct a node48 instance with populated child pointers.
fn make_node48(path: &[u8]) -> TrieNode48 {
    let mut node48 = TrieNode48::new(path);
    for i in 0..48u8 {
        let inserted = node48.insert(&TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1));
        debug_assert!(inserted);
    }
    node48
}

/// Construct a node256 instance with populated child pointers.
fn make_node256(path: &[u8]) -> TrieNode256 {
    let mut node256 = TrieNode256::new(path);
    for i in 0..=255u8 {
        node256.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1);
    }
    node256
}

/// Build encoded pointer-byte payload for ptr decode benchmarks.
fn make_ptr_bytes(node_id: TrieNodeID) -> Vec<u8> {
    let num_ptrs = match node_id {
        TrieNodeID::Leaf => 1,
        TrieNodeID::Node4 => 4,
        TrieNodeID::Node16 => 16,
        TrieNodeID::Node48 => 48,
        TrieNodeID::Node256 => 256,
        TrieNodeID::Empty => unreachable!("Empty is not encoded as a node body"),
        // NOTE: The TrieNodeID::Patch type was added at commit 0317850e7f042de98e7bc6a1f26f6183e7d20f98,
        // and using exhaustive matching would prevent this benchmark from being used prior to that via
        // marf-bench.
        _ => unreachable!("Unsupported trie node ID for fixed-size node body benchmark"),
    };

    let mut bytes = vec![0u8; 1 + num_ptrs * TRIEPTR_SIZE];
    bytes[0] = node_id as u8;

    for i in 0..num_ptrs {
        let off = 1 + i * TRIEPTR_SIZE;
        bytes[off] = TrieNodeID::Leaf as u8;
        bytes[off + 1] = i as u8;
        bytes[off + 2..off + 6].copy_from_slice(&(i as u32 + 1).to_be_bytes());
        bytes[off + 6..off + 10].copy_from_slice(&0u32.to_be_bytes());
    }

    bytes
}

/// Serialize one node body with associated hash bytes.
fn serialize_nodetype(node: &TrieNodeType, hash: TrieHash) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::with_capacity(bits::get_node_byte_len(node)));
    bits::write_nodetype_bytes(&mut cursor, node, hash).expect("serialize nodetype");
    cursor.into_inner()
}

/// In-memory trie fixture for trie primitive cases.
struct TrieFixture {
    store: TrieFileStorage<StacksBlockId>,
    tip: StacksBlockId,
    walk_path: TrieHash,
    existing_path: TrieHash,
    missing_path: TrieHash,
}

/// Build and pre-populate trie fixture used by trie primitive tests.
fn make_trie_fixture(cache_strategy: &str) -> TrieFixture {
    let mut store = TrieFileStorage::open(
        ":memory:",
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true),
    )
    .expect("failed to create trie store");

    let tip = block_id(1);
    let walk_path = path_from_seed(96);
    let existing_path = path_from_seed(42);
    let missing_path = missing_path_hash();

    let mut tx = store
        .transaction()
        .expect("failed to create transaction for trie fixture");
    MARF::format(&mut tx, &tip).expect("failed to format trie fixture");
    tx.open_block(&tip).expect("failed to open fixture tip");

    for i in 0..192u32 {
        trie_insert(&mut tx, &path_from_seed(i as u8), MARFValue::from(i + 1))
            .expect("failed to pre-populate trie fixture");
    }

    tx.commit_tx();

    TrieFixture {
        store,
        tip,
        walk_path,
        existing_path,
        missing_path,
    }
}

/// In-memory storage fixture for storage primitive cases.
struct StorageFixture {
    store: TrieFileStorage<StacksBlockId>,
    parent: StacksBlockId,
    tip: StacksBlockId,
}

/// Build and pre-populate storage fixture used by storage primitive tests.
fn make_storage_fixture(cache_strategy: &str) -> StorageFixture {
    let mut store = TrieFileStorage::open(
        ":memory:",
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true),
    )
    .expect("failed to create storage fixture store");

    let parent = StacksBlockId::sentinel();
    let tip = block_id(12);

    {
        let mut tx = store
            .transaction()
            .expect("failed to start storage fixture transaction");

        MARF::format(&mut tx, &tip).expect("failed to format storage fixture tip");
        tx.open_block(&tip)
            .expect("failed to open storage fixture tip");
        for i in 0..192u32 {
            trie_insert(
                &mut tx,
                &path_from_seed(i as u8),
                MARFValue::from(i.wrapping_add(10_001)),
            )
            .expect("failed to populate tip block for storage fixture");
        }

        tx.commit_tx();
    }

    StorageFixture { store, parent, tip }
}

/// Run primitive benchmark subcommand and return summary rows.
pub fn run(args: &[String], output_mode: OutputMode) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage(args);
        return None;
    }

    let iters = parse_usize_env("ITERS", DEFAULT_ITERS);
    assert!(iters > 0, "ITERS must be > 0");

    let path = sample_path();
    let leaf_data = [0x11u8; 40];
    let hash = TrieHash([0xAB; TRIEHASH_ENCODED_SIZE]);

    let node4 = make_node4(&path);
    let node16 = make_node16(&path);
    let node48 = make_node48(&path);
    let node256 = make_node256(&path);
    let leaf = TrieLeaf::new(&path, &leaf_data);

    let node_variants = vec![
        (
            "node4",
            TrieNodeID::Node4 as u8,
            TrieNodeType::Node4(node4.clone()),
        ),
        (
            "node16",
            TrieNodeID::Node16 as u8,
            TrieNodeType::Node16(node16.clone()),
        ),
        (
            "node48",
            TrieNodeID::Node48 as u8,
            TrieNodeType::Node48(Box::new(node48.clone())),
        ),
        (
            "node256",
            TrieNodeID::Node256 as u8,
            TrieNodeType::Node256(Box::new(node256.clone())),
        ),
        (
            "leaf",
            TrieNodeID::Leaf as u8,
            TrieNodeType::Leaf(leaf.clone()),
        ),
    ];

    let encoded_node4 = serialize_nodetype(&TrieNodeType::Node4(node4.clone()), hash);
    let encoded_node256 =
        serialize_nodetype(&TrieNodeType::Node256(Box::new(node256.clone())), hash);
    let encoded_leaf = serialize_nodetype(&TrieNodeType::Leaf(leaf.clone()), hash);

    let encoded_with_hash: Vec<(&str, u8, Vec<u8>)> = node_variants
        .iter()
        .map(|(name, ptr_id, node)| (*name, *ptr_id, serialize_nodetype(node, hash)))
        .collect();

    let ptr_bytes_node4 = make_ptr_bytes(TrieNodeID::Node4);
    let ptr_bytes_node16 = make_ptr_bytes(TrieNodeID::Node16);
    let ptr_bytes_node48 = make_ptr_bytes(TrieNodeID::Node48);
    let ptr_bytes_node256 = make_ptr_bytes(TrieNodeID::Node256);

    let empty_path_bytes = [0u8];
    let mut max_len_path_bytes = Vec::with_capacity(1 + path.len());
    max_len_path_bytes.push(path.len() as u8);
    max_len_path_bytes.extend_from_slice(&path);

    if output_mode.is_raw() {
        println!("iters={iters}\trounds={}", configured_rounds());
    }

    let mut summary = Summary::new("primitives", 64);

    record_case(&mut summary, "new_node4", output_mode, || {
        for _ in 0..iters {
            black_box(TrieNode4::new(&path));
        }
    });

    record_case(&mut summary, "new_node16", output_mode, || {
        for _ in 0..iters {
            black_box(TrieNode16::new(&path));
        }
    });

    record_case(&mut summary, "new_node48", output_mode, || {
        for _ in 0..iters {
            black_box(TrieNode48::new(&path));
        }
    });

    record_case(&mut summary, "clone_node4", output_mode, || {
        for _ in 0..iters {
            black_box(node4.clone());
        }
    });

    record_case(&mut summary, "clone_node16", output_mode, || {
        for _ in 0..iters {
            black_box(node16.clone());
        }
    });

    record_case(&mut summary, "clone_node48", output_mode, || {
        for _ in 0..iters {
            black_box(node48.clone());
        }
    });

    record_case(&mut summary, "clone_node256", output_mode, || {
        for _ in 0..iters {
            black_box(node256.clone());
        }
    });

    record_case(&mut summary, "new_leaf", output_mode, || {
        for _ in 0..iters {
            black_box(TrieLeaf::new(&path, &leaf_data));
        }
    });

    record_case(&mut summary, "clone_leaf", output_mode, || {
        for _ in 0..iters {
            black_box(leaf.clone());
        }
    });

    record_case(&mut summary, "decode_node4_nohash", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_node4.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Node4 as u8)
                    .expect("decode node4"),
            );
        }
    });

    record_case(&mut summary, "decode_leaf_nohash", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_leaf.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Leaf as u8)
                    .expect("decode leaf"),
            );
        }
    });

    record_case(&mut summary, "decode_node256_nohash", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_node256.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Node256 as u8)
                    .expect("decode node256"),
            );
        }
    });

    record_case(&mut summary, "decode_path_len_0", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(empty_path_bytes.as_slice());
            black_box(bits::path_from_bytes(&mut cursor).expect("path decode"));
        }
    });

    record_case(&mut summary, "decode_path_len_32", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(max_len_path_bytes.as_slice());
            black_box(bits::path_from_bytes(&mut cursor).expect("path decode"));
        }
    });

    let mut ptrs4 = vec![TriePtr::default(); 4];
    record_case(&mut summary, "decode_ptrs_node4", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(ptr_bytes_node4.as_slice());
            black_box(
                bits::ptrs_from_bytes(TrieNodeID::Node4 as u8, &mut cursor, ptrs4.as_mut_slice())
                    .expect("ptr decode node4"),
            );
            black_box(&ptrs4);
        }
    });

    let mut ptrs16 = vec![TriePtr::default(); 16];
    record_case(&mut summary, "decode_ptrs_node16", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(ptr_bytes_node16.as_slice());
            black_box(
                bits::ptrs_from_bytes(TrieNodeID::Node16 as u8, &mut cursor, ptrs16.as_mut_slice())
                    .expect("ptr decode node16"),
            );
            black_box(&ptrs16);
        }
    });

    let mut ptrs48 = vec![TriePtr::default(); 48];
    record_case(&mut summary, "decode_ptrs_node48", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(ptr_bytes_node48.as_slice());
            black_box(
                bits::ptrs_from_bytes(TrieNodeID::Node48 as u8, &mut cursor, ptrs48.as_mut_slice())
                    .expect("ptr decode node48"),
            );
            black_box(&ptrs48);
        }
    });

    let mut ptrs256 = vec![TriePtr::default(); 256];
    record_case(&mut summary, "decode_ptrs_node256", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(ptr_bytes_node256.as_slice());
            black_box(
                bits::ptrs_from_bytes(
                    TrieNodeID::Node256 as u8,
                    &mut cursor,
                    ptrs256.as_mut_slice(),
                )
                .expect("ptr decode node256"),
            );
            black_box(&ptrs256);
        }
    });

    for (name, ptr_id, encoded) in &encoded_with_hash {
        record_case(
            &mut summary,
            &format!("decode_{}_with_hash", name),
            output_mode,
            || {
                for _ in 0..iters {
                    let mut cursor = Cursor::new(encoded.as_slice());
                    black_box(
                        bits::read_nodetype_at_head(&mut cursor, *ptr_id)
                            .expect("node decode + hash"),
                    );
                }
            },
        );
    }

    for (name, _ptr_id, node) in &node_variants {
        record_case(
            &mut summary,
            &format!("encode_{}", name),
            output_mode,
            || {
                let mut cursor = Cursor::new(Vec::with_capacity(bits::get_node_byte_len(node)));
                for _ in 0..iters {
                    cursor.set_position(0);
                    cursor.get_mut().clear();
                    black_box(
                        bits::write_nodetype_bytes(&mut cursor, node, hash).expect("node encode"),
                    );
                    black_box(cursor.get_ref().len());
                }
            },
        );
    }

    record_case(
        &mut summary,
        "trie_read_root_with_hash",
        output_mode,
        || {
            let mut fixture = make_trie_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open trie fixture tip");
            for _ in 0..iters {
                black_box(Trie::read_root(&mut conn).expect("read_root failed"));
            }
        },
    );

    record_case(&mut summary, "trie_read_root_nohash", output_mode, || {
        let mut fixture = make_trie_fixture("noop");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.tip)
            .expect("failed to open trie fixture tip");
        for _ in 0..iters {
            black_box(Trie::read_root_nohash(&mut conn).expect("read_root_nohash failed"));
        }
    });

    record_case(
        &mut summary,
        "trie_walk_from_with_hash",
        output_mode,
        || {
            let mut fixture = make_trie_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open trie fixture tip");
            let walk_path = fixture.walk_path;

            for _ in 0..iters {
                let mut cursor = TrieCursor::new(&walk_path, conn.root_trieptr());
                let (mut node, mut node_hash) =
                    Trie::read_root(&mut conn).expect("read_root failed");

                for _ in 0..=32 {
                    match Trie::walk_from(&mut conn, &node, &mut cursor) {
                        Ok(Some((_next_ptr, next_node, next_hash))) => {
                            node = next_node;
                            node_hash = next_hash;
                        }
                        Ok(None) => break,
                        Err(IndexError::CursorError(
                            CursorError::PathDiverged | CursorError::ChrNotFound,
                        )) => break,
                        Err(e) => panic!("walk_from failed: {e:?}"),
                    }
                }

                black_box((cursor.ptr(), node_hash));
            }
        },
    );

    record_case(&mut summary, "trie_walk_from_nohash", output_mode, || {
        let mut fixture = make_trie_fixture("noop");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.tip)
            .expect("failed to open trie fixture tip");
        let walk_path = fixture.walk_path;

        for _ in 0..iters {
            let mut cursor = TrieCursor::new(&walk_path, conn.root_trieptr());
            let mut node = Trie::read_root_nohash(&mut conn).expect("read_root_nohash failed");

            for _ in 0..=32 {
                match Trie::walk_from_nohash(&mut conn, &node, &mut cursor) {
                    Ok(Some((_next_ptr, next_node))) => {
                        node = next_node;
                    }
                    Ok(None) => break,
                    Err(IndexError::CursorError(
                        CursorError::PathDiverged | CursorError::ChrNotFound,
                    )) => break,
                    Err(e) => panic!("walk_from_nohash failed: {e:?}"),
                }
            }

            black_box(cursor.ptr());
        }
    });

    record_case(
        &mut summary,
        "trie_get_children_hashes_root",
        output_mode,
        || {
            let mut fixture = make_trie_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open trie fixture tip");
            for _ in 0..iters {
                let root = Trie::read_root_nohash(&mut conn).expect("read_root_nohash failed");
                black_box(
                    Trie::get_children_hashes(&mut conn, &root)
                        .expect("get_children_hashes failed"),
                );
            }
        },
    );

    record_case(
        &mut summary,
        "trie_add_value_update_root_hash_replace_leaf",
        output_mode,
        || {
            let mut fixture = make_trie_fixture("noop");
            for i in 0..iters {
                let mut tx = fixture
                    .store
                    .transaction()
                    .expect("failed to start tx for replace bench");
                tx.open_block(&fixture.tip)
                    .expect("failed to open fixture tip");

                let mut cursor =
                    walk_to_insertion_point(&mut tx, &fixture.existing_path).expect("walk failed");
                let mut leaf = TrieLeaf::from_value(&[], MARFValue::from((i as u32) + 10_000));
                black_box(
                    Trie::add_value(&mut tx, &mut cursor, &mut leaf).expect("add_value failed"),
                );
                Trie::update_root_hash(&mut tx, &cursor).expect("update_root_hash failed");
                tx.rollback();
            }
        },
    );

    record_case(
        &mut summary,
        "trie_add_value_update_root_hash_insert_missing_leaf",
        output_mode,
        || {
            let mut fixture = make_trie_fixture("noop");
            for _ in 0..iters {
                let mut tx = fixture
                    .store
                    .transaction()
                    .expect("failed to start tx for insert bench");
                tx.open_block(&fixture.tip)
                    .expect("failed to open fixture tip");

                let mut cursor =
                    walk_to_insertion_point(&mut tx, &fixture.missing_path).expect("walk failed");
                let mut leaf = TrieLeaf::from_value(&[], MARFValue::from(0xA5A5_A5A5));
                black_box(
                    Trie::add_value(&mut tx, &mut cursor, &mut leaf).expect("add_value failed"),
                );
                Trie::update_root_hash(&mut tx, &cursor).expect("update_root_hash failed");
                tx.rollback();
            }
        },
    );

    record_case(
        &mut summary,
        "storage_open_block_switch_committed",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("noop");
            let mut conn = fixture.store.connection();
            for _ in 0..iters {
                conn.open_block(&fixture.parent)
                    .expect("open parent block failed");
                conn.open_block(&fixture.tip)
                    .expect("open tip block failed");
                black_box(conn.get_cur_block_and_id());
            }
        },
    );

    record_case(
        &mut summary,
        "storage_open_block_same_block_noop",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("open tip block for noop benchmark failed");
            for _ in 0..iters {
                conn.open_block(&fixture.tip)
                    .expect("open_block noop path failed");
                black_box(conn.get_cur_block_and_id());
            }
        },
    );

    record_case(
        &mut summary,
        "storage_read_nodetype_with_hash_noop",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open tip for read_nodetype/noop");
            let root_ptr = conn.root_trieptr();
            for _ in 0..iters {
                black_box(
                    conn.read_nodetype(&root_ptr)
                        .expect("read_nodetype with hash failed"),
                );
            }
        },
    );

    record_case(
        &mut summary,
        "storage_read_nodetype_nohash_noop",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open tip for read_nodetype/noop");
            let root_ptr = conn.root_trieptr();
            for _ in 0..iters {
                black_box(
                    conn.read_nodetype_nohash(&root_ptr)
                        .expect("read_nodetype_nohash failed"),
                );
            }
        },
    );

    record_case(
        &mut summary,
        "storage_read_nodetype_with_hash_everything_hot",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("everything");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open tip for read_nodetype/everything");
            let root_ptr = conn.root_trieptr();
            conn.read_nodetype(&root_ptr)
                .expect("cache priming read_nodetype failed");
            for _ in 0..iters {
                black_box(
                    conn.read_nodetype(&root_ptr)
                        .expect("read_nodetype cache-hot failed"),
                );
            }
        },
    );

    record_case(
        &mut summary,
        "storage_read_nodetype_nohash_everything_hot",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("everything");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open tip for read_nodetype/everything");
            let root_ptr = conn.root_trieptr();
            conn.read_nodetype_nohash(&root_ptr)
                .expect("cache priming read_nodetype_nohash failed");
            for _ in 0..iters {
                black_box(
                    conn.read_nodetype_nohash(&root_ptr)
                        .expect("read_nodetype_nohash cache-hot failed"),
                );
            }
        },
    );

    record_case(
        &mut summary,
        "storage_read_node_hash_bytes_noop",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open tip for read_node_hash_bytes/noop");
            let root_ptr = conn.root_trieptr();
            for _ in 0..iters {
                black_box(
                    conn.read_node_hash_bytes(&root_ptr)
                        .expect("read_node_hash_bytes noop failed"),
                );
            }
        },
    );

    record_case(
        &mut summary,
        "storage_read_node_hash_bytes_everything_hot",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("everything");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open tip for read_node_hash_bytes/everything");
            let root_ptr = conn.root_trieptr();
            conn.read_node_hash_bytes(&root_ptr)
                .expect("cache priming read_node_hash_bytes failed");
            for _ in 0..iters {
                black_box(
                    conn.read_node_hash_bytes(&root_ptr)
                        .expect("read_node_hash_bytes cache-hot failed"),
                );
            }
        },
    );

    record_case(
        &mut summary,
        "storage_write_children_hashes_committed_root",
        output_mode,
        || {
            let mut fixture = make_storage_fixture("noop");
            let mut conn = fixture.store.connection();
            conn.open_block(&fixture.tip)
                .expect("failed to open tip for committed write_children_hashes");
            let root_ptr = conn.root_trieptr();
            let root_node = conn
                .read_nodetype_nohash(&root_ptr)
                .expect("failed to read root node for committed write_children_hashes");
            let mut out = Vec::with_capacity(32 * 256);
            for _ in 0..iters {
                out.clear();
                conn.write_children_hashes(&root_node, &mut out)
                    .expect("write_children_hashes committed path failed");
                black_box(out.len());
            }
        },
    );

    Some(summary)
}
