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

use clarity::types::chainstate::TrieHash;

use crate::chainstate::stacks::index::marf::MARFOpenOpts;
use crate::chainstate::stacks::index::test::{make_test_insert_data, opts};
use crate::chainstate::stacks::index::MARFValue;

mod utils {
    use std::fs;
    use std::time::SystemTime;

    use clarity::types::chainstate::{BlockHeaderHash, TrieHash};

    use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
    use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
    use crate::chainstate::stacks::index::test::merkle_test_marf;
    use crate::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue, TrieLeaf};

    /// Runs a MARF test using string keys.
    ///
    /// Keys are converted to `TrieHash` values internally. Inserts are performed
    /// using batched writes when `batch_size > 0`, and raw inserts otherwise.
    ///
    /// Returns the root hash at the final block.
    pub fn run_test_with_string_keys(
        test_name: &str,
        data: &Vec<Vec<(String, MARFValue)>>,
        marf_opts: &MARFOpenOpts,
        batch_size: usize,
    ) -> TrieHash {
        run_test_with_batch_common(
            test_name,
            data,
            marf_opts,
            batch_size,
            |marf, block_data, batch_size| {
                if batch_size > 0 {
                    for chunk in block_data.chunks(batch_size) {
                        let keys: Vec<_> = chunk.iter().map(|(k, _)| k.clone()).collect();
                        let values = chunk.iter().map(|(_, v)| v.clone()).collect();
                        marf.insert_batch(&keys, values).unwrap();
                    }
                } else {
                    for (key, value) in block_data.iter() {
                        let leaf = TrieLeaf::from_value(&[], value.clone());
                        marf.insert_raw(TrieHash::from_key(key), leaf).unwrap();
                    }
                }
            },
            |k| TrieHash::from_key(k),
        )
    }

    /// Runs a MARF test using precomputed `TrieHash` keys.
    ///
    /// Only raw inserts are supported for `TrieHash` keys.
    /// This variant avoids key hashing and is useful when paths are already materialized.
    ///
    /// Returns the root hash at the final block.
    pub fn run_test_with_triehash_keys(
        test_name: &str,
        data: &Vec<Vec<(TrieHash, MARFValue)>>,
        marf_opts: &MARFOpenOpts,
    ) -> TrieHash {
        run_test_with_batch_common(
            test_name,
            data,
            marf_opts,
            0,
            |marf, block_data, _| {
                for (key, value) in block_data.iter() {
                    let leaf = TrieLeaf::from_value(&[], value.clone());
                    marf.insert_raw(key.clone(), leaf).unwrap();
                }
            },
            |k| k.clone(),
        )
    }

    /// Executes a full MARF test cycle (write/read) over a sequence of blocks
    ///
    /// This is a generic implementation used by the public helpers. Callers provide:
    /// - an insertion strategy (e.g. raw inserts or batched inserts)
    /// - a key-to-`TrieHash` mapping function
    ///
    /// The function initializes storage, applies all blocks,
    /// benchmarks reads/writes, and returns the final root hash.
    fn run_test_with_batch_common<K, FInsert, FPath>(
        test_name: &str,
        data: &Vec<Vec<(K, MARFValue)>>,
        marf_opts: &MARFOpenOpts,
        batch_size: usize,
        mut insert_fn: FInsert,
        path_fn: FPath,
    ) -> TrieHash
    where
        K: Clone,
        FInsert: FnMut(&mut MARF<BlockHeaderHash>, &[(K, MARFValue)], usize),
        FPath: Fn(&K) -> TrieHash,
    {
        let test_file = if test_name == ":memory:" {
            test_name.to_string()
        } else {
            let cache_str = &marf_opts.cache_strategy;
            let hash_str = match marf_opts.hash_calculation_mode {
                TrieHashCalculationMode::Immediate => "imm",
                TrieHashCalculationMode::Deferred => "def",
                TrieHashCalculationMode::All => "all",
            };
            let compress_str = if marf_opts.compress { "com" } else { "unc" };

            let test_dir = format!(
                "/tmp/stacks-marf-tests/{}-{}-{}-{}-{}",
                test_name, cache_str, hash_str, compress_str, batch_size
            );

            if fs::metadata(&test_dir).is_ok() {
                fs::remove_dir_all(&test_dir).unwrap();
            }
            fs::create_dir_all(&test_dir).unwrap();
            format!("{test_dir}/marf.sqlite")
        };

        let f = TrieFileStorage::open(&test_file, marf_opts.clone()).unwrap();
        let mut marf = MARF::from_storage(f);
        let mut last_block_header = BlockHeaderHash::sentinel();

        for (i, block_data) in data.iter().enumerate() {
            test_debug!("Write block {}", i);

            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            let block_header = BlockHeaderHash(block_hash_bytes);

            marf.begin(&last_block_header, &block_header).unwrap();
            insert_fn(&mut marf, block_data, batch_size);
            marf.commit().unwrap();

            last_block_header = block_header.clone();

            let proof_block_data = &data[i / 2];
            test_debug!("Prove block {}", i / 2);

            for (key, value) in proof_block_data.iter() {
                merkle_test_marf(
                    &mut marf.borrow_storage_backend(),
                    &block_header,
                    path_fn(key).as_bytes(),
                    value.as_bytes(),
                    None,
                );
            }
        }

        let mut total_read_time = 0;
        for (i, block_data) in data.iter().enumerate() {
            test_debug!("Read block {}", i);
            for (key, value) in block_data.iter() {
                let start = SystemTime::now();
                let leaf = MARF::get_path(
                    &mut marf.borrow_storage_backend(),
                    &last_block_header,
                    &path_fn(key),
                )
                .unwrap()
                .unwrap();

                total_read_time += start.elapsed().unwrap().as_nanos();
                assert_eq!(leaf.data, TrieLeaf::from_value(&[], value.clone()).data);
            }
        }

        marf.get_root_hash_at(&last_block_header).unwrap()
    }
}

/// Tests MARF cache behavior (no compression) using 128 inserts across 128 blocks,
///
/// The test is executed across a wide range of MARF configurations and insert
/// batch sizes to exercise all cache strategies.
/// For all configurations, the resulting root hash must remain stable.
#[rstest]
#[case::noop_immediate_batch_0(&opts::OPTS_NOOP_IMM_EXT, 0)]
#[case::noop_immediate_batch_13(&opts::OPTS_NOOP_IMM_EXT, 13)]
#[case::noop_immediate_batch_64(&opts::OPTS_NOOP_IMM_EXT, 64)]
#[case::noop_immediate_batch_67(&opts::OPTS_NOOP_IMM_EXT, 67)]
#[case::noop_immediate_batch_128(&opts::OPTS_NOOP_IMM_EXT, 128)]
#[case::noop_deferred_batch_0(&opts::OPTS_NOOP_DEF_EXT, 0)]
#[case::noop_deferred_batch_13(&opts::OPTS_NOOP_DEF_EXT, 13)]
#[case::noop_deferred_batch_64(&opts::OPTS_NOOP_DEF_EXT, 64)]
#[case::noop_deferred_batch_67(&opts::OPTS_NOOP_DEF_EXT, 67)]
#[case::noop_deferred_batch_128(&opts::OPTS_NOOP_DEF_EXT, 128)]
#[case::node256_immediate_batch_0(&opts::OPTS_N256_IMM_EXT, 0)]
#[case::node256_immediate_batch_13(&opts::OPTS_N256_IMM_EXT, 13)]
#[case::node256_immediate_batch_64(&opts::OPTS_N256_IMM_EXT, 64)]
#[case::node256_immediate_batch_67(&opts::OPTS_N256_IMM_EXT, 67)]
#[case::node256_immediate_batch_128(&opts::OPTS_N256_IMM_EXT, 128)]
#[case::all_immediate_batch_0(&opts::OPTS_EVER_IMM_EXT, 0)]
#[case::all_immediate_batch_13(&opts::OPTS_EVER_IMM_EXT, 13)]
#[case::all_immediate_batch_64(&opts::OPTS_EVER_IMM_EXT, 64)]
#[case::all_immediate_batch_67(&opts::OPTS_EVER_IMM_EXT, 67)]
#[case::all_immediate_batch_128(&opts::OPTS_EVER_IMM_EXT, 128)]
#[case::all_deferred_batch_0(&opts::OPTS_EVER_DEF_EXT, 0)]
#[case::all_deferred_batch_13(&opts::OPTS_EVER_DEF_EXT, 13)]
#[case::all_deferred_batch_64(&opts::OPTS_EVER_DEF_EXT, 64)]
#[case::all_deferred_batch_67(&opts::OPTS_EVER_DEF_EXT, 67)]
#[case::all_deferred_batch_128(&opts::OPTS_EVER_DEF_EXT, 128)]
fn test_marf_cache_128_128(#[case] marf_opts: &MARFOpenOpts, #[case] batch_size: usize) {
    let test_data = make_test_insert_data(128, 128);
    let root_hash =
        utils::run_test_with_string_keys(function_name_no_ns!(), &test_data, marf_opts, batch_size);
    assert_eq!(
        "a19887150b55ced50245a7c29b037e037dd99234ab9dda4a12c9c48fc698b47d",
        root_hash.to_hex()
    );
}

/// Tests MARF cache behavior (no compression) using 15.500 inserts across 10 blocks.
///
/// The batch size is intentionally set above 10.000 to force batched insertion
/// and exercise the `eta` batching logic.
/// For all configurations, the resulting root hash must remain stable.
#[rstest]
#[case::noop_immediate_batch_15500(&opts::OPTS_NOOP_IMM_EXT, 15500)]
#[case::node256_deferred_batch_15500(&opts::OPTS_N256_DEF_EXT, 15500)]
fn test_marf_cache_15500_10(#[case] marf_opts: &MARFOpenOpts, #[case] batch_size: usize) {
    let test_data = make_test_insert_data(15500, 10);
    let root_hash =
        utils::run_test_with_string_keys(function_name_no_ns!(), &test_data, marf_opts, batch_size);
    assert_eq!(
        "d579b5f6ac46ee7ac40376cf88dd4b1fef93e1963ccf82bd7c8b0aeb08d52bf9",
        root_hash.to_hex()
    );
}

/// Tests MARF cache behavior with compression using 1 insert across 256 blocks.
///
/// The purpose of this test is to verify that enabling compression produces
/// the same root hash as running without compression.
/// For all configurations, the resulting root hash must remain stable.
#[rstest]
#[case::noop_immediate(&opts::OPTS_NOOP_IMM_EXT)]
#[case::noop_immediate_compress(&opts::OPTS_NOOP_IMM_EXT_COMP)]
#[case::noop_deferred_compress(&opts::OPTS_NOOP_DEF_EXT_COMP)]
fn test_marf_compress_1_256(#[case] marf_opts: &MARFOpenOpts) {
    let test_data = make_test_insert_data(1, 256);
    let root_hash =
        utils::run_test_with_string_keys(function_name_no_ns!(), &test_data, marf_opts, 0);
    assert_eq!(
        "121bc70a287841705094027210e4fe03a89a9f090d2df80a4a8c1d782623fdf0",
        root_hash.to_hex()
    );
}

/// Tests MARF cache behavior with compression using 2048 insert within 1 block.
///
/// The purpose of this test is to verify that enabling compression produces
/// the same root hash as running without compression.
/// For all configurations, the resulting root hash must remain stable.
#[rstest]
#[case::noop_immediate(&opts::OPTS_NOOP_IMM_EXT)]
#[case::noop_immediate_compress(&opts::OPTS_NOOP_IMM_EXT_COMP)]
#[case::noop_deferred_compress(&opts::OPTS_NOOP_DEF_EXT_COMP)]
fn test_marf_compressed_2048_1(#[case] marf_opts: &MARFOpenOpts) {
    let test_data = make_test_insert_data(2048, 1);
    let root_hash =
        utils::run_test_with_string_keys(function_name_no_ns!(), &test_data, marf_opts, 8);
    assert_eq!(
        "1db4f6390c21e80600fbbd3f5a6df2875a92aa5680d1448b560356dc6489a805",
        root_hash.to_hex()
    );
}

/// Tests MARF cache behavior with compression using 8 insert across 256 blocks.
///
/// The purpose of this test is to verify that enabling compression produces
/// the same root hash as running without compression.
/// For all configurations, the resulting root hash must remain stable.
#[rstest]
#[case::noop_immediate_batch_8(&opts::OPTS_NOOP_IMM_EXT, 8)]
#[case::noop_immediate_compress_batch_8(&opts::OPTS_NOOP_IMM_EXT_COMP, 8)]
#[case::noop_immediate_compress_batch_5(&opts::OPTS_NOOP_IMM_EXT_COMP, 5)]
fn test_marf_compress_8_256(#[case] marf_opts: &MARFOpenOpts, #[case] batch_size: usize) {
    let test_data = make_test_insert_data(8, 256);
    let root_hash =
        utils::run_test_with_string_keys(function_name_no_ns!(), &test_data, marf_opts, batch_size);
    assert_eq!(
        "7f69e13a7ff6911a9fa79b3592c8432536adc30d39accb5a7070eff0cb71beef",
        root_hash.to_hex()
    );
}

/// Tests MARF cache behavior with compression during repeated path expansion.
///
/// This test exercises the expansion of a single trie path through successive
/// node types (leaf, node4, node16, node48, and then node256), ensuring that the
/// resulting patch nodes are correctly produced and can be read back.
/// For all configurations, the resulting root hash must remain stable.
#[rstest]
#[case::noop_immediate_compress(&opts::OPTS_NOOP_IMM_EXT_COMP)]
#[case::noop_deferred_compress(&opts::OPTS_NOOP_DEF_EXT_COMP)]
fn test_marf_patch_expansion(#[case] marf_opts: &MARFOpenOpts) {
    let test_data: Vec<_> = (0u8..=255u8)
        .map(|i| {
            let mut path = [0u8; 32];
            path[31] = i;
            vec![(TrieHash(path), MARFValue::from(u32::from(i)))]
        })
        .collect();
    let root_hash =
        utils::run_test_with_triehash_keys(function_name_no_ns!(), &test_data, marf_opts);
    assert_eq!(
        "aa05b16d1c59a9cb019efeac1276dfdec41f932072d2254d35675c691f79214e",
        root_hash.to_hex()
    );
}
