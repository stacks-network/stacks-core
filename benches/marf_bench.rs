#[macro_use]
extern crate criterion;
extern crate blockstack_lib;
extern crate rand;

use std::fs;

use rand::prelude::*;

use blockstack_lib::chainstate::stacks::index::{marf::MARF, storage::TrieFileStorage};
use blockstack_lib::types::chainstate::MARFValue;
use blockstack_lib::types::BlockHeaderHash;
use criterion::Criterion;

fn benchmark_marf_usage(
    filename: &str,
    blocks: u32,
    writes_per_block: u32,
    reads_per_block: u32,
    batch: bool,
) {
    if fs::metadata(filename).is_ok() {
        fs::remove_file(filename).unwrap();
    };
    let f = TrieFileStorage::new(filename).unwrap();
    let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
    let mut marf = MARF::from_storage(f);
    marf.begin(&TrieFileStorage::block_sentinel(), &block_header)
        .unwrap();

    let mut rng = rand::thread_rng();

    let mut values = vec![];

    for i in 0..blocks {
        if batch {
            let mut batch_keys = Vec::new();
            let mut batch_vals = Vec::new();
            for k in 0..writes_per_block {
                let key = format!("{}::{}", i, k);
                let mut value = [0u8; 40];
                rng.fill_bytes(&mut value);
                batch_keys.push(key.clone());
                batch_vals.push(MARFValue(value.clone()));
                values.push((key, MARFValue(value)));
            }
            marf.insert_batch(&batch_keys, batch_vals).unwrap();
        } else {
            for k in 0..writes_per_block {
                let key = format!("{}::{}", i, k);
                let mut value = [0u8; 40];
                rng.fill_bytes(&mut value);
                marf.insert(&key, MARFValue(value.clone())).unwrap();
                values.push((key, MARFValue(value)));
            }
        }

        for _k in 0..reads_per_block {
            let (key, value) = values.as_slice().choose(&mut rng).unwrap();
            assert_eq!(marf.get(&block_header, key).unwrap().unwrap(), *value);
        }

        let mut next_block_header = (i + 1).to_le_bytes().to_vec();
        next_block_header.resize(32, 0);
        let next_block_header = BlockHeaderHash::from_bytes(next_block_header.as_slice()).unwrap();

        marf.commit().unwrap();
        marf.begin(&block_header, &next_block_header).unwrap();
        block_header = next_block_header;
    }
    marf.commit().unwrap();
}

fn benchmark_marf_read(filename: &str, reads: u32, block: u32, writes_per_block: u32) {
    let f = TrieFileStorage::new(filename).unwrap();
    let mut block_header = block.to_le_bytes().to_vec();
    block_header.resize(32, 0);
    let block_header = BlockHeaderHash::from_bytes(block_header.as_slice()).unwrap();

    let mut marf = MARF::from_storage(f);

    let mut rng = rand::thread_rng();

    for _i in 0..reads {
        let i: u32 = rng.gen_range(0, block);
        let k: u32 = rng.gen_range(0, writes_per_block);
        let key = format!("{}::{}", i, k);
        marf.get(&block_header, &key).unwrap().unwrap();
    }
}

pub fn basic_usage_benchmark(c: &mut Criterion) {
    c.bench_function("marf_setup_1000b_5kW", |b| {
        b.iter(|| benchmark_marf_usage("/tmp/db.1k.sqlite", 1000, 5000, 0, false))
    });
    c.bench_function("marf_setup_400b_5kW", |b| {
        b.iter(|| benchmark_marf_usage("/tmp/db.400.sqlite", 1000, 5000, 0, false))
    });
    c.bench_function("marf_read_1000b_1kW", |b| {
        b.iter(|| benchmark_marf_read("/tmp/db.1k.sqlite", 1000, 1000, 5000))
    });
    c.bench_function("marf_read_400b_1kW", |b| {
        b.iter(|| benchmark_marf_read("/tmp/db.400.sqlite", 1000, 400, 5000))
    });

    c.bench_function("marf_usage_1b_10kW_0kR", |b| {
        b.iter(|| benchmark_marf_usage("/tmp/foo.bar.z.sqlite", 1, 10000, 0, false))
    });
    c.bench_function("marf_usage_10b_1kW_2kR", |b| {
        b.iter(|| benchmark_marf_usage("/tmp/foo.bar.z.sqlite", 10, 1000, 2000, false))
    });
    c.bench_function("marf_usage_100b_5kW_20kR", |b| {
        b.iter(|| benchmark_marf_usage("/tmp/foo.bar.z.sqlite", 20, 5000, 20000, false))
    });
    c.bench_function("marf_usage_batches_10b_1kW_2kR", |b| {
        b.iter(|| benchmark_marf_usage("/tmp/foo.bar.z.sqlite", 10, 1000, 2000, true))
    });
}

pub fn scaling_read_ratio(_c: &mut Criterion) {}

criterion_group!(benches, basic_usage_benchmark);
criterion_main!(benches);
