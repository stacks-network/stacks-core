extern crate blockstack_lib;
extern crate criterion;
extern crate rand;

use blockstack_lib::address::c32::{c32_address, c32_address_decode};
use blockstack_lib::address::c32_old::c32_address_decode as c32_address_decode_old;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::Rng;

fn bench_c32_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("C32 Decoding");

    let mut addrs: Vec<String> = vec![];
    for _ in 0..5 {
        // random version
        let random_version: u8 = rand::thread_rng().gen_range(0, 31);
        // random 20 bytes
        let random_bytes = rand::thread_rng().gen::<[u8; 20]>();
        let addr = c32_address(random_version, &random_bytes).unwrap();
        addrs.push(addr);
    }

    for addr in addrs.iter() {
        group.bench_with_input(BenchmarkId::new("Legacy", addr), addr, |b, i| {
            b.iter(|| c32_address_decode_old(i))
        });
        group.bench_with_input(BenchmarkId::new("Updated", addr), addr, |b, i| {
            b.iter(|| c32_address_decode(i))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_c32_decoding);
criterion_main!(benches);
