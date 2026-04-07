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

//! Benchmark comparing contract execution with and without the contract cache.
//!
//! Run with: `cargo bench -p clarity --bench contract_cache`

use std::hint::black_box;
use std::time::Duration;

use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::database::{ClarityDatabase, ContractCache, MemoryBackingStore};
use clarity::vm::test_util::symbols_from_values;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use stacks_common::types::StacksEpochId;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const EPOCH: StacksEpochId = StacksEpochId::Epoch21;

const CALLEE_CONTRACT: &str = "
    (define-data-var counter uint u0)
    (define-map balances { owner: principal } { amount: uint })

    (define-read-only (get-counter)
      (var-get counter))

    (define-public (increment (amount uint))
      (begin
        (var-set counter (+ (var-get counter) amount))
        (ok (var-get counter))))

    (define-public (store (owner principal) (amount uint))
      (begin
        (map-set balances { owner: owner } { amount: amount })
        (try! (increment amount))
        (ok true)))
";

const CALLER_CONTRACT: &str = "
    (define-public (proxy-increment (amount uint))
      (contract-call? .callee increment amount))

    (define-public (proxy-store (owner principal) (amount uint))
      (contract-call? .callee store owner amount))
";

// Deep call chain: 4 layers + orchestrator with fold.

const LAYER_0: &str = "
    (define-data-var counter uint u0)
    (define-public (execute (amount uint))
      (begin
        (var-set counter (+ (var-get counter) amount))
        (ok (var-get counter))))
";

const LAYER_1: &str = "
    (define-public (execute (amount uint))
      (contract-call? .layer-0 execute amount))
";

const LAYER_2: &str = "
    (define-public (execute (amount uint))
      (contract-call? .layer-1 execute amount))
";

const LAYER_3: &str = "
    (define-public (execute (amount uint))
      (contract-call? .layer-2 execute amount))
";

const ORCHESTRATOR: &str = "
    (define-private (process-one (amount uint) (acc uint))
      (let ((result (unwrap-panic (contract-call? .layer-3 execute amount))))
        (+ acc result)))

    (define-public (run-batch)
      (ok (fold process-one
        (list u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1 u1)
        u0)))
";

fn sender() -> PrincipalData {
    PrincipalData::parse("SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE").unwrap()
}

/// Deploy test contracts and prepare the store for benchmarking.
fn setup_store(store: &mut MemoryBackingStore) {
    let mut db = store.as_clarity_db();
    db.begin();
    db.set_clarity_epoch_version(EPOCH).unwrap();
    db.commit().unwrap();

    let mut owned_env = OwnedEnvironment::new(db, EPOCH);

    let callee_id = QualifiedContractIdentifier::local("callee").unwrap();
    owned_env
        .initialize_contract(callee_id, CALLEE_CONTRACT, None)
        .unwrap();

    let caller_id = QualifiedContractIdentifier::local("caller").unwrap();
    owned_env
        .initialize_contract(caller_id, CALLER_CONTRACT, None)
        .unwrap();
}

/// Deploy the deep call chain contracts (layer-0 through layer-3 + orchestrator).
fn setup_deep_chain(store: &mut MemoryBackingStore) {
    let mut db = store.as_clarity_db();
    db.begin();
    db.set_clarity_epoch_version(EPOCH).unwrap();
    db.commit().unwrap();

    let mut owned_env = OwnedEnvironment::new(db, EPOCH);
    for (name, src) in [
        ("layer-0", LAYER_0),
        ("layer-1", LAYER_1),
        ("layer-2", LAYER_2),
        ("layer-3", LAYER_3),
        ("orchestrator", ORCHESTRATOR),
    ] {
        let id = QualifiedContractIdentifier::local(name).unwrap();
        owned_env.initialize_contract(id, src, None).unwrap();
    }
}

/// Create an OwnedEnvironment from a store, optionally with a cache attached.
fn make_env<'a>(
    db: ClarityDatabase<'a>,
    cache: Option<&'a ContractCache>,
) -> OwnedEnvironment<'a, 'a> {
    let mut db = db;
    db.set_contract_cache(cache);
    OwnedEnvironment::new(db, EPOCH)
}

fn bench_direct_call(c: &mut Criterion) {
    let mut group = c.benchmark_group("direct_call");
    let sender = sender();
    let callee_id = QualifiedContractIdentifier::local("callee").unwrap();
    let args = symbols_from_values(vec![Value::UInt(1)]);

    for (label, use_cache) in [("no_cache", false), ("cached", true)] {
        group.bench_function(BenchmarkId::new("increment", label), |b| {
            let mut store = MemoryBackingStore::new();
            setup_store(&mut store);
            let cache = ContractCache::new(64 * 1024 * 1024);
            let db = store.as_clarity_db();
            let mut env = make_env(db, if use_cache { Some(&cache) } else { None });

            b.iter_batched(
                || (sender.clone(), callee_id.clone()),
                |(s, id)| {
                    black_box(
                        env.execute_transaction(s, None, id, "increment", &args)
                            .unwrap(),
                    )
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_contract_call(c: &mut Criterion) {
    let mut group = c.benchmark_group("contract_call");
    let sender = sender();
    let caller_id = QualifiedContractIdentifier::local("caller").unwrap();
    let args = symbols_from_values(vec![Value::UInt(1)]);

    for (label, use_cache) in [("no_cache", false), ("cached", true)] {
        group.bench_function(BenchmarkId::new("proxy_increment", label), |b| {
            let mut store = MemoryBackingStore::new();
            setup_store(&mut store);
            let cache = ContractCache::new(64 * 1024 * 1024);
            let db = store.as_clarity_db();
            let mut env = make_env(db, if use_cache { Some(&cache) } else { None });

            b.iter_batched(
                || (sender.clone(), caller_id.clone()),
                |(s, id)| {
                    black_box(
                        env.execute_transaction(s, None, id, "proxy-increment", &args)
                            .unwrap(),
                    )
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_repeated_calls(c: &mut Criterion) {
    let mut group = c.benchmark_group("repeated_calls");
    group.sample_size(150);
    group.measurement_time(Duration::from_secs(20));
    let sender = sender();
    let caller_id = QualifiedContractIdentifier::local("caller").unwrap();
    let args = symbols_from_values(vec![Value::UInt(1)]);

    for (label, use_cache) in [("no_cache", false), ("cached", true)] {
        group.bench_function(BenchmarkId::new("10x_proxy_increment", label), |b| {
            let mut store = MemoryBackingStore::new();
            setup_store(&mut store);
            let cache = ContractCache::new(64 * 1024 * 1024);
            let db = store.as_clarity_db();
            let mut env = make_env(db, if use_cache { Some(&cache) } else { None });

            b.iter_batched(
                || std::array::from_fn::<_, 10, _>(|_| (sender.clone(), caller_id.clone())),
                |batch| {
                    for (s, id) in batch {
                        black_box(
                            env.execute_transaction(s, None, id, "proxy-increment", &args)
                                .unwrap(),
                        );
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// 4-deep `contract-call?` chain × 20 fold iterations including nested calls.
fn bench_deep_fold(c: &mut Criterion) {
    let mut group = c.benchmark_group("deep_fold");
    group.sample_size(150);
    group.measurement_time(Duration::from_secs(20));
    let sender = sender();
    let orch_id = QualifiedContractIdentifier::local("orchestrator").unwrap();

    for (label, use_cache) in [("no_cache", false), ("cached", true)] {
        group.bench_function(BenchmarkId::new("4_deep_x20_fold", label), |b| {
            let mut store = MemoryBackingStore::new();
            setup_deep_chain(&mut store);
            let cache = ContractCache::new(64 * 1024 * 1024);
            let db = store.as_clarity_db();
            let mut env = make_env(db, if use_cache { Some(&cache) } else { None });

            b.iter_batched(
                || (sender.clone(), orch_id.clone()),
                |(s, id)| {
                    black_box(
                        env.execute_transaction(s, None, id, "run-batch", &[])
                            .unwrap(),
                    )
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(300)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(5))
        .noise_threshold(0.03)
        .nresamples(200_000);
    targets = bench_direct_call, bench_contract_call, bench_repeated_calls, bench_deep_fold
}
criterion_main!(benches);
