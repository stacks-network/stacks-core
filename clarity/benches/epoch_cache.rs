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

//! Baseline benchmarks for `get_clarity_epoch_version()` overhead.
//!
//! These benchmarks exercise the DB-heavy hot paths that call
//! `get_clarity_epoch_version()` on every operation:
//!
//! 1. **map_set_get** — Repeated `(map-set …)` + `(map-get? …)` in a loop.
//!    Each `map-set` calls `get_clarity_epoch_version()` twice (key + value
//!    `admits` checks). Each `map-get?` calls it once. This is the single
//!    hottest path for epoch lookups.
//!
//! 2. **var_set_get** — Repeated `(var-set …)` + `(var-get …)`.
//!    Each `var-set` calls `get_clarity_epoch_version()` once for the
//!    `admits` check.
//!
//! 3. **contract_call_heavy** — Inter-contract calls that trigger
//!    `get_contract` → `get_clarity_epoch_version()` on every call.
//!
//! Run with:
//!   cargo bench --bench epoch_cache -p clarity

use std::hint::black_box;

use clarity::vm::contexts::{ContractContext, GlobalContext};
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::version::ClarityVersion;
use clarity::vm::{ast, eval_all};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse(source: &str) -> Vec<SymbolicExpression> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut cost = LimitedCostTracker::new_free();
    ast::build_ast(
        &contract_id,
        source,
        &mut cost,
        ClarityVersion::Clarity2,
        StacksEpochId::Epoch30,
    )
    .expect("failed to parse benchmark program")
    .expressions
}

/// Create a `MemoryBackingStore` with the epoch stored in the KV store,
/// matching production behavior where the epoch is written during epoch
/// initialization.
fn setup_store() -> MemoryBackingStore {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_clarity_db();
    db.begin();
    db.set_clarity_epoch_version(StacksEpochId::Epoch30)
        .expect("failed to set epoch");
    db.commit().unwrap();
    marf
}

/// Execute `parsed` in a fresh environment.
/// `marf` is provided by the caller (created in `iter_batched` setup) so that
/// SQLite initialisation is excluded from the timing window.
fn run(parsed: &[SymbolicExpression], mut marf: MemoryBackingStore) {
    let contract_id = QualifiedContractIdentifier::transient();
    let db = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        db,
        LimitedCostTracker::new_free(),
        StacksEpochId::Epoch30,
    );
    let mut ctx = ContractContext::new(contract_id, ClarityVersion::Clarity2);
    black_box(
        global_context
            .execute(|g| eval_all(parsed, &mut ctx, g, None))
            .unwrap(),
    );
}

// ---------------------------------------------------------------------------
// Program generators
// ---------------------------------------------------------------------------

/// Generates a program that defines a map and does `iters` rounds of
/// `(map-set …)` + `(map-get? …)`.
///
/// Each map-set triggers 2× `get_clarity_epoch_version()` (key admits + value
/// admits) plus serialization. Each map-get triggers 1× epoch lookup.
/// Total epoch lookups ≈ 3 × iters.
fn make_map_program(iters: usize) -> String {
    // Build a sequence of (map-set m {id: <i>} {val: <i>}) (map-get? m {id: <i>})
    let mut body = String::new();
    for i in 0..iters {
        body.push_str(&format!(
            "(map-set m {{id: {i}}} {{val: {i}}})\n\
             (map-get? m {{id: {i}}})\n"
        ));
    }
    format!(
        "(define-map m {{id: int}} {{val: int}})\n\
         {body}\n\
         true"
    )
}

/// Generates a program that defines a data-var and does `iters` rounds of
/// `(var-set …)` + `(var-get …)`.
///
/// Each var-set triggers 1× `get_clarity_epoch_version()` (admits check).
/// Total epoch lookups ≈ iters.
fn make_var_program(iters: usize) -> String {
    let mut body = String::new();
    for i in 0..iters {
        body.push_str(&format!(
            "(var-set counter {i})\n\
             (var-get counter)\n"
        ));
    }
    format!(
        "(define-data-var counter int 0)\n\
         {body}\n\
         true"
    )
}

/// Generates a program that does `iters` intra-contract private function calls,
/// each of which reads a data-var (triggering epoch lookups).
///
/// This exercises the var-get path under call overhead, closer to real workloads.
fn make_call_heavy_program(iters: usize) -> String {
    let calls = (0..iters)
        .map(|_| "(do-read)".to_string())
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "(define-data-var counter int 0)\n\
         (define-private (do-read) (var-get counter))\n\
         {calls}\n\
         true"
    )
}

/// Generates a program that does `iters` rounds of map-insert (checking
/// existence via full deserialization) + map-delete.
///
/// `map-insert` calls `get_clarity_epoch_version()` 2× for admits, then
/// `data_map_entry_exists` which does a full get+deserialize.
/// `map-delete` calls `get_clarity_epoch_version()` 1× for admits.
/// Total epoch lookups ≈ 3 × iters.
fn make_map_insert_delete_program(iters: usize) -> String {
    let mut body = String::new();
    for i in 0..iters {
        body.push_str(&format!(
            "(map-insert m {{id: {i}}} {{val: {i}}})\n\
             (map-delete m {{id: {i}}})\n"
        ));
    }
    format!(
        "(define-map m {{id: int}} {{val: int}})\n\
         {body}\n\
         true"
    )
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_map_set_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("epoch_cache/map_set_get");
    for &iters in &[50usize, 200] {
        let program = make_map_program(iters);
        let parsed = parse(&program);

        group.bench_function(BenchmarkId::new("iters", iters), |b| {
            b.iter_batched(
                setup_store,
                |marf| run(&parsed, marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_var_set_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("epoch_cache/var_set_get");
    for &iters in &[50usize, 200] {
        let program = make_var_program(iters);
        let parsed = parse(&program);

        group.bench_function(BenchmarkId::new("iters", iters), |b| {
            b.iter_batched(
                setup_store,
                |marf| run(&parsed, marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_call_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("epoch_cache/call_heavy");
    for &iters in &[50usize, 200] {
        let program = make_call_heavy_program(iters);
        let parsed = parse(&program);

        group.bench_function(BenchmarkId::new("iters", iters), |b| {
            b.iter_batched(
                setup_store,
                |marf| run(&parsed, marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_map_insert_delete(c: &mut Criterion) {
    let mut group = c.benchmark_group("epoch_cache/map_insert_delete");
    for &iters in &[50usize, 200] {
        let program = make_map_insert_delete_program(iters);
        let parsed = parse(&program);

        group.bench_function(BenchmarkId::new("iters", iters), |b| {
            b.iter_batched(
                setup_store,
                |marf| run(&parsed, marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_map_set_get,
    bench_var_set_get,
    bench_call_heavy,
    bench_map_insert_delete,
);
criterion_main!(benches);
