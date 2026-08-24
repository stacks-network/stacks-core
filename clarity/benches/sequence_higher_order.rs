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

//! End-to-end benchmarks for `fold`, `map`, and `filter` after the
//! `IntoIterator` + `apply_evaluated` refactor.
//!
//! Previous behaviour (pre-refactor):
//!   `atom_values()` → `Vec<SymbolicExpression>` (N wrapper allocations)
//!   → each element fed through `apply()` → `eval()` → `Value` (N eval round-trips)
//!
//! Current behaviour:
//!   `SequenceData::into_iter()` (lazy, zero intermediate Vec)
//!   → element passed directly to `apply_evaluated()` (no SymbolicExpression wrap/unwrap)
//!
//! Three groups:
//!   `higher_order/fold`   — sum a list of integers via `fold`
//!   `higher_order/map`    — increment every element via `map`
//!   `higher_order/filter` — keep even elements via `filter`
//!
//! Each group varies the list size across [100, 500, 2000] to show scaling.

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

const VERSION: ClarityVersion = ClarityVersion::Clarity2;
const EPOCH: StacksEpochId = StacksEpochId::Epoch34;

// ---------------------------------------------------------------------------
// Helpers (identical to value_ref.rs)
// ---------------------------------------------------------------------------

fn parse(source: &str) -> Vec<SymbolicExpression> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut cost = LimitedCostTracker::new_free();
    ast::build_ast(&contract_id, source, &mut cost, VERSION, EPOCH)
        .expect("failed to parse benchmark program")
        .expressions
}

fn run(parsed: &[SymbolicExpression], mut marf: MemoryBackingStore) {
    let contract_id = QualifiedContractIdentifier::transient();
    let db = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        db,
        LimitedCostTracker::new_free(),
        EPOCH,
    );
    let mut ctx = ContractContext::new(contract_id, VERSION);
    black_box(
        global_context
            .execute(|g| eval_all(parsed, &mut ctx, g, None))
            .unwrap(),
    );
    black_box(&ctx);
}

// ---------------------------------------------------------------------------
// Program generators
// ---------------------------------------------------------------------------

/// `(fold add-one-acc (list 0 1 … n-1) 0)` — accumulates a sum.
/// Each fold step calls a private function that does `(+ acc elem)`.
fn make_fold_sum_program(n: usize) -> String {
    let list_elems: String = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
    format!(
        r#"
(define-private (add-to-acc (elem int) (acc int))
  (+ acc elem))
(fold add-to-acc (list {list_elems}) 0)"#
    )
}

/// `(map inc-elem (list 0 1 … n-1))` — increments every element.
fn make_map_increment_program(n: usize) -> String {
    let list_elems: String = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
    format!(
        r#"
(define-private (inc-elem (x int))
  (+ x 1))
(map inc-elem (list {list_elems}))"#
    )
}

/// `(filter is-even (list 0 1 … n-1))` — keeps even elements.
fn make_filter_even_program(n: usize) -> String {
    let list_elems: String = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
    format!(
        r#"
(define-private (is-even (x int))
  (is-eq (mod x 2) 0))
(filter is-even (list {list_elems}))"#
    )
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_fold(c: &mut Criterion) {
    let mut group = c.benchmark_group("higher_order/fold");
    for &n in &[100usize, 500, 2000] {
        let program = make_fold_sum_program(n);
        let parsed = parse(&program);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(black_box(&parsed), marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("higher_order/map");
    for &n in &[100usize, 500, 2000] {
        let program = make_map_increment_program(n);
        let parsed = parse(&program);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(black_box(&parsed), marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("higher_order/filter");
    for &n in &[100usize, 500, 2000] {
        let program = make_filter_even_program(n);
        let parsed = parse(&program);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(black_box(&parsed), marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fold, bench_map, bench_filter);
criterion_main!(benches);
