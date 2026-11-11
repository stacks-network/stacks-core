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

//! Benchmarks for the ValueRef zero-copy variable lookup change.
//!
//! Compares Epoch33 (old: `lookup_variable` always clones + sanitizes) against
//! Epoch34 (new: `lookup_variable` returns a borrowed reference for pre-sanitized
//! epochs, deferring or eliminating the clone entirely).
//!
//! Three scenarios exercise the primary beneficiaries:
//!
//! 1. `fold_buf_cmp`   — fold over a list where each step does `(>= BIG-BUF BIG-BUF)`.
//!    Each step looks up a 128-byte contract constant twice.  `special_geq_v2` uses
//!    `as_ref()` throughout, so Epoch34 allocates nothing for the operands.
//!
//! 2. `fold_ascii_cmp` — same pattern with a 128-char ASCII string constant.
//!
//! 3. `let_local_refs` — a `let` that binds a 128-byte buffer to `x`, then references
//!    `x` N times via `(>= x 0x00)`.  Shows the local-variable lookup benefit.

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse(source: &str, epoch: StacksEpochId) -> Vec<SymbolicExpression> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut cost = LimitedCostTracker::new_free();
    ast::build_ast(&contract_id, source, &mut cost, VERSION, epoch)
        .expect("failed to parse benchmark program")
        .expressions
}

/// Execute `parsed` in a fresh environment for `epoch`.
/// `marf` is provided by the caller (created in `iter_batched` setup) so that
/// SQLite initialisation is excluded from the timing window.
fn run(parsed: &[SymbolicExpression], epoch: StacksEpochId, mut marf: MemoryBackingStore) {
    let contract_id = QualifiedContractIdentifier::transient();
    let db = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        db,
        LimitedCostTracker::new_free(),
        epoch,
    );
    let mut ctx = ContractContext::new(contract_id, VERSION);
    black_box(
        global_context
            .execute(|g| eval_all(parsed, &mut ctx, g, None))
            .unwrap(),
    );
}

// ---------------------------------------------------------------------------
// Program generators
// ---------------------------------------------------------------------------

/// `(fold cmp-step (list 1 … steps) true)` where `cmp-step` does
/// `(>= BIG-BUF BIG-BUF)` — 2 contract-constant lookups per step.
fn make_fold_buf_program(steps: usize) -> String {
    let buf_hex = "ab".repeat(128); // 128-byte buffer
    let list_elems = (1..=steps)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"
(define-constant BIG-BUF 0x{buf_hex})
(define-private (cmp-step (i int) (acc bool))
  (>= BIG-BUF BIG-BUF))
(fold cmp-step (list {list_elems}) true)"#
    )
}

/// Same as above but with a 128-char ASCII string constant.
fn make_fold_ascii_program(steps: usize) -> String {
    let str_content = "a".repeat(128);
    let list_elems = (1..=steps)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"
(define-constant BIG-STR "{str_content}")
(define-private (cmp-step (i int) (acc bool))
  (>= BIG-STR BIG-STR))
(fold cmp-step (list {list_elems}) true)"#
    )
}

/// `(let ((x BIG-BUF)) (and (>= x 0x00) … refs times …))`
/// Measures lookup of a local context variable `refs` times.
fn make_let_local_program(refs: usize) -> String {
    let buf_hex = "ab".repeat(128);
    let comparisons = (0..refs)
        .map(|_| "(>= x 0x00)".to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"
(define-constant BIG-BUF 0x{buf_hex})
(let ((x BIG-BUF))
  (and {comparisons}))"#
    )
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_fold_buf(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_ref/fold_buf_cmp");
    for &steps in &[50usize, 200] {
        let program = make_fold_buf_program(steps);
        let parsed_33 = parse(&program, StacksEpochId::Epoch33);
        let parsed_34 = parse(&program, StacksEpochId::Epoch34);

        group.bench_function(BenchmarkId::new("epoch33", steps), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(&parsed_33, StacksEpochId::Epoch33, marf),
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("epoch34", steps), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(&parsed_34, StacksEpochId::Epoch34, marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_fold_ascii(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_ref/fold_ascii_cmp");
    for &steps in &[50usize, 200] {
        let program = make_fold_ascii_program(steps);
        let parsed_33 = parse(&program, StacksEpochId::Epoch33);
        let parsed_34 = parse(&program, StacksEpochId::Epoch34);

        group.bench_function(BenchmarkId::new("epoch33", steps), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(&parsed_33, StacksEpochId::Epoch33, marf),
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("epoch34", steps), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(&parsed_34, StacksEpochId::Epoch34, marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_let_local(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_ref/let_local_refs");
    for &refs in &[10usize, 50] {
        let program = make_let_local_program(refs);
        let parsed_33 = parse(&program, StacksEpochId::Epoch33);
        let parsed_34 = parse(&program, StacksEpochId::Epoch34);

        group.bench_function(BenchmarkId::new("epoch33", refs), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(&parsed_33, StacksEpochId::Epoch33, marf),
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("epoch34", refs), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(&parsed_34, StacksEpochId::Epoch34, marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fold_buf, bench_fold_ascii, bench_let_local);
criterion_main!(benches);
