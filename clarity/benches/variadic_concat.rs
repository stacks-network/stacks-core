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

//! End-to-end benchmarks for Clarity 6's variadic `concat` runtime
//! (`special_concat_v600`).
//!
//! `concat` reuses the existing `ClarityCostFunction::Concat` cost
//! function with `linear(total_len, 37, 220)` — i.e., 37 cost units per
//! byte of combined output plus 220 fixed per call. The variadic
//! implementation charges this once per `(concat ...)` invocation, with
//! `n = total_len`, regardless of arity. The 2-arg case is therefore
//! byte-for-byte equivalent to the pre-Clarity-6 v205 implementation.
//!
//! These benchmarks measure actual runtime cost so that the calibration
//! of `linear(n, 37, 220)` can be validated against real execution time,
//! and so regressions in `special_concat_v600` (the two-pass evaluate /
//! reserve / append path) get caught.
//!
//! Three groups:
//!   `variadic_concat/by_arg_count`     — fixed per-arg size, vary N
//!   `variadic_concat/by_total_size`    — vary total bytes at fixed N
//!   `variadic_concat/nested_vs_variadic` — same total work, two syntactic
//!                                          forms, to validate the
//!                                          variadic-is-cheaper property.

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

const VERSION: ClarityVersion = ClarityVersion::Clarity6;
const EPOCH: StacksEpochId = StacksEpochId::Epoch40;

// ---------------------------------------------------------------------------
// Helpers
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

/// Build a hex-encoded buffer literal of `bytes_per_arg` bytes containing
/// repeated `0xab`s. Cheap to generate and produces a deterministic input.
fn buff_literal(bytes_per_arg: usize) -> String {
    let mut s = String::with_capacity(2 + bytes_per_arg * 2);
    s.push_str("0x");
    for _ in 0..bytes_per_arg {
        s.push_str("ab");
    }
    s
}

// ---------------------------------------------------------------------------
// Program generators
// ---------------------------------------------------------------------------

/// `(concat <arg> <arg> ... <arg>)` with `n_args` copies of the same arg.
fn make_variadic_concat_program(n_args: usize, bytes_per_arg: usize) -> String {
    let arg = buff_literal(bytes_per_arg);
    let args: Vec<&str> = std::iter::repeat(arg.as_str()).take(n_args).collect();
    format!("(concat {})", args.join(" "))
}

/// `(concat (concat (concat ... a b) c) d)` — the equivalent left-nested
/// binary chain for `n_args` total arguments. Used to compare variadic
/// vs. nested-binary cost and runtime.
fn make_nested_binary_concat_program(n_args: usize, bytes_per_arg: usize) -> String {
    assert!(n_args >= 2, "concat requires ≥2 args");
    let arg = buff_literal(bytes_per_arg);
    let mut expr = format!("(concat {arg} {arg})");
    for _ in 2..n_args {
        expr = format!("(concat {expr} {arg})");
    }
    expr
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

/// Vary the argument count at a fixed per-arg size. This isolates per-arg
/// overhead from per-byte work. With a small per-arg size, any non-linear
/// behavior in N would show up here.
fn bench_by_arg_count(c: &mut Criterion) {
    let bytes_per_arg = 32;
    let mut group = c.benchmark_group("variadic_concat/by_arg_count");
    for &n_args in &[2usize, 4, 16, 64, 256] {
        let program = make_variadic_concat_program(n_args, bytes_per_arg);
        let parsed = parse(&program);
        group.bench_function(BenchmarkId::from_parameter(n_args), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(black_box(&parsed), marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Vary the total byte count at a fixed argument count. This isolates the
/// per-byte memcpy cost — should be linear in total bytes if the cost
/// formula `linear(total_len, 37, 220)` is accurate.
fn bench_by_total_size(c: &mut Criterion) {
    let n_args = 8;
    let mut group = c.benchmark_group("variadic_concat/by_total_size");
    for &bytes_per_arg in &[16usize, 64, 256, 1024, 4096] {
        let program = make_variadic_concat_program(n_args, bytes_per_arg);
        let parsed = parse(&program);
        group.bench_function(BenchmarkId::from_parameter(n_args * bytes_per_arg), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(black_box(&parsed), marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Compare `(concat a b c d ...)` against `(concat (concat ... a b) c)`.
/// Both produce identical output and copy the same number of bytes — the
/// variadic form should be faster because it does one allocation + N-1
/// appends, while the nested form does N-1 separate concat invocations,
/// each with its own dispatch and reserve.
fn bench_nested_vs_variadic(c: &mut Criterion) {
    let bytes_per_arg = 64;
    let mut group = c.benchmark_group("variadic_concat/nested_vs_variadic");
    for &n_args in &[4usize, 16, 64] {
        let variadic = parse(&make_variadic_concat_program(n_args, bytes_per_arg));
        group.bench_function(BenchmarkId::new("variadic", n_args), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(black_box(&variadic), marf),
                BatchSize::SmallInput,
            );
        });

        let nested = parse(&make_nested_binary_concat_program(n_args, bytes_per_arg));
        group.bench_function(BenchmarkId::new("nested_binary", n_args), |b| {
            b.iter_batched(
                MemoryBackingStore::new,
                |marf| run(black_box(&nested), marf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_by_arg_count,
    bench_by_total_size,
    bench_nested_vs_variadic,
);
criterion_main!(benches);
