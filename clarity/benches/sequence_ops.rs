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
use std::hint::black_box;

use clarity::vm::ast::build_ast;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::types::{
    ListData, ListTypeData, QualifiedContractIdentifier, SequenceSubtype, TypeSignature, Value,
};
use clarity::vm::{ClarityVersion, ContractContext, eval_all};
use clarity_types::representations::SymbolicExpression;
use clarity_types::types::{ASCIIData, BuffData, CharType, SequenceData, UTF8Data};
use criterion::{Criterion, criterion_group, criterion_main};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

// ---------------------------------------------------------------------------
// Factory helpers — each returns a SequenceData ready to benchmark
// ---------------------------------------------------------------------------

fn make_int_list(n: usize) -> SequenceData {
    let elements: Vec<Value> = (0..n).map(|i| Value::Int(i as i128)).collect();
    SequenceData::List(ListData {
        data: elements,
        type_signature: ListTypeData::new_list(TypeSignature::IntType, n as u32).unwrap(),
    })
}

fn make_nested_list(n: usize, inner_size: usize) -> SequenceData {
    let inner_type = ListTypeData::new_list(TypeSignature::IntType, inner_size as u32).unwrap();
    let outer_type = ListTypeData::new_list(
        TypeSignature::SequenceType(SequenceSubtype::ListType(inner_type)),
        n as u32,
    )
    .unwrap();

    let inner_elements: Vec<Value> = (0..inner_size).map(|i| Value::Int(i as i128)).collect();
    let inner_list = Value::list_from(inner_elements).unwrap();
    let elements: Vec<Value> = (0..n).map(|_| inner_list.clone()).collect();

    SequenceData::List(ListData {
        data: elements,
        type_signature: outer_type,
    })
}

fn make_buffer(n: usize) -> SequenceData {
    SequenceData::Buffer(BuffData {
        data: vec![0xABu8; n],
    })
}

fn make_ascii_string(n: usize) -> SequenceData {
    // Repeating printable ASCII character
    SequenceData::String(CharType::ASCII(ASCIIData {
        data: vec![b'x'; n],
    }))
}

fn make_utf8_string(n: usize) -> SequenceData {
    // Each UTF8 "character" is stored as a Vec<u8> (one codepoint).
    // Use a 3-byte codepoint (e.g. U+2603 SNOWMAN = 0xE2 0x98 0x83) to make
    // each element a heap-allocated Vec, so clone cost is visible.
    let codepoint: Vec<u8> = vec![0xE2, 0x98, 0x83];
    SequenceData::String(CharType::UTF8(UTF8Data {
        data: (0..n).map(|_| codepoint.clone()).collect(),
    }))
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_atom_values_int_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/int_list");
    for size in [100, 1_000, 8_000] {
        group.bench_function(size.to_string(), |b| {
            b.iter_batched(
                move || make_int_list(size),
                |mut seq| black_box(seq.atom_values().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_atom_values_nested_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/nested_list");
    for &(outer, inner) in &[(100, 5), (500, 5), (500, 10)] {
        group.bench_function(format!("{outer}x{inner}"), |b| {
            b.iter_batched(
                move || make_nested_list(outer, inner),
                |mut seq| black_box(seq.atom_values().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_atom_values_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/buffer");
    for size in [100, 1_000, 8_000] {
        group.bench_function(size.to_string(), |b| {
            b.iter_batched(
                move || make_buffer(size),
                |mut seq| black_box(seq.atom_values().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_atom_values_ascii(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/ascii");
    for size in [100, 1_000, 8_000] {
        group.bench_function(size.to_string(), |b| {
            b.iter_batched(
                move || make_ascii_string(size),
                |mut seq| black_box(seq.atom_values().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_atom_values_utf8(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/utf8");
    for size in [100, 1_000, 8_000] {
        group.bench_function(size.to_string(), |b| {
            b.iter_batched(
                move || make_utf8_string(size),
                |mut seq| black_box(seq.atom_values().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// special_map end-to-end benchmarks
//
// Runs `(map f seq ...)` through the full Clarity VM (MemoryBackingStore +
// GlobalContext + eval_all).  Each benchmark variant:
//   - Pre-parses the snippet once, outside the timed region.
//   - Puts MemoryBackingStore::new() (SQLite schema init) in the iter_batched
//     setup so it is NOT in the timed region.
//   - Times: ContractContext + GlobalContext construction + eval_all.
//
// Variants:
//   unary_int        — (map to-uint (list 0 1 ... n))        single sequence
//   binary_int       — (map + (list 0..n) (list 0..n))       two equal sequences
//   binary_int_unequal — longer sequence first               exercises take(min_args_len)
// ---------------------------------------------------------------------------

fn map_snippet_unary_int(n: usize) -> String {
    let elems: String = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
    format!("(map to-uint (list {elems}))")
}

fn map_snippet_binary_int(n: usize) -> String {
    let elems: String = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
    format!("(map + (list {elems}) (list {elems}))")
}

fn map_snippet_binary_unequal(long: usize, short: usize) -> String {
    let long_elems: String = (0..long)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let short_elems: String = (0..short)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("(map + (list {long_elems}) (list {short_elems}))")
}

fn parse_map_snippet(
    snippet: &str,
    epoch: StacksEpochId,
    version: ClarityVersion,
) -> Vec<SymbolicExpression> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut cost_track = LimitedCostTracker::new_free();
    build_ast(&contract_id, snippet, &mut cost_track, version, epoch)
        .unwrap()
        .expressions
}

/// Run `parsed` in a fresh execution environment, with `marf` pre-initialized
/// (so SQLite setup is NOT in the timed region).
fn run_parsed(
    mut marf: MemoryBackingStore,
    parsed: &[SymbolicExpression],
    epoch: StacksEpochId,
    version: ClarityVersion,
) -> Option<Value> {
    let conn = marf.as_clarity_db();
    let mut contract_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        conn,
        LimitedCostTracker::new_free(),
        epoch,
    );
    global_context
        .execute(|g| eval_all(parsed, &mut contract_context, g, None))
        .unwrap()
}

fn bench_map_variant(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    label: &str,
    parsed: &[SymbolicExpression],
    epoch: StacksEpochId,
    version: ClarityVersion,
) {
    group.bench_function(label, |b| {
        b.iter_batched(
            MemoryBackingStore::new,
            |marf| black_box(run_parsed(marf, parsed, epoch, version)),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_special_map(c: &mut Criterion) {
    let epoch = StacksEpochId::latest();
    let version = ClarityVersion::latest();
    let mut group = c.benchmark_group("special_map");

    for size in [100, 1_000, 8_000] {
        let parsed = parse_map_snippet(&map_snippet_unary_int(size), epoch, version);
        bench_map_variant(
            &mut group,
            &format!("unary_int/{size}"),
            &parsed,
            epoch,
            version,
        );

        let parsed = parse_map_snippet(&map_snippet_binary_int(size), epoch, version);
        bench_map_variant(
            &mut group,
            &format!("binary_int/{size}"),
            &parsed,
            epoch,
            version,
        );
    }

    for (long, short) in [(1_000usize, 100usize), (8_000, 500)] {
        let parsed = parse_map_snippet(&map_snippet_binary_unequal(long, short), epoch, version);
        bench_map_variant(
            &mut group,
            &format!("binary_int_unequal/{long}vs{short}"),
            &parsed,
            epoch,
            version,
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_atom_values_int_list,
    bench_atom_values_nested_list,
    bench_atom_values_buffer,
    bench_atom_values_ascii,
    bench_atom_values_utf8,
    bench_special_map,
);
criterion_main!(benches);
