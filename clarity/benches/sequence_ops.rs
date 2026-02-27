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

use clarity::vm::types::{
    ListData, ListTypeData, SequenceSubtype, SequencedValue, TypeSignature, Value,
};
use clarity_types::representations::SymbolicExpression;
use clarity_types::types::{ASCIIData, BuffData, CharType, SequenceData, UTF8Data};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

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
// Compare three strategies:
//   1. drain+clone: old drained_items (renamed take_items) (drain().collect()) + old to_value (clone)
//   2. take+clone:  new take_items (mem::take) + old to_value (clone)
//   3. take+move:   new take_items (mem::take) + new into_value (move)
//
// Comparing 1 vs 2 isolates the drain→take improvement.
// Comparing 2 vs 3 isolates the clone→move improvement.
// ---------------------------------------------------------------------------

/// Old behavior: drain(..).collect() + iter + to_value (clone) + SymbolicExpression wrap.
fn drain_and_clone(sequence_data: &mut SequenceData) {
    let result: Vec<_> = match sequence_data {
        SequenceData::Buffer(data) => data
            .data
            .drain(..)
            .collect::<Vec<_>>()
            .iter()
            .map(|item| SymbolicExpression::atom_value(BuffData::to_value(item).unwrap()))
            .collect(),
        SequenceData::List(data) => data
            .data
            .drain(..)
            .collect::<Vec<_>>()
            .iter()
            .map(|item| SymbolicExpression::atom_value(ListData::to_value(item).unwrap()))
            .collect(),
        SequenceData::String(CharType::ASCII(data)) => data
            .data
            .drain(..)
            .collect::<Vec<_>>()
            .iter()
            .map(|item| SymbolicExpression::atom_value(ASCIIData::to_value(item).unwrap()))
            .collect(),
        SequenceData::String(CharType::UTF8(data)) => data
            .data
            .drain(..)
            .collect::<Vec<_>>()
            .iter()
            .map(|item| SymbolicExpression::atom_value(UTF8Data::to_value(item).unwrap()))
            .collect(),
    };
    black_box(result);
}

/// Intermediate: mem::take + iter + to_value (clone) + SymbolicExpression wrap — isolates drain improvement.
fn take_and_clone(sequence_data: &mut SequenceData) {
    let result: Vec<_> = match sequence_data {
        SequenceData::Buffer(data) => {
            let items = std::mem::take(&mut data.data);
            items
                .iter()
                .map(|item| SymbolicExpression::atom_value(BuffData::to_value(item).unwrap()))
                .collect()
        }
        SequenceData::List(data) => {
            let items = std::mem::take(&mut data.data);
            items
                .iter()
                .map(|item| SymbolicExpression::atom_value(ListData::to_value(item).unwrap()))
                .collect()
        }
        SequenceData::String(CharType::ASCII(data)) => {
            let items = std::mem::take(&mut data.data);
            items
                .iter()
                .map(|item| SymbolicExpression::atom_value(ASCIIData::to_value(item).unwrap()))
                .collect()
        }
        SequenceData::String(CharType::UTF8(data)) => {
            let items = std::mem::take(&mut data.data);
            items
                .iter()
                .map(|item| SymbolicExpression::atom_value(UTF8Data::to_value(item).unwrap()))
                .collect()
        }
    };
    black_box(result);
}

/// New behavior: mem::take + into_iter + into_value (move) — current atom_values().
fn take_and_move(sequence_data: &mut SequenceData) {
    let result = sequence_data.atom_values().unwrap();
    black_box(result);
}

// ---------------------------------------------------------------------------
// Generic bench runner
// ---------------------------------------------------------------------------

fn bench_three_ways(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    label: &str,
    make: impl Fn() -> SequenceData,
) {
    group.bench_function(BenchmarkId::new("drain+clone", label), |b| {
        b.iter_batched(
            &make,
            |mut seq| drain_and_clone(&mut seq),
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("take+clone", label), |b| {
        b.iter_batched(
            &make,
            |mut seq| take_and_clone(&mut seq),
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("take+move", label), |b| {
        b.iter_batched(
            &make,
            |mut seq| take_and_move(&mut seq),
            criterion::BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_atom_values_int_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/int_list");
    for size in [100, 1_000, 8_000] {
        bench_three_ways(&mut group, &size.to_string(), move || make_int_list(size));
    }
    group.finish();
}

fn bench_atom_values_nested_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/nested_list");
    for &(outer, inner) in &[(100, 5), (500, 5), (500, 10)] {
        bench_three_ways(&mut group, &format!("{outer}x{inner}"), move || {
            make_nested_list(outer, inner)
        });
    }
    group.finish();
}

fn bench_atom_values_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/buffer");
    for size in [100, 1_000, 8_000] {
        bench_three_ways(&mut group, &size.to_string(), move || make_buffer(size));
    }
    group.finish();
}

fn bench_atom_values_ascii(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/ascii");
    for size in [100, 1_000, 8_000] {
        bench_three_ways(&mut group, &size.to_string(), move || {
            make_ascii_string(size)
        });
    }
    group.finish();
}

fn bench_atom_values_utf8(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/utf8");
    for size in [100, 1_000, 8_000] {
        bench_three_ways(&mut group, &size.to_string(), move || {
            make_utf8_string(size)
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// retain_values benchmarks (O(n) swap-to-front vs old O(n²) Vec::remove)
// ---------------------------------------------------------------------------

/// Simulates the old O(n²) retain_values: Vec::remove(i) on every discard.
fn old_retain_values_quadratic(
    sequence_data: &mut SequenceData,
    predicate: &mut impl FnMut(SymbolicExpression) -> Result<bool, ()>,
) {
    macro_rules! retain_old {
        ($data:expr, $seq_type:ident) => {{
            let mut i = 0;
            while i != $data.data.len() {
                let atom_value =
                    SymbolicExpression::atom_value($seq_type::to_value(&$data.data[i]).unwrap());
                let keep = predicate(atom_value).unwrap();
                if keep {
                    i += 1;
                } else {
                    $data.data.remove(i);
                }
            }
        }};
    }
    match sequence_data {
        SequenceData::Buffer(data) => retain_old!(data, BuffData),
        SequenceData::List(data) => retain_old!(data, ListData),
        SequenceData::String(CharType::ASCII(data)) => retain_old!(data, ASCIIData),
        SequenceData::String(CharType::UTF8(data)) => retain_old!(data, UTF8Data),
    }
}

/// Uses the new O(n) retain_values (swap-to-front + truncate).
fn new_retain_values_linear(
    sequence_data: &mut SequenceData,
    predicate: &mut impl FnMut(SymbolicExpression) -> Result<bool, ()>,
) {
    sequence_data
        .retain_values::<(), _>(|sym| predicate(sym))
        .unwrap();
}

fn bench_retain_values(c: &mut Criterion) {
    let mut group = c.benchmark_group("retain_values");

    // Alternate keep/discard (~50% filtered out).
    let mut counter = 0usize;

    for &(outer, inner) in &[(100, 5), (500, 5), (500, 10)] {
        let label = format!("{outer}x{inner}");

        group.bench_with_input(
            BenchmarkId::new("old_quadratic", &label),
            &(outer, inner),
            |b, &(outer, inner)| {
                b.iter_batched(
                    || make_nested_list(outer, inner),
                    |mut seq| {
                        counter = 0;
                        old_retain_values_quadratic(&mut seq, &mut |_sym| {
                            counter += 1;
                            Ok(counter % 2 == 0)
                        });
                        black_box(seq);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("new_linear", &label),
            &(outer, inner),
            |b, &(outer, inner)| {
                b.iter_batched(
                    || make_nested_list(outer, inner),
                    |mut seq| {
                        counter = 0;
                        new_retain_values_linear(&mut seq, &mut |_sym| {
                            counter += 1;
                            Ok(counter % 2 == 0)
                        });
                        black_box(seq);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
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
    bench_retain_values,
);
criterion_main!(benches);
