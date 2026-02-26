use std::hint::black_box;

use clarity::vm::types::{
    ListData, ListTypeData, SequenceSubtype, SequencedValue, TypeSignature, Value,
};
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
// Clone vs move helpers
// ---------------------------------------------------------------------------

/// Simulates the old `atom_values` behavior: drain + clone each element via `to_value`.
fn old_atom_values_clone(sequence_data: &mut SequenceData) {
    let result: Vec<_> = match sequence_data {
        SequenceData::Buffer(data) => data
            .drained_items()
            .iter()
            .map(|item| black_box(BuffData::to_value(item).unwrap()))
            .collect(),
        SequenceData::List(data) => data
            .drained_items()
            .iter()
            .map(|item| black_box(ListData::to_value(item).unwrap()))
            .collect(),
        SequenceData::String(CharType::ASCII(data)) => data
            .drained_items()
            .iter()
            .map(|item| black_box(ASCIIData::to_value(item).unwrap()))
            .collect(),
        SequenceData::String(CharType::UTF8(data)) => data
            .drained_items()
            .iter()
            .map(|item| black_box(UTF8Data::to_value(item).unwrap()))
            .collect(),
    };
    black_box(result);
}

/// Uses the new `atom_values` which drains + moves each element via `into_value`.
fn new_atom_values_move(sequence_data: &mut SequenceData) {
    let result = sequence_data.atom_values().unwrap();
    black_box(result);
}

// ---------------------------------------------------------------------------
// Generic bench runner
// ---------------------------------------------------------------------------

fn bench_clone_vs_move(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    label: &str,
    make: impl Fn() -> SequenceData,
) {
    group.bench_function(BenchmarkId::new("clone", label), |b| {
        b.iter_batched(
            &make,
            |mut seq| old_atom_values_clone(&mut seq),
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("move", label), |b| {
        b.iter_batched(
            &make,
            |mut seq| new_atom_values_move(&mut seq),
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
        bench_clone_vs_move(&mut group, &size.to_string(), move || make_int_list(size));
    }
    group.finish();
}

fn bench_atom_values_nested_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/nested_list");
    for &(outer, inner) in &[(100, 5), (500, 5), (500, 10)] {
        bench_clone_vs_move(&mut group, &format!("{outer}x{inner}"), move || {
            make_nested_list(outer, inner)
        });
    }
    group.finish();
}

fn bench_atom_values_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/buffer");
    for size in [100, 1_000, 8_000] {
        bench_clone_vs_move(&mut group, &size.to_string(), move || make_buffer(size));
    }
    group.finish();
}

fn bench_atom_values_ascii(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/ascii");
    for size in [100, 1_000, 8_000] {
        bench_clone_vs_move(&mut group, &size.to_string(), move || {
            make_ascii_string(size)
        });
    }
    group.finish();
}

fn bench_atom_values_utf8(c: &mut Criterion) {
    let mut group = c.benchmark_group("atom_values/utf8");
    for size in [100, 1_000, 8_000] {
        bench_clone_vs_move(&mut group, &size.to_string(), move || {
            make_utf8_string(size)
        });
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
);
criterion_main!(benches);
