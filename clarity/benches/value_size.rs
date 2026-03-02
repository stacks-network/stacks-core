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

use clarity::vm::types::{TupleData, TypeSignature, Value};
use clarity_types::representations::ClarityName;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

// ---------------------------------------------------------------------------
// Factory helpers
// ---------------------------------------------------------------------------

/// Build a flat tuple with `n` integer fields: { field_0: 0, field_1: 1, … }
fn make_flat_tuple(n: usize) -> Value {
    let fields: Vec<(ClarityName, Value)> = (0..n)
        .map(|i| {
            (
                ClarityName::try_from(format!("f{i}")).unwrap(),
                Value::Int(i as i128),
            )
        })
        .collect();
    TupleData::from_data(fields).unwrap().into()
}

/// Build a nested tuple: { inner: { inner: { … { leaf: 1 } } } } with `depth` levels.
fn make_nested_tuple(depth: usize) -> Value {
    let mut val = Value::Int(1);
    for _ in 0..depth {
        val = TupleData::from_data(vec![("inner".into(), val)])
            .unwrap()
            .into();
    }
    val
}

/// Build a list of flat tuples: each element is a tuple with `fields_per_tuple` int fields.
fn make_list_of_tuples(list_len: usize, fields_per_tuple: usize) -> Value {
    let elements: Vec<Value> = (0..list_len)
        .map(|_| make_flat_tuple(fields_per_tuple))
        .collect();
    Value::list_from(elements).unwrap()
}

/// Build a response wrapping a nested tuple.
fn make_response_nested(depth: usize) -> Value {
    Value::okay(make_nested_tuple(depth)).unwrap()
}

/// Build an optional wrapping a flat tuple.
fn make_optional_tuple(fields: usize) -> Value {
    Value::some(make_flat_tuple(fields)).unwrap()
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_scalar_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_size/scalar");

    group.bench_function("int", |b| {
        let v = Value::Int(42);
        b.iter(|| black_box(black_box(&v).size().unwrap()));
    });
    group.bench_function("uint", |b| {
        let v = Value::UInt(42);
        b.iter(|| black_box(black_box(&v).size().unwrap()));
    });
    group.bench_function("bool", |b| {
        let v = Value::Bool(true);
        b.iter(|| black_box(black_box(&v).size().unwrap()));
    });

    group.finish();
}

fn bench_tuple_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_size/tuple");

    // Flat tuples with increasing field count
    for n_fields in [1, 5, 10, 20] {
        group.bench_with_input(
            BenchmarkId::new("flat/first_call", n_fields),
            &n_fields,
            |b, &n| {
                b.iter_batched_ref(
                    || make_flat_tuple(n),
                    |v| black_box(v.size().unwrap()),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("flat/cached_call", n_fields),
            &n_fields,
            |b, &n| {
                b.iter_batched_ref(
                    || {
                        let v = make_flat_tuple(n);
                        v.size().unwrap(); // prime the cache
                        v
                    },
                    |v| black_box(v.size().unwrap()),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    // Nested tuples — stress the recursive size computation
    for depth in [1, 5, 10, 15] {
        group.bench_with_input(
            BenchmarkId::new("nested/first_call", depth),
            &depth,
            |b, &d| {
                b.iter_batched_ref(
                    || make_nested_tuple(d),
                    |v| black_box(v.size().unwrap()),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("nested/cached_call", depth),
            &depth,
            |b, &d| {
                b.iter_batched_ref(
                    || {
                        let v = make_nested_tuple(d);
                        v.size().unwrap();
                        v
                    },
                    |v| black_box(v.size().unwrap()),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_list_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_size/list");

    // List of ints — exercises ListTypeData cache
    for len in [100, 1_000] {
        let v = Value::list_from((0..len).map(|i| Value::Int(i as i128)).collect()).unwrap();
        group.bench_with_input(BenchmarkId::new("int_list/first_call", len), &v, |b, v| {
            b.iter_batched_ref(
                || v.clone(),
                |v| black_box(v.size().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
        group.bench_with_input(BenchmarkId::new("int_list/cached_call", len), &v, |b, v| {
            b.iter_batched_ref(
                || {
                    let v = v.clone();
                    v.size().unwrap();
                    v
                },
                |v| black_box(v.size().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // List of tuples — both ListTypeData and TupleTypeSignature caches
    for (len, fields) in [(100, 5), (50, 10)] {
        let label = format!("{len}x{fields}fields");
        group.bench_function(BenchmarkId::new("tuple_list/first_call", &label), |b| {
            b.iter_batched_ref(
                || make_list_of_tuples(len, fields),
                |v| black_box(v.size().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("tuple_list/cached_call", &label), |b| {
            b.iter_batched_ref(
                || {
                    let v = make_list_of_tuples(len, fields);
                    v.size().unwrap();
                    v
                },
                |v| black_box(v.size().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_compound_wrappers(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_size/compound");

    // Optional wrapping a tuple
    for fields in [5, 10] {
        group.bench_with_input(
            BenchmarkId::new("optional_tuple", fields),
            &fields,
            |b, &f| {
                b.iter_batched_ref(
                    || make_optional_tuple(f),
                    |v| black_box(v.size().unwrap()),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    // Response wrapping nested tuple
    for depth in [5, 10] {
        group.bench_with_input(
            BenchmarkId::new("response_nested_tuple", depth),
            &depth,
            |b, &d| {
                b.iter_batched_ref(
                    || make_response_nested(d),
                    |v| black_box(v.size().unwrap()),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    // Optional(None)
    group.bench_function("optional_none", |b| {
        let v = Value::none();
        b.iter(|| black_box(black_box(&v).size().unwrap()));
    });

    group.finish();
}

/// The old implementation: TypeSignature::type_of(v)?.size()
/// Kept here as a baseline to measure improvement against.
fn old_value_size(v: &Value) -> u32 {
    TypeSignature::type_of(v).unwrap().size().unwrap()
}

/// Compare three paths:
/// - "old": always recomputes via TypeSignature::type_of(v)?.size()
/// - "new_first": fresh value each iteration (cold cache)
/// - "new_cached": cache already primed (hot path)
fn bench_old_vs_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_size/old_vs_new");

    // (label, factory fn)
    let cases: Vec<(&str, Box<dyn Fn() -> Value>)> = vec![
        ("int", Box::new(|| Value::Int(42))),
        ("bool", Box::new(|| Value::Bool(true))),
        ("tuple_5f", Box::new(|| make_flat_tuple(5))),
        ("tuple_10f", Box::new(|| make_flat_tuple(10))),
        ("tuple_20f", Box::new(|| make_flat_tuple(20))),
        ("nested_5", Box::new(|| make_nested_tuple(5))),
        ("nested_10", Box::new(|| make_nested_tuple(10))),
        ("optional_none", Box::new(Value::none)),
        ("optional_tuple_5f", Box::new(|| make_optional_tuple(5))),
        ("response_nested_5", Box::new(|| make_response_nested(5))),
    ];

    for (label, make) in &cases {
        // Both "old" and "new_first" use iter_batched with clone so they pay
        // identical allocation and CPU-cache costs. The only difference is the
        // size() implementation path.
        group.bench_function(BenchmarkId::new("old", *label), |b| {
            let template = make();
            b.iter_batched_ref(
                || template.clone(),
                |v| black_box(old_value_size(&v)),
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("new_first", *label), |b| {
            let template = make(); // never call .size() on this
            b.iter_batched_ref(
                || template.clone(),
                |v| black_box(v.size().unwrap()),
                criterion::BatchSize::SmallInput,
            );
        });

        // New path, hot cache: call size() once to prime, then measure repeat calls
        group.bench_function(BenchmarkId::new("new_cached", *label), |b| {
            let v = make();
            v.size().unwrap(); // prime cache
            b.iter(|| black_box(black_box(&v).size().unwrap()));
        });
    }

    group.finish();
}

/// Simulate a hot loop calling size() repeatedly on the same value,
/// as happens during fold/map with tuple accumulators.
/// Compares old uncached path vs new cached path over 10 iterations.
fn bench_repeated_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_size/repeated_10x");

    for n_fields in [5, 10, 20] {
        group.bench_with_input(BenchmarkId::new("old", n_fields), &n_fields, |b, &n| {
            let v = make_flat_tuple(n);
            b.iter(|| {
                let mut total = 0u32;
                for _ in 0..10 {
                    total += black_box(old_value_size(black_box(&v)));
                }
                black_box(total)
            });
        });
        group.bench_with_input(BenchmarkId::new("new", n_fields), &n_fields, |b, &n| {
            let v = make_flat_tuple(n);
            b.iter(|| {
                let mut total = 0u32;
                for _ in 0..10 {
                    total += black_box(black_box(&v).size().unwrap());
                }
                black_box(total)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_scalar_types,
    bench_tuple_size,
    bench_list_size,
    bench_compound_wrappers,
    bench_old_vs_new,
    bench_repeated_size,
);
criterion_main!(benches);
