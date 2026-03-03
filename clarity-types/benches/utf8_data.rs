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

use clarity_types::types::Utf8Char;
use criterion::{Criterion, criterion_group, criterion_main};

// --- Helpers to build comparable data structures ---

/// New representation: Vec<Utf8Char>
fn make_new_ascii(n: usize) -> Vec<Utf8Char> {
    (0..n).map(|_| Utf8Char::from_char('A')).collect()
}

fn make_new_multibyte(n: usize) -> Vec<Utf8Char> {
    // U+2603 snowman = 0xE2 0x98 0x83 (3 bytes)
    (0..n).map(|_| Utf8Char::from_char('\u{2603}')).collect()
}

/// Old representation: Vec<Vec<u8>>
fn make_old_ascii(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|_| vec![b'A']).collect()
}

fn make_old_multibyte(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|_| vec![0xE2, 0x98, 0x83]).collect()
}

fn bench_utf8(c: &mut Criterion) {
    let mut group = c.benchmark_group("utf8_data");

    for size in [100, 1000] {
        let new_ascii = make_new_ascii(size);
        let old_ascii = make_old_ascii(size);
        let new_multi = make_new_multibyte(size);
        let old_multi = make_old_multibyte(size);

        group.bench_function(format!("new_clone_ascii_{size}"), |b| {
            b.iter(|| black_box(new_ascii.clone()));
        });
        group.bench_function(format!("old_clone_ascii_{size}"), |b| {
            b.iter(|| black_box(old_ascii.clone()));
        });

        group.bench_function(format!("new_clone_multibyte_{size}"), |b| {
            b.iter(|| black_box(new_multi.clone()));
        });
        group.bench_function(format!("old_clone_multibyte_{size}"), |b| {
            b.iter(|| black_box(old_multi.clone()));
        });

        // --- Construction: raw data structure comparison ---
        group.bench_function(format!("new_construct_ascii_{size}"), |b| {
            b.iter(|| {
                black_box(
                    (0..size)
                        .map(|_| Utf8Char::from_char('A'))
                        .collect::<Vec<_>>(),
                );
            });
        });
        group.bench_function(format!("old_construct_ascii_{size}"), |b| {
            b.iter(|| {
                black_box((0..size).map(|_| vec![b'A']).collect::<Vec<Vec<u8>>>());
            });
        });

        group.bench_function(format!("new_construct_multibyte_{size}"), |b| {
            b.iter(|| {
                black_box(
                    (0..size)
                        .map(|_| Utf8Char::from_char('\u{2603}'))
                        .collect::<Vec<_>>(),
                );
            });
        });
        group.bench_function(format!("old_construct_multibyte_{size}"), |b| {
            b.iter(|| {
                black_box(
                    (0..size)
                        .map(|_| vec![0xE2u8, 0x98, 0x83])
                        .collect::<Vec<Vec<u8>>>(),
                );
            });
        });

        // --- Full bytes→data pipeline (end-to-end) ---
        // Both paths: validate UTF-8 → decode chars → collect.
        // New: Vec<Utf8Char> (stack-allocated per char).
        // Old: Vec<Vec<u8>> (heap-allocated per char).
        let ascii_bytes: Vec<u8> = "A".repeat(size).into_bytes();
        let multi_bytes: Vec<u8> = "\u{2603}".repeat(size).into_bytes();

        group.bench_function(format!("new_value_construct_ascii_{size}"), |b| {
            b.iter(|| {
                let s = std::str::from_utf8(&ascii_bytes).unwrap();
                black_box(s.chars().map(Utf8Char::from_char).collect::<Vec<_>>());
            });
        });
        group.bench_function(format!("old_value_construct_ascii_{size}"), |b| {
            b.iter(|| {
                let s = std::str::from_utf8(&ascii_bytes).unwrap();
                black_box(
                    s.chars()
                        .map(|c| {
                            let mut buf = vec![0u8; c.len_utf8()];
                            c.encode_utf8(&mut buf);
                            buf
                        })
                        .collect::<Vec<Vec<u8>>>(),
                );
            });
        });

        group.bench_function(format!("new_value_construct_multibyte_{size}"), |b| {
            b.iter(|| {
                let s = std::str::from_utf8(&multi_bytes).unwrap();
                black_box(s.chars().map(Utf8Char::from_char).collect::<Vec<_>>());
            });
        });
        group.bench_function(format!("old_value_construct_multibyte_{size}"), |b| {
            b.iter(|| {
                let s = std::str::from_utf8(&multi_bytes).unwrap();
                black_box(
                    s.chars()
                        .map(|c| {
                            let mut buf = vec![0u8; c.len_utf8()];
                            c.encode_utf8(&mut buf);
                            buf
                        })
                        .collect::<Vec<Vec<u8>>>(),
                );
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_utf8);
criterion_main!(benches);
