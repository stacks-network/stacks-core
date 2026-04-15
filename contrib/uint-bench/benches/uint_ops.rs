//! Benchmarks for `stacks-common::util::uint`.
//!
//! Part 1: Comparing current vs. old (`eef1647d`) for primitive Uint ops.
//! Part 2: Comparing `weighted_geometric_average` (root-then-pow) vs.
//!         `weighted_geometric_average_log` (log-space) on FixedPointU256.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use stacks_common_new::util::uint::{
    FixedPointU256, Uint256 as NewU256, Uint512 as NewU512,
};
use stacks_common_old::util::uint::{Uint256 as OldU256, Uint512 as OldU512};

type FP = FixedPointU256<64>;

/// Build a representative pair of `Uint256` operands with bits set across all
/// four limbs so the inner loops do real work.
fn u256_operands() -> ([u64; 4], [u64; 4]) {
    let a = [
        0x0123_4567_89ab_cdefu64,
        0xfedc_ba98_7654_3210u64,
        0xdead_beef_cafe_babeu64,
        0x0000_0000_ffff_ffffu64,
    ];
    let b = [
        0x1111_2222_3333_4444u64,
        0x5555_6666_7777_8888u64,
        0x9999_aaaa_bbbb_ccccu64,
        0x0000_0000_0000_ffffu64,
    ];
    (a, b)
}

fn u512_operands() -> [u64; 8] {
    [
        0x0123_4567_89ab_cdefu64,
        0xfedc_ba98_7654_3210u64,
        0xdead_beef_cafe_babeu64,
        0x1111_2222_3333_4444u64,
        0x5555_6666_7777_8888u64,
        0x9999_aaaa_bbbb_ccccu64,
        0xaaaa_5555_aaaa_5555u64,
        0x0000_0000_ffff_ffffu64,
    ]
}

fn bench_u256_add(c: &mut Criterion) {
    let (a, b) = u256_operands();
    let a_new = NewU256(a);
    let b_new = NewU256(b);
    let a_old = OldU256(a);
    let b_old = OldU256(b);

    let mut g = c.benchmark_group("u256_add");
    g.bench_function("new", |bench| {
        bench.iter(|| black_box(black_box(a_new) + black_box(b_new)))
    });
    g.bench_function("old", |bench| {
        bench.iter(|| black_box(black_box(a_old) + black_box(b_old)))
    });
    g.finish();
}

fn bench_u256_sub(c: &mut Criterion) {
    let (a, b) = u256_operands();
    // Make sure a >= b so subtraction doesn't wrap (both versions wrap, but
    // we want consistent inputs across runs).
    let a_new = NewU256(a);
    let b_new = NewU256(b);
    let a_old = OldU256(a);
    let b_old = OldU256(b);

    let mut g = c.benchmark_group("u256_sub");
    g.bench_function("new", |bench| {
        bench.iter(|| black_box(black_box(a_new) - black_box(b_new)))
    });
    g.bench_function("old", |bench| {
        bench.iter(|| black_box(black_box(a_old) - black_box(b_old)))
    });
    g.finish();
}

fn bench_u256_mul(c: &mut Criterion) {
    let (a, b) = u256_operands();
    let a_new = NewU256(a);
    let b_new = NewU256(b);
    let a_old = OldU256(a);
    let b_old = OldU256(b);

    let mut g = c.benchmark_group("u256_mul");
    g.bench_function("new", |bench| {
        bench.iter(|| black_box(black_box(a_new) * black_box(b_new)))
    });
    g.bench_function("old", |bench| {
        bench.iter(|| black_box(black_box(a_old) * black_box(b_old)))
    });
    g.finish();
}

fn bench_u256_shl(c: &mut Criterion) {
    let (a, _) = u256_operands();
    let a_new = NewU256(a);
    let a_old = OldU256(a);
    // 67 = cross-limb shift (>64) so we exercise both word- and bit-shift paths.
    let amt: usize = 67;

    let mut g = c.benchmark_group("u256_shl");
    g.bench_function("new", |bench| {
        bench.iter(|| black_box(black_box(a_new) << black_box(amt)))
    });
    g.bench_function("old", |bench| {
        bench.iter(|| black_box(black_box(a_old) << black_box(amt)))
    });
    g.finish();
}

fn bench_u256_shr(c: &mut Criterion) {
    let (a, _) = u256_operands();
    let a_new = NewU256(a);
    let a_old = OldU256(a);
    let amt: usize = 67;

    let mut g = c.benchmark_group("u256_shr");
    g.bench_function("new", |bench| {
        bench.iter(|| black_box(black_box(a_new) >> black_box(amt)))
    });
    g.bench_function("old", |bench| {
        bench.iter(|| black_box(black_box(a_old) >> black_box(amt)))
    });
    g.finish();
}

fn bench_u512_shl(c: &mut Criterion) {
    let words = u512_operands();
    let a_new = NewU512(words);
    let a_old = OldU512(words);
    let amt: usize = 131;

    let mut g = c.benchmark_group("u512_shl");
    g.bench_function("new", |bench| {
        bench.iter(|| black_box(black_box(a_new) << black_box(amt)))
    });
    g.bench_function("old", |bench| {
        bench.iter(|| black_box(black_box(a_old) << black_box(amt)))
    });
    g.finish();
}

fn bench_u512_shr(c: &mut Criterion) {
    let words = u512_operands();
    let a_new = NewU512(words);
    let a_old = OldU512(words);
    let amt: usize = 131;

    let mut g = c.benchmark_group("u512_shr");
    g.bench_function("new", |bench| {
        bench.iter(|| black_box(black_box(a_new) >> black_box(amt)))
    });
    g.bench_function("old", |bench| {
        bench.iter(|| black_box(black_box(a_old) >> black_box(amt)))
    });
    g.finish();
}

// ---------------------------------------------------------------------------
// FixedPointU256 weighted geometric average: root-then-pow vs log-space
// ---------------------------------------------------------------------------

/// Build FP values that look like realistic block-time ratios (small integers
/// with fractional noise).  Values are in roughly [0.5, 5.0].
fn fp_operands() -> (FP, [FP; 4]) {
    let current = FP::from_u64(3);
    let priors = [
        FP::from_u64(2),
        FP::from_u64(4),
        FP::from_u64(1),
        FP::from_u64(5),
    ];
    (current, priors)
}

fn bench_geo_avg_1_prior(c: &mut Criterion) {
    let (current, priors) = fp_operands();
    let one_prior = &priors[..1];

    let mut g = c.benchmark_group("geo_avg_1_prior");
    g.bench_function("root_pow", |bench| {
        bench.iter(|| {
            black_box(FP::weighted_geometric_average(
                black_box(&current),
                black_box(one_prior),
            ))
        })
    });
    g.bench_function("log", |bench| {
        bench.iter(|| {
            black_box(FP::weighted_geometric_average_log(
                black_box(&current),
                black_box(one_prior),
            ))
        })
    });
    g.finish();
}

fn bench_geo_avg_4_priors(c: &mut Criterion) {
    let (current, priors) = fp_operands();

    let mut g = c.benchmark_group("geo_avg_4_priors");
    g.bench_function("root_pow", |bench| {
        bench.iter(|| {
            black_box(FP::weighted_geometric_average(
                black_box(&current),
                black_box(&priors),
            ))
        })
    });
    g.bench_function("log", |bench| {
        bench.iter(|| {
            black_box(FP::weighted_geometric_average_log(
                black_box(&current),
                black_box(&priors),
            ))
        })
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_u256_add,
    bench_u256_sub,
    bench_u256_mul,
    bench_u256_shl,
    bench_u256_shr,
    bench_u512_shl,
    bench_u512_shr,
    bench_geo_avg_1_prior,
    bench_geo_avg_4_priors,
);
criterion_main!(benches);
