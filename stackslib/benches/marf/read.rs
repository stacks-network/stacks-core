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

//! Read-heavy MARF timing benchmark focused on `MARF::get` and
//! `MARF::get_with_proof` backpointer walks.

use std::collections::HashMap;
use std::hint::black_box;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::chainstate::stacks::index::{ClarityMarfTrieId as _, MARFValue};
use stacks_common::types::chainstate::StacksBlockId;
use tempfile::TempDir;

use crate::common::{
    apply_optional_wal_autocheckpoint, maybe_run_post_setup_wal_checkpoint, measure_with_allocs,
    parse_optional_wal_autocheckpoint_pages, parse_optional_wal_checkpoint_mode, BenchMeasurement,
    WalCheckpointMode,
};
use crate::utils::{
    block_id, has_help_flag, parse_csv_string_env, parse_csv_u32_env, parse_u32_env,
    parse_usize_env,
};
use crate::{OutputMode, Summary};

/// Default read operations per measured case.
const DEFAULT_READ_ITERS: usize = 200_000;
/// Default independent repetitions per case.
const DEFAULT_READ_ROUNDS: usize = 2;
/// Default number of non-measured keys inserted per fixture block.
const DEFAULT_KEYS_PER_BLOCK: u32 = 16;
/// Default read depths sampled from the tip.
const DEFAULT_DEPTHS: [u32; 4] = [32, 128, 768, 2047];
/// Default MARF cache strategies exercised by the benchmark.
const DEFAULT_CACHE_STRATEGIES: [&str; 2] = ["noop", "node256"];
/// Extra fixture blocks added above max depth when CHAIN_LEN is not set.
const DEFAULT_CHAIN_LEN_DEPTH_SLACK: u32 = 16;

/// Read API variant under test.
#[derive(Clone, Copy)]
enum ReadVariant {
    /// Measure `MARF::get`.
    Get,
    /// Measure `MARF::get_with_proof`.
    GetWithProof,
}

impl ReadVariant {
    /// Stable output label for the read variant.
    fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::GetWithProof => "get-with-proof",
        }
    }
}

/// Aggregated timing and allocation totals for one case across rounds.
#[derive(Clone, Copy, Default)]
struct CaseAggregate {
    total_ms: f64,
    alloc_calls: u64,
    alloc_bytes: u64,
}

/// Backed MARF fixture used by read-case execution.
struct MarfReadFixture {
    marf: MARF<StacksBlockId>,
    tip: StacksBlockId,
    tip_height: u32,
    _db_dir: TempDir,
}

#[rustfmt::skip]
fn print_usage(args: &[String]) {
    if has_help_flag(args) {
        let default_depths = DEFAULT_DEPTHS
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let default_max_depth = *DEFAULT_DEPTHS
            .iter()
            .max()
            .expect("DEFAULT_DEPTHS must not be empty");
        let default_chain_len = default_max_depth + DEFAULT_CHAIN_LEN_DEPTH_SLACK;
        let default_cache_strategies = DEFAULT_CACHE_STRATEGIES.join(",");
        let default_keys_per_block = DEFAULT_KEYS_PER_BLOCK;
        let default_total_fixture_keys = default_keys_per_block + 1;

        println!("read: MARF::get benchmark");
        println!();
        println!("CLI Args:");
        println!("  --proofs     Use MARF::get_with_proof instead of MARF::get [default: false]");
        println!();
        println!("Environment Variables:");
        println!("  ITERS       Reads per measured case [default: {DEFAULT_READ_ITERS}]");
        println!("              Higher values reduce measurement noise but increase runtime linearly");
        println!("              Affects elapsed_ms/alloc totals directly; per-op metrics remain normalized");
        println!("  ROUNDS      Independent repetitions per case [default: {DEFAULT_READ_ROUNDS}]");
        println!("              Higher values improve stability estimates (summary min/max)");
        println!("  CHAIN_LEN   Number of sequential blocks/tries created [default: max(DEPTHS)+{DEFAULT_CHAIN_LEN_DEPTH_SLACK}; with defaults: {default_chain_len}]");
        println!("              Must be greater than the maximum `DEPTHS` value.");
        println!("              Higher values increase fixture construction time and temporary DB size");
        println!("  DEPTHS      Comma-separated depths [default: {default_depths}]");
        println!("              Must be less than CHAIN_LEN");
        println!("              Example: DEPTHS=16,64,255");
        println!("  KEYS_PER_BLOCK");
        println!("              Additional noise/bulk keys inserted per fixture block [default: {default_keys_per_block}]");
        println!("              Must be >= 0; fixture keys per block = 1 measured depth key + KEYS_PER_BLOCK (total default: {default_total_fixture_keys})");
        println!("              Read measurements always target the single measured depth key");
        println!("  READ_PROOFS");
        println!("              Set to true/false to steer proofed reads [default: false]");
        println!("  CACHE_STRATEGIES");
        println!("              Comma-separated MARF cache strategies [default: {default_cache_strategies}]");
        println!("              Example: CACHE_STRATEGIES=noop,node256,everything");
        println!("  SQLITE_WAL_AUTOCHECKPOINT");
        println!("              Optional SQLite WAL auto-checkpoint page threshold");
        println!("              Example: SQLITE_WAL_AUTOCHECKPOINT=0 (disable auto-checkpoint)");
        println!("  SQLITE_WAL_CHECKPOINT_MODE");
        println!("              WAL checkpoint mode for explicit post-setup checkpoint when auto-checkpoint is disabled");
        println!("              Post-setup checkpoint runs only when SQLITE_WAL_AUTOCHECKPOINT=0");
        println!("              Allowed: PASSIVE, FULL, RESTART, TRUNCATE [default: PASSIVE]");
        println!("  OUTPUT_FORMAT");
        println!("              Output mode [default: summary]");
        println!("              'summary': unified summary lines only");
        println!("              'raw': config/result lines + unified summary lines");
        println!();
        println!("Output Lines:");
        println!("  config      Effective benchmark settings");
        println!("  result      Per-round measurement: strategy/depth/time + alloc totals + per-op metrics");
        println!("  summary     Unified summary lines emitted by marf bench main");
        return;
    }
}

/// Build fixture key for a block height.
fn depth_key(height: u32) -> String {
    format!("depth:{height:08x}")
}

/// Build key corresponding to a depth measured from current tip.
fn key_for_depth_from_tip(tip_height: u32, depth: u32) -> String {
    assert!(depth < tip_height);
    depth_key(tip_height - depth)
}

/// Create and populate a read fixture MARF chain.
fn make_fixture(
    cache_strategy: &str,
    chain_len: u32,
    keys_per_block: u32,
    wal_autocheckpoint_pages: Option<i64>,
    wal_checkpoint_mode: Option<WalCheckpointMode>,
) -> MarfReadFixture {
    let db_dir = tempfile::Builder::new()
        .prefix(&format!("marf-read-profile-{cache_strategy}-"))
        .tempdir()
        .expect("failed to create MARF read benchmark dir");
    let db_path = db_dir.path().join("marf-read.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert MARF read benchmark path to UTF-8")
        .to_string();
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true);
    let mut marf = MARF::from_path(&db_path_str, open_opts.clone())
        .expect("failed to open MARF for read profile");

    apply_optional_wal_autocheckpoint(marf.sqlite_conn(), wal_autocheckpoint_pages)
        .expect("failed to set wal_autocheckpoint for read profile fixture");

    let mut parent = StacksBlockId::sentinel();
    let mut tip = parent.clone();

    for height in 1..=chain_len {
        let next = block_id(height);

        let mut tx = marf
            .begin_tx()
            .expect("failed to begin tx while building read profile fixture");
        tx.begin(&parent, &next)
            .expect("failed to begin block extension while building read profile fixture");

        let total_fixture_keys = keys_per_block + 1;
        let mut keys = Vec::with_capacity(total_fixture_keys as usize);
        let mut values = Vec::with_capacity(total_fixture_keys as usize);

        keys.push(depth_key(height));
        values.push(MARFValue::from(height));

        for noise_ix in 0..keys_per_block {
            keys.push(format!("noise:{height:08x}:{noise_ix:02x}"));
            values.push(MARFValue::from(
                height.wrapping_mul(97).wrapping_add(noise_ix + 1),
            ));
        }

        tx.insert_batch(&keys, values)
            .expect("failed to insert fixture keys");
        tx.commit()
            .expect("failed to commit block while building read profile fixture");

        parent = next.clone();
        tip = next;
    }

    maybe_run_post_setup_wal_checkpoint(
        marf.sqlite_conn(),
        wal_autocheckpoint_pages,
        wal_checkpoint_mode,
    )
    .expect("failed to run post-setup WAL checkpoint for read profile fixture");

    MarfReadFixture {
        marf,
        tip,
        tip_height: chain_len,
        _db_dir: db_dir,
    }
}

/// Parse keys-per-block setting from env.
fn parse_keys_per_block() -> u32 {
    parse_u32_env("KEYS_PER_BLOCK", DEFAULT_KEYS_PER_BLOCK)
}

/// Parse chain length from env with depth-based default.
fn parse_chain_len(depths: &[u32]) -> u32 {
    let max_depth = *depths.iter().max().expect("depth list must not be empty");
    let default_chain_len = max_depth.saturating_add(DEFAULT_CHAIN_LEN_DEPTH_SLACK);
    parse_u32_env("CHAIN_LEN", default_chain_len)
}

/// Resolve proofed-read setting from CLI flags and env.
fn parse_proofs_setting(args: &[String]) -> bool {
    let cli_proofs = args.iter().any(|arg| arg == "--proofs");
    let env_proofs = std::env::var("READ_PROOFS")
        .ok()
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false);
    cli_proofs || env_proofs
}

/// Measure a single read case for key/variant over `iters` operations.
fn measure_case(
    fixture: &mut MarfReadFixture,
    key: &str,
    iters: usize,
    variant: ReadVariant,
) -> BenchMeasurement {
    measure_with_allocs(|| {
        for _ in 0..iters {
            match variant {
                ReadVariant::Get => {
                    black_box(
                        fixture
                            .marf
                            .get(&fixture.tip, key)
                            .expect("MARF::get failed in read profile"),
                    );
                }
                ReadVariant::GetWithProof => {
                    black_box(
                        fixture
                            .marf
                            .get_with_proof(&fixture.tip, key)
                            .expect("MARF::get_with_proof failed in read profile"),
                    );
                }
            }
        }
    })
}

/// Execute selected read variants and summarize per strategy/depth.
fn run_with_variants(
    args: &[String],
    output_mode: OutputMode,
    benchmark_name: &'static str,
    variants: &[ReadVariant],
) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage(args);
        return None;
    }

    let iters = parse_usize_env("ITERS", DEFAULT_READ_ITERS);
    let rounds = parse_usize_env("ROUNDS", DEFAULT_READ_ROUNDS);
    let keys_per_block = parse_keys_per_block();
    let total_fixture_keys = keys_per_block + 1;
    let depths = parse_csv_u32_env("DEPTHS", &DEFAULT_DEPTHS);
    let chain_len = parse_chain_len(&depths);
    let wal_autocheckpoint_pages = parse_optional_wal_autocheckpoint_pages();
    let wal_checkpoint_mode = parse_optional_wal_checkpoint_mode();
    let cache_strategies = parse_csv_string_env("CACHE_STRATEGIES", &DEFAULT_CACHE_STRATEGIES);

    assert!(iters > 0, "ITERS must be > 0");
    assert!(rounds > 0, "ROUNDS must be > 0");

    let max_depth = *depths.iter().max().expect("depth list must not be empty");
    assert!(
        chain_len > max_depth,
        "CHAIN_LEN ({chain_len}) must be greater than max depth ({max_depth})"
    );
    if let Some(pages) = wal_autocheckpoint_pages {
        assert!(
            pages >= 0,
            "SQLITE_WAL_AUTOCHECKPOINT must be >= 0 (0 disables auto-checkpoint)"
        );
    }

    if output_mode.is_raw() {
        println!(
            "config\tchain_len={chain_len}\titers={iters}\trounds={rounds}\tkeys_per_block={keys_per_block}\ttotal_fixture_keys_per_block={total_fixture_keys}\tdepths={depths:?}\tstrategies={cache_strategies:?}\tsqlite_wal_autocheckpoint={wal_autocheckpoint_pages:?}\tsqlite_wal_checkpoint_mode={wal_checkpoint_mode:?}\tsqlite_post_setup_checkpoint_ran={}"
            ,
            wal_autocheckpoint_pages == Some(0)
        );
    }

    let mut results: HashMap<(String, u32, &'static str), CaseAggregate> = HashMap::new();

    for round in 1..=rounds {
        for strategy in &cache_strategies {
            let mut fixture = make_fixture(
                strategy,
                chain_len,
                keys_per_block,
                wal_autocheckpoint_pages,
                wal_checkpoint_mode,
            );

            for &depth in &depths {
                let key = key_for_depth_from_tip(fixture.tip_height, depth);
                for &variant in variants {
                    let measurement = measure_case(&mut fixture, &key, iters, variant);
                    let elapsed_ms = measurement.elapsed_ms;
                    let us_per_op = (elapsed_ms * 1000.0) / (iters as f64);
                    let alloc_calls_per_op =
                        (measurement.snapshot.alloc_calls as f64) / (iters as f64);
                    let alloc_bytes_per_op =
                        (measurement.snapshot.alloc_bytes as f64) / (iters as f64);

                    if output_mode.is_raw() {
                        println!(
                            "result\tround={round}\tstrategy={strategy}\tdepth={depth}\tvariant={}\telapsed_ms={elapsed_ms:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\tus_per_op={us_per_op:.6}\talloc_calls_per_op={alloc_calls_per_op:.6}\talloc_bytes_per_op={alloc_bytes_per_op:.6}",
                            variant.name(),
                            measurement.snapshot.alloc_calls,
                            measurement.snapshot.alloc_bytes,
                            measurement.snapshot.realloc_calls,
                            measurement.snapshot.dealloc_calls,
                            measurement.snapshot.dealloc_bytes,
                        );
                    }

                    let agg = results
                        .entry((strategy.to_string(), depth, variant.name()))
                        .or_default();
                    agg.total_ms += elapsed_ms;
                    agg.alloc_calls += measurement.snapshot.alloc_calls;
                    agg.alloc_bytes += measurement.snapshot.alloc_bytes;
                }
            }
        }
    }

    let mut summary = Summary::new(
        benchmark_name,
        cache_strategies.len() * depths.len() * variants.len(),
    );
    for strategy in &cache_strategies {
        for &depth in &depths {
            for &variant in variants {
                let key = (strategy.to_string(), depth, variant.name());
                let case = results
                    .get(&key)
                    .expect("missing case samples while summarizing read profile");
                summary.push_line(
                    format!("{strategy}/depth={depth}/variant={}", variant.name()),
                    case.total_ms,
                    case.alloc_calls,
                    case.alloc_bytes,
                );
            }
        }
    }

    Some(summary)
}

/// Run the read benchmark subcommand.
pub fn run(args: &[String], output_mode: OutputMode) -> Option<Summary> {
    if parse_proofs_setting(args) {
        run_with_variants(args, output_mode, "read", &[ReadVariant::GetWithProof])
    } else {
        run_with_variants(args, output_mode, "read", &[ReadVariant::Get])
    }
}
