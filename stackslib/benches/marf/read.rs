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

//! Read-heavy MARF timing benchmark focused on `MARF::get` and `MARF::get_with_proof` backpointer
//! walks.

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
    OutputMode, Summary, WalCheckpointMode,
};
use crate::utils::{block_id, has_help_flag, parse_csv_u32_env, parse_u32_env, parse_usize_env};

/// Default read operations per measured case.
const DEFAULT_READ_ITERS: usize = 200_000;
/// Default independent repetitions per case.
const DEFAULT_READ_ROUNDS: usize = 2;
/// Default keys-per-block levels (blob-size axis).
/// Higher values create larger per-block blobs.
const DEFAULT_KPB: [u32; 2] = [1, 16];
/// Default gap-phase lengths (backpointer-density axis).
/// Higher values create more backpointer indirection between tip and target data.
const DEFAULT_GAP: [u32; 2] = [0, 512];
/// Default compression modes.
const DEFAULT_COMPRESSION: [bool; 2] = [false, true];
/// Default number of density-phase blocks.
const DEFAULT_CHAIN_LEN: u32 = 256;

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
    realloc_calls: u64,
}

/// Backed MARF fixture used by read-case execution.
struct MarfReadFixture {
    marf: MARF<StacksBlockId>,
    tip: StacksBlockId,
    /// The key inserted at the end of the density phase (the read target).
    target_key: String,
    _db_dir: TempDir,
}

#[rustfmt::skip]
fn print_usage() {
    let default_kpb = DEFAULT_KPB.iter().map(|k| k.to_string()).collect::<Vec<_>>().join(",");
    let default_gap = DEFAULT_GAP.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(",");
    let default_compression = DEFAULT_COMPRESSION.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");

    println!("read: MARF::get benchmark (two-phase fixture)");
    println!();
    println!("The fixture builds a density-phase chain (large blobs) followed by a");
    println!("gap-phase chain (tiny blobs), then reads a key inserted at the end of");
    println!("the density phase. KPB and GAP are independent axes:");
    println!();
    println!("  KPB  controls blob size of blocks that backpointers resolve to");
    println!("  GAP  controls backpointer indirection depth between tip and target");
    println!();
    println!("CLI Args:");
    println!("  --proofs     Use MARF::get_with_proof instead of MARF::get [default: false]");
    println!();
    println!("Environment Variables:");
    println!("  ITERS       Reads per measured case [default: {DEFAULT_READ_ITERS}]");
    println!("  ROUNDS      Independent repetitions per case [default: {DEFAULT_READ_ROUNDS}]");
    println!("  CHAIN_LEN   Number of density-phase blocks [default: {DEFAULT_CHAIN_LEN}]");
    println!("  KPB         Comma-separated keys-per-block for density phase (blob-size axis) [default: {default_kpb}]");
    println!("              Higher values create larger per-block blobs");
    println!("              Example: KPB=1,16,100");
    println!("  GAP         Comma-separated gap-phase lengths (backpointer-density axis) [default: {default_gap}]");
    println!("              Higher values add more backpointer indirection between tip and target");
    println!("              Example: GAP=0,256,1024");
    println!("  READ_PROOFS");
    println!("              Set to true/false to steer proofed reads [default: false]");
    println!("  COMPRESSION");
    println!("              Comma-separated compression modes: true,false [default: {default_compression}]");
    println!("  SQLITE_WAL_AUTOCHECKPOINT");
    println!("              Optional SQLite WAL auto-checkpoint page threshold");
    println!("  SQLITE_WAL_CHECKPOINT_MODE");
    println!("              WAL checkpoint mode when SQLITE_WAL_AUTOCHECKPOINT=0");
    println!("              Allowed: PASSIVE, FULL, RESTART, TRUNCATE [default: PASSIVE]");
    println!("  OUTPUT_FORMAT");
    println!("              Output mode [default: summary]");
    println!("              'summary': unified summary lines only");
    println!("              'raw': config/result lines + unified summary lines");
}

/// Create a two-phase read fixture.
///
/// Phase 1 (density): `chain_len` blocks with `kpb` keys each.
///   The target read key is inserted at the last density-phase block.
///
/// Phase 2 (gap): `gap` blocks with 1 filler key each.
///   These create backpointer indirection without inflating blobs.
fn make_fixture(
    compress: bool,
    chain_len: u32,
    kpb: u32,
    gap: u32,
    wal_autocheckpoint_pages: Option<i64>,
    wal_checkpoint_mode: Option<WalCheckpointMode>,
) -> MarfReadFixture {
    let compress_tag = if compress {
        "compressed"
    } else {
        "uncompressed"
    };
    let db_dir = tempfile::Builder::new()
        .prefix(&format!("marf-read-{compress_tag}-kpb{kpb}-gap{gap}-"))
        .tempdir()
        .expect("failed to create MARF read benchmark dir");
    let db_path = db_dir.path().join("marf-read.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert MARF read benchmark path to UTF-8")
        .to_string();
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true)
        .with_compression(compress);
    let mut marf = MARF::from_path(&db_path_str, open_opts.clone())
        .expect("failed to open MARF for read profile");

    apply_optional_wal_autocheckpoint(marf.sqlite_conn(), wal_autocheckpoint_pages)
        .expect("failed to set wal_autocheckpoint for read profile fixture");

    let mut parent = StacksBlockId::sentinel();
    let mut height = 0u32;

    // Phase 1: density phase — build trie with kpb keys per block.
    for _ in 0..chain_len {
        height += 1;
        let next = block_id(height);

        let mut tx = marf
            .begin_tx()
            .expect("failed to begin tx in density phase");
        tx.begin(&parent, &next)
            .expect("failed to begin block in density phase");

        let mut keys = Vec::with_capacity((kpb + 1) as usize);
        let mut values = Vec::with_capacity((kpb + 1) as usize);

        // One measured key per block (used as filler; the target is at the last block).
        keys.push(format!("density:{height:08x}"));
        values.push(MARFValue::from(height));

        for noise_ix in 0..kpb {
            keys.push(format!("noise:{height:08x}:{noise_ix:04x}"));
            values.push(MARFValue::from(
                height.wrapping_mul(97).wrapping_add(noise_ix + 1),
            ));
        }

        tx.insert_batch(&keys, values)
            .expect("failed to insert density-phase keys");
        tx.commit().expect("failed to commit density-phase block");

        parent = next;
    }

    // The target key is the density key from the last density-phase block.
    let target_key = format!("density:{height:08x}");

    // Phase 2: gap phase — extend chain with 1 filler key per block.
    for gap_ix in 0..gap {
        height += 1;
        let next = block_id(height);

        let mut tx = marf.begin_tx().expect("failed to begin tx in gap phase");
        tx.begin(&parent, &next)
            .expect("failed to begin block in gap phase");

        let keys = vec![format!("gap:{gap_ix:08x}")];
        let values = vec![MARFValue::from(height.wrapping_add(10_000))];
        tx.insert_batch(&keys, values)
            .expect("failed to insert gap-phase key");
        tx.commit().expect("failed to commit gap-phase block");

        parent = next;
    }

    let tip = parent;

    maybe_run_post_setup_wal_checkpoint(
        marf.sqlite_conn(),
        wal_autocheckpoint_pages,
        wal_checkpoint_mode,
    )
    .expect("failed to run post-setup WAL checkpoint for read profile fixture");

    MarfReadFixture {
        marf,
        tip,
        target_key,
        _db_dir: db_dir,
    }
}

/// Parse keys-per-block levels from env.
fn parse_kpb_levels() -> Vec<u32> {
    parse_csv_u32_env("KPB", &DEFAULT_KPB)
}

/// Parse gap-phase lengths from env.
fn parse_gap_levels() -> Vec<u32> {
    parse_csv_u32_env("GAP", &DEFAULT_GAP)
}

/// Parse compression modes from COMPRESSION env var or return defaults.
fn parse_compression_modes() -> Vec<bool> {
    let Some(raw) = std::env::var("COMPRESSION").ok() else {
        return DEFAULT_COMPRESSION.to_vec();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| match s {
            "true" | "1" | "on" => true,
            "false" | "0" | "off" => false,
            _ => panic!("COMPRESSION values must be true/false, got '{s}'"),
        })
        .collect()
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

/// Measure a single read case over `iters` operations.
fn measure_case(
    fixture: &mut MarfReadFixture,
    iters: usize,
    variant: ReadVariant,
) -> BenchMeasurement {
    let key = &fixture.target_key;
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

/// Execute selected read variants and summarize per compression/kpb/gap.
fn run_with_variants(
    args: &[String],
    output_mode: OutputMode,
    benchmark_name: &'static str,
    variants: &[ReadVariant],
) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage();
        return None;
    }

    let iters = parse_usize_env("ITERS", DEFAULT_READ_ITERS);
    let rounds = parse_usize_env("ROUNDS", DEFAULT_READ_ROUNDS);
    let kpb_levels = parse_kpb_levels();
    let gap_levels = parse_gap_levels();
    let chain_len = parse_u32_env("CHAIN_LEN", DEFAULT_CHAIN_LEN);
    let wal_autocheckpoint_pages = parse_optional_wal_autocheckpoint_pages();
    let wal_checkpoint_mode = parse_optional_wal_checkpoint_mode();
    let compression_modes = parse_compression_modes();

    assert!(iters > 0, "ITERS must be > 0");
    assert!(rounds > 0, "ROUNDS must be > 0");
    assert!(chain_len > 0, "CHAIN_LEN must be > 0");
    if let Some(pages) = wal_autocheckpoint_pages {
        assert!(
            pages >= 0,
            "SQLITE_WAL_AUTOCHECKPOINT must be >= 0 (0 disables auto-checkpoint)"
        );
    }

    if output_mode.is_raw() {
        println!(
            "config\tchain_len={chain_len}\titers={iters}\trounds={rounds}\tkpb={kpb_levels:?}\tgap={gap_levels:?}\tcompression={compression_modes:?}\tsqlite_wal_autocheckpoint={wal_autocheckpoint_pages:?}\tsqlite_wal_checkpoint_mode={wal_checkpoint_mode:?}\tsqlite_post_setup_checkpoint_ran={}",
            wal_autocheckpoint_pages == Some(0)
        );
    }

    // Results key: (compress_label, kpb, gap, variant_name)
    let mut results: HashMap<(String, u32, u32, &'static str), CaseAggregate> = HashMap::new();

    for round in 1..=rounds {
        for &compress in &compression_modes {
            let compress_label = if compress {
                "compressed"
            } else {
                "uncompressed"
            };
            for &kpb in &kpb_levels {
                for &gap in &gap_levels {
                    let mut fixture = make_fixture(
                        compress,
                        chain_len,
                        kpb,
                        gap,
                        wal_autocheckpoint_pages,
                        wal_checkpoint_mode,
                    );

                    for &variant in variants {
                        let measurement = measure_case(&mut fixture, iters, variant);
                        let elapsed_ms = measurement.elapsed_ms;
                        let us_per_op = (elapsed_ms * 1000.0) / (iters as f64);
                        let alloc_calls_per_op =
                            (measurement.snapshot.alloc_calls as f64) / (iters as f64);
                        let alloc_bytes_per_op =
                            (measurement.snapshot.alloc_bytes as f64) / (iters as f64);

                        if output_mode.is_raw() {
                            println!(
                                "result\tround={round}\tcompression={compress_label}\tkpb={kpb}\tgap={gap}\tvariant={}\telapsed_ms={elapsed_ms:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\tus_per_op={us_per_op:.6}\talloc_calls_per_op={alloc_calls_per_op:.6}\talloc_bytes_per_op={alloc_bytes_per_op:.6}",
                                variant.name(),
                                measurement.snapshot.alloc_calls,
                                measurement.snapshot.alloc_bytes,
                                measurement.snapshot.realloc_calls,
                                measurement.snapshot.dealloc_calls,
                                measurement.snapshot.dealloc_bytes,
                            );
                        }

                        let agg = results
                            .entry((compress_label.to_string(), kpb, gap, variant.name()))
                            .or_default();
                        agg.total_ms += elapsed_ms;
                        agg.alloc_calls += measurement.snapshot.alloc_calls;
                        agg.alloc_bytes += measurement.snapshot.alloc_bytes;
                        agg.realloc_calls += measurement.snapshot.realloc_calls;
                    }
                }
            }
        }
    }

    let mut summary = Summary::new(
        benchmark_name,
        compression_modes.len() * kpb_levels.len() * gap_levels.len() * variants.len(),
    );
    for &compress in &compression_modes {
        let compress_label = if compress {
            "compressed"
        } else {
            "uncompressed"
        };
        for &kpb in &kpb_levels {
            for &gap in &gap_levels {
                for &variant in variants {
                    let key = (compress_label.to_string(), kpb, gap, variant.name());
                    let case = results
                        .get(&key)
                        .expect("missing case samples while summarizing read profile");
                    summary.push_line(
                        format!(
                            "{compress_label}/kpb={kpb}/gap={gap}/variant={}",
                            variant.name()
                        ),
                        case.total_ms,
                        case.alloc_calls,
                        case.alloc_bytes,
                        case.realloc_calls,
                    );
                }
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
