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

//! Production-scale MARF block commit benchmark.
//!
//! Simulates the mainnet block commit workload: a parent chain where every block
//! carries a realistic key count, followed by a single measured block that inserts
//! new keys and updates a configurable fraction of existing ones.
//!
//! Unlike `write`, which isolates individual node-promotion steps with minimal keys,
//! this benchmark measures the four top-level phases of a full block commit at
//! realistic trie density and back-pointer depth:
//!
//!   begin_block  — open the new trie block
//!   insert_phase — all key insertions and updates as one measurement
//!   seal         — Merkle hash walk over the completed trie
//!   commit_flush — trie blob serialisation and SQLite write
//!
//! Parent chain blocks are also built with `BLOCK_KEYS` keys each so that
//! back-pointer structures reflect production trie density throughout the chain.

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::chainstate::stacks::index::{
    ClarityMarfTrieId as _, Error as IndexError, MARFValue,
};
use stacks_common::types::chainstate::StacksBlockId;
use tempfile::TempDir;

use crate::common::{
    apply_optional_wal_autocheckpoint, maybe_run_post_setup_wal_checkpoint,
    measure_result_with_allocs, parse_optional_wal_autocheckpoint_pages,
    parse_optional_wal_checkpoint_mode, BenchMeasurement, OutputMode, Summary,
};
use crate::utils::{block_id, has_help_flag, parse_csv_usize_env, parse_usize_env};

/// Default keys inserted per block (both parent setup and measured block).
const DEFAULT_BLOCK_KEYS: usize = 1000;
/// Default parent chain depth (number of ancestor blocks).
const DEFAULT_BLOCK_DEPTH: usize = 256;
/// Default percentage of measured block writes that update existing keys.
const DEFAULT_KEY_UPDATES_PERCENT: usize = 25;
/// Default independent measurement rounds.
const DEFAULT_ROUNDS: usize = 3;

/// Aggregated timing and allocation totals across rounds for one step.
#[derive(Clone, Copy, Default)]
struct StepAggregate {
    total_ms: f64,
    alloc_calls: u64,
    alloc_bytes: u64,
    realloc_calls: u64,
}

impl StepAggregate {
    fn accumulate(&mut self, m: &BenchMeasurement) {
        self.total_ms += m.elapsed_ms;
        self.alloc_calls = self.alloc_calls.saturating_add(m.snapshot.alloc_calls);
        self.alloc_bytes = self.alloc_bytes.saturating_add(m.snapshot.alloc_bytes);
        self.realloc_calls = self.realloc_calls.saturating_add(m.snapshot.realloc_calls);
    }
}

#[rustfmt::skip]
fn print_usage() {
    println!("block-commit: Production-scale MARF block commit profiler");
    println!();
    println!("Measures a full block commit at realistic trie density: a parent chain");
    println!("built with BLOCK_KEYS keys per block, then one measured block that");
    println!("inserts new keys and updates a share of existing ones.");
    println!();
    println!("Environment Variables:");
    println!("  BLOCK_KEYS   Comma-separated keys-per-block values for setup chain and measured block [default: {DEFAULT_BLOCK_KEYS}]");
    println!("               Example: BLOCK_KEYS=512,2048,4096");
    println!("  BLOCK_DEPTH  Comma-separated parent-chain depths [default: {DEFAULT_BLOCK_DEPTH}]");
    println!("               Example: BLOCK_DEPTH=256,1024,2048");
    println!("  KEY_UPDATES  Comma-separated percents (0-100) of measured block writes that update existing keys");
    println!("               Example: KEY_UPDATES=0,25,50,75");
    println!("               Update keys are drawn evenly from all parent blocks [default {DEFAULT_KEY_UPDATES_PERCENT}]");
    println!("  COMPRESSION  Comma-separated compression modes: true,false [default: true]");
    println!("  ROUNDS       Independent measurement rounds [default {DEFAULT_ROUNDS}]");
    println!("  SQLITE_WAL_AUTOCHECKPOINT");
    println!("               Optional WAL auto-checkpoint page threshold (0 = disabled)");
    println!("  SQLITE_WAL_CHECKPOINT_MODE");
    println!("               WAL checkpoint mode for explicit post-setup checkpoint");
    println!("               when SQLITE_WAL_AUTOCHECKPOINT=0 (PASSIVE|FULL|RESTART|TRUNCATE)");
    println!("  OUTPUT_FORMAT");
    println!("               'summary': summary lines only [default]");
    println!("               'raw': per-round result lines + summary lines");
    println!();
    println!("Output Lines:");
    println!("  config  Effective configuration");
    println!("  result  Per-round per-step timing and allocation totals (raw mode only)");
    println!("  summary Unified summary lines");
}

fn make_marf(compress: bool, compress_label: &str) -> (TempDir, MARF<StacksBlockId>) {
    let db_dir = tempfile::Builder::new()
        .prefix(&format!("marf-block-commit-{compress_label}-"))
        .tempdir()
        .expect("failed to create block_commit MARF dir");
    let db_path = db_dir.path().join("marf.sqlite");
    let db_path_str = db_path.to_str().expect("failed to convert path to UTF-8");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true)
        .with_compression(compress);
    let marf = MARF::from_path(db_path_str, open_opts).expect("failed to open block_commit MARF");
    (db_dir, marf)
}

fn parse_compression_modes() -> Vec<bool> {
    let Some(raw) = std::env::var("COMPRESSION").ok() else {
        return vec![true]; // production default: compressed
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

fn parse_block_keys() -> Vec<usize> {
    parse_csv_usize_env("BLOCK_KEYS", &[DEFAULT_BLOCK_KEYS])
}

fn parse_block_depths() -> Vec<usize> {
    parse_csv_usize_env("BLOCK_DEPTH", &[DEFAULT_BLOCK_DEPTH])
}

fn parse_key_updates_pcts() -> Vec<usize> {
    parse_csv_usize_env("KEY_UPDATES", &[DEFAULT_KEY_UPDATES_PERCENT])
}

fn measure_step<R, F>(f: F) -> Result<BenchMeasurement, IndexError>
where
    F: FnOnce() -> Result<R, IndexError>,
{
    measure_result_with_allocs(f)
}

fn run_workflow(output_mode: OutputMode) -> Result<Summary, IndexError> {
    let rounds = parse_usize_env("ROUNDS", DEFAULT_ROUNDS);
    let wal_autocheckpoint_pages = parse_optional_wal_autocheckpoint_pages();
    let wal_checkpoint_mode = parse_optional_wal_checkpoint_mode();
    let block_keys_values = parse_block_keys();
    let block_depth_values = parse_block_depths();
    let key_updates_pcts = parse_key_updates_pcts();
    let compression_modes = parse_compression_modes();

    assert!(
        block_keys_values.iter().all(|value| *value > 0),
        "BLOCK_KEYS entries must be > 0"
    );
    assert!(
        block_depth_values.iter().all(|value| *value > 0),
        "BLOCK_DEPTH entries must be > 0"
    );
    assert!(
        key_updates_pcts.iter().all(|value| *value <= 100),
        "KEY_UPDATES entries must be in range 0..=100"
    );
    assert!(rounds > 0, "ROUNDS must be > 0");

    if output_mode.is_raw() {
        println!(
            "config\tblock_keys={block_keys_values:?}\tblock_depth={block_depth_values:?}\tkey_updates_pct={key_updates_pcts:?}\trounds={rounds}\tcompression={compression_modes:?}\tsqlite_wal_autocheckpoint={wal_autocheckpoint_pages:?}\tsqlite_wal_checkpoint_mode={wal_checkpoint_mode:?}\tsqlite_post_setup_checkpoint_ran={}"
            ,
            wal_autocheckpoint_pages == Some(0)
        );
    }

    let mut summary = Summary::new(
        "block_commit",
        4 * compression_modes.len()
            * block_keys_values.len()
            * block_depth_values.len()
            * key_updates_pcts.len(),
    );

    for (compress_idx, &compress) in compression_modes.iter().enumerate() {
        let compress_label = if compress {
            "compressed"
        } else {
            "uncompressed"
        };
        for &block_keys in &block_keys_values {
            for &block_depth in &block_depth_values {
                for &key_updates_pct in &key_updates_pcts {
                    let mut begin_agg = StepAggregate::default();
                    let mut insert_agg = StepAggregate::default();
                    let mut seal_agg = StepAggregate::default();
                    let mut commit_agg = StepAggregate::default();

                    for round in 1..=rounds {
                        // Unique seed space per round and matrix dimensions to avoid key collisions.
                        let base_seed = 4_000_000u32
                            .wrapping_add((compress_idx as u32).wrapping_mul(1_000_000))
                            .wrapping_add((round as u32).wrapping_mul(100_000))
                            .wrapping_add((block_depth as u32).wrapping_mul(10))
                            .wrapping_add(key_updates_pct as u32);

                        let (_db_dir, mut marf) = make_marf(compress, compress_label);

                        apply_optional_wal_autocheckpoint(
                            marf.sqlite_conn(),
                            wal_autocheckpoint_pages,
                        )
                        .map_err(IndexError::from)?;

                        // --- Build parent chain (unmeasured setup) ---
                        //
                        // Each block carries BLOCK_KEYS insertions so that back-pointer structures
                        // in the measured block reflect realistic production trie density.
                        let mut parent = StacksBlockId::sentinel();
                        let mut update_candidates: Vec<String> = Vec::new();

                        for depth in 0..block_depth {
                            let blk = block_id(base_seed.wrapping_add(depth as u32));
                            let mut tx = marf.begin_tx()?;
                            tx.begin(&parent, &blk)?;

                            let keys: Vec<String> = (0..block_keys)
                                .map(|i| format!("bc:setup:{depth:06x}/{i:08x}"))
                                .collect();
                            let values: Vec<MARFValue> = (0..block_keys as u32)
                                .map(|i| MARFValue::from(base_seed.wrapping_add(i).wrapping_add(1)))
                                .collect();
                            tx.insert_batch(&keys, values)?;
                            tx.commit()?;

                            update_candidates.extend(keys);
                            parent = blk;
                        }

                        maybe_run_post_setup_wal_checkpoint(
                            marf.sqlite_conn(),
                            wal_autocheckpoint_pages,
                            wal_checkpoint_mode,
                        )
                        .map_err(IndexError::from)?;

                        // --- Compute measured block insert/update split ---
                        let requested_updates = (block_keys.saturating_mul(key_updates_pct)) / 100;
                        let effective_updates = requested_updates.min(update_candidates.len());
                        let new_key_count = block_keys.saturating_sub(effective_updates);

                        let measured_blk = block_id(base_seed.wrapping_add(block_depth as u32));
                        let mut tx = marf.begin_tx()?;

                        // Measure begin_block
                        let begin_m = measure_step(|| tx.begin(&parent, &measured_blk))?;
                        begin_agg.accumulate(&begin_m);

                        // Build insert batch: new keys followed by evenly-spaced update keys.
                        let mut all_keys: Vec<String> = (0..new_key_count)
                            .map(|i| format!("bc:meas:{round:04x}/{i:08x}"))
                            .collect();
                        for i in 0..effective_updates {
                            let pool_idx = (i * update_candidates.len()) / effective_updates;
                            all_keys.push(update_candidates[pool_idx].clone());
                        }
                        let values: Vec<MARFValue> = (0..all_keys.len() as u32)
                            .map(|i| {
                                MARFValue::from(base_seed.wrapping_add(900_000).wrapping_add(i))
                            })
                            .collect();

                        // Measure insert_phase
                        let insert_m = measure_step(|| tx.insert_batch(&all_keys, values))?;
                        insert_agg.accumulate(&insert_m);

                        // Measure seal
                        let seal_m = measure_step(|| tx.seal())?;
                        seal_agg.accumulate(&seal_m);

                        // Measure commit_flush
                        let commit_m = measure_step(|| tx.commit())?;
                        commit_agg.accumulate(&commit_m);

                        if output_mode.is_raw() {
                            let total_keys = all_keys.len();
                            println!(
                                "result\tround={round}\tcompression={compress_label}\tblock_keys={block_keys}\tblock_depth={block_depth}\tkey_updates={key_updates_pct}\tstep=begin_block\telapsed_ms={:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}",
                                begin_m.elapsed_ms,
                                begin_m.snapshot.alloc_calls,
                                begin_m.snapshot.alloc_bytes,
                                begin_m.snapshot.realloc_calls,
                            );
                            println!(
                                "result\tround={round}\tcompression={compress_label}\tblock_keys={block_keys}\tblock_depth={block_depth}\tkey_updates={key_updates_pct}\tstep=insert_phase\tkeys={total_keys}\tnew={new_key_count}\tupdates={effective_updates}\telapsed_ms={:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}",
                                insert_m.elapsed_ms,
                                insert_m.snapshot.alloc_calls,
                                insert_m.snapshot.alloc_bytes,
                                insert_m.snapshot.realloc_calls,
                            );
                            println!(
                                "result\tround={round}\tcompression={compress_label}\tblock_keys={block_keys}\tblock_depth={block_depth}\tkey_updates={key_updates_pct}\tstep=seal\telapsed_ms={:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}",
                                seal_m.elapsed_ms,
                                seal_m.snapshot.alloc_calls,
                                seal_m.snapshot.alloc_bytes,
                                seal_m.snapshot.realloc_calls,
                            );
                            println!(
                                "result\tround={round}\tcompression={compress_label}\tblock_keys={block_keys}\tblock_depth={block_depth}\tkey_updates={key_updates_pct}\tstep=commit_flush\telapsed_ms={:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}",
                                commit_m.elapsed_ms,
                                commit_m.snapshot.alloc_calls,
                                commit_m.snapshot.alloc_bytes,
                                commit_m.snapshot.realloc_calls,
                            );
                        }
                    }

                    let prefix = format!(
                        "{compress_label}/block_keys={block_keys}/block_depth={block_depth}/key_updates={key_updates_pct}"
                    );
                    summary.push_line(
                        format!("{prefix}/begin_block"),
                        begin_agg.total_ms,
                        begin_agg.alloc_calls,
                        begin_agg.alloc_bytes,
                        begin_agg.realloc_calls,
                    );
                    summary.push_line(
                        format!("{prefix}/insert_phase"),
                        insert_agg.total_ms,
                        insert_agg.alloc_calls,
                        insert_agg.alloc_bytes,
                        insert_agg.realloc_calls,
                    );
                    summary.push_line(
                        format!("{prefix}/seal"),
                        seal_agg.total_ms,
                        seal_agg.alloc_calls,
                        seal_agg.alloc_bytes,
                        seal_agg.realloc_calls,
                    );
                    summary.push_line(
                        format!("{prefix}/commit_flush"),
                        commit_agg.total_ms,
                        commit_agg.alloc_calls,
                        commit_agg.alloc_bytes,
                        commit_agg.realloc_calls,
                    );
                }
            }
        }
    }

    Ok(summary)
}

/// Run the block-commit benchmark subcommand.
pub fn run(args: &[String], output_mode: OutputMode) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage();
        return None;
    }
    Some(run_workflow(output_mode).expect("block_commit benchmark failed"))
}
