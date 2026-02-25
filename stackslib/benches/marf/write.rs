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

//! Write-heavy MARF profiling benchmark focused on a controlled block-write workflow.

use std::collections::HashMap;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::chainstate::stacks::index::{
    ClarityMarfTrieId as _, Error as IndexError, MARFValue,
};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use tempfile::TempDir;

use crate::common::{
    apply_optional_wal_autocheckpoint, maybe_run_post_setup_wal_checkpoint,
    measure_result_with_allocs, parse_optional_wal_autocheckpoint_pages,
    parse_optional_wal_checkpoint_mode, BenchMeasurement,
};
use crate::utils::{block_id, has_help_flag, parse_csv_usize_env, parse_usize_env};
use crate::{OutputMode, Summary};

/// Default independent repetitions per write case.
const DEFAULT_WRITE_ROUNDS: usize = 2;
/// Default parent-chain depths used for write workflow setup.
const DEFAULT_WRITE_DEPTHS: [usize; 1] = [1];
/// Default percentage of keys treated as updates.
const DEFAULT_KEY_UPDATES_PERCENT: usize = 0;
/// Default search budget when deriving promotion-driving keys.
const DEFAULT_KEY_SEARCH_MAX_TRIES: usize = 200_000;
/// Minimum inserted-key count needed to force node promotions through node256.
const REQUIRED_BRANCHES: usize = 49;
/// Cache strategies exercised by the write benchmark.
const WRITE_CACHE_STRATEGIES: [&str; 2] = ["noop", "node256"];

/// Aggregated timing and allocation totals for one workflow step.
#[derive(Clone, Copy, Default)]
struct StepAggregate {
    total_ms: f64,
    alloc_calls: u64,
    alloc_bytes: u64,
}

/// Half-open key range belonging to one insertion workflow step.
#[derive(Clone, Copy)]
struct InsertStep {
    name: &'static str,
    start: usize,
    end: usize,
}

/// Canonical insertion step templates used by the workflow.
const INSERT_STEP_TEMPLATES: [InsertStep; 8] = [
    InsertStep {
        name: "insert_first_leaf",
        start: 0,
        end: 1,
    },
    InsertStep {
        name: "split_leaf_to_node4",
        start: 1,
        end: 2,
    },
    InsertStep {
        name: "fill_node4_to_capacity",
        start: 2,
        end: 4,
    },
    InsertStep {
        name: "promote_node4_to_node16",
        start: 4,
        end: 5,
    },
    InsertStep {
        name: "fill_node16_to_capacity",
        start: 5,
        end: 16,
    },
    InsertStep {
        name: "promote_node16_to_node48",
        start: 16,
        end: 17,
    },
    InsertStep {
        name: "fill_node48_to_capacity",
        start: 17,
        end: 48,
    },
    InsertStep {
        name: "promote_node48_to_node256",
        start: 48,
        end: 49,
    },
];

/// Key set metadata for promotion-driving inserts.
struct PromotionKeys {
    keys: Vec<String>,
    shared_first_byte: u8,
    search_tries: usize,
}

/// Result of preparing the parent chain before measured writes.
struct ParentChainInfo {
    tip: StacksBlockId,
    update_candidate_keys: Vec<String>,
}

#[rustfmt::skip]
fn print_usage() {
    println!("write: Step-wise MARF write workflow profiler");
    println!();
    println!("Environment Variables:");
    println!("  ITERS       Inserted keys per workflow round [default {REQUIRED_BRANCHES}]");
    println!("              Higher values increase write/rehash/seal work");
    println!("  WRITE_DEPTHS");
    println!("              Comma-separated parent-chain depths [default: 1]");
    println!("              Example: WRITE_DEPTHS=1,64,1024");
    println!("  KEY_UPDATES");
    println!("              Percent (0-100) of writes that are key updates [default {DEFAULT_KEY_UPDATES_PERCENT}]");
    println!("              Updates target existing keys from prior tries (excluding first parent/genesis trie)");
    println!("  SQLITE_WAL_AUTOCHECKPOINT");
    println!("              Optional SQLite WAL auto-checkpoint page threshold");
    println!("              Example: SQLITE_WAL_AUTOCHECKPOINT=0 (disable auto-checkpoint)");
    println!("  SQLITE_WAL_CHECKPOINT_MODE");
    println!("              WAL checkpoint mode for explicit post-setup checkpoint when auto-checkpoint is disabled");
    println!("              Post-setup checkpoint runs only when SQLITE_WAL_AUTOCHECKPOINT=0");
    println!("              Allowed: PASSIVE, FULL, RESTART, TRUNCATE [default: PASSIVE]");
    println!("  ROUNDS      Independent rounds per strategy [default {DEFAULT_WRITE_ROUNDS}]");
    println!("  KEY_SEARCH_MAX_TRIES");
    println!("              Max key candidates when searching for promotion-driving keys [default {DEFAULT_KEY_SEARCH_MAX_TRIES}]");
    println!("  OUTPUT_FORMAT");
    println!("              Output mode [default: summary]");
    println!("              'summary': unified summary lines only");
    println!("              'raw': config/result lines + unified summary lines");
    println!();
    println!("Output Lines:");
    println!("  config      Effective configuration");
    println!("  keys        Metadata about generated key set used to drive node promotions");
    println!("  result      Per-round/per-step elapsed time and allocation totals + per-item rates");
    println!("  summary     Unified summary lines emitted by marf bench main");
}

/// Measure a fallible write step with allocation counters.
fn measure_step_with_allocs<R, F>(f: F) -> Result<BenchMeasurement, IndexError>
where
    F: FnOnce() -> Result<R, IndexError>,
{
    measure_result_with_allocs(f)
}

/// Build deterministic MARF values for batch inserts.
fn make_values(start: u32, count: usize) -> Vec<MARFValue> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        values.push(MARFValue::from(
            start.wrapping_add(i as u32).wrapping_add(1),
        ));
    }
    values
}

/// Create a benchmark MARF instance for a cache strategy.
fn make_marf(cache_strategy: &str) -> (TempDir, MARF<StacksBlockId>) {
    let db_dir = tempfile::Builder::new()
        .prefix(&format!("marf-write-profile-{cache_strategy}-"))
        .tempdir()
        .expect("failed to create MARF write benchmark dir");
    let db_path = db_dir.path().join("marf-write.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert MARF write benchmark path to UTF-8");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true);
    let marf = MARF::from_path(db_path_str, open_opts).expect("failed to open MARF write profile");
    (db_dir, marf)
}

/// Build a committed parent chain and collect update-candidate keys.
fn initialize_parent_chain(
    marf: &mut MARF<StacksBlockId>,
    first_height: u32,
    chain_len: usize,
) -> Result<ParentChainInfo, IndexError> {
    let mut parent = StacksBlockId::sentinel();
    let mut update_candidate_keys = Vec::new();

    for offset in 0..chain_len {
        let next = block_id(first_height.wrapping_add(offset as u32));
        let mut tx = marf.begin_tx()?;
        tx.begin(&parent, &next)?;

        let key = format!("bootstrap:parent:{offset:08x}");
        let keys = vec![key.clone()];
        let values = vec![MARFValue::from((offset as u32).wrapping_add(1))];
        tx.insert_batch(&keys, values)?;
        tx.commit()?;

        if offset > 0 {
            update_candidate_keys.push(key);
        }

        parent = next;
    }

    Ok(ParentChainInfo {
        tip: parent,
        update_candidate_keys,
    })
}

/// Pick distributed update keys from an existing-key pool.
fn select_distributed_update_keys(pool: &[String], count: usize) -> Vec<String> {
    if pool.is_empty() || count == 0 {
        return vec![];
    }

    let count = count.min(pool.len());
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let idx = (i * pool.len()) / count;
        out.push(pool[idx].clone());
    }
    out
}

/// Find keys that share first hash byte and span second-byte branches.
fn find_promotion_keys(seed_prefix: &str, max_tries: usize, key_count: usize) -> PromotionKeys {
    let mut buckets: Vec<HashMap<u8, String>> = (0..256).map(|_| HashMap::new()).collect();

    for i in 0..max_tries {
        let key = format!("{seed_prefix}:{i:08x}");
        let hash = TrieHash::from_key(&key);
        let bytes = hash.as_bytes();

        let first = bytes[0] as usize;
        let second = bytes[1];
        let bucket = &mut buckets[first];
        bucket.entry(second).or_insert(key);

        if bucket.len() >= key_count {
            let mut pairs: Vec<(u8, String)> =
                bucket.iter().map(|(&chr, k)| (chr, k.clone())).collect();
            pairs.sort_by_key(|(chr, _)| *chr);
            pairs.truncate(key_count);

            return PromotionKeys {
                keys: pairs.into_iter().map(|(_, key)| key).collect(),
                shared_first_byte: first as u8,
                search_tries: i + 1,
            };
        }
    }

    panic!(
        "failed to find {key_count} promotion-driving keys within KEY_SEARCH_MAX_TRIES={max_tries}"
    );
}

/// Build insertion steps truncated or extended for actual key count.
fn build_insert_steps(total_keys: usize) -> Vec<InsertStep> {
    let mut steps = Vec::new();
    for template in INSERT_STEP_TEMPLATES {
        if template.start >= total_keys {
            break;
        }
        let end = template.end.min(total_keys);
        steps.push(InsertStep {
            name: template.name,
            start: template.start,
            end,
        });
    }
    if total_keys > REQUIRED_BRANCHES {
        steps.push(InsertStep {
            name: "insert_bulk_keys",
            start: REQUIRED_BRANCHES,
            end: total_keys,
        });
    }
    steps
}

/// Build full workflow step order for summary output.
fn build_step_order(insert_steps: &[InsertStep]) -> Vec<&'static str> {
    let mut step_order = vec!["begin_block"];
    step_order.extend(insert_steps.iter().map(|s| s.name));
    step_order.push("seal");
    step_order.push("commit_flush");
    step_order
}

/// Parse write depths from env.
fn parse_write_depths() -> Vec<usize> {
    parse_csv_usize_env("WRITE_DEPTHS", &DEFAULT_WRITE_DEPTHS)
}

/// Run the full write workflow benchmark and return summary rows.
fn run_workflow(output_mode: OutputMode) -> Result<Summary, IndexError> {
    let iters = parse_usize_env("ITERS", REQUIRED_BRANCHES);
    let write_depths = parse_write_depths();
    let key_updates_pct = parse_usize_env("KEY_UPDATES", DEFAULT_KEY_UPDATES_PERCENT);
    let rounds = parse_usize_env("ROUNDS", DEFAULT_WRITE_ROUNDS);
    let max_tries = parse_usize_env("KEY_SEARCH_MAX_TRIES", DEFAULT_KEY_SEARCH_MAX_TRIES);
    let wal_autocheckpoint_pages = parse_optional_wal_autocheckpoint_pages();
    let wal_checkpoint_mode = parse_optional_wal_checkpoint_mode();

    assert!(iters > 0, "ITERS must be > 0");
    assert!(
        write_depths.iter().all(|depth| *depth > 0),
        "WRITE_DEPTHS entries must be > 0"
    );
    assert!(
        key_updates_pct <= 100,
        "KEY_UPDATES must be in range 0..=100"
    );
    assert!(rounds > 0, "ROUNDS must be > 0");
    assert!(max_tries > 0, "KEY_SEARCH_MAX_TRIES must be > 0");
    if let Some(pages) = wal_autocheckpoint_pages {
        assert!(
            pages >= 0,
            "SQLITE_WAL_AUTOCHECKPOINT must be >= 0 (0 disables auto-checkpoint)"
        );
    }

    let insert_steps = build_insert_steps(iters);
    let step_order = build_step_order(&insert_steps);

    if output_mode.is_raw() {
        println!(
            "config\titers={iters}\twrite_depths={write_depths:?}\tkey_updates={key_updates_pct}\trounds={rounds}\tkey_search_max_tries={max_tries}\tsqlite_wal_autocheckpoint={wal_autocheckpoint_pages:?}\tsqlite_wal_checkpoint_mode={wal_checkpoint_mode:?}\tsqlite_post_setup_checkpoint_ran={}\trequired_branches={REQUIRED_BRANCHES}\tstrategies={WRITE_CACHE_STRATEGIES:?}"
            ,
            wal_autocheckpoint_pages == Some(0)
        );
    }

    let mut results: HashMap<(String, usize, String), StepAggregate> = HashMap::new();

    for round in 1..=rounds {
        for &write_depth in &write_depths {
            for (strategy_idx, strategy) in WRITE_CACHE_STRATEGIES.into_iter().enumerate() {
                let (_db_dir, mut marf) = make_marf(strategy);

                apply_optional_wal_autocheckpoint(marf.sqlite_conn(), wal_autocheckpoint_pages)
                    .map_err(IndexError::from)?;

                let base_seed = 1_000_000u32
                    .wrapping_add((round as u32).wrapping_mul(100_000))
                    .wrapping_add((write_depth as u32).wrapping_mul(100))
                    .wrapping_add((strategy_idx as u32).wrapping_mul(2));
                let parent_chain = initialize_parent_chain(&mut marf, base_seed, write_depth)?;
                maybe_run_post_setup_wal_checkpoint(
                    marf.sqlite_conn(),
                    wal_autocheckpoint_pages,
                    wal_checkpoint_mode,
                )
                .map_err(IndexError::from)?;
                let parent_block = parent_chain.tip;
                let next_block = block_id(base_seed.wrapping_add(write_depth as u32));

                let requested_updates = (iters.saturating_mul(key_updates_pct)) / 100;
                let max_updates = iters.saturating_sub(REQUIRED_BRANCHES);
                let effective_updates = requested_updates
                    .min(max_updates)
                    .min(parent_chain.update_candidate_keys.len());
                let insert_key_count = iters.saturating_sub(effective_updates);
                let promotion_key_count = insert_key_count.min(REQUIRED_BRANCHES);

                let promotion_keys = find_promotion_keys(
                    &format!("write-profile:{strategy}:{round}:chain:{write_depth}:promote"),
                    max_tries,
                    promotion_key_count,
                );

                let mut all_keys = promotion_keys.keys.clone();

                if insert_key_count > promotion_key_count {
                    for extra_ix in promotion_key_count..insert_key_count {
                        all_keys.push(format!(
                            "write-profile:{strategy}:{round}:chain:{write_depth}:bulk:{extra_ix:08x}"
                        ));
                    }
                }

                let update_keys = select_distributed_update_keys(
                    &parent_chain.update_candidate_keys,
                    effective_updates,
                );
                all_keys.extend(update_keys);

                if output_mode.is_raw() {
                    println!(
                        "keys\tround={round}\tdepth={write_depth}\tstrategy={strategy}\tshared_first_byte={}\tsearch_tries={}\tinsert_count={}\tupdate_count={}\tkey_count={}",
                        promotion_keys.shared_first_byte,
                        promotion_keys.search_tries,
                        insert_key_count,
                        effective_updates,
                        all_keys.len()
                    );
                }

                let mut tx = marf.begin_tx()?;

                let begin_measurement =
                    measure_step_with_allocs(|| tx.begin(&parent_block, &next_block))?;
                emit_result_and_store(
                    &mut results,
                    round,
                    write_depth,
                    strategy,
                    "begin_block",
                    1,
                    begin_measurement,
                    output_mode,
                );

                let mut value_cursor = 10_000u32;
                for step in &insert_steps {
                    let keys = &all_keys[step.start..step.end];
                    let values = make_values(value_cursor, keys.len());
                    value_cursor = value_cursor.wrapping_add(keys.len() as u32);

                    let measurement = measure_step_with_allocs(|| tx.insert_batch(keys, values))?;
                    emit_result_and_store(
                        &mut results,
                        round,
                        write_depth,
                        strategy,
                        step.name,
                        keys.len(),
                        measurement,
                        output_mode,
                    );
                }

                let seal_measurement = measure_step_with_allocs(|| tx.seal())?;
                emit_result_and_store(
                    &mut results,
                    round,
                    write_depth,
                    strategy,
                    "seal",
                    1,
                    seal_measurement,
                    output_mode,
                );

                let commit_measurement = measure_step_with_allocs(|| tx.commit())?;
                emit_result_and_store(
                    &mut results,
                    round,
                    write_depth,
                    strategy,
                    "commit_flush",
                    1,
                    commit_measurement,
                    output_mode,
                );
            }
        }
    }

    let mut summary = Summary::new(
        "write",
        WRITE_CACHE_STRATEGIES.len() * step_order.len() * write_depths.len(),
    );
    for &write_depth in &write_depths {
        for strategy in WRITE_CACHE_STRATEGIES {
            for step in &step_order {
                let key = (strategy.to_string(), write_depth, step.to_string());
                let agg = results
                    .get(&key)
                    .expect("missing step samples while summarizing write profile");
                summary.push_line(
                    format!("{strategy}/depth={write_depth}/{step}"),
                    agg.total_ms,
                    agg.alloc_calls,
                    agg.alloc_bytes,
                );
            }
        }
    }

    Ok(summary)
}

/// Emit one raw result line and fold metrics into summary aggregate.
fn emit_result_and_store(
    results: &mut HashMap<(String, usize, String), StepAggregate>,
    round: usize,
    write_depth: usize,
    strategy: &str,
    step: &str,
    items: usize,
    measurement: BenchMeasurement,
    output_mode: OutputMode,
) {
    let elapsed_ms = measurement.elapsed_ms;
    let us_per_item = (elapsed_ms * 1000.0) / (items as f64);
    let alloc_calls_per_item = (measurement.snapshot.alloc_calls as f64) / (items as f64);
    let alloc_bytes_per_item = (measurement.snapshot.alloc_bytes as f64) / (items as f64);

    if output_mode.is_raw() {
        println!(
            "result\tround={round}\tdepth={write_depth}\tstrategy={strategy}\tstep={step}\titems={items}\telapsed_ms={elapsed_ms:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\tus_per_item={us_per_item:.6}\talloc_calls_per_item={alloc_calls_per_item:.6}\talloc_bytes_per_item={alloc_bytes_per_item:.6}",
            measurement.snapshot.alloc_calls,
            measurement.snapshot.alloc_bytes,
            measurement.snapshot.realloc_calls,
            measurement.snapshot.dealloc_calls,
            measurement.snapshot.dealloc_bytes,
        );
    }

    let agg = results
        .entry((strategy.to_string(), write_depth, step.to_string()))
        .or_default();
    agg.total_ms += elapsed_ms;
    agg.alloc_calls += measurement.snapshot.alloc_calls;
    agg.alloc_bytes += measurement.snapshot.alloc_bytes;
}

/// Run the write benchmark subcommand.
pub fn run(args: &[String], output_mode: OutputMode) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage();
        return None;
    }
    Some(run_workflow(output_mode).expect("marf_write_profile failed"))
}
