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

use std::fs;
use std::path::Path;

use stackslib::chainstate::stacks::db::snapshot::{
    SortitionTipCopyBoundary, copy_burnchain_db, copy_clarity_side_tables, copy_index_side_tables,
    copy_sortition_side_tables_with_boundary, copy_spv_headers,
};
use stackslib::chainstate::stacks::index::MarfTrieId;
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts};

use crate::layout::TargetPaths;

#[derive(Clone)]
pub enum SideTableMode {
    Clarity,
    Index {
        first_bitcoin_height: u32,
        reward_cycle_len: u32,
    },
    Sortition {
        stacks_tip_boundary: SortitionTipCopyBoundary,
    },
}

/// The source and output endpoints of a single squash: the MARF being squashed
/// and the MARF being written. The recurring pair the per-step helpers operate on.
#[derive(Clone, Copy)]
pub struct SquashIo<'a> {
    pub source: &'a TargetPaths,
    pub out: &'a TargetPaths,
}

/// One MARF squash job: the source/output paths, the boundary (`tip` +
/// `squash_height`) to squash to, the side tables to copy, and the open-opts for
/// the source DB.
pub struct SquashJob<'a, T: MarfTrieId + Send + Sync> {
    pub label: &'a str,
    pub source: &'a TargetPaths,
    pub out: &'a TargetPaths,
    pub tip: &'a T,
    pub squash_height: u32,
    pub side_table_mode: SideTableMode,
    pub open_opts: MARFOpenOpts,
}

/// Squash a single MARF target and copy its side tables. Exits on error.
pub fn squash_and_copy_one<T: MarfTrieId + Send + Sync>(job: SquashJob<T>) {
    let SquashJob {
        label,
        source,
        out,
        tip,
        squash_height,
        side_table_mode,
        open_opts,
    } = job;
    let io = SquashIo { source, out };

    if let Some(parent) = out.db.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!(
            "Failed to create output directory '{}': {e}",
            parent.display()
        );
        std::process::exit(1);
    }

    let stats = match MARF::squash_to_path(
        source.db.to_str().unwrap(),
        out.db.to_str().unwrap(),
        open_opts,
        tip,
        squash_height,
        label,
    ) {
        Ok(stats) => stats,
        Err(e) => {
            eprintln!("Failed to squash {label} MARF: {e:?}");
            std::process::exit(1);
        }
    };

    copy_side_tables(io, &side_table_mode);
    report_size_savings(io, label, squash_height, stats.node_count);
}

/// Copy the side tables selected by `side_table_mode` from source into output.
/// Exits on any copy failure, leaving the partial output in place for inspection.
fn copy_side_tables(io: SquashIo, side_table_mode: &SideTableMode) {
    match side_table_mode {
        SideTableMode::Clarity => copy_clarity_tables(io),
        SideTableMode::Index {
            first_bitcoin_height,
            reward_cycle_len,
        } => copy_index_tables(io, *first_bitcoin_height, *reward_cycle_len),
        SideTableMode::Sortition {
            stacks_tip_boundary,
        } => copy_sortition_tables(io, stacks_tip_boundary),
    }
}

/// Copy the Clarity side tables; exits on failure.
fn copy_clarity_tables(io: SquashIo) {
    println!("Copying Clarity side tables...");
    match copy_clarity_side_tables(io.source.db.to_str().unwrap(), io.out.db.to_str().unwrap()) {
        Ok(st) => {
            println!(
                "Side-table copy complete: data_table={} rows, metadata_table={} rows",
                st.data_table_rows, st.metadata_table_rows
            );
        }
        Err(e) => {
            eprintln!("Failed to copy Clarity side tables: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Copy the index side tables; exits on failure.
fn copy_index_tables(io: SquashIo, first_bitcoin_height: u32, reward_cycle_len: u32) {
    println!("Copying index side tables...");
    match copy_index_side_tables(
        io.source.db.to_str().unwrap(),
        io.out.db.to_str().unwrap(),
        u64::from(first_bitcoin_height),
        u64::from(reward_cycle_len),
    ) {
        Ok(st) => {
            println!(
                "Index side-table copy complete: block_headers={}, nakamoto_headers={}, payments={}, transactions={}, tenure_events={}, reward_sets={}, signer_stats={}, matured_rewards={}, burnchain_txids={}, epoch_transitions={}, staging_blocks={}, fork_storage={}",
                st.block_headers_rows,
                st.nakamoto_block_headers_rows,
                st.payments_rows,
                st.transactions_rows,
                st.nakamoto_tenure_events_rows,
                st.nakamoto_reward_sets_rows,
                st.signer_stats_rows,
                st.matured_rewards_rows,
                st.burnchain_txids_rows,
                st.epoch_transitions_rows,
                st.staging_blocks_rows,
                st.fork_storage_rows
            );
        }
        Err(e) => {
            eprintln!("Failed to copy index side tables: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Copy the sortition side tables; exits on failure.
fn copy_sortition_tables(io: SquashIo, stacks_tip_boundary: &SortitionTipCopyBoundary) {
    println!("Copying sortition side tables...");
    match copy_sortition_side_tables_with_boundary(
        io.source.db.to_str().unwrap(),
        io.out.db.to_str().unwrap(),
        Some(stacks_tip_boundary),
    ) {
        Ok(st) => {
            println!(
                "Sortition side-table copy complete: snapshots={}, leader_keys={}, block_commits={}, epochs={}, fork_storage={}",
                st.snapshots_rows,
                st.leader_keys_rows,
                st.block_commits_rows,
                st.epochs_rows,
                st.fork_storage_rows
            );
        }
        Err(e) => {
            eprintln!("Failed to copy sortition side tables: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Print the original-vs-squashed size summary and the squash stats.
fn report_size_savings(io: SquashIo, label: &str, squash_height: u32, node_count: u64) {
    let source = io.source;
    let out = io.out;
    let original_db_size = fs::metadata(&source.db).map(|m| m.len()).unwrap_or(0);
    let original_blobs_size = source
        .blobs
        .as_ref()
        .and_then(|b| fs::metadata(b).ok())
        .map(|m| m.len())
        .unwrap_or(0);
    let squashed_db_size = fs::metadata(&out.db).map(|m| m.len()).unwrap_or(0);
    let squashed_blobs_size = out
        .blobs
        .as_ref()
        .and_then(|b| fs::metadata(b).ok())
        .map(|m| m.len())
        .unwrap_or(0);

    let original_total = original_db_size + original_blobs_size;
    let squashed_total = squashed_db_size + squashed_blobs_size;
    let savings = original_total.saturating_sub(squashed_total);
    let savings_pct = if original_total == 0 {
        0.0
    } else {
        (savings as f64 / original_total as f64) * 100.0
    };

    println!("Squash complete ({label}) at MARF height {squash_height}");
    println!("Node count: {node_count}");
    println!(
        "Original: db={original_db_size} bytes, blobs={original_blobs_size} bytes, total={original_total} bytes"
    );
    println!(
        "Squashed: db={squashed_db_size} bytes, blobs={squashed_blobs_size} bytes, total={squashed_total} bytes"
    );
    println!("Savings: {savings} bytes ({savings_pct:.2}%)");
    println!("Output db: {}", out.db.display());
    if let Some(ref blobs) = out.blobs {
        println!("Output blobs: {}", blobs.display());
    }
}

/// Source/destination paths for the Bitcoin auxiliary files plus the squashed
/// sortition DB and the boundary Bitcoin height, as needed by
/// [`copy_bitcoin_aux_files`].
pub struct BitcoinAuxFiles<'a> {
    pub src_bc_db: &'a Path,
    pub dst_bc_db: &'a Path,
    pub squashed_sort: &'a Path,
    pub src_hdr: &'a Path,
    pub dst_hdr: &'a Path,
    pub bitcoin_height: u64,
}

/// Copy Bitcoin auxiliary files (burnchain.sqlite + headers.sqlite).
/// Exits on error.
pub fn copy_bitcoin_aux_files(files: BitcoinAuxFiles) {
    let BitcoinAuxFiles {
        src_bc_db,
        dst_bc_db,
        squashed_sort,
        src_hdr,
        dst_hdr,
        bitcoin_height,
    } = files;

    println!("Copying burnchain.sqlite (canonical only)...");
    match copy_burnchain_db(
        src_bc_db.to_str().unwrap(),
        dst_bc_db.to_str().unwrap(),
        squashed_sort.to_str().unwrap(),
        bitcoin_height,
    ) {
        Ok(bc_stats) => {
            println!(
                "  block_headers={}, block_ops={}, commit_metadata={}, anchor_blocks={}",
                bc_stats.block_headers_rows,
                bc_stats.block_ops_rows,
                bc_stats.block_commit_metadata_rows,
                bc_stats.anchor_blocks_rows,
            );
        }
        Err(e) => {
            eprintln!("Failed to copy burnchain.sqlite: {e:?}");
            std::process::exit(1);
        }
    }

    println!("Copying headers.sqlite (SPV, up to Bitcoin height {bitcoin_height})...");
    match copy_spv_headers(
        src_hdr.to_str().unwrap(),
        dst_hdr.to_str().unwrap(),
        bitcoin_height,
    ) {
        Ok(spv_stats) => {
            println!(
                "  headers={}, chain_work={}",
                spv_stats.headers_rows, spv_stats.chain_work_rows
            );
        }
        Err(e) => {
            eprintln!("Failed to copy headers.sqlite: {e:?}");
            std::process::exit(1);
        }
    };
}
