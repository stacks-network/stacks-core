use std::fs;
use std::path::Path;

use stacks_common::types::chainstate::{SortitionId, StacksBlockId};
use stackslib::chainstate::stacks::db::snapshot::{
    copy_burnchain_db, copy_index_side_tables, copy_sortition_side_tables, copy_spv_headers,
};
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts};
use stackslib::clarity_vm::database::snapshot::copy_clarity_side_tables;

use crate::cli::TargetPaths;
use crate::util::ensure_blobs_match;

#[derive(Clone)]
pub enum SideTableMode {
    Clarity,
    Index {
        first_burn_height: u64,
        reward_cycle_len: u64,
    },
    Sortition,
}

/// Squash a single MARF target and copy its side tables. Exits on error.
pub fn squash_and_copy_one(
    label: &str,
    source: &TargetPaths,
    out: &TargetPaths,
    height: u32,
    side_table_mode: SideTableMode,
    open_opts: MARFOpenOpts,
) {
    if let Some(ref blobs) = source.blobs {
        ensure_blobs_match(source.db.to_str().unwrap(), blobs.to_str().unwrap());
    }

    if let Some(parent) = out.db.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!(
            "Failed to create output directory '{}': {e}",
            parent.display()
        );
        std::process::exit(1);
    }

    let is_sortition = matches!(side_table_mode, SideTableMode::Sortition);
    let stats = if is_sortition {
        match MARF::<SortitionId>::squash_to_path(
            source.db.to_str().unwrap(),
            out.db.to_str().unwrap(),
            open_opts,
            height,
            label,
        ) {
            Ok(stats) => stats,
            Err(e) => {
                eprintln!("Failed to squash {label} MARF: {e:?}");
                std::process::exit(1);
            }
        }
    } else {
        match MARF::<StacksBlockId>::squash_to_path(
            source.db.to_str().unwrap(),
            out.db.to_str().unwrap(),
            open_opts,
            height,
            label,
        ) {
            Ok(stats) => stats,
            Err(e) => {
                eprintln!("Failed to squash {label} MARF: {e:?}");
                std::process::exit(1);
            }
        }
    };

    match &side_table_mode {
        SideTableMode::Clarity => {
            println!("Copying Clarity side tables...");
            match copy_clarity_side_tables(source.db.to_str().unwrap(), out.db.to_str().unwrap()) {
                Ok(st) => {
                    println!(
                        "Side-table copy complete: data_table={} rows, metadata_table={} rows",
                        st.data_table_rows, st.metadata_table_rows
                    );
                }
                Err(e) => {
                    eprintln!("Failed to copy Clarity side tables: {e:?}");
                    eprintln!("Cleaning up output files...");
                    let _ = fs::remove_file(&out.db);
                    if let Some(ref blobs) = out.blobs {
                        let _ = fs::remove_file(blobs);
                    }
                    std::process::exit(1);
                }
            }
        }
        SideTableMode::Index {
            first_burn_height,
            reward_cycle_len,
        } => {
            println!("Copying index side tables...");
            match copy_index_side_tables(
                source.db.to_str().unwrap(),
                out.db.to_str().unwrap(),
                *first_burn_height,
                *reward_cycle_len,
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
                    eprintln!("Cleaning up output files...");
                    let _ = fs::remove_file(&out.db);
                    if let Some(ref blobs) = out.blobs {
                        let _ = fs::remove_file(blobs);
                    }
                    std::process::exit(1);
                }
            }
        }
        SideTableMode::Sortition => {
            println!("Copying sortition side tables...");
            match copy_sortition_side_tables(source.db.to_str().unwrap(), out.db.to_str().unwrap())
            {
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
                    eprintln!("Cleaning up output files...");
                    let _ = fs::remove_file(&out.db);
                    std::process::exit(1);
                }
            }
        }
    }

    // Size savings summary.
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

    println!("Squash complete ({label}) at height {height}");
    println!("Node count: {}", stats.node_count);
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

/// Copy Bitcoin auxiliary files (burnchain.sqlite + headers.sqlite).
/// Exits on error.
pub fn copy_bitcoin_aux_files(
    src_bc_db: &Path,
    dst_bc_db: &Path,
    squashed_sort: &Path,
    src_hdr: &Path,
    dst_hdr: &Path,
    burn_height: u32,
) {
    println!("Copying burnchain.sqlite (canonical only)...");
    match copy_burnchain_db(
        src_bc_db.to_str().unwrap(),
        dst_bc_db.to_str().unwrap(),
        squashed_sort.to_str().unwrap(),
        burn_height,
    ) {
        Ok(bc_stats) => {
            println!(
                "  block_headers={}, block_ops={}, commit_metadata={}, anchor_blocks={}, overrides={}, affirmation_maps={}",
                bc_stats.block_headers_rows,
                bc_stats.block_ops_rows,
                bc_stats.block_commit_metadata_rows,
                bc_stats.anchor_blocks_rows,
                bc_stats.overrides_rows,
                bc_stats.affirmation_maps_rows
            );
        }
        Err(e) => {
            eprintln!("Failed to copy burnchain.sqlite: {e:?}");
            std::process::exit(1);
        }
    }

    println!("Copying headers.sqlite (SPV, up to burn height {burn_height})...");
    match copy_spv_headers(
        src_hdr.to_str().unwrap(),
        dst_hdr.to_str().unwrap(),
        burn_height,
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
