use stackslib::chainstate::stacks::db::snapshot::{
    copy_confirmed_epoch2_microblocks, copy_epoch2_block_files, copy_nakamoto_staging_blocks,
};

use crate::cli::{BlocksSection, SquashArgs};
use crate::manifest::generate_manifest;
use crate::ops::{SideTableMode, copy_bitcoin_aux_files, squash_and_copy_one};
use crate::util::{
    bitcoin_height_to_sortition_marf_height, build_pox_constants, chainstate_paths,
    enforce_minimum_tenure_height, ensure_flag_requires, ensure_targets_selected,
    find_tenure_end_stacks_height, read_db_config, read_first_burn_height, selected_targets,
    sortition_open_opts_for_path, squash_marf_open_opts, target_out_paths,
    target_out_paths_sortition, warn_if_in_prepare_phase,
};

pub fn run_squash(args: SquashArgs) {
    ensure_targets_selected(
        args.clarity,
        args.index,
        args.sortition,
        args.blocks,
        args.bitcoin,
        args.all,
    );

    // Require --out-dir to be absent or empty. Re-running into an existing
    // output tree can leave partial or duplicate data (e.g. nakamoto.sqlite
    // rows inserted twice) that is difficult to diagnose.
    if args.out_dir.exists() {
        let is_empty = std::fs::read_dir(&args.out_dir)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        if !is_empty {
            eprintln!(
                "Error: --out-dir '{}' already exists and is not empty.\n\
                 Remove it or choose a different path to avoid partial/duplicate output.",
                args.out_dir.display()
            );
            std::process::exit(1);
        }
    }

    let paths = chainstate_paths(&args.chainstate);
    let (do_clarity, do_index, do_sortition) =
        selected_targets(args.clarity, args.index, args.sortition, args.all);

    let bitcoin_height = args.tenure_start_bitcoin_height;

    // Read network config.
    let (mainnet, chain_id) = read_db_config(&paths.index.db);
    let pox = build_pox_constants(mainnet, args.config.as_deref());

    // A squashed snapshot is only usable from epoch 3.4 onwards.
    enforce_minimum_tenure_height(bitcoin_height, mainnet, args.config.as_deref());

    // Derive chainstate root: paths.index.db = ".../chainstate/vm/index.sqlite"
    let chainstate_root = paths
        .index
        .db
        .parent() // .../chainstate/vm
        .and_then(|p| p.parent()) // .../chainstate
        .expect("cannot derive chainstate root from index path");

    // Derive the sortition DB directory path (parent of marf.sqlite).
    let sortition_db_dir = paths
        .sortition
        .db
        .parent()
        .expect("cannot derive sortition dir from sortition db path");

    // Find the Stacks height at the end of this tenure.
    let stacks_height = find_tenure_end_stacks_height(
        chainstate_root.to_str().unwrap(),
        sortition_db_dir.to_str().unwrap(),
        bitcoin_height,
        mainnet,
        chain_id,
        pox.clone(),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    eprintln!(
        "Squash at tenure start Bitcoin height {bitcoin_height}, \
         Stacks tenure end height {stacks_height}"
    );

    // Prepare-phase warning.
    let first_burn_height = read_first_burn_height(paths.sortition.db.to_str().unwrap());
    warn_if_in_prepare_phase(bitcoin_height, &pox, first_burn_height);

    // Sortition MARF height.
    let sortition_marf_height = bitcoin_height_to_sortition_marf_height(
        paths.sortition.db.to_str().unwrap(),
        bitcoin_height,
    );

    let mut clarity_out = None;
    let mut index_out = None;
    let mut sortition_out = None;

    // Phase 1: Squash & Copy

    if do_clarity {
        let out = target_out_paths(&args.out_dir, &paths.clarity.db);
        squash_and_copy_one(
            "clarity",
            &paths.clarity,
            &out,
            stacks_height,
            SideTableMode::Clarity,
            squash_marf_open_opts(),
        );
        clarity_out = Some(out);
    }

    if do_index {
        let out = target_out_paths(&args.out_dir, &paths.index.db);
        squash_and_copy_one(
            "index",
            &paths.index,
            &out,
            stacks_height,
            SideTableMode::Index {
                first_burn_height,
                reward_cycle_len: pox.reward_cycle_length as u64,
            },
            squash_marf_open_opts(),
        );
        index_out = Some(out);
    }

    if do_sortition {
        let out = target_out_paths_sortition(&args.out_dir, &paths.sortition.db);
        squash_and_copy_one(
            "sortition",
            &paths.sortition,
            &out,
            sortition_marf_height,
            SideTableMode::Sortition,
            sortition_open_opts_for_path(&paths.sortition.db),
        );
        sortition_out = Some((out, sortition_marf_height));
    }

    // Block preservation: requires --index.
    let do_blocks = args.blocks || args.all;
    ensure_flag_requires("blocks", do_blocks, "index", do_index);

    let mut blocks_stats: Option<BlocksSection> = None;
    let mut copied_block_rel_paths: Vec<String> = Vec::new();

    // These variables are needed by the copy phase for blocks.
    let dst_blocks_dir = args.out_dir.join("chainstate/blocks");
    let src_nakamoto = args.chainstate.join("chainstate/blocks/nakamoto.sqlite");
    let dst_nakamoto = dst_blocks_dir.join("nakamoto.sqlite");

    if do_blocks {
        // Ensure destination blocks directory exists before any copy step.
        std::fs::create_dir_all(&dst_blocks_dir).unwrap_or_else(|e| {
            eprintln!(
                "Failed to create blocks dir {}: {e}",
                dst_blocks_dir.display()
            );
            std::process::exit(1);
        });

        let i_out = index_out
            .as_ref()
            .expect("--blocks requires --index; index_out must be set");

        let src_index_path = paths.index.db.to_str().unwrap();
        let dst_index_path = i_out.db.to_str().unwrap();
        let src_blocks_dir = args.chainstate.join("chainstate/blocks");

        // 1. Copy confirmed epoch-2 microblock streams.
        println!("Copying confirmed epoch-2 microblock streams...");
        let mblock_stats = match copy_confirmed_epoch2_microblocks(src_index_path, dst_index_path) {
            Ok(st) => {
                println!(
                    "Microblock copy complete: streams_copied={}, streams_skipped={}, rows={}, bytes={}",
                    st.streams_copied,
                    st.streams_skipped,
                    st.microblock_rows_copied,
                    st.microblock_bytes_copied
                );
                st
            }
            Err(e) => {
                eprintln!("Failed to copy microblock streams: {e:?}");
                std::process::exit(1);
            }
        };

        // 2. Copy epoch 2.x block files.
        println!("Copying epoch 2.x block files...");
        let file_stats = match copy_epoch2_block_files(
            dst_index_path,
            src_blocks_dir.to_str().unwrap(),
            dst_blocks_dir.to_str().unwrap(),
        ) {
            Ok(st) => {
                println!(
                    "Epoch 2.x block files copied: files={}, bytes={}, genesis_skipped={}",
                    st.files_copied, st.total_bytes, st.genesis_skipped
                );
                st
            }
            Err(e) => {
                eprintln!("Failed to copy epoch 2.x block files: {e:?}");
                std::process::exit(1);
            }
        };

        // 3. Copy nakamoto staging blocks.
        if !src_nakamoto.exists() {
            eprintln!(
                "Source nakamoto.sqlite not found at {}; required for --blocks",
                src_nakamoto.display()
            );
            std::process::exit(1);
        }
        println!("Copying nakamoto staging blocks...");
        let nak_stats = match copy_nakamoto_staging_blocks(
            src_nakamoto.to_str().unwrap(),
            dst_nakamoto.to_str().unwrap(),
            dst_index_path,
        ) {
            Ok(st) => {
                println!(
                    "Nakamoto blocks copied: rows={}, blob_bytes={}",
                    st.rows_copied, st.total_blob_bytes
                );
                st
            }
            Err(e) => {
                eprintln!("Failed to copy nakamoto staging blocks: {e:?}");
                std::process::exit(1);
            }
        };

        blocks_stats = Some(BlocksSection {
            epoch2x_files: file_stats.files_copied,
            epoch2x_bytes: file_stats.total_bytes,
            epoch2x_microblock_rows: mblock_stats.microblock_rows_copied,
            epoch2x_microblock_bytes: mblock_stats.microblock_bytes_copied,
            nakamoto_rows: nak_stats.rows_copied,
            nakamoto_bytes: nak_stats.total_blob_bytes,
        });

        // Record copied block file paths for the expected-file whitelist.
        // Epoch2x paths are relative to dst_blocks_dir; prefix with chainstate/blocks/.
        for rel in &file_stats.copied_paths {
            copied_block_rel_paths.push(format!("chainstate/blocks/{}", rel.replace('\\', "/")));
        }
        // Nakamoto staging DB.
        copied_block_rel_paths.push("chainstate/blocks/nakamoto.sqlite".to_string());
    }

    // Bitcoin auxiliary files: burnchain.sqlite + headers.sqlite.
    // Requires --sortition (or --all) for the squashed sortition DB and burn heights.
    let do_bitcoin_aux = args.bitcoin || args.all;
    ensure_flag_requires("bitcoin", do_bitcoin_aux, "sortition", do_sortition);
    let src_bc_db = args.chainstate.join("burnchain/burnchain.sqlite");
    let dst_bc_db = args.out_dir.join("burnchain/burnchain.sqlite");
    let squashed_sort = args.out_dir.join("burnchain/sortition/marf.sqlite");
    let src_hdr = args.chainstate.join("headers.sqlite");
    let dst_hdr = args.out_dir.join("headers.sqlite");

    if do_bitcoin_aux {
        copy_bitcoin_aux_files(
            &src_bc_db,
            &dst_bc_db,
            &squashed_sort,
            &src_hdr,
            &dst_hdr,
            bitcoin_height as u32,
        );
    }

    // Generate manifest only for a complete GSS (all MARFs + blocks + bitcoin aux).
    if do_clarity && do_index && do_sortition && do_blocks && do_bitcoin_aux {
        let (sort_paths, sort_height) = sortition_out.unwrap();
        generate_manifest(
            &args.out_dir,
            clarity_out.as_ref().unwrap(),
            index_out.as_ref().unwrap(),
            (&sort_paths, sort_height),
            stacks_height,
            bitcoin_height,
            blocks_stats.unwrap(),
            &copied_block_rel_paths,
        );
    }
}
