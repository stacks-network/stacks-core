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

use std::path::{Path, PathBuf};

use stackslib::chainstate::stacks::db::snapshot::{
    Epoch2BlockFileCopyStats, Epoch2MicroblockCopyStats, NakamotoBlockCopyStats,
    SortitionTipCopyBoundary, copy_confirmed_epoch2_microblocks, copy_epoch2_block_files,
    copy_nakamoto_staging_blocks,
};

use crate::cli::SquashArgs;
use crate::config::{build_pox_constants, enforce_minimum_tenure_height};
use crate::db::{DbConfig, read_db_config, read_marf_open_opts};
use crate::layout::{
    BLOCKS_DIR_REL, BURNCHAIN_DB_REL, CLARITY_MARF_REL, ChainstatePaths, HEADERS_DB_REL,
    INDEX_DB_REL, NAKAMOTO_DB_REL, SORTITION_MARF_REL, TargetPaths, chainstate_paths,
    target_out_paths,
};
use crate::manifest::{BlocksSection, ManifestInputs, generate_manifest};
use crate::ops::{
    BitcoinAuxFiles, SideTableMode, SquashJob, copy_bitcoin_aux_files, squash_and_copy_one,
};
use crate::targets::{CanonicalSquashTargets, SquashTargetQuery, resolve_canonical_squash_targets};

/// The resolved set of squash targets for one `squash` invocation. `--all`
/// selects all five; `from_args` validates that at least one target is selected
/// and that the `blocks ⇒ index` and `bitcoin ⇒ sortition` dependencies hold, so
/// an invalid flag combo is rejected before any output is created.
pub struct SquashPlan {
    pub clarity: bool,
    pub index: bool,
    pub sortition: bool,
    pub blocks: bool,
    pub bitcoin: bool,
}

impl SquashPlan {
    /// Resolve the selected targets from the CLI flags, applying `--all` and
    /// validating the selection. Exits on an empty or invalid flag combo.
    pub fn from_args(args: &SquashArgs) -> Self {
        let plan = SquashPlan {
            clarity: args.clarity || args.all,
            index: args.index || args.all,
            sortition: args.sortition || args.all,
            blocks: args.blocks || args.all,
            bitcoin: args.bitcoin || args.all,
        };
        if !plan.has_any_target() {
            eprintln!(
                "Must specify at least one target: --clarity, --index, --sortition, --blocks, --bitcoin, or --all"
            );
            std::process::exit(1);
        }
        // --blocks copies into the squashed index, --bitcoin needs the squashed
        // sortition DB.
        ensure_flag_requires("blocks", plan.blocks, "index", plan.index);
        ensure_flag_requires("bitcoin", plan.bitcoin, "sortition", plan.sortition);
        plan
    }

    /// Whether at least one target is selected.
    fn has_any_target(&self) -> bool {
        self.clarity || self.index || self.sortition || self.blocks || self.bitcoin
    }

    /// Whether this is a complete PCS (all three MARFs + blocks + bitcoin aux) --
    /// the only case for which a manifest is written.
    pub fn is_full_pcs(&self) -> bool {
        self.clarity && self.index && self.sortition && self.blocks && self.bitcoin
    }
}

/// Verify that `--{flag}` is only used when `--{dep}` (or `--all`) is also set.
fn ensure_flag_requires(flag: &str, flag_val: bool, dep: &str, dep_val: bool) {
    if flag_val && !dep_val {
        eprintln!("--{flag} requires --{dep} (or --all)");
        std::process::exit(1);
    }
}

fn sortition_tip_copy_boundary(targets: &CanonicalSquashTargets) -> SortitionTipCopyBoundary {
    SortitionTipCopyBoundary {
        max_stacks_height: u64::from(targets.stacks_height),
        anchor_consensus_hash: targets.stacks_tip_consensus_hash.clone(),
        anchor_burn_view_consensus_hash: targets.stacks_tip_burn_view_consensus_hash.clone(),
        anchor_block_hash: targets.stacks_tip_block_hash.clone(),
        anchor_block_height: u64::from(targets.stacks_height),
    }
}

/// Network subdirectories marf-squash can target.
const KNOWN_NETWORK_SUBDIRS: &[&str] = &["mainnet", "krypton"];

fn is_known_network(subdir: &str) -> bool {
    KNOWN_NETWORK_SUBDIRS.contains(&subdir)
}

/// Resolve the `working_dir/<network>/` subdirectory for the squash output.
///
/// Mainnet is unambiguous. For any other network the mode (`krypton`, `xenon`,
/// ...) is not recoverable from the chainstate alone (testnet/regtest share a
/// chain id), so mirror the source chainstate's own subdirectory name.
fn network_subdir(mainnet: bool, chainstate: &Path) -> Result<String, String> {
    if mainnet {
        return Ok("mainnet".to_string());
    }
    let subdir = chainstate
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "cannot derive the network subdirectory from --chainstate '{}'; \
                 pass a path ending in the network name, e.g. /stacks/krypton",
                chainstate.display()
            )
        })?;
    if subdir == "mainnet" {
        return Err(format!(
            "--chainstate '{}' ends in 'mainnet' but the chainstate is not mainnet; \
             refusing to write a 'mainnet' subdirectory for a testnet/regtest chainstate",
            chainstate.display()
        ));
    }
    if !is_known_network(&subdir) {
        return Err(format!(
            "'{subdir}' is not a recognized stacks-node network ({}); stacks-node would reject \
             this mode. Point --chainstate at a path ending in the network name.",
            KNOWN_NETWORK_SUBDIRS.join(", ")
        ));
    }
    Ok(subdir)
}

/// Resolve the `<out-dir>/<network>/` output root and ensure it exists and is
/// empty. Exits on an undeterminable network or a non-empty existing tree.
fn prepare_output_dir(args: &SquashArgs, mainnet: bool) -> PathBuf {
    let subdir = network_subdir(mainnet, &args.chainstate).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });
    let out_root = args.out_dir.join(&subdir);

    // Require the destination network dir to be absent or empty. Re-running into
    // an existing tree can leave partial or duplicate data (e.g. nakamoto.sqlite
    // rows inserted twice) that is difficult to diagnose.
    if out_root.exists() {
        let is_empty = std::fs::read_dir(&out_root)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        if !is_empty {
            eprintln!(
                "Error: output '{}' already exists and is not empty.\n\
                 Remove it or choose a different --out-dir to avoid partial/duplicate output.",
                out_root.display()
            );
            std::process::exit(1);
        }
    }
    std::fs::create_dir_all(&out_root).unwrap_or_else(|e| {
        eprintln!("Failed to create output dir {}: {e}", out_root.display());
        std::process::exit(1);
    });
    out_root
}

/// Output paths produced by [`squash_marfs`] for each selected MARF, plus the
/// sortition MARF squash height (set whenever `sortition` is). Later phases and
/// the manifest reference these.
struct SquashOutputs {
    clarity: Option<TargetPaths>,
    index: Option<TargetPaths>,
    sortition: Option<TargetPaths>,
    sortition_marf_height: u32,
}

/// Phase 1: squash each selected MARF and copy its side tables. Both Stacks
/// MARFs (Clarity, Index) anchor at the tenure-start Stacks tip/height; the
/// sortition MARF anchors at the canonical sortition tip/height. The source's
/// open-opts are auto-detected (external blob storage from the `.blobs` sidecar).
fn squash_marfs(
    plan: &SquashPlan,
    paths: &ChainstatePaths,
    out_root: &Path,
    targets: &CanonicalSquashTargets,
    pox: &stackslib::burnchains::PoxConstants,
) -> SquashOutputs {
    let stacks_tip = &targets.stacks_tip;
    let stacks_height = targets.stacks_height;
    let sortition_tip = &targets.sortition_canonical_tip;
    let sortition_marf_height = targets.sortition_marf_height;

    let clarity_out = plan.clarity.then(|| {
        let out = target_out_paths(out_root, CLARITY_MARF_REL);
        squash_and_copy_one(SquashJob {
            label: "clarity",
            source: &paths.clarity,
            out: &out,
            tip: stacks_tip,
            squash_height: stacks_height,
            side_table_mode: SideTableMode::Clarity,
            open_opts: read_marf_open_opts(&paths.clarity.db),
        });
        out
    });

    let index_out = plan.index.then(|| {
        let out = target_out_paths(out_root, INDEX_DB_REL);
        squash_and_copy_one(SquashJob {
            label: "index",
            source: &paths.index,
            out: &out,
            tip: stacks_tip,
            squash_height: stacks_height,
            side_table_mode: SideTableMode::Index {
                first_bitcoin_height: targets.first_bitcoin_height,
                reward_cycle_len: pox.reward_cycle_length,
            },
            open_opts: read_marf_open_opts(&paths.index.db),
        });
        out
    });

    let sortition_out = plan.sortition.then(|| {
        let out = target_out_paths(out_root, SORTITION_MARF_REL);
        squash_and_copy_one(SquashJob {
            label: "sortition",
            source: &paths.sortition,
            out: &out,
            tip: sortition_tip,
            squash_height: sortition_marf_height,
            side_table_mode: SideTableMode::Sortition {
                stacks_tip_boundary: sortition_tip_copy_boundary(targets),
            },
            open_opts: read_marf_open_opts(&paths.sortition.db),
        });
        out
    });

    SquashOutputs {
        clarity: clarity_out,
        index: index_out,
        sortition: sortition_out,
        sortition_marf_height,
    }
}

/// Phase 2: copy canonical block data (epoch-2 microblocks, epoch-2 block files,
/// nakamoto staging blocks) into the squashed index. `index_out` is the squashed
/// index produced by [`squash_marfs`]. Exits on any copy failure.
fn copy_blocks(
    args: &SquashArgs,
    out_root: &Path,
    paths: &ChainstatePaths,
    index_out: &TargetPaths,
) -> BlocksSection {
    let src_blocks_dir = args.chainstate.join(BLOCKS_DIR_REL);
    let dst_blocks_dir = out_root.join(BLOCKS_DIR_REL);
    let src_nakamoto = args.chainstate.join(NAKAMOTO_DB_REL);
    let dst_nakamoto = out_root.join(NAKAMOTO_DB_REL);

    // Ensure destination blocks directory exists before any copy step.
    std::fs::create_dir_all(&dst_blocks_dir).unwrap_or_else(|e| {
        eprintln!(
            "Failed to create blocks dir {}: {e}",
            dst_blocks_dir.display()
        );
        std::process::exit(1);
    });

    let src_index_path = paths.index.db.to_str().unwrap();
    let squashed_index_path = index_out.db.to_str().unwrap();

    let mblock_stats = copy_microblock_streams(src_index_path, squashed_index_path);
    let file_stats = copy_epoch2_files(squashed_index_path, &src_blocks_dir, &dst_blocks_dir);
    let nak_stats = copy_nakamoto_blocks(squashed_index_path, &src_nakamoto, &dst_nakamoto);

    BlocksSection {
        epoch2x_files: file_stats.files_copied,
        epoch2x_bytes: file_stats.total_bytes,
        epoch2x_microblock_rows: mblock_stats.microblock_rows_copied,
        epoch2x_microblock_bytes: mblock_stats.microblock_bytes_copied,
        nakamoto_rows: nak_stats.rows_copied,
        nakamoto_bytes: nak_stats.total_blob_bytes,
    }
}

/// Copy confirmed epoch-2 microblock streams between the source and squashed
/// index DBs. Exits on failure, leaving the partial output in place for inspection.
fn copy_microblock_streams(
    src_index_path: &str,
    squashed_index_path: &str,
) -> Epoch2MicroblockCopyStats {
    println!("Copying confirmed epoch-2 microblock streams...");
    match copy_confirmed_epoch2_microblocks(src_index_path, squashed_index_path) {
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
    }
}

/// Copy epoch 2.x block files from `src_blocks_dir` to `dst_blocks_dir`,
/// recording them against the squashed index. Exits on failure.
fn copy_epoch2_files(
    squashed_index_path: &str,
    src_blocks_dir: &Path,
    dst_blocks_dir: &Path,
) -> Epoch2BlockFileCopyStats {
    println!("Copying epoch 2.x block files...");
    match copy_epoch2_block_files(
        squashed_index_path,
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
    }
}

/// Copy nakamoto staging blocks into the squashed nakamoto.sqlite, recording
/// them against the squashed index. Exits on failure, leaving the partial output
/// in place for inspection.
fn copy_nakamoto_blocks(
    squashed_index_path: &str,
    src_nakamoto: &Path,
    dst_nakamoto: &Path,
) -> NakamotoBlockCopyStats {
    if !src_nakamoto.exists() {
        eprintln!(
            "Source nakamoto.sqlite not found at {}; required for --blocks",
            src_nakamoto.display()
        );
        std::process::exit(1);
    }
    println!("Copying nakamoto staging blocks...");
    match copy_nakamoto_staging_blocks(
        squashed_index_path,
        src_nakamoto.to_str().unwrap(),
        dst_nakamoto.to_str().unwrap(),
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
    }
}

/// Phase 3: copy the Bitcoin auxiliary files (burnchain.sqlite + headers.sqlite).
fn copy_bitcoin_aux(args: &SquashArgs, out_root: &Path, squash_bitcoin_height: u32) {
    let src_bc_db = args.chainstate.join(BURNCHAIN_DB_REL);
    let dst_bc_db = out_root.join(BURNCHAIN_DB_REL);
    let squashed_sort = out_root.join(SORTITION_MARF_REL);
    let src_hdr = args.chainstate.join(HEADERS_DB_REL);
    let dst_hdr = out_root.join(HEADERS_DB_REL);

    copy_bitcoin_aux_files(BitcoinAuxFiles {
        src_bc_db: &src_bc_db,
        dst_bc_db: &dst_bc_db,
        squashed_sort: &squashed_sort,
        src_hdr: &src_hdr,
        dst_hdr: &dst_hdr,
        bitcoin_height: u64::from(squash_bitcoin_height),
    });
}

/// Resolve the canonical squash targets from the source chainstate/sortition
/// DBs and log the resolved boundary. Exits on resolution failure.
fn resolve_targets(
    paths: &ChainstatePaths,
    tenure_start_bitcoin_height: u32,
    db_config: &DbConfig,
    pox: &stackslib::burnchains::PoxConstants,
) -> CanonicalSquashTargets {
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

    let targets = resolve_canonical_squash_targets(SquashTargetQuery {
        chainstate_root: chainstate_root.to_str().unwrap(),
        sortition_db_dir: sortition_db_dir.to_str().unwrap(),
        tenure_start_bitcoin_height,
        mainnet: db_config.mainnet,
        chain_id: db_config.chain_id,
        pox_constants: pox.clone(),
    })
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    eprintln!(
        "Squash at tenure start Bitcoin height {tenure_start_bitcoin_height}, \
         Stacks tenure-start anchor height {}, anchor tip {} \
         (squash Bitcoin height {}, sortition MARF height {})",
        targets.stacks_height,
        targets.stacks_tip,
        targets.squash_bitcoin_height,
        targets.sortition_marf_height
    );

    targets
}

/// Run the `squash` subcommand: resolve the boundary, squash the selected MARFs,
/// copy block/Bitcoin data, and write the manifest for a full PCS. Exits on error.
pub fn run_squash(args: SquashArgs) {
    let plan = SquashPlan::from_args(&args);

    let paths = chainstate_paths(&args.chainstate);
    let tenure_start_bitcoin_height = args.tenure_start_bitcoin_height;
    let db_config = read_db_config(&paths.index.db);

    let pox = build_pox_constants(db_config.mainnet, args.config.as_deref());

    // A squashed snapshot is only usable from epoch 3.4 onwards.
    enforce_minimum_tenure_height(
        tenure_start_bitcoin_height,
        db_config.mainnet,
        args.config.as_deref(),
    );

    let targets = resolve_targets(&paths, tenure_start_bitcoin_height, &db_config, &pox);
    let stacks_height = targets.stacks_height;
    let squash_bitcoin_height = targets.squash_bitcoin_height;

    let out_root = prepare_output_dir(&args, db_config.mainnet);

    // Phase 1: Squash & Copy
    let outputs = squash_marfs(&plan, &paths, &out_root, &targets, &pox);

    // Phase 2: Block preservation (the --blocks ⇒ --index dependency is enforced
    // in SquashPlan::from_args).
    let blocks_stats = plan.blocks.then(|| {
        let i_out = outputs
            .index
            .as_ref()
            .expect("--blocks requires --index; outputs.index must be set");
        copy_blocks(&args, &out_root, &paths, i_out)
    });

    // Phase 3: Bitcoin auxiliary files (the --bitcoin ⇒ --sortition dependency is
    // enforced in SquashPlan::from_args; --sortition provides the squashed
    // sortition DB and burn heights).
    if plan.bitcoin {
        copy_bitcoin_aux(&args, &out_root, squash_bitcoin_height);
    }

    // Generate manifest only for a complete PCS (all MARFs + blocks + bitcoin aux).
    if plan.is_full_pcs() {
        let sort_paths = outputs.sortition.unwrap();
        generate_manifest(ManifestInputs {
            out_dir: &out_root,
            clarity_out: outputs.clarity.as_ref().unwrap(),
            index_out: outputs.index.as_ref().unwrap(),
            sortition_paths: &sort_paths,
            stacks_height,
            bitcoin_height: squash_bitcoin_height,
            sortition_marf_height: outputs.sortition_marf_height,
            expected_stacks_tip: &targets.stacks_tip,
            expected_sortition_tip: &targets.sortition_boundary_tip,
            blocks_section: blocks_stats.unwrap(),
        });
    }

    eprintln!(
        "Squash complete. Output: {}\n  \
         - Boot: set the node's working_dir = \"{}\"",
        out_root.display(),
        args.out_dir.display()
    );
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use rstest::rstest;

    use super::{SquashPlan, is_known_network, network_subdir};
    use crate::cli::SquashArgs;

    /// Build a `SquashArgs` from the target-flag tuple
    /// `(clarity, index, sortition, blocks, bitcoin, all)`; the non-flag fields
    /// are fixed placeholders.
    fn args_with_flags(flags: (bool, bool, bool, bool, bool, bool)) -> SquashArgs {
        let (clarity, index, sortition, blocks, bitcoin, all) = flags;
        SquashArgs {
            chainstate: PathBuf::from("/tmp/chainstate"),
            out_dir: PathBuf::from("/tmp/out"),
            tenure_start_bitcoin_height: 100,
            clarity,
            index,
            sortition,
            all,
            blocks,
            bitcoin,
            config: None,
        }
    }

    /// `from_args` over (input flags `clarity,index,sortition,blocks,bitcoin,all`)
    /// → (expected plan fields `clarity,index,sortition,blocks,bitcoin`, full PCS).
    /// Each case satisfies the `blocks ⇒ index` / `bitcoin ⇒ sortition`
    /// dependencies, so none triggers the fail-fast exit.
    #[rstest]
    // --all selects everything (full PCS).
    #[case((false, false, false, false, false, true), (true, true, true, true, true), true)]
    // --index alone.
    #[case((false, true, false, false, false, false), (false, true, false, false, false), false)]
    // --clarity alone.
    #[case((true, false, false, false, false, false), (true, false, false, false, false), false)]
    // --blocks with --index and --bitcoin with --sortition both satisfy their deps.
    #[case((false, true, true, true, true, false), (false, true, true, true, true), false)]
    fn from_args_selection(
        #[case] flags: (bool, bool, bool, bool, bool, bool),
        #[case] expected: (bool, bool, bool, bool, bool),
        #[case] is_full_pcs: bool,
    ) {
        let plan = SquashPlan::from_args(&args_with_flags(flags));
        let (e_clarity, e_index, e_sortition, e_blocks, e_bitcoin) = expected;
        assert_eq!(plan.clarity, e_clarity);
        assert_eq!(plan.index, e_index);
        assert_eq!(plan.sortition, e_sortition);
        assert_eq!(plan.blocks, e_blocks);
        assert_eq!(plan.bitcoin, e_bitcoin);
        assert_eq!(plan.is_full_pcs(), is_full_pcs);
    }

    // The failure paths of `from_args` (no target selected; `--blocks` without
    // `--index`; `--bitcoin` without `--sortition`) call `std::process::exit`,
    // which would abort the test process. They are intentionally not exercised
    // here: testing them would require introducing a `Result` error model purely
    // for tests, which the crate deliberately avoids in favor of `eprintln!` +
    // `exit`. The passing selection cases above cover the field wiring.

    /// `network_subdir` over (mainnet, source path) → expected `Ok(subdir)` or an
    /// `Err`. Mainnet is forced to `mainnet/` regardless of the path; a testnet
    /// path mirrors its own last component (trailing slash stripped); an
    /// undeterminable path, a `mainnet`-named non-mainnet path, and an unknown
    /// network all error.
    #[rstest]
    // Mainnet is forced to `mainnet/`, regardless of the source path.
    #[case(true, "/stacks/anything", Some("mainnet"))]
    #[case(true, "/", Some("mainnet"))]
    // Testnet mirrors its own subdir name.
    #[case(false, "/stacks/krypton", Some("krypton"))]
    // Trailing slash is stripped.
    #[case(false, "/stacks/krypton/", Some("krypton"))]
    // Undeterminable paths error.
    #[case(false, "/", None)]
    #[case(false, "..", None)]
    // A testnet/regtest chainstate can never boot as mainnet.
    #[case(false, "/stacks/mainnet", None)]
    // An unrecognized network errors.
    #[case(false, "/stacks/weirdnet", None)]
    fn network_subdir_cases(
        #[case] mainnet: bool,
        #[case] path: &str,
        #[case] expected: Option<&str>,
    ) {
        let result = network_subdir(mainnet, Path::new(path));
        match expected {
            Some(subdir) => assert_eq!(result.unwrap(), subdir),
            None => assert!(result.is_err()),
        }
    }

    #[test]
    fn known_networks() {
        assert!(is_known_network("krypton"));
        assert!(is_known_network("mainnet"));
        assert!(!is_known_network("weirdnet"));
    }

    #[test]
    fn output_lands_under_network_subdir() {
        use crate::layout::{CLARITY_MARF_REL, INDEX_DB_REL, target_out_paths};

        // The layout contract: `--out-dir` is the working_dir, and the squash
        // targets land at `<out-dir>/<network>/...`.
        let out_dir = Path::new("/tmp/out");

        // Testnet: the source subdir is mirrored.
        let subdir = network_subdir(false, Path::new("/data/krypton")).unwrap();
        let out_root = out_dir.join(subdir);
        let tp = target_out_paths(&out_root, CLARITY_MARF_REL);
        assert_eq!(
            tp.db.to_str().unwrap(),
            "/tmp/out/krypton/chainstate/vm/clarity/marf.sqlite"
        );

        // Mainnet is forced into `mainnet/` regardless of the source path.
        let mainnet_root = out_dir.join(network_subdir(true, Path::new("/data/x")).unwrap());
        let tp_m = target_out_paths(&mainnet_root, INDEX_DB_REL);
        assert_eq!(
            tp_m.db.to_str().unwrap(),
            "/tmp/out/mainnet/chainstate/vm/index.sqlite"
        );
    }
}
