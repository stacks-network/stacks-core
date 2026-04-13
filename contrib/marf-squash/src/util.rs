use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use stacks_common::types::StacksEpochId;
use stackslib::burnchains::PoxConstants;
use stackslib::chainstate::burn::db::sortdb::SortitionDB;
use stackslib::chainstate::nakamoto::NakamotoChainState;
use stackslib::chainstate::stacks::db::StacksChainState;
use stackslib::chainstate::stacks::index::marf::MARFOpenOpts;
use stackslib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use stackslib::config::{Config, ConfigFile};

use crate::cli::{ChainstatePaths, GSS_MANIFEST, SQLITE_SIDECAR_EXTENSIONS, TargetPaths};

/// On mainnet, Bitcoin height 943332 was a fast-block (no Stacks tenure
/// started there), so the last tenure that belongs entirely to epoch 3.3
/// is at height 943331. This is the minimum acceptable value for
/// squash on mainnet.
const MAINNET_MIN_TENURE_HEIGHT: u64 = 943_331;

/// Enforce that `bitcoin_height` is at least the last tenure of epoch 3.3.
///
/// A squashed snapshot is only usable from epoch 3.4 onwards, so the
/// selected tenure must be the last tenure of epoch 3.3 or later.
///
/// * Mainnet: the minimum is [`MAINNET_MIN_TENURE_HEIGHT`]
/// * non-mainnet: the minimum is `epoch_3.4_start_height - 1`, derived
///   from the node config TOML.
pub fn enforce_minimum_tenure_height(
    bitcoin_height: u64,
    mainnet: bool,
    config_path: Option<&Path>,
) {
    let min = if mainnet {
        MAINNET_MIN_TENURE_HEIGHT
    } else {
        let config_path = config_path
            .expect("enforce_minimum_tenure_height called for non-mainnet without --config");
        let config_file =
            ConfigFile::from_path(config_path.to_str().unwrap()).unwrap_or_else(|e| {
                eprintln!(
                    "Failed to parse config file '{}': {e}",
                    config_path.display()
                );
                std::process::exit(1);
            });
        let config = Config::from_config_file(config_file, false).unwrap_or_else(|e| {
            eprintln!("Failed to load config '{}': {e}", config_path.display());
            std::process::exit(1);
        });
        let epochs = config.burnchain.get_epoch_list();
        let epoch_34 = epochs.get(StacksEpochId::Epoch34).unwrap_or_else(|| {
            eprintln!(
                "Error: config '{}' does not define epoch 3.4.\n\
                 Epoch 3.4 activation height is required to validate \
                 --tenure-start-bitcoin-height.",
                config_path.display()
            );
            std::process::exit(1);
        });
        epoch_34.start_height - 1
    };

    if bitcoin_height < min {
        eprintln!(
            "Error: --tenure-start-bitcoin-height {bitcoin_height} is below the minimum \
             acceptable height {min}.\n\
             A squashed snapshot can only be used from epoch 3.4 onwards. The tenure at \
             height {min} is the last tenure of epoch 3.3; its blocks are the last ones \
             included before epoch 3.4 activates."
        );
        std::process::exit(1);
    }
}

/// Compute SHA-256 checksums for selected files in `out_dir`, allowing a set of
/// files to be present on disk without materializing individual checksum
/// entries for them.
pub fn compute_checksums(
    out_dir: &Path,
    expected_files: Option<&HashSet<String>>,
    skipped_files: Option<&HashSet<String>>,
) -> Result<BTreeMap<String, String>, String> {
    let mut checksums = BTreeMap::new();
    let mut entries: Vec<PathBuf> = Vec::new();
    let empty_skipped = HashSet::new();
    let skipped_files = skipped_files.unwrap_or(&empty_skipped);

    collect_files_recursive(out_dir, out_dir, &mut entries)?;
    entries.sort();

    for path in &entries {
        let rel = path
            .strip_prefix(out_dir)
            .map_err(|e| format!("strip_prefix: {e}"))?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        // Skip the manifest files themselves.
        if rel_str == GSS_MANIFEST {
            continue;
        }

        // Allow some files to be present without individual checksum entries.
        if skipped_files.contains(&rel_str) {
            continue;
        }

        // When an expected set is provided, reject unexpected files.
        if let Some(expected) = expected_files
            && !expected.contains(&rel_str)
        {
            return Err(format!(
                "unexpected file in output directory: {rel_str} \
                     (reuse a clean --out-dir or remove stale files)"
            ));
        }

        let hash = sha256_file(path)?;
        checksums.insert(rel_str, hash);
    }

    // When an expected set is provided, verify all expected files were found.
    if let Some(expected) = expected_files {
        for name in expected {
            if !checksums.contains_key(name) {
                return Err(format!(
                    "expected file missing from output directory: {name}"
                ));
            }
        }
    }

    Ok(checksums)
}

pub fn compute_aggregate_checksum(base_dir: &Path, rel_paths: &[String]) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut sorted_paths: Vec<&String> = rel_paths.iter().collect();
    sorted_paths.sort();

    for rel_path in sorted_paths {
        let file_path = base_dir.join(rel_path);
        let rel_bytes = rel_path.as_bytes();
        hasher.update((rel_bytes.len() as u64).to_le_bytes());
        hasher.update(rel_bytes);

        let metadata = fs::metadata(&file_path)
            .map_err(|e| format!("metadata {}: {e}", file_path.display()))?;
        if !metadata.is_file() {
            return Err(format!("expected regular file: {}", file_path.display()));
        }
        hasher.update(metadata.len().to_le_bytes());

        let mut file =
            fs::File::open(&file_path).map_err(|e| format!("open {}: {e}", file_path.display()))?;
        let mut buf = [0u8; 65536];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| format!("read {}: {e}", file_path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Recursively collect regular files, rejecting symlinks and non-regular
/// files. SQLite sidecars are ignored.
pub fn collect_files_recursive(
    base: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let read_dir = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;

        // Reject symlinks.
        if metadata.is_symlink() {
            return Err(format!(
                "symlink found in GSS directory: {}",
                path.strip_prefix(base).unwrap_or(&path).display()
            ));
        }

        if metadata.is_dir() {
            collect_files_recursive(base, &path, out)?;
            continue;
        }

        if !metadata.is_file() {
            return Err(format!(
                "non-regular file in GSS directory: {}",
                path.strip_prefix(base).unwrap_or(&path).display()
            ));
        }

        // Ignore transient SQLite sidecars. These can legitimately appear
        // around WAL-mode databases and should not be hashed or manifested.
        if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && SQLITE_SIDECAR_EXTENSIONS.contains(&ext)
        {
            continue;
        }

        out.push(path);
    }
    Ok(())
}

/// Compute the SHA-256 hex digest of a file using streaming reads.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn chainstate_paths(root: &Path) -> ChainstatePaths {
    let clarity_db = root.join("chainstate/vm/clarity/marf.sqlite");
    let index_db = root.join("chainstate/vm/index.sqlite");
    let sortition_db = root.join("burnchain/sortition/marf.sqlite");
    let sortition_blobs = PathBuf::from(format!("{}.blobs", sortition_db.display()));
    ChainstatePaths {
        clarity: TargetPaths {
            blobs: Some(PathBuf::from(format!("{}.blobs", clarity_db.display()))),
            db: clarity_db,
        },
        index: TargetPaths {
            blobs: Some(PathBuf::from(format!("{}.blobs", index_db.display()))),
            db: index_db,
        },
        sortition: TargetPaths {
            blobs: sortition_blobs.exists().then_some(sortition_blobs),
            db: sortition_db,
        },
    }
}

pub fn selected_targets(
    clarity: bool,
    index: bool,
    sortition: bool,
    all: bool,
) -> (bool, bool, bool) {
    if all {
        (true, true, true)
    } else {
        (clarity, index, sortition)
    }
}

pub fn ensure_targets_selected(
    clarity: bool,
    index: bool,
    sortition: bool,
    blocks: bool,
    bitcoin: bool,
    all: bool,
) {
    let (c, i, s) = selected_targets(clarity, index, sortition, all);
    if !c && !i && !s && !blocks && !bitcoin {
        eprintln!(
            "Must specify at least one target: --clarity, --index, --sortition, --blocks, --bitcoin, or --all"
        );
        std::process::exit(1);
    }
}

/// Verify that `--{flag}` is only used when `--{dep}` (or `--all`) is also set.
pub fn ensure_flag_requires(flag: &str, flag_val: bool, dep: &str, dep_val: bool) {
    if flag_val && !dep_val {
        eprintln!("--{flag} requires --{dep} (or --all)");
        std::process::exit(1);
    }
}

pub fn format_timestamp(unix_ts: i64) -> String {
    // Convert Unix timestamp to ISO 8601 UTC without external crate.
    const SECS_PER_DAY: i64 = 86400;
    const SECS_PER_HOUR: i64 = 3600;
    const SECS_PER_MIN: i64 = 60;

    let days = unix_ts / SECS_PER_DAY;
    let rem = unix_ts % SECS_PER_DAY;
    let hour = rem / SECS_PER_HOUR;
    let min = (rem % SECS_PER_HOUR) / SECS_PER_MIN;
    let sec = rem % SECS_PER_MIN;

    // Civil date from days since 1970-01-01 (algorithm from Howard Hinnant).
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

pub fn ensure_blobs_match(db_path: &str, blobs_path: &str) {
    let expected_blobs = PathBuf::from(format!("{db_path}.blobs"));
    if expected_blobs != Path::new(blobs_path) {
        eprintln!(
            "Expected blobs path '{blobs_path}' to match '{}'",
            expected_blobs.display()
        );
        std::process::exit(1);
    }
}

pub fn target_out_paths(out_dir: &Path, source_db: &Path) -> TargetPaths {
    let file_name = source_db.file_name().expect("source db missing filename");
    let mut rel_path = PathBuf::new();
    if let Some(parent) = source_db.parent() {
        rel_path = parent
            .components()
            .skip_while(|c| c.as_os_str() != "chainstate")
            .collect();
    }
    let out_parent = out_dir.join(rel_path);
    let out_db = out_parent.join(file_name);
    TargetPaths {
        blobs: Some(PathBuf::from(format!("{}.blobs", out_db.display()))),
        db: out_db,
    }
}

pub fn target_out_paths_sortition(out_dir: &Path, source_db: &Path) -> TargetPaths {
    let file_name = source_db.file_name().expect("source db missing filename");
    let mut rel_path = PathBuf::new();
    if let Some(parent) = source_db.parent() {
        rel_path = parent
            .components()
            .skip_while(|c| c.as_os_str() != "burnchain")
            .collect();
    }
    let out_parent = out_dir.join(rel_path);
    let out_db = out_parent.join(file_name);
    TargetPaths {
        blobs: Some(PathBuf::from(format!("{}.blobs", out_db.display()))),
        db: out_db,
    }
}

fn marf_open_opts(external_blobs: bool) -> MARFOpenOpts {
    let mut open_opts = MARFOpenOpts::default();
    open_opts.hash_calculation_mode = TrieHashCalculationMode::Deferred;
    open_opts.cache_strategy = "noop".to_string();
    open_opts.external_blobs = external_blobs;
    open_opts
}

pub fn squash_marf_open_opts() -> MARFOpenOpts {
    marf_open_opts(true)
}

pub fn sortition_open_opts_for_path(db_path: &Path) -> MARFOpenOpts {
    let blobs_path = PathBuf::from(format!("{}.blobs", db_path.display()));
    marf_open_opts(blobs_path.exists())
}

/// Read (mainnet, chain_id) from the index DB's db_config table.
pub fn read_db_config(index_db_path: &Path) -> (bool, u32) {
    let conn = rusqlite::Connection::open(index_db_path).unwrap_or_else(|e| {
        eprintln!(
            "Failed to open index DB '{}' for db_config: {e}",
            index_db_path.display()
        );
        std::process::exit(1);
    });
    let (mainnet_i, chain_id): (i64, i64) = conn
        .query_row(
            "SELECT mainnet, chain_id FROM db_config LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to read db_config: {e}");
            std::process::exit(1);
        });
    (mainnet_i != 0, chain_id as u32)
}

/// Build PoxConstants. For mainnet the built-in constants are canonical.
/// For any other network, the node config TOML is required because each
/// testnet has its own PoX parameters.
pub fn build_pox_constants(mainnet: bool, config_path: Option<&Path>) -> PoxConstants {
    if mainnet {
        let mut pox = PoxConstants::mainnet_default();
        if let Some(p) = config_path {
            apply_config_overrides(p, &mut pox);
        }
        pox
    } else {
        let config_path = config_path.unwrap_or_else(|| {
            eprintln!(
                "Error: --config is required for non-mainnet networks.\n\
                 Each testnet has its own PoX parameters (reward cycle length, \
                 prepare phase length, etc.) that cannot be inferred from the \
                 database. Pass the node config TOML with --config."
            );
            std::process::exit(1);
        });
        // Start from nakamoto_testnet_default as a baseline, then apply
        // overrides from the config file.
        let mut pox = PoxConstants::nakamoto_testnet_default();
        apply_config_overrides(config_path, &mut pox);
        pox
    }
}

/// Read first_burn_height from the sortition DB.
pub fn read_first_burn_height(sortition_db_path: &str) -> u64 {
    let conn = rusqlite::Connection::open_with_flags(
        sortition_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to open sortition DB: {e}");
        std::process::exit(1);
    });
    conn.query_row(
        "SELECT MIN(block_height) FROM snapshots WHERE pox_valid = 1",
        [],
        |row| row.get::<_, i64>(0),
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to read first burn height from sortition DB: {e}");
        std::process::exit(1);
    }) as u64
}

/// Convert a Bitcoin block height to the sortition MARF height.
/// sortition_marf_height = bitcoin_height - first_burn_height
pub fn bitcoin_height_to_sortition_marf_height(
    sortition_db_path: &str,
    bitcoin_height: u64,
) -> u32 {
    let first_burn_height = read_first_burn_height(sortition_db_path);
    if bitcoin_height < first_burn_height {
        eprintln!("Bitcoin height {bitcoin_height} is below first burn height {first_burn_height}");
        std::process::exit(1);
    }
    (bitcoin_height - first_burn_height) as u32
}

/// Find the highest canonical Stacks block in the tenure that started at
/// `bitcoin_height`.
///
/// Validates that the Bitcoin height is a canonical tenure start (sortition=true)
/// by walking the canonical burn chain from the tip. Uses the existing
/// `NakamotoChainState::find_highest_known_block_header_in_tenure_by_block_height`
/// helper for burn_view-aware canonical selection.
///
/// Returns the Stacks block height at the end of the tenure.
pub fn find_tenure_end_stacks_height(
    chainstate_root: &str,
    sortition_db_dir: &str,
    bitcoin_height: u64,
    mainnet: bool,
    chain_id: u32,
    pox_constants: PoxConstants,
) -> Result<u32, String> {
    // Open the DBs with the correct APIs.
    let (chainstate, _) = StacksChainState::open(mainnet, chain_id, chainstate_root, None)
        .map_err(|e| format!("Failed to open chainstate at '{chainstate_root}': {e}"))?;

    let sortition_db = SortitionDB::open(sortition_db_dir, false, pox_constants, None)
        .map_err(|e| format!("Failed to open sortition DB at '{sortition_db_dir}': {e}"))?;

    // Walk the canonical burn chain to find the snapshot at this height.
    let canonical_tip = SortitionDB::get_canonical_burn_chain_tip(sortition_db.conn())
        .map_err(|e| format!("Failed to get canonical burn tip: {e}"))?;

    let ic = sortition_db.index_handle_at_tip();
    let snapshot =
        SortitionDB::get_ancestor_snapshot(&ic, bitcoin_height, &canonical_tip.sortition_id)
            .map_err(|e| {
                format!("Failed to get ancestor snapshot at burn height {bitcoin_height}: {e}")
            })?
            .ok_or_else(|| format!("No canonical sortition at Bitcoin height {bitcoin_height}"))?;

    if !snapshot.sortition {
        // Find nearby tenure starts for a helpful error message.
        let mut nearby = Vec::new();
        let search_radius = 10u64;
        let search_start = bitcoin_height.saturating_sub(search_radius);
        let search_end = bitcoin_height.saturating_add(search_radius);
        for h in search_start..=search_end {
            if h == bitcoin_height {
                continue;
            }
            if let Ok(Some(s)) =
                SortitionDB::get_ancestor_snapshot(&ic, h, &canonical_tip.sortition_id)
                && s.sortition
            {
                nearby.push(h);
            }
        }
        let nearby_str = if nearby.is_empty() {
            String::new()
        } else {
            format!(
                "\n  Nearby tenure starts: {}",
                nearby
                    .iter()
                    .map(|h| h.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return Err(format!(
            "Bitcoin height {bitcoin_height} did not start a Nakamoto tenure \
             (sortition=false).{nearby_str}"
        ));
    }

    // Use the existing NakamotoChainState helper for burn_view-aware selection.
    let header = NakamotoChainState::find_highest_known_block_header_in_tenure_by_block_height(
        &chainstate,
        &sortition_db,
        bitcoin_height,
    )
    .map_err(|e| format!("Failed to find tenure end at burn height {bitcoin_height}: {e}"))?
    .ok_or_else(|| {
        format!("No Nakamoto blocks found at Bitcoin height {bitcoin_height}. This may predate Nakamoto activation.")
    })?;

    Ok(header.stacks_block_height as u32)
}

/// Apply PoX overrides from a node config TOML file to the given PoxConstants.
/// Reads the [burnchain] section and applies any pox_reward_length,
/// pox_prepare_length, sunset_start, and sunset_end overrides.
pub fn apply_config_overrides(config_path: &Path, pox: &mut PoxConstants) {
    let config = ConfigFile::from_path(config_path.to_str().unwrap()).unwrap_or_else(|e| {
        eprintln!(
            "Failed to parse config file '{}': {e}",
            config_path.display()
        );
        std::process::exit(1);
    });
    let bc = match config.burnchain {
        Some(bc) => bc,
        None => return,
    };
    if let Some(v) = bc.pox_reward_length {
        eprintln!("Config override: pox_reward_length = {v}");
        pox.reward_cycle_length = v;
    }
    if let Some(v) = bc.pox_prepare_length {
        eprintln!("Config override: pox_prepare_length = {v}");
        pox.prepare_length = v;
    }
    if let Some(v) = bc.sunset_start {
        pox.sunset_start = v as u64;
    }
    if let Some(v) = bc.sunset_end {
        pox.sunset_end = v as u64;
    }
    if let Some(v) = bc.pox_2_activation {
        pox.v1_unlock_height = v;
    }
}

/// Warn if the tenure-start Bitcoin height is inside the Nakamoto prepare
/// phase. Uses `is_in_naka_prepare_phase()` which excludes the `mod 0`
/// block (unlike the broader `is_in_prepare_phase()`).
///
/// The cycle number is derived from the burn height directly using Nakamoto
/// prepare-phase semantics: if inside the prepare phase, the corresponding
/// cycle is the one being prepared for (i.e., the next cycle).
pub fn warn_if_in_prepare_phase(bitcoin_height: u64, pox: &PoxConstants, first_burn_height: u64) {
    if pox.is_in_naka_prepare_phase(first_burn_height, bitcoin_height) {
        // Derive the cycle being prepared for using the same Nakamoto-specific
        // semantics. In Nakamoto prepare phase (which excludes the mod-0 block),
        // the corresponding cycle is always current_cycle + 1.
        let current_cycle = pox.block_height_to_reward_cycle(first_burn_height, bitcoin_height);
        if let Some(cycle) = current_cycle {
            let preparing_for = cycle + 1;
            eprintln!(
                "Warning: Bitcoin height {bitcoin_height} is inside the Nakamoto prepare \
                 phase for reward cycle {preparing_for}. The node may stall on startup \
                 for missing the anchor block for cycle {preparing_for}."
            );
        }
    }
}
