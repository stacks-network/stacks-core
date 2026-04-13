use std::collections::HashSet;
use std::fs;
use std::path::Path;

use stacks_common::types::chainstate::{SortitionId, StacksBlockId};
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts, MarfConnection};
use stackslib::chainstate::stacks::index::{MarfTrieId, trie_sql};

use crate::cli::{
    BlocksSection, ChecksumsSection, GSS_MANIFEST, RootsSection, SnapshotSection, SquashManifest,
    SquashRootsSection, TargetPaths,
};
use crate::util::{
    compute_aggregate_checksum, compute_checksums, format_timestamp, sortition_open_opts_for_path,
    squash_marf_open_opts,
};

/// Read squash metadata from a just-squashed MARF DB.
/// Returns (tip, archival_root_hash, squash_root_node_hash, height).
pub fn read_squash_metadata<T: MarfTrieId + std::fmt::Display>(
    db_path: &str,
    open_opts: MARFOpenOpts,
) -> (T, String, Option<String>, u32) {
    let marf = MARF::<T>::from_path(db_path, open_opts).unwrap_or_else(|e| {
        eprintln!("Failed to open squashed MARF for manifest: {e:?}");
        std::process::exit(1);
    });
    let tip =
        trie_sql::get_latest_confirmed_block_hash::<T>(marf.sqlite_conn()).unwrap_or_else(|e| {
            eprintln!("Failed to read latest block hash: {e:?}");
            std::process::exit(1);
        });
    let squash_info = trie_sql::read_squash_info(marf.sqlite_conn()).unwrap_or_else(|e| {
        eprintln!("Failed to read squash info: {e:?}");
        std::process::exit(1);
    });
    match squash_info {
        Some((archival_hash, squash_hash, height)) => (
            tip,
            format!("0x{archival_hash}"),
            squash_hash.map(|h| format!("0x{h}")),
            height,
        ),
        None => {
            eprintln!("No squash info found in DB");
            std::process::exit(1);
        }
    }
}

/// Insert the relative path of `abs_path` (relative to `base`) into `set`.
fn insert_expected_rel(base: &Path, abs_path: &Path, set: &mut HashSet<String>) {
    if let Ok(rel) = abs_path.strip_prefix(base) {
        set.insert(rel.to_string_lossy().replace('\\', "/"));
    }
}

/// Read the burn_header_timestamp for the snapshot at the squash height.
/// When sortition DB is available, uses the explicit burn_height to look up
/// the canonical sortition ID rather than re-deriving from MAX(height).
pub fn read_snapshot_timestamp(
    sortition_out: Option<(&TargetPaths, u32)>,
    index_out: &TargetPaths,
    height: u32,
) -> Option<String> {
    // Try sortition DB first, using the explicit burn_height.
    if let Some((s_out, burn_height)) = sortition_out {
        let conn = rusqlite::Connection::open(s_out.db.to_str().unwrap()).ok()?;
        let sort_id: Option<String> = conn
            .query_row(
                "SELECT block_hash FROM marf_squash_block_heights WHERE height = ?1",
                [burn_height],
                |row| row.get(0),
            )
            .ok();
        if let Some(sid) = sort_id {
            let ts: Option<i64> = conn
                .query_row(
                    "SELECT burn_header_timestamp FROM snapshots WHERE sortition_id = ?1",
                    [&sid],
                    |row| row.get(0),
                )
                .ok();
            if let Some(ts) = ts {
                return Some(format_timestamp(ts));
            }
        }
    }

    // Fallback: try index DB block_headers, then nakamoto_block_headers.
    let conn = rusqlite::Connection::open(index_out.db.to_str().unwrap()).ok()?;
    let ibh: Option<String> = conn
        .query_row(
            "SELECT block_hash FROM marf_squash_block_heights WHERE height = ?1",
            [height],
            |row| row.get(0),
        )
        .ok();
    if let Some(ibh) = ibh {
        // Try epoch 2.x headers first.
        let ts: Option<i64> = conn
            .query_row(
                "SELECT burn_header_timestamp FROM block_headers WHERE index_block_hash = ?1",
                [&ibh],
                |row| row.get(0),
            )
            .ok();
        if let Some(ts) = ts {
            return Some(format_timestamp(ts));
        }
        // Try Nakamoto headers.
        let ts: Option<i64> = conn
            .query_row(
                "SELECT burn_header_timestamp FROM nakamoto_block_headers WHERE index_block_hash = ?1",
                [&ibh],
                |row| row.get(0),
            )
            .ok();
        if let Some(ts) = ts {
            return Some(format_timestamp(ts));
        }
    }

    None
}

/// Generate the GSS manifest. Only called for a complete GSS (all MARFs +
/// blocks + bitcoin aux).
///
/// `copied_block_rel_paths` contains the relative paths (under
/// `chainstate/blocks/`) of epoch-2.x block files and nakamoto.sqlite that
/// were actually written during the copy step.  This is used to build the
/// exact expected file set for checksum generation, avoiding the need to
/// re-walk the blocks directory (which could include stale files).
#[allow(clippy::too_many_arguments)]
pub fn generate_manifest(
    out_dir: &Path,
    clarity_out: &TargetPaths,
    index_out: &TargetPaths,
    sortition_out: (&TargetPaths, u32),
    stacks_height: u32,
    bitcoin_height: u64,
    blocks_section: BlocksSection,
    copied_block_rel_paths: &[String],
) {
    let (i_tip, i_archival, i_squash, i_height) = read_squash_metadata::<StacksBlockId>(
        index_out.db.to_str().unwrap(),
        squash_marf_open_opts(),
    );

    if i_height != stacks_height {
        eprintln!("Manifest error: Index squash height {i_height} != requested {stacks_height}");
        std::process::exit(1);
    }

    let (c_tip, c_archival, c_squash, c_h) = read_squash_metadata::<StacksBlockId>(
        clarity_out.db.to_str().unwrap(),
        squash_marf_open_opts(),
    );
    if c_h != stacks_height {
        eprintln!("Manifest error: Clarity squash height {c_h} != requested {stacks_height}");
        std::process::exit(1);
    }
    if c_tip != i_tip {
        eprintln!("Manifest error: Clarity tip {c_tip} != Index tip {i_tip}");
        std::process::exit(1);
    }

    let (s_out, _) = &sortition_out;
    let (_s_tip, s_archival, s_squash, _s_h) = read_squash_metadata::<SortitionId>(
        s_out.db.to_str().unwrap(),
        sortition_open_opts_for_path(&s_out.db),
    );

    // Read db_config from the squashed index DB.
    let (chain_id, mainnet) = {
        let conn = rusqlite::Connection::open(index_out.db.to_str().unwrap()).unwrap_or_else(|e| {
            eprintln!("Failed to open index DB for db_config: {e}");
            std::process::exit(1);
        });
        let row: (i64, i64) = conn
            .query_row(
                "SELECT chain_id, mainnet FROM db_config LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or_else(|e| {
                eprintln!("Failed to read db_config: {e}");
                std::process::exit(1);
            });
        (row.0 as u32, row.1 != 0)
    };

    // Read timestamp from sortition snapshots, falling back to index headers.
    let timestamp = read_snapshot_timestamp(Some(sortition_out), index_out, stacks_height);

    // Read bitcoin block hash from sortition DB.
    let bitcoin_block_hash = {
        let (s_out, bh) = &sortition_out;
        let conn = rusqlite::Connection::open(s_out.db.to_str().unwrap()).unwrap_or_else(|e| {
            eprintln!("Failed to open squashed sortition DB for bitcoin metadata: {e}");
            std::process::exit(1);
        });
        let sort_id: String = conn
            .query_row(
                "SELECT block_hash FROM marf_squash_block_heights WHERE height = ?1",
                [bh],
                |row| row.get(0),
            )
            .unwrap_or_else(|e| {
                eprintln!(
                    "Failed to read sortition ID at MARF height {bh} from squashed sortition DB: {e}"
                );
                std::process::exit(1);
            });
        let btc_hash: String = conn
            .query_row(
                "SELECT burn_header_hash FROM snapshots WHERE sortition_id = ?1",
                [&sort_id],
                |row| row.get(0),
            )
            .unwrap_or_else(|e| {
                eprintln!("Failed to read burn_header_hash for sortition_id {sort_id}: {e}");
                std::process::exit(1);
            });
        format!("0x{btc_hash}")
    };

    // Build the set of individually hashed files so that stale files in a
    // reused out-dir are rejected rather than blessed into the manifest.
    let mut expected = HashSet::new();

    // MARF databases + blobs.
    insert_expected_rel(out_dir, &clarity_out.db, &mut expected);
    if let Some(b) = &clarity_out.blobs {
        insert_expected_rel(out_dir, b, &mut expected);
    }
    insert_expected_rel(out_dir, &index_out.db, &mut expected);
    if let Some(b) = &index_out.blobs {
        insert_expected_rel(out_dir, b, &mut expected);
    }
    insert_expected_rel(out_dir, &sortition_out.0.db, &mut expected);
    if let Some(b) = &sortition_out.0.blobs {
        insert_expected_rel(out_dir, b, &mut expected);
    }

    // Bitcoin auxiliary files.
    expected.insert("burnchain/burnchain.sqlite".to_string());
    expected.insert("headers.sqlite".to_string());

    // `nakamoto.sqlite` is hashed individually; epoch-2 block files are
    // covered by one aggregate checksum to keep the manifest compact.
    expected.insert("chainstate/blocks/nakamoto.sqlite".to_string());
    let epoch2_block_rel_paths: Vec<String> = copied_block_rel_paths
        .iter()
        .filter(|rel| rel.as_str() != "chainstate/blocks/nakamoto.sqlite")
        .cloned()
        .collect();
    if epoch2_block_rel_paths.len() as u64 != blocks_section.epoch2x_files {
        eprintln!(
            "Manifest error: copied {} epoch-2 block files, expected {}",
            epoch2_block_rel_paths.len(),
            blocks_section.epoch2x_files
        );
        std::process::exit(1);
    }

    let skipped_epoch2: HashSet<String> = epoch2_block_rel_paths.iter().cloned().collect();
    let files =
        compute_checksums(out_dir, Some(&expected), Some(&skipped_epoch2)).unwrap_or_else(|e| {
            eprintln!("Failed to compute checksums: {e}");
            std::process::exit(1);
        });
    let epoch2_block_archive_hash = compute_aggregate_checksum(out_dir, &epoch2_block_rel_paths)
        .unwrap_or_else(|e| {
            eprintln!("Failed to compute epoch-2 block archive hash: {e}");
            std::process::exit(1);
        });
    println!(
        "Computed SHA-256 checksums for {} files plus one epoch-2 block archive hash",
        files.len()
    );

    let manifest = SquashManifest {
        snapshot: SnapshotSection {
            version: 1,
            stacks_height,
            bitcoin_height,
            block_hash: format!("0x{i_tip}"),
            bitcoin_block_hash: Some(bitcoin_block_hash),
            timestamp,
            chain_id,
            mainnet,
        },
        roots: RootsSection {
            clarity_archival_marf_root_hash: Some(c_archival),
            index_archival_marf_root_hash: i_archival,
            sortition_archival_marf_root_hash: Some(s_archival),
        },
        squash_roots: SquashRootsSection {
            clarity_squash_root_node_hash: c_squash,
            index_squash_root_node_hash: i_squash,
            sortition_squash_root_node_hash: s_squash,
        },
        blocks: Some(blocks_section),
        checksums: Some(ChecksumsSection {
            files,
            epoch2_block_archive_hash: Some(epoch2_block_archive_hash),
        }),
    };

    let toml_str = toml::to_string(&manifest).unwrap_or_else(|e| {
        eprintln!("Failed to serialize manifest: {e}");
        std::process::exit(1);
    });

    let manifest_path = out_dir.join(GSS_MANIFEST);
    fs::write(&manifest_path, toml_str).unwrap_or_else(|e| {
        eprintln!(
            "Failed to write manifest to '{}': {e}",
            manifest_path.display()
        );
        std::process::exit(1);
    });
    println!("Manifest written to {}", manifest_path.display());
}
