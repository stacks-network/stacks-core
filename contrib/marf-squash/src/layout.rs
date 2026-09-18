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

//! Single source of truth for the PCS on-disk layout: the relative paths of the
//! databases and directories within a chainstate / squashed-output tree, the
//! manifest file name, and helpers to derive per-target paths.

use std::path::{Path, PathBuf};

use stacks_common::types::chainstate::StacksBlockId;
use stackslib::chainstate::stacks::db::StacksChainState;

/// Relative path of the Clarity MARF within a chainstate tree.
pub const CLARITY_MARF_REL: &str = "chainstate/vm/clarity/marf.sqlite";
/// Relative path of the Index MARF.
pub const INDEX_DB_REL: &str = "chainstate/vm/index.sqlite";
/// Relative path of the Sortition MARF.
pub const SORTITION_MARF_REL: &str = "burnchain/sortition/marf.sqlite";
/// Relative path of the burnchain DB.
pub const BURNCHAIN_DB_REL: &str = "burnchain/burnchain.sqlite";
/// Relative path of the SPV headers DB.
pub const HEADERS_DB_REL: &str = "headers.sqlite";
/// Relative path of the blocks directory.
pub const BLOCKS_DIR_REL: &str = "chainstate/blocks";
/// Relative path of the Nakamoto staging DB.
pub const NAKAMOTO_DB_REL: &str = "chainstate/blocks/nakamoto.sqlite";

/// Manifest file name.
pub const PCS_MANIFEST: &str = "PCS_manifest.toml";

/// File extensions that indicate SQLite sidecars (WAL, SHM, journal).
pub const SQLITE_SIDECAR_EXTENSIONS: &[&str] = &["sqlite-wal", "sqlite-shm", "sqlite-journal"];

/// A MARF database plus its optional external `.blobs` sidecar.
#[derive(Debug, Clone)]
pub struct TargetPaths {
    pub db: PathBuf,
    pub blobs: Option<PathBuf>,
}

/// The three source MARFs within a chainstate tree.
#[derive(Debug, Clone)]
pub struct ChainstatePaths {
    pub clarity: TargetPaths,
    pub index: TargetPaths,
    pub sortition: TargetPaths,
}

/// Derive the source MARF paths from a chainstate root.
pub fn chainstate_paths(root: &Path) -> ChainstatePaths {
    let clarity_db = root.join(CLARITY_MARF_REL);
    let index_db = root.join(INDEX_DB_REL);
    let sortition_db = root.join(SORTITION_MARF_REL);
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

/// A relative path as a `/`-separated string. Normalizes Windows `\` so manifest
/// entries and checksum keys match across host OSes (no-op on POSIX).
pub fn canonical_rel_path(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

/// Relative path of an epoch-2.x block file: the blocks dir followed by the
/// node's own index-hash sharding ([`StacksChainState::index_block_hash_to_rel_path`]).
pub fn epoch2_block_rel_path(index_block_hash: &StacksBlockId) -> String {
    format!(
        "{BLOCKS_DIR_REL}/{}",
        canonical_rel_path(&StacksChainState::index_block_hash_to_rel_path(
            index_block_hash
        ))
    )
}

/// Output paths for a target MARF: `out_dir` joined with the target's canonical
/// relative path (one of [`CLARITY_MARF_REL`], [`INDEX_DB_REL`],
/// [`SORTITION_MARF_REL`]), plus its derived `.blobs` sidecar. The output layout
/// is fixed by the layout consts and does not depend on the source path's shape.
pub fn target_out_paths(out_dir: &Path, rel: &str) -> TargetPaths {
    let out_db = out_dir.join(rel);
    TargetPaths {
        blobs: Some(PathBuf::from(format!("{}.blobs", out_db.display()))),
        db: out_db,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rstest::rstest;

    use super::{CLARITY_MARF_REL, INDEX_DB_REL, SORTITION_MARF_REL, target_out_paths};

    /// `target_out_paths` over (`out_dir`, rel-const) → expected `(db, blobs)`
    /// output paths. The output is always `out_dir.join(rel)` plus its `.blobs`
    /// sidecar, fixed by the layout consts.
    ///
    /// The last two cases are the regression for a nested `chainstate`/`burnchain`
    /// component in the `out_dir` itself (e.g. `…/chainstate/mainnet`): the
    /// previous component-scan derived the output from the source path's shape and
    /// would mis-map such a tree, whereas the output now depends solely on
    /// `out_dir` + the const.
    #[rstest]
    #[case(
        "/tmp/out/mainnet",
        CLARITY_MARF_REL,
        "/tmp/out/mainnet/chainstate/vm/clarity/marf.sqlite",
        "/tmp/out/mainnet/chainstate/vm/clarity/marf.sqlite.blobs"
    )]
    #[case(
        "/tmp/out/mainnet",
        INDEX_DB_REL,
        "/tmp/out/mainnet/chainstate/vm/index.sqlite",
        "/tmp/out/mainnet/chainstate/vm/index.sqlite.blobs"
    )]
    #[case(
        "/tmp/out/mainnet",
        SORTITION_MARF_REL,
        "/tmp/out/mainnet/burnchain/sortition/marf.sqlite",
        "/tmp/out/mainnet/burnchain/sortition/marf.sqlite.blobs"
    )]
    // Regression: a nested `chainstate` component in `out_dir` does not perturb
    // the destination layout.
    #[case(
        "/data/chainstate/mainnet/chainstate/mainnet",
        INDEX_DB_REL,
        "/data/chainstate/mainnet/chainstate/mainnet/chainstate/vm/index.sqlite",
        "/data/chainstate/mainnet/chainstate/mainnet/chainstate/vm/index.sqlite.blobs"
    )]
    #[case(
        "/data/burnchain/krypton/burnchain/krypton",
        SORTITION_MARF_REL,
        "/data/burnchain/krypton/burnchain/krypton/burnchain/sortition/marf.sqlite",
        "/data/burnchain/krypton/burnchain/krypton/burnchain/sortition/marf.sqlite.blobs"
    )]
    fn target_out_paths_uses_layout_consts(
        #[case] out_dir: &str,
        #[case] rel: &str,
        #[case] expected_db: &str,
        #[case] expected_blobs: &str,
    ) {
        let tp = target_out_paths(Path::new(out_dir), rel);
        assert_eq!(tp.db.to_str().unwrap(), expected_db);
        assert_eq!(tp.blobs.unwrap().to_str().unwrap(), expected_blobs);
    }
}
