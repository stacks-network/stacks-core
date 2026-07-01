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

//! SHA-256 checksum computation and directory traversal for PCS artifacts.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::layout::{PCS_MANIFEST, SQLITE_SIDECAR_EXTENSIONS, canonical_rel_path};

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
        if let Some((rel_str, hash)) = checksum_entry(out_dir, path, expected_files, skipped_files)?
        {
            checksums.insert(rel_str, hash);
        }
    }

    // When an expected set is provided, verify all expected files were found.
    if let Some(expected) = expected_files {
        verify_all_expected_present(&checksums, expected)?;
    }

    Ok(checksums)
}

/// Error if any name in `expected` has no checksum entry (i.e. an expected file
/// was missing from the output directory).
fn verify_all_expected_present(
    checksums: &BTreeMap<String, String>,
    expected: &HashSet<String>,
) -> Result<(), String> {
    for name in expected {
        if !checksums.contains_key(name) {
            return Err(format!(
                "expected file missing from output directory: {name}"
            ));
        }
    }
    Ok(())
}

/// Resolve one collected `path` to its `(rel_str, hash)` checksum entry, or
/// `None` if it is skipped (the manifest itself or a `skipped_files` member).
/// Errors when `expected_files` is provided and the file is not in it.
fn checksum_entry(
    out_dir: &Path,
    path: &Path,
    expected_files: Option<&HashSet<String>>,
    skipped_files: &HashSet<String>,
) -> Result<Option<(String, String)>, String> {
    let rel = path
        .strip_prefix(out_dir)
        .map_err(|e| format!("strip_prefix: {e}"))?;
    let rel_str = canonical_rel_path(rel);

    // Skip the manifest files themselves.
    if rel_str == PCS_MANIFEST {
        return Ok(None);
    }

    // Allow some files to be present without individual checksum entries.
    if skipped_files.contains(&rel_str) {
        return Ok(None);
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
    Ok(Some((rel_str, hash)))
}

/// Compute a single SHA-256 over the contents of `rel_paths` (relative to
/// `base_dir`), hashed in sorted path order so the result is deterministic.
pub fn compute_aggregate_checksum(base_dir: &Path, rel_paths: &[String]) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut sorted_paths: Vec<&String> = rel_paths.iter().collect();
    sorted_paths.sort();

    for rel_path in sorted_paths {
        hash_one_aggregate_entry(&mut hasher, base_dir, rel_path)?;
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Fold one `rel_path`'s length-prefixed name, byte length, and contents into
/// `hasher`. Errors if the path is not a regular file.
fn hash_one_aggregate_entry(
    hasher: &mut Sha256,
    base_dir: &Path,
    rel_path: &str,
) -> Result<(), String> {
    let file_path = base_dir.join(rel_path);
    let rel_bytes = rel_path.as_bytes();
    hasher.update((rel_bytes.len() as u64).to_le_bytes());
    hasher.update(rel_bytes);

    let metadata =
        fs::metadata(&file_path).map_err(|e| format!("metadata {}: {e}", file_path.display()))?;
    if !metadata.is_file() {
        return Err(format!("expected regular file: {}", file_path.display()));
    }
    hasher.update(metadata.len().to_le_bytes());

    hash_file_into(hasher, &file_path)
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
                "symlink found in PCS directory: {}",
                path.strip_prefix(base).unwrap_or(&path).display()
            ));
        }

        if metadata.is_dir() {
            collect_files_recursive(base, &path, out)?;
            continue;
        }

        if !metadata.is_file() {
            return Err(format!(
                "non-regular file in PCS directory: {}",
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

/// Stream `path`'s contents into `hasher`. Shared by [`sha256_file`] and
/// [`hash_one_aggregate_entry`].
fn hash_file_into(hasher: &mut Sha256, path: &Path) -> Result<(), String> {
    let file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut reader = BufReader::with_capacity(65536, file);
    std::io::copy(&mut reader, hasher).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(())
}

/// Compute the SHA-256 hex digest of a file.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hash_file_into(&mut hasher, path)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::sha256_file;

    /// Known-answer vector: SHA-256("abc"). Guards the streaming-hash refactor.
    #[test]
    fn sha256_file_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
