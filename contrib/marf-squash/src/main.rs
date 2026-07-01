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

mod checksums;
mod cli;
mod commands;
mod config;
mod db;
mod layout;
mod manifest;
mod ops;
mod targets;

use clap::Parser;
use cli::{Cli, Command};
use commands::run_squash;

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Squash(args) => run_squash(args),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use rstest::rstest;

    use crate::checksums::{compute_checksums, sha256_file};
    use crate::cli::{Cli, Command};
    use crate::layout::PCS_MANIFEST;

    //  Helpers

    fn create_test_pcs_dir(dir: &std::path::Path, files: &[&str]) {
        for f in files {
            let path = dir.join(f);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, format!("content of {f}")).unwrap();
        }
    }

    //  CLI parsing

    /// Parse `squash` argv over (selected target flag) → expected
    /// `(clarity, index, sortition)` flag values. `--chainstate`,
    /// `--tenure-start-bitcoin-height`, and `--out-dir` are fixed and asserted in
    /// every case.
    #[rstest]
    #[case("--index", (false, true, false))]
    #[case("--sortition", (false, false, true))]
    fn test_parse_squash_args(#[case] target_flag: &str, #[case] expected: (bool, bool, bool)) {
        let args = vec![
            "marf-squash",
            "squash",
            "--chainstate",
            "/tmp/chainstate",
            "--tenure-start-bitcoin-height",
            "869704",
            "--out-dir",
            "/tmp/out",
            target_flag,
        ]
        .into_iter()
        .map(String::from);

        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command {
            Command::Squash(args) => {
                assert_eq!(args.chainstate, PathBuf::from("/tmp/chainstate"));
                assert_eq!(args.tenure_start_bitcoin_height, 869704);
                let (clarity, index, sortition) = expected;
                assert_eq!(args.clarity, clarity);
                assert_eq!(args.index, index);
                assert_eq!(args.sortition, sortition);
            }
        }
    }

    //  compute_checksums / collect_files_recursive

    #[test]
    fn test_compute_checksums_clean_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        create_test_pcs_dir(dir, &["a.sqlite", "sub/b.sqlite"]);
        std::fs::write(dir.join(PCS_MANIFEST), "dummy").unwrap();

        let checksums = compute_checksums(dir, None, None).unwrap();
        assert_eq!(checksums.len(), 2);
        assert!(checksums.contains_key("a.sqlite"));
        assert!(checksums.contains_key("sub/b.sqlite"));
        let expected = sha256_file(&dir.join("a.sqlite")).unwrap();
        assert_eq!(checksums["a.sqlite"], expected);
    }

    #[test]
    fn test_compute_checksums_ignores_sqlite_sidecars() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        create_test_pcs_dir(dir, &["a.sqlite", "a.sqlite-wal"]);

        let checksums = compute_checksums(dir, None, None).unwrap();
        assert_eq!(checksums.len(), 1);
        assert!(checksums.contains_key("a.sqlite"));
    }

    #[test]
    fn test_manifest_rejects_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        create_test_pcs_dir(dir, &["a.sqlite"]);
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("a.sqlite"), dir.join("link.sqlite")).unwrap();

        #[cfg(unix)]
        {
            let result = compute_checksums(dir, None, None);
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("symlink"));
        }
    }

    #[test]
    fn test_manifest_rejects_extra_file_in_outdir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        create_test_pcs_dir(dir, &["expected.sqlite", "stale.sqlite"]);

        let mut expected = std::collections::HashSet::new();
        expected.insert("expected.sqlite".to_string());

        let result = compute_checksums(dir, Some(&expected), None);
        let err = result.unwrap_err();
        assert!(err.contains("unexpected file"), "got: {err}");
        assert!(err.contains("stale.sqlite"), "got: {err}");
    }

    #[test]
    fn test_compute_checksums_rejects_stale_block_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let blocks_dir = dir.join("chainstate/blocks/ab/cd");
        std::fs::create_dir_all(&blocks_dir).unwrap();
        std::fs::write(blocks_dir.join("legit_block"), "data").unwrap();
        std::fs::write(blocks_dir.join("stale_block"), "old data").unwrap();

        let mut expected = std::collections::HashSet::new();
        expected.insert("chainstate/blocks/ab/cd/legit_block".to_string());

        let result = compute_checksums(dir, Some(&expected), None);
        let err = result.unwrap_err();
        assert!(err.contains("unexpected file"), "got: {err}");
        assert!(err.contains("stale_block"), "got: {err}");
    }
}
