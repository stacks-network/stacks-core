mod cli;
mod commands;
mod manifest;
mod ops;
mod util;

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

    use crate::cli::{Cli, Command, GSS_MANIFEST};
    use crate::util::{compute_checksums, sha256_file};

    //  Helpers

    fn create_test_gss_dir(dir: &std::path::Path, files: &[&str]) {
        for f in files {
            let path = dir.join(f);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, format!("content of {f}")).unwrap();
        }
    }

    //  CLI parsing

    #[test]
    fn test_parse_squash_args_ok() {
        let args = vec![
            "marf-squash",
            "squash",
            "--chainstate",
            "/tmp/chainstate",
            "--tenure-start-bitcoin-height",
            "869704",
            "--out-dir",
            "/tmp/out",
            "--index",
        ]
        .into_iter()
        .map(String::from);

        let cli = Cli::try_parse_from(args).unwrap();
        let Command::Squash(args) = cli.command;
        assert_eq!(args.chainstate, PathBuf::from("/tmp/chainstate"));
        assert_eq!(args.tenure_start_bitcoin_height, 869704);
        assert!(args.index);
    }

    #[test]
    fn test_parse_squash_args_sortition() {
        let args = vec![
            "marf-squash",
            "squash",
            "--chainstate",
            "/tmp/chainstate",
            "--tenure-start-bitcoin-height",
            "869704",
            "--out-dir",
            "/tmp/out",
            "--sortition",
        ]
        .into_iter()
        .map(String::from);

        let cli = Cli::try_parse_from(args).unwrap();
        let Command::Squash(args) = cli.command;
        assert!(args.sortition);
        assert!(!args.clarity);
        assert!(!args.index);
    }

    //  compute_checksums / collect_files_recursive

    #[test]
    fn test_compute_checksums_clean_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        create_test_gss_dir(dir, &["a.sqlite", "sub/b.sqlite"]);
        std::fs::write(dir.join(GSS_MANIFEST), "dummy").unwrap();

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
        create_test_gss_dir(dir, &["a.sqlite", "a.sqlite-wal"]);

        let checksums = compute_checksums(dir, None, None).unwrap();
        assert_eq!(checksums.len(), 1);
        assert!(checksums.contains_key("a.sqlite"));
    }

    #[test]
    fn test_manifest_rejects_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        create_test_gss_dir(dir, &["a.sqlite"]);
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
        create_test_gss_dir(dir, &["expected.sqlite", "stale.sqlite"]);

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
