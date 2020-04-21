//! Support library for `cargo xtask` command.
//!
//! See https://github.com/matklad/cargo-xtask/

pub mod not_bash;
pub mod install;
pub mod dist;
pub mod pre_commit;

use std::{
    env,
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

use crate::{
    not_bash::{fs2, rm_rf, run},
};

pub use anyhow::Result;

pub fn project_root() -> PathBuf {
    Path::new(
        &env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned()),
    )
    .ancestors()
    .nth(1)
    .unwrap()
    .to_path_buf()
}

pub fn rust_files(path: &Path) -> impl Iterator<Item = PathBuf> {
    let iter = WalkDir::new(path);
    return iter
        .into_iter()
        .filter_entry(|e| !is_hidden(e))
        .map(|e| e.unwrap())
        .filter(|e| !e.file_type().is_dir())
        .map(|e| e.into_path())
        .filter(|path| path.extension().map(|it| it == "rs").unwrap_or(false));

    fn is_hidden(entry: &DirEntry) -> bool {
        entry.file_name().to_str().map(|s| s.starts_with('.')).unwrap_or(false)
    }
}

/// Cleans the `./target` dir after the build such that only
/// dependencies are cached on CI.
pub fn run_pre_cache() -> Result<()> {
    for entry in Path::new("./target/debug").read_dir()? {
        let entry = entry?;
        if entry.file_type().map(|it| it.is_file()).ok() == Some(true) {
            // Can't delete yourself on windows :-(
            if !entry.path().ends_with("xtask.exe") {
                rm_rf(&entry.path())?
            }
        }
    }

    fs2::remove_file("./target/.rustc_info.json")?;
    let to_delete = ["ra_", "heavy_test", "xtask"];
    for &dir in ["./target/debug/deps", "target/debug/.fingerprint"].iter() {
        for entry in Path::new(dir).read_dir()? {
            let entry = entry?;
            if to_delete.iter().any(|&it| entry.path().display().to_string().contains(it)) {
                // Can't delete yourself on windows :-(
                if !entry.path().ends_with("xtask.exe") {
                    rm_rf(&entry.path())?
                }
            }
        }
    }

    Ok(())
}

pub fn run_release(dry_run: bool) -> Result<()> {
    if !dry_run {
        run!("git switch release")?;
        run!("git fetch upstream")?;
        run!("git reset --hard upstream/master")?;
        run!("git push")?;
    }

    let website_root = project_root().join("../stacks-blockchain.github.io");
    let changelog_dir = website_root.join("./thisweek/_posts");

    let today = run!("date --iso")?;
    let commit = run!("git rev-parse HEAD")?;
    let changelog_n = fs2::read_dir(changelog_dir.as_path())?.count();

    let contents = format!(
        "\
= Changelog #{}
:sectanchors:
:page-layout: post

Commit: commit:{}[] +
Release: release:{}[]

== New Features

* pr:[] .

== Fixes

== Internal Improvements
",
        changelog_n, commit, today
    );

    let path = changelog_dir.join(format!("{}-changelog-{}.adoc", today, changelog_n));
    fs2::write(&path, &contents)?;

    fs2::copy(project_root().join("./docs/user/readme.adoc"), website_root.join("manual.adoc"))?;

    let tags = run!("git tag --list"; echo = false)?;
    let prev_tag = tags.lines().filter(|line| is_release_tag(line)).last().unwrap();

    println!("\n    git log {}..HEAD --merges --reverse", prev_tag);

    Ok(())
}

fn is_release_tag(tag: &str) -> bool {
    tag.len() == "2020-02-24".len() && tag.starts_with(|c: char| c.is_ascii_digit())
}
