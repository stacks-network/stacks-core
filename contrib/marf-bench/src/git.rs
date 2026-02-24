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

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

use crate::util::run_checked;

/// Return the repository root for the current working directory.
pub fn current_repo_root() -> Result<PathBuf> {
    let repo_root = git_capture_output(["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(repo_root.trim()))
}

/// Validate that a revision resolves to a commit object.
pub fn verify_revision(repo_root: &Path, revision: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .arg("rev-parse")
        .arg("--verify")
        .arg(format!("{revision}^{{commit}}"));

    run_checked(cmd, &format!("invalid revision: {revision}"))
}

/// Resolve a user-provided base revision, including special keywords.
pub fn resolve_base_revision(repo_root: &Path, base: &str) -> Result<(String, String)> {
    if base.eq_ignore_ascii_case("staged") {
        let commit = create_staged_snapshot_commit(repo_root)?;
        return Ok((commit, "staged".to_string()));
    }

    if let Some((_, upstream_ref)) = base.split_once(':')
        && base.starts_with("merge-base:")
    {
        if upstream_ref.trim().is_empty() {
            bail!("invalid --base value: '{base}'. Expected merge-base:<upstream-ref>");
        }
        return resolve_merge_base_revision(repo_root, upstream_ref.trim());
    }

    if base.eq_ignore_ascii_case("merge-base") {
        bail!("invalid --base value: '{base}'. Use --base merge-base:<upstream-ref>");
    }

    verify_revision(repo_root, base)?;
    Ok((base.to_string(), base.to_string()))
}

/// Resolve merge-base against HEAD for a given upstream reference.
pub fn resolve_merge_base_revision(
    repo_root: &Path,
    upstream_ref: &str,
) -> Result<(String, String)> {
    verify_revision(repo_root, upstream_ref)?;

    let merge_base = git_capture_output_in(repo_root, ["merge-base", upstream_ref, "HEAD"])?;
    let merge_base = merge_base.trim().to_string();
    if merge_base.is_empty() {
        bail!("failed to resolve merge-base for {upstream_ref} and HEAD");
    }

    Ok((merge_base, format!("merge-base({upstream_ref})")))
}

/// Create an ephemeral commit that snapshots the current staged index.
fn create_staged_snapshot_commit(repo_root: &Path) -> Result<String> {
    let tree = git_capture_output_in(repo_root, ["write-tree"])?;
    let tree = tree.trim().to_string();

    let head = git_capture_output_in(repo_root, ["rev-parse", "--verify", "HEAD^{commit}"])
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .arg("commit-tree")
        .arg(&tree)
        .arg("-m")
        .arg("marf-bench staged snapshot");
    if let Some(head) = head {
        cmd.arg("-p").arg(head);
    }

    let out = cmd
        .output()
        .context("failed to create staged snapshot commit")?;
    if !out.status.success() {
        bail!(
            "failed to create staged snapshot commit: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let commit = String::from_utf8(out.stdout)
        .map_err(|err| anyhow!(err))?
        .trim()
        .to_string();
    if commit.is_empty() {
        bail!("failed to create staged snapshot commit: empty commit hash");
    }
    Ok(commit)
}

/// Run a git command and return stdout as UTF-8 text.
fn git_capture_output<I, S>(args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new("git");
    cmd.args(args);

    let out = cmd.output().context("failed to run git command")?;
    if !out.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    String::from_utf8(out.stdout).map_err(|err| anyhow!(err))
}

/// Run a git command in a specific repository and return stdout as UTF-8 text.
fn git_capture_output_in<I, S>(repo_root: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root).args(args);

    let out = cmd.output().context("failed to run git command")?;
    if !out.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    String::from_utf8(out.stdout).map_err(|err| anyhow!(err))
}
