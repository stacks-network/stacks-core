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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use tempfile::TempDir;

use crate::git::{
    add_detached_worktree, list_worktree_paths, prune_worktrees_now, remove_worktree_force,
};
use crate::report::SummaryRow;
use crate::util::{
    combine_output_text, extract_summary_lines, log, print_output, run_checked, sanitize_revision,
};
use crate::{BenchKind, OutputFormat, TempBuilder};

const MARF_BENCH_FILES: [&str; 8] = [
    "allocator.rs",
    "primitives.rs",
    "patch.rs",
    "common.rs",
    "main.rs",
    "read.rs",
    "utils.rs",
    "write.rs",
];
const SRC_BENCH_DIR: &str = "stackslib/benches/marf";
const STACKSLIB_CARGO_TOML: &str = "stackslib/Cargo.toml";
const PATCH_SUPPORT_INTRO_COMMIT: &str = "0317850e7f042de98e7bc6a1f26f6183e7d20f98";
const WORKTREE_PREFIX: &str = "marf-bench-";
const WORKTREE_CACHE_DIR: &str = "marf-bench-worktrees";

/// Environment overrides passed to marf benchmark subprocesses.
#[derive(Debug, Clone, Default)]
pub struct BenchEnvOverrides {
    pub iters: Option<usize>,
    pub rounds: Option<usize>,
    pub chain_len: Option<u32>,
    pub write_depths: Option<String>,
    pub key_updates: Option<usize>,
    pub sqlite_wal_autocheckpoint: Option<usize>,
    pub sqlite_wal_checkpoint_mode: Option<String>,
    pub read_proofs: Option<bool>,
    pub keys_per_block: Option<u32>,
    pub depths: Option<String>,
    pub cache_strategies: Option<String>,
    pub key_search_max_tries: Option<usize>,
    pub node_types: Option<String>,
    pub ptr_states: Option<String>,
    pub patch_diffs: Option<String>,
}

/// A single benchmark invocation request.
#[derive(Debug, Clone)]
pub struct BenchRunRequest {
    pub kind: BenchKind,
    pub env: BenchEnvOverrides,
}

impl BenchRunRequest {
    /// Create a benchmark run request.
    pub fn new(kind: BenchKind, env: BenchEnvOverrides) -> Self {
        Self { kind, env }
    }
}

/// Tracked git worktree lifecycle information.
struct ManagedWorktree {
    path: PathBuf,
    _temp_root: Option<TempDir>,
}

/// A worktree that has been prepared (created, overlaid, built) but not yet
/// registered with a [`Runner`]. Produced by [`prepare_worktree`] and consumed
/// by [`Runner::register_prepared_worktree`].
pub struct PreparedWorktree {
    /// Path to the worktree root.
    pub path: PathBuf,
    /// Temporary directory handle for non-cached worktrees.
    /// Dropping this removes the temporary directory.
    pub temp_root: Option<TempDir>,
    /// Whether the bench file overlay changed any files.
    pub overlay_changed: bool,
    /// Set of bench target names that have been built.
    pub built_benches: HashSet<String>,
}

/// Orchestrates worktree setup, build, execution, and cleanup.
pub struct Runner {
    repo_root: PathBuf,
    source_bench_dir: PathBuf,
    keep_worktrees: bool,
    worktrees: Vec<ManagedWorktree>,
    worktrees_by_revision: HashMap<String, PathBuf>,
    built_targets: HashSet<(PathBuf, String)>,
    overlay_changed_roots: HashMap<PathBuf, bool>,
}

impl Runner {
    /// Create a runner rooted at the current repository.
    pub fn new(repo_root: PathBuf, keep_worktrees: bool) -> Result<Self> {
        if !keep_worktrees {
            cleanup_stale_marf_bench_worktrees(&repo_root)?;
        } else {
            let cache_root = keep_worktrees_root(&repo_root);
            log(format!(
                "Keep-worktrees cache root: {}",
                cache_root.display()
            ));
        }

        let source_bench_dir = repo_root.join(SRC_BENCH_DIR);
        if !source_bench_dir.is_dir() {
            bail!(
                "source bench directory not found: {}",
                source_bench_dir.display()
            );
        }

        for name in MARF_BENCH_FILES {
            let path = source_bench_dir.join(name);
            if !path.is_file() {
                bail!("missing source bench file: {}", path.display());
            }
        }

        Ok(Self {
            repo_root,
            source_bench_dir,
            keep_worktrees,
            worktrees: Vec::new(),
            worktrees_by_revision: HashMap::new(),
            built_targets: HashSet::new(),
            overlay_changed_roots: HashMap::new(),
        })
    }

    /// Return the source bench directory path.
    pub fn source_bench_dir(&self) -> &Path {
        &self.source_bench_dir
    }

    /// Register a [`PreparedWorktree`] into this runner for lifecycle management
    /// and build-cache tracking.
    pub fn register_prepared_worktree(&mut self, revision: &str, prepared: PreparedWorktree) {
        self.worktrees_by_revision
            .insert(revision.to_string(), prepared.path.clone());
        self.overlay_changed_roots
            .insert(prepared.path.clone(), prepared.overlay_changed);
        for bench_name in &prepared.built_benches {
            self.built_targets
                .insert((prepared.path.clone(), bench_name.clone()));
        }
        if prepared.temp_root.is_some() {
            self.worktrees.push(ManagedWorktree {
                path: prepared.path,
                _temp_root: prepared.temp_root,
            });
        }
    }

    /// Run requested benchmarks in the current checkout.
    pub fn run_current_tree(
        &mut self,
        label: &str,
        requests: &[BenchRunRequest],
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        self.ensure_requests_supported(&self.repo_root, requests)?;

        let marf_bench_dir = self.repo_root.join(SRC_BENCH_DIR);
        if !marf_bench_dir.is_dir() {
            bail!(
                "current tree missing {SRC_BENCH_DIR}: {}",
                marf_bench_dir.display()
            );
        }

        let cargo_toml = self.repo_root.join(STACKSLIB_CARGO_TOML);
        let cargo_toml_text = fs::read_to_string(&cargo_toml)
            .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
        if requests
            .iter()
            .any(|request| request.kind.bench_name() == "marf")
            && !cargo_toml_text.contains("name = \"marf\"")
        {
            bail!(
                "current tree Cargo.toml missing marf bench target: {}",
                cargo_toml.display()
            );
        }

        let repo_root = self.repo_root.clone();
        self.run_benches(label, &repo_root, requests, output_format)
    }

    /// Run requested benchmarks in a worktree checked out at a revision.
    pub fn run_revision_via_worktree(
        &mut self,
        label: &str,
        revision: &str,
        requests: &[BenchRunRequest],
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        let wt = if let Some(existing) = self.worktrees_by_revision.get(revision) {
            existing.clone()
        } else {
            let wt = self.create_worktree(revision)?;
            self.worktrees_by_revision
                .insert(revision.to_string(), wt.clone());
            wt
        };

        self.ensure_requests_supported(&wt, requests)?;

        let overlay_changed = self.overlay_benches(&wt, requests)?;
        self.ensure_bench_target(&wt.join(STACKSLIB_CARGO_TOML), requests)?;
        self.overlay_changed_roots
            .entry(wt.clone())
            .and_modify(|changed| *changed |= overlay_changed)
            .or_insert(overlay_changed);

        self.run_benches(label, &wt, requests, output_format)
    }

    /// Create or reuse a git worktree for a revision.
    fn create_worktree(&mut self, revision: &str) -> Result<PathBuf> {
        let (path, temp_root) = create_worktree_at(&self.repo_root, self.keep_worktrees, revision)?;
        if let Some(temp_root) = temp_root {
            self.worktrees.push(ManagedWorktree {
                path: path.clone(),
                _temp_root: Some(temp_root),
            });
        }
        Ok(path)
    }

    /// Overlay benchmark source files into a target root.
    fn overlay_benches(&self, root: &Path, requests: &[BenchRunRequest]) -> Result<bool> {
        overlay_bench_files(&self.source_bench_dir, root, requests)
    }

    /// Ensure required benchmark target/dependencies exist in Cargo.toml.
    fn ensure_bench_target(&self, cargo_toml: &Path, requests: &[BenchRunRequest]) -> Result<()> {
        ensure_bench_target_at(cargo_toml, requests)
    }

    /// Build once if needed and run all requested benchmark cases.
    pub fn run_benches(
        &mut self,
        label: &str,
        root: &Path,
        requests: &[BenchRunRequest],
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        self.ensure_requests_supported(root, requests)?;

        log(format!("Running marf benches for {label}"));

        let mut rows = Vec::new();
        for request in requests {
            let bench_name = request.kind.bench_name();
            let build_key = (root.to_path_buf(), bench_name.to_string());

            if !self.built_targets.contains(&build_key) {
                let overlay_changed = self
                    .overlay_changed_roots
                    .get(root)
                    .copied()
                    .unwrap_or(true);

                let can_reuse_cached_build =
                    self.keep_worktrees && self.is_cached_worktree_path(root) && !overlay_changed;

                if can_reuse_cached_build {
                    log(format!(
                        "[{label}] Reusing existing {bench_name} build artifacts (worktree unchanged)"
                    ));
                } else {
                    self.build_bench_profile(label, root, bench_name)?;
                }

                self.built_targets.insert(build_key);
            }

            rows.extend(self.run_bench_case(label, root, request, output_format)?);
        }

        Ok(rows)
    }

    /// Build stackslib marf benchmark with bench profile.
    fn build_bench_profile(&self, label: &str, root: &Path, bench_name: &str) -> Result<()> {
        log(format!(
            "[{label}] Building {bench_name} bench with 'bench' profile"
        ));

        let cmd = build_stackslib_bench_profile_cmd(root, bench_name);
        run_checked(cmd, "failed to build marf bench profile")
    }

    /// Execute one benchmark case and parse summary rows from output.
    fn run_bench_case(
        &self,
        label: &str,
        root: &Path,
        request: &BenchRunRequest,
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        let bench = request.kind;
        let bench_name = bench.bench_name();
        let subcommand = bench.harness_subcommand();
        let target_label = subcommand.unwrap_or(bench_name);
        log(format!("[{label}] Running {target_label}"));

        let marf_output_mode = if output_format == OutputFormat::Raw {
            "raw"
        } else {
            "summary"
        };

        let mut cmd = run_stackslib_bench_cmd(root, bench_name, marf_output_mode);
        apply_bench_env_overrides(&mut cmd, &request.env);

        if let Some(subcommand) = subcommand {
            cmd.arg(subcommand);
        }

        let output = cmd
            .output()
            .with_context(|| format!("failed to launch cargo bench for {target_label}"))?;

        if output_format == OutputFormat::Raw {
            print_output(&output);
        }

        if !output.status.success() {
            if output_format != OutputFormat::Raw {
                print_output(&output);
            }
            bail!("benchmark failed for {label} ({target_label})");
        }

        let combined = combine_output_text(&output);
        Ok(extract_summary_lines(&combined))
    }

    /// Return true if the path is under the keep-worktrees cache root.
    fn is_cached_worktree_path(&self, path: &Path) -> bool {
        path.starts_with(keep_worktrees_root(&self.repo_root))
    }

    /// Ensure requested benchmark kinds are supported by the source tree at `root`.
    fn ensure_requests_supported(&self, root: &Path, requests: &[BenchRunRequest]) -> Result<()> {
        ensure_requests_supported_at(root, requests)
    }
}

/// Prepare a revision worktree for benchmarking: create (or reuse), overlay bench
/// files, patch Cargo.toml, and build. This function is [`Send`]-safe and can be
/// called from multiple threads concurrently for different revisions.
///
/// The returned [`PreparedWorktree`] should be registered with
/// [`Runner::register_prepared_worktree`] before running benchmarks.
pub fn prepare_worktree(
    repo_root: &Path,
    source_bench_dir: &Path,
    keep_worktrees: bool,
    label: &str,
    revision: &str,
    requests: &[BenchRunRequest],
) -> Result<PreparedWorktree> {
    let (path, temp_root) = create_worktree_at(repo_root, keep_worktrees, revision)?;

    ensure_requests_supported_at(&path, requests)?;
    let overlay_changed = overlay_bench_files(source_bench_dir, &path, requests)?;
    ensure_bench_target_at(&path.join(STACKSLIB_CARGO_TOML), requests)?;

    let is_cached_path = path.starts_with(keep_worktrees_root(repo_root));
    let mut built_benches = HashSet::new();
    for request in requests {
        let bench_name = request.kind.bench_name();
        if built_benches.contains(bench_name) {
            continue;
        }

        let can_reuse = keep_worktrees && is_cached_path && !overlay_changed;
        if can_reuse {
            log(format!(
                "[{label}] Reusing existing {bench_name} build artifacts (worktree unchanged)"
            ));
        } else {
            log(format!(
                "[{label}] Building {bench_name} bench with 'bench' profile"
            ));
            let cmd = build_stackslib_bench_profile_cmd(&path, bench_name);
            run_checked(cmd, "failed to build marf bench profile")?;
        }
        built_benches.insert(bench_name.to_string());
    }

    Ok(PreparedWorktree {
        path,
        temp_root,
        overlay_changed,
        built_benches,
    })
}

/// Create or reuse a git worktree for a revision.
/// Returns `(worktree_path, temp_dir_handle)`. The temp dir handle is `Some` only
/// for non-cached worktrees and must be kept alive for the worktree's lifetime.
fn create_worktree_at(
    repo_root: &Path,
    keep_worktrees: bool,
    revision: &str,
) -> Result<(PathBuf, Option<TempDir>)> {
    let revision_tag: String = sanitize_revision(revision).chars().take(40).collect();

    if keep_worktrees {
        let cache_root = keep_worktrees_root(repo_root);
        fs::create_dir_all(&cache_root)
            .with_context(|| format!("failed to create {}", cache_root.display()))?;
        let path = cache_root.join(format!("{WORKTREE_PREFIX}{revision_tag}"));

        if path.is_dir() {
            let is_registered = {
                let requested = normalize_worktree_path_for_compare(&path);
                list_worktree_paths(repo_root)?
                    .into_iter()
                    .map(|c| normalize_worktree_path_for_compare(&c))
                    .any(|c| c == requested)
            };
            if is_registered {
                log(format!(
                    "Reusing worktree for {revision} at {}",
                    path.display()
                ));
                return Ok((path, None));
            }

            log(format!(
                "Removing unregistered cached worktree dir: {}",
                path.display()
            ));
            fs::remove_dir_all(&path).with_context(|| {
                format!(
                    "failed to remove stale cached worktree dir {}",
                    path.display()
                )
            })?;
        }

        log(format!(
            "Creating worktree for {revision} at {}",
            path.display()
        ));
        add_detached_worktree(repo_root, &path, revision)?;
        return Ok((path, None));
    }

    let temp_root = TempBuilder::new()
        .prefix(&format!(
            "{WORKTREE_PREFIX}{}-",
            sanitize_revision(revision)
        ))
        .tempdir()
        .context("failed to create temporary directory for worktree")?;
    let short_tag: String = revision_tag.chars().take(12).collect();
    let path = temp_root
        .path()
        .join(format!("{WORKTREE_PREFIX}{short_tag}"));

    log(format!(
        "Creating worktree for {revision} at {}",
        path.display()
    ));
    add_detached_worktree(repo_root, &path, revision)?;
    Ok((path, Some(temp_root)))
}

/// Overlay benchmark source files from the current tree into a worktree root.
fn overlay_bench_files(
    source_bench_dir: &Path,
    root: &Path,
    requests: &[BenchRunRequest],
) -> Result<bool> {
    let mut changed = false;

    if requests
        .iter()
        .any(|request| request.kind.bench_name() == "marf")
    {
        let dest = root.join(SRC_BENCH_DIR);
        fs::create_dir_all(&dest)
            .with_context(|| format!("failed to create {}", dest.display()))?;

        for name in MARF_BENCH_FILES {
            let src = source_bench_dir.join(name);
            let dst = dest.join(name);
            changed |= copy_if_different(&src, &dst)?;
        }
    }

    Ok(changed)
}

/// Ensure required benchmark target/dependencies exist in a Cargo.toml.
fn ensure_bench_target_at(cargo_toml: &Path, requests: &[BenchRunRequest]) -> Result<()> {
    let mut text = fs::read_to_string(cargo_toml)
        .with_context(|| format!("failed to read {}", cargo_toml.display()))?;

    let mut updated = false;

    let wants_marf = requests
        .iter()
        .any(|request| request.kind.bench_name() == "marf");
    if wants_marf && !text.contains("name = \"marf\"") {
        text.push_str(
            "\n[[bench]]\nname = \"marf\"\nharness = false\npath = \"benches/marf/main.rs\"\n",
        );
        updated = true;
    }

    if !text.contains("tikv-jemallocator") {
        text.push_str(
            "\n# Included for profiling/benchmark entrypoints\n[target.'cfg(not(any(target_os = \"macos\", target_os=\"windows\", target_arch = \"arm\")))'.dev-dependencies]\ntikv-jemallocator = { workspace = true }\n",
        );
        updated = true;
    }

    if updated {
        fs::write(cargo_toml, text)
            .with_context(|| format!("failed to update {}", cargo_toml.display()))?;
    }

    Ok(())
}

/// Ensure requested benchmark kinds are supported by the source tree at `root`.
fn ensure_requests_supported_at(root: &Path, requests: &[BenchRunRequest]) -> Result<()> {
    if requests
        .iter()
        .any(|request| matches!(request.kind, BenchKind::Patch))
        && !supports_patch_nodes(root)?
    {
        bail!(
            "patch benchmark requested but revision does not support TrieNodePatch/TrieNodeID::Patch: {}",
            root.display()
        );
    }

    Ok(())
}

/// Normalize worktree path shape for stable equality checks across symlinked temp roots.
fn normalize_worktree_path_for_compare(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Return true if this checkout includes TrieNodePatch support in node definitions.
fn supports_patch_nodes(root: &Path) -> Result<bool> {
    let output = Command::new("git")
        .current_dir(root)
        .arg("merge-base")
        .arg("--is-ancestor")
        .arg(PATCH_SUPPORT_INTRO_COMMIT)
        .arg("HEAD")
        .output()
        .with_context(|| {
            format!(
                "failed to check patch benchmark support ancestry in {}",
                root.display()
            )
        })?;

    let fallback_supported = supports_patch_nodes_via_source_scan(root)?;

    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ if fallback_supported => Ok(true),
        _ => bail!(
            "failed to evaluate patch support ancestry at {} (this can happen in shallow or history-rewritten clones), and source fallback did not detect patch support: {}",
            root.display(),
            combine_output_text(&output)
        ),
    }
}

/// Return true if node definitions in this checkout include patch-node symbols.
fn supports_patch_nodes_via_source_scan(root: &Path) -> Result<bool> {
    let node_rs_path = root.join("stackslib/src/chainstate/stacks/index/node.rs");
    if !node_rs_path.is_file() {
        return Ok(false);
    }

    let contents = fs::read_to_string(&node_rs_path)
        .with_context(|| format!("failed to read {}", node_rs_path.display()))?;

    Ok(contents.contains("TrieNodePatch") && contents.contains("TrieNodeID::Patch"))
}

impl Drop for Runner {
    /// Remove temporary worktrees and prune stale registrations on drop.
    fn drop(&mut self) {
        if !self.keep_worktrees {
            for worktree in self.worktrees.drain(..) {
                let path = worktree.path;
                if !path.is_dir() {
                    continue;
                }

                log(format!("Removing worktree: {}", path.display()));
                let _ = remove_worktree_force(&self.repo_root, &path);
            }
        }

        let _ = prune_worktrees_now(&self.repo_root);
    }
}

/// Remove stale marf-bench git worktrees from the repository.
pub fn cleanup_stale_marf_bench_worktrees(repo_root: &Path) -> Result<()> {
    let stale_paths = list_stale_marf_bench_worktrees(repo_root)?;

    for stale in stale_paths {
        log(format!(
            "Removing stale marf-bench worktree: {}",
            stale.display()
        ));
        let _ = remove_worktree_force(repo_root, &stale);
    }

    let _ = prune_worktrees_now(repo_root);

    Ok(())
}

/// List stale marf-bench git worktree paths discovered by `git worktree list`.
pub fn list_stale_marf_bench_worktrees(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let stale_paths: Vec<PathBuf> = list_worktree_paths(repo_root)?
        .into_iter()
        .filter(|path| is_marf_bench_worktree_path(path, repo_root))
        .collect();

    Ok(stale_paths)
}

/// Return keep-worktrees cache root if it currently exists.
pub fn cached_keep_worktrees_root_if_exists(repo_root: &Path) -> Option<PathBuf> {
    let root = keep_worktrees_root(repo_root);
    if root.exists() { Some(root) } else { None }
}

/// List orphan temporary marf-bench worktree directories in the temp dir.
pub fn list_orphan_temp_worktree_dirs() -> Result<Vec<PathBuf>> {
    let temp_root = std::env::temp_dir();
    let entries = fs::read_dir(&temp_root)
        .with_context(|| format!("failed to read temp dir {}", temp_root.display()))?;

    let mut paths = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if !name.starts_with(WORKTREE_PREFIX) {
            continue;
        }

        if name == WORKTREE_CACHE_DIR {
            continue;
        }

        paths.push(path);
    }

    Ok(paths)
}

/// Remove persisted keep-worktrees cache directory.
pub fn cleanup_cached_keep_worktrees(repo_root: &Path) -> Result<bool> {
    let Some(root) = cached_keep_worktrees_root_if_exists(repo_root) else {
        return Ok(false);
    };

    log(format!(
        "Removing cached keep-worktrees root: {}",
        root.display()
    ));
    fs::remove_dir_all(&root).with_context(|| {
        format!(
            "failed to remove cached keep-worktrees root {}",
            root.display()
        )
    })?;
    Ok(true)
}

/// Remove orphan temporary marf-bench worktree directories.
pub fn cleanup_orphan_temp_worktree_dirs() -> Result<usize> {
    let orphan_paths = list_orphan_temp_worktree_dirs()?;

    let mut removed = 0usize;
    for path in orphan_paths {
        log(format!(
            "Removing orphan temp marf-bench dir: {}",
            path.display()
        ));
        if fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }

    Ok(removed)
}

/// Return true if the path matches marf-bench temporary worktree naming.
fn is_marf_bench_worktree_path(path: &Path, repo_root: &Path) -> bool {
    if path.starts_with(keep_worktrees_root(repo_root)) {
        return false;
    }

    let under_cache_dir = path
        .ancestors()
        .filter_map(|ancestor| ancestor.file_name().and_then(|name| name.to_str()))
        .any(|name| name == WORKTREE_CACHE_DIR);
    if under_cache_dir {
        return false;
    }

    let name_matches = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with(WORKTREE_PREFIX))
        .unwrap_or(false);

    let has_prefixed_ancestor = path
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .filter_map(|ancestor| ancestor.file_name().and_then(|name| name.to_str()))
        .any(|name| name.starts_with(WORKTREE_PREFIX));

    name_matches && has_prefixed_ancestor
}

/// Compute per-repository keep-worktrees cache root path.
fn keep_worktrees_root(repo_root: &Path) -> PathBuf {
    let repo_tag: String = sanitize_revision(&repo_root.to_string_lossy())
        .chars()
        .take(96)
        .collect();
    std::env::temp_dir().join(WORKTREE_CACHE_DIR).join(repo_tag)
}

/// Copy source file to destination only when file content differs.
fn copy_if_different(src: &Path, dst: &Path) -> Result<bool> {
    let should_copy = if dst.is_file() {
        let src_bytes =
            fs::read(src).with_context(|| format!("failed to read {}", src.display()))?;
        let dst_bytes =
            fs::read(dst).with_context(|| format!("failed to read {}", dst.display()))?;
        src_bytes != dst_bytes
    } else {
        true
    };

    if !should_copy {
        return Ok(false);
    }

    fs::copy(src, dst)
        .with_context(|| format!("failed to copy {} -> {}", src.display(), dst.display()))?;
    Ok(true)
}

/// Apply benchmark env override settings to a spawned cargo command.
fn apply_bench_env_overrides(cmd: &mut Command, env: &BenchEnvOverrides) {
    if let Some(iters) = env.iters {
        cmd.env("ITERS", iters.to_string());
    }
    if let Some(rounds) = env.rounds {
        cmd.env("ROUNDS", rounds.to_string());
    }
    if let Some(chain_len) = env.chain_len {
        cmd.env("CHAIN_LEN", chain_len.to_string());
    }
    if let Some(write_depths) = &env.write_depths {
        cmd.env("WRITE_DEPTHS", write_depths);
    }
    if let Some(key_updates) = env.key_updates {
        cmd.env("KEY_UPDATES", key_updates.to_string());
    }
    if let Some(sqlite_wal_autocheckpoint) = env.sqlite_wal_autocheckpoint {
        cmd.env(
            "SQLITE_WAL_AUTOCHECKPOINT",
            sqlite_wal_autocheckpoint.to_string(),
        );
    }
    if let Some(sqlite_wal_checkpoint_mode) = &env.sqlite_wal_checkpoint_mode {
        cmd.env("SQLITE_WAL_CHECKPOINT_MODE", sqlite_wal_checkpoint_mode);
    }
    if let Some(read_proofs) = env.read_proofs {
        cmd.env("READ_PROOFS", if read_proofs { "1" } else { "0" });
    }
    if let Some(keys_per_block) = env.keys_per_block {
        cmd.env("KEYS_PER_BLOCK", keys_per_block.to_string());
    }
    if let Some(depths) = &env.depths {
        cmd.env("DEPTHS", depths);
    }
    if let Some(cache_strategies) = &env.cache_strategies {
        cmd.env("CACHE_STRATEGIES", cache_strategies);
    }
    if let Some(key_search_max_tries) = env.key_search_max_tries {
        cmd.env("KEY_SEARCH_MAX_TRIES", key_search_max_tries.to_string());
    }
    if let Some(node_types) = &env.node_types {
        cmd.env("NODE_TYPES", node_types);
    }
    if let Some(ptr_states) = &env.ptr_states {
        cmd.env("PTR_STATES", ptr_states);
    }
    if let Some(patch_diffs) = &env.patch_diffs {
        cmd.env("PATCH_DIFFS", patch_diffs);
    }
}

/// Build stackslib marf bench target with bench profile.
fn build_stackslib_bench_profile_cmd(root: &Path, bench_name: &str) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root)
        .arg("build")
        .arg("--profile")
        .arg("bench")
        .arg("-p")
        .arg("stackslib")
        .arg("--bench")
        .arg(bench_name);
    cmd
}

/// Run stackslib marf bench for a specific bench subcommand and output mode.
fn run_stackslib_bench_cmd(root: &Path, bench_name: &str, output_mode: &str) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root)
        .arg("bench")
        .arg("-p")
        .arg("stackslib")
        .arg("--bench")
        .arg(bench_name)
        .arg("--")
        .env("OUTPUT_FORMAT", output_mode);
    cmd
}
