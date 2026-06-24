// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use tempfile::TempDir;

#[derive(Debug)]
pub struct FileDeltaReport {
    pub path: PathBuf,
    pub size_delta_bytes: i64,
    pub was_modified: bool,
}

#[derive(Debug)]
pub struct ShadowDirDeltaReport {
    pub net_growth_bytes: i64,
    pub estimated_bytes_written: u64,
    pub file_reports: Vec<FileDeltaReport>,
}

#[derive(Debug)]
pub struct ShadowDir {
    /// `None` in passthrough mode (no CoW copy was taken; `root == source`).
    /// `Some(TempDir)` in normal mode, where dropping the temp dir deletes
    /// the CoW copy on cleanup.
    _tmp: Option<TempDir>,
    source: PathBuf,
    root: PathBuf,
    watched_files: Vec<PathBuf>,
}

impl AsRef<Path> for ShadowDir {
    fn as_ref(&self) -> &Path {
        &self.root
    }
}

impl ShadowDir {
    /// Prefix for temporary shadow directories.
    const TMP_PREFIX: &'static str = "stacks-bench-";

    /// Construct a passthrough `ShadowDir` that operates **directly on the
    /// source chainstate without taking a CoW copy**. Writes during a bench
    /// run will mutate the source data permanently — intended only for
    /// ephemeral-VM setups where the host has already CoW-copied the disk
    /// image attached to the VM, so an additional in-VM copy would add a
    /// redundant CoW layer.
    ///
    /// In passthrough mode, [`Self::calculate_storage_delta`] fails (there's
    /// no base to compare against), [`Self::is_passthrough`] returns `true`,
    /// and dropping the `ShadowDir` is a no-op (the source dir is left
    /// intact).
    pub fn passthrough<P: AsRef<Path>>(source: P) -> Result<Self> {
        let source = source.as_ref();
        let canonical = source.canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize source dir {} for passthrough",
                source.display()
            )
        })?;
        Ok(Self {
            _tmp: None,
            source: canonical.clone(),
            root: canonical,
            watched_files: Vec::new(),
        })
    }

    pub fn is_passthrough(&self) -> bool {
        self._tmp.is_none()
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn watch_file<P: AsRef<Path>>(&mut self, path: P) {
        self.watched_files.push(path.as_ref().to_path_buf());
    }

    /// Keep the temp directory instead of deleting it on drop, consuming this
    /// [`ShadowDir`] and returning its path. Returns `None` in passthrough
    /// mode (there is no temp dir to keep).
    pub fn keep(self) -> Option<PathBuf> {
        self._tmp.map(|t| t.keep())
    }

    /// Calculates the storage delta between a base directory and a shadow directory.
    /// Returns a detailed report.
    pub fn calculate_storage_delta(&self) -> Result<ShadowDirDeltaReport> {
        if self.is_passthrough() {
            bail!(
                "storage-delta is not supported in passthrough mode \
                 (`--dangerous-no-chainstate-copy`); there is no base directory to compare against"
            );
        }
        let base_root = &self.source;
        let shadow_root = &self.root;
        let mut net_growth: i64 = 0;
        let mut estimated_written: u64 = 0;
        let mut file_reports = Vec::new();

        // If watched files are defined, only check them, avoiding a full recursive directory walk
        // which is slow on large chainstates.
        if !self.watched_files.is_empty() {
            for relative_path in &self.watched_files {
                let shadow_path = shadow_root.join(relative_path);

                // We only care if the file exists in the shadow dir (it's the active state)
                if let Ok(shadow_meta) = fs::metadata(&shadow_path) {
                    let shadow_len = shadow_meta.len();
                    let shadow_modified = shadow_meta.modified()?;

                    let base_path = base_root.join(relative_path);

                    if let Ok(base_meta) = fs::metadata(&base_path) {
                        let base_len = base_meta.len();
                        let base_modified = base_meta.modified()?;

                        let diff = (shadow_len as i64) - (base_len as i64);
                        net_growth += diff;

                        // If modified time changed, the file was touched
                        let was_modified = base_modified != shadow_modified;
                        if was_modified {
                            // Count positive growth as written data
                            if diff > 0 {
                                estimated_written += diff as u64;
                            }
                        }

                        if was_modified || diff != 0 {
                            file_reports.push(FileDeltaReport {
                                path: relative_path.clone(),
                                size_delta_bytes: diff,
                                was_modified,
                            });
                        }
                    } else {
                        // New file created (or didn't exist in source)
                        net_growth += shadow_len as i64;
                        estimated_written += shadow_len;
                        file_reports.push(FileDeltaReport {
                            path: relative_path.clone(),
                            size_delta_bytes: shadow_len as i64,
                            was_modified: true,
                        });
                    }
                }
            }
            return Ok(ShadowDirDeltaReport {
                net_growth_bytes: net_growth,
                estimated_bytes_written: estimated_written,
                file_reports,
            });
        }

        // Use a stack for recursive directory traversal
        let mut stack = vec![shadow_root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    stack.push(path);
                } else {
                    let shadow_meta = entry.metadata()?;
                    let shadow_len = shadow_meta.len();
                    let shadow_modified = shadow_meta.modified()?;

                    // Calculate relative path to find base file
                    let relative_path = path
                        .strip_prefix(shadow_root)
                        .context("Failed to determine relative path")?
                        .to_path_buf();
                    let base_path = base_root.join(&relative_path);

                    if base_path.exists() {
                        let base_meta = fs::metadata(&base_path)?;
                        let base_len = base_meta.len();
                        let base_modified = base_meta.modified()?;

                        let diff = (shadow_len as i64) - (base_len as i64);
                        net_growth += diff;

                        // If modified time changed, the file was touched
                        let was_modified = base_modified != shadow_modified;
                        if was_modified {
                            // Count positive growth as written data
                            if diff > 0 {
                                estimated_written += diff as u64;
                            }
                        }

                        if was_modified || diff != 0 {
                            file_reports.push(FileDeltaReport {
                                path: relative_path,
                                size_delta_bytes: diff,
                                was_modified,
                            });
                        }
                    } else {
                        // New file created
                        net_growth += shadow_len as i64;
                        estimated_written += shadow_len;
                        file_reports.push(FileDeltaReport {
                            path: relative_path,
                            size_delta_bytes: shadow_len as i64,
                            was_modified: true,
                        });
                    }
                }
            }
        }

        Ok(ShadowDirDeltaReport {
            net_growth_bytes: net_growth,
            estimated_bytes_written: estimated_written,
            file_reports,
        })
    }
}

// Builder for ShadowDir using `ignore` glob filtering
#[derive(Debug)]
pub struct ShadowDirBuilder {
    source: PathBuf,
    globs: Vec<String>,
    allow_plain_copy: bool, // false => strict reflink
    watch_files: Vec<PathBuf>,
    /// Parent directory under which the uniquely-named shadow tempdir is
    /// created. `None` falls back to `source.parent()` for reflink locality;
    /// `Some` lets sandboxed callers redirect creation to a writable root.
    parent_dir: Option<PathBuf>,
}

impl ShadowDirBuilder {
    pub fn new<P: Into<PathBuf>>(source: P) -> Self {
        Self {
            source: source.into(),
            globs: Vec::new(),
            allow_plain_copy: false,
            watch_files: Vec::new(),
            parent_dir: None,
        }
    }

    /// Override the directory under which the shadow tempdir is created.
    /// When unset (the default), the tempdir is created next to the source
    /// directory to maximize reflink locality.
    pub fn parent_dir<P: Into<PathBuf>>(mut self, parent: P) -> Self {
        self.parent_dir = Some(parent.into());
        self
    }

    // Add a glob relative to the source root (e.g., "burnchain/**", "chainstate/**")
    pub fn glob<S: AsRef<str>>(mut self, pattern: S) -> Self {
        self.globs.push(pattern.as_ref().to_owned());
        self
    }

    // Allow plain copies (disables strict reflink requirement)
    pub fn allow_plain_copy(mut self) -> Self {
        self.allow_plain_copy = true;
        self
    }

    /// Watch a specific file for changes (relative path from source)
    pub fn watch<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.watch_files.push(path.as_ref().to_path_buf());
        self
    }

    // Execute the copy and return the ShadowDir
    pub fn copy(self) -> Result<ShadowDir> {
        let source = self.source;

        // Choose the parent under which the shadow tempdir is created:
        // caller override wins, otherwise fall back to `source.parent()` to
        // maximize reflink locality (same filesystem).
        let parent: &Path = self
            .parent_dir
            .as_deref()
            .unwrap_or_else(|| source.parent().unwrap_or_else(|| Path::new("/")));

        // Reject overrides that resolve inside the source tree. The
        // `WalkBuilder` below walks the source, and if the shadow tempdir is
        // also under `source`, the walker discovers its own destination and
        // tries to copy it into itself — recursively, until inode/disk
        // exhaustion. Canonicalize both paths so symlinks don't sneak past.
        if let Some(parent_override) = self.parent_dir.as_deref()
            && parent_override.exists()
        {
            let canon_source = fs::canonicalize(&source).with_context(|| {
                format!("failed to canonicalize source dir {}", source.display())
            })?;
            let canon_parent = fs::canonicalize(parent_override).with_context(|| {
                format!(
                    "failed to canonicalize shadow_dir_root {}",
                    parent_override.display()
                )
            })?;
            if canon_parent.starts_with(&canon_source) {
                bail!(
                    "shadow_dir_root ({}) resolves inside the source tree ({}); \
                     choose a parent directory outside the source dir to avoid recursive copying",
                    canon_parent.display(),
                    canon_source.display(),
                );
            }
        }

        let tmp = tempfile::Builder::new()
            .prefix(ShadowDir::TMP_PREFIX)
            .tempdir_in(parent)
            .with_context(|| format!("failed to create tempdir under {}", parent.display()))?;
        let root = tmp.path().to_path_buf();

        // Strict mode: refuse if not same device
        #[cfg(unix)]
        if !self.allow_plain_copy {
            use std::os::unix::fs::MetadataExt;
            let src_dev = fs::metadata(&source)?.dev();
            let dst_dev = fs::metadata(&root)?.dev();
            if src_dev != dst_dev {
                use anyhow::bail;

                bail!(
                    "shadow tempdir ({}) is on a different filesystem than source ({}); \
                     reflinks will fail (use allow_plain_copy() to bypass)",
                    root.display(),
                    source.display()
                );
            }
        }

        // Build whitelist overrides (default: include everything)
        let mut ob = OverrideBuilder::new(&source);
        if self.globs.is_empty() {
            ob.add("**")?;
        } else {
            for pat in &self.globs {
                ob.add(pat)?;
            }
        }
        let overrides = ob.build()?;

        // Walk with ignore
        let walker = WalkBuilder::new(&source)
            .follow_links(false)
            .standard_filters(false)
            .hidden(false)
            .parents(false)
            .overrides(overrides)
            .build();

        fs::create_dir_all(&root).with_context(|| format!("mkdir {}", root.display()))?;

        for dent in walker {
            let dent = dent.context("Walk error")?;
            let path = dent.path();
            if path == source {
                continue;
            }

            // Determine type
            let ft = if let Some(t) = dent.file_type() {
                t
            } else {
                fs::metadata(path)
                    .map(|m| m.file_type())
                    .with_context(|| format!("stat {}", path.display()))?
            };

            let rel = path
                .strip_prefix(&source)
                .with_context(|| format!("strip_prefix {}", path.display()))?;
            let out = root.join(rel);

            if ft.is_dir() {
                fs::create_dir_all(&out).with_context(|| format!("mkdir {}", out.display()))?;
                continue;
            }

            #[cfg(unix)]
            if ft.is_symlink() {
                use anyhow::bail;

                bail!("Encountered symlink at {}, refuse to clone", path.display());
            }

            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir {}", parent.display()))?;
            }

            if ft.is_file() {
                if self.allow_plain_copy {
                    fs::copy(path, &out)
                        .with_context(|| format!("copy {} -> {}", path.display(), out.display()))?;
                } else {
                    reflink_copy::reflink(path, &out).with_context(|| {
                        format!(
                            "reflink {} -> {} failed (use allow_plain_copy() to fallback)",
                            path.display(),
                            out.display()
                        )
                    })?;
                }
            }
        }

        Ok(ShadowDir {
            _tmp: Some(tmp),
            root,
            source,
            watched_files: self.watch_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `shadow_dir_root` pointing inside the source tree must be rejected —
    /// otherwise the `WalkBuilder` discovers the shadow tempdir as a copy
    /// candidate and recurses into itself.
    #[test]
    fn rejects_parent_dir_inside_source() {
        let source_tmp = tempfile::tempdir().unwrap();
        let source = source_tmp.path();
        // Pretend the source has a `chainstate/vm` subdir; aim the override
        // at it so the resulting tempdir would land inside the source tree.
        let inner = source.join("chainstate").join("vm");
        fs::create_dir_all(&inner).unwrap();

        let err = ShadowDirBuilder::new(source)
            .parent_dir(&inner)
            .copy()
            .expect_err("expected rejection for parent_dir inside source");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("inside the source tree"),
            "unexpected error message: {msg}"
        );
    }

    /// Same-path is also "inside" — `parent_dir == source` must reject.
    #[test]
    fn rejects_parent_dir_equal_to_source() {
        let source_tmp = tempfile::tempdir().unwrap();
        let source = source_tmp.path();

        let err = ShadowDirBuilder::new(source)
            .parent_dir(source)
            .copy()
            .expect_err("expected rejection for parent_dir == source");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("inside the source tree"),
            "unexpected error message: {msg}"
        );
    }
}
