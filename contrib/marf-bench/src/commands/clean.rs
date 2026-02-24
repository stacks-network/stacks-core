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

use anyhow::Result;
use clap::Args;

use crate::git::current_repo_root;
use crate::runner::{
    cached_keep_worktrees_root_if_exists, cleanup_cached_keep_worktrees,
    cleanup_orphan_temp_worktree_dirs, cleanup_stale_marf_bench_worktrees,
    list_orphan_temp_worktree_dirs, list_stale_marf_bench_worktrees,
};
use crate::util::log;

/// Arguments for the `clean` command.
#[derive(Debug, Args)]
pub struct CleanArgs {
    /// Show what would be removed without deleting anything.
    #[arg(long)]
    dry_run: bool,
}

/// Remove marf-bench temporary resources or print dry-run plan.
pub fn run_command(args: CleanArgs) -> Result<()> {
    let repo_root = current_repo_root()?;

    if args.dry_run {
        let stale_worktrees = list_stale_marf_bench_worktrees(&repo_root)?;
        let cached_root = cached_keep_worktrees_root_if_exists(&repo_root);
        let orphan_temp_dirs = list_orphan_temp_worktree_dirs()?;

        for path in &stale_worktrees {
            log(&format!(
                "[dry-run] would remove stale worktree: {}",
                path.display()
            ));
        }
        if let Some(path) = &cached_root {
            log(&format!(
                "[dry-run] would remove cached keep-worktrees root: {}",
                path.display()
            ));
        }
        for path in &orphan_temp_dirs {
            log(&format!(
                "[dry-run] would remove orphan temp marf-bench dir: {}",
                path.display()
            ));
        }

        log(&format!(
            "Dry-run complete (stale_worktrees={}, cached_keep_root_present={}, orphan_temp_dirs={})",
            stale_worktrees.len(),
            cached_root.is_some(),
            orphan_temp_dirs.len()
        ));
        return Ok(());
    }

    cleanup_stale_marf_bench_worktrees(&repo_root)?;
    let removed_cache_root = cleanup_cached_keep_worktrees(&repo_root)?;
    let removed_orphan_temp_dirs = cleanup_orphan_temp_worktree_dirs()?;

    log(&format!(
        "Clean complete (removed_cache_root={removed_cache_root}, removed_orphan_temp_dirs={removed_orphan_temp_dirs})"
    ));

    Ok(())
}
