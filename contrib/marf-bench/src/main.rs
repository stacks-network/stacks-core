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

mod commands;
mod git;
mod report;
mod runner;
mod table;
mod tsv;
mod util;

use std::panic;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use tempfile::Builder as TempBuilder;

use crate::git::current_repo_root;
use crate::runner::cleanup_stale_marf_bench_worktrees;

/// Output formatting mode for benchmark reporting.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Summary,
    Raw,
    Tsv,
}

/// Supported marf benchmark targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
enum BenchKind {
    Primitives,
    Read,
    Write,
    Patch,
    BlockCommit,
}

impl BenchKind {
    /// Return Cargo bench target name for this benchmark kind.
    fn bench_name(self) -> &'static str {
        match self {
            Self::Primitives | Self::Read | Self::Write | Self::Patch | Self::BlockCommit => "marf",
        }
    }

    /// Convert a benchmark kind into the harness subcommand argument when needed.
    fn harness_subcommand(self) -> Option<&'static str> {
        match self {
            Self::Primitives => Some("primitives"),
            Self::Read => Some("read"),
            Self::Write => Some("write"),
            Self::Patch => Some("patch"),
            Self::BlockCommit => Some("block-commit"),
        }
    }

    /// Return the benchmark-specific source file(s) needed for this kind.
    /// Shared infrastructure files (`main.rs`, `common.rs`, `utils.rs`,
    /// `allocator.rs`) are always overlaid and not listed here.
    fn bench_source_files(self) -> &'static [&'static str] {
        match self {
            Self::Primitives => &["primitives.rs"],
            Self::Read => &["read.rs"],
            Self::Write => &["write.rs"],
            Self::Patch => &["patch.rs"],
            Self::BlockCommit => &["block_commit.rs"],
        }
    }

    /// Return the module name used in `mod` declarations for this benchmark.
    fn module_name(self) -> &'static str {
        match self {
            Self::Primitives => "primitives",
            Self::Read => "read",
            Self::Write => "write",
            Self::Patch => "patch",
            Self::BlockCommit => "block_commit",
        }
    }
}

#[derive(Debug, Parser)]
/// Run MARF benches in the current tree or compare revisions via temporary worktrees.
#[command(name = "marf-bench")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Top-level CLI commands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Run one benchmark target in the current working tree.
    Run(commands::run::RunArgs),
    /// Compare benchmark results between base and target revisions.
    Bench(commands::bench::BenchArgs),
    /// Remove marf-bench temporary worktrees and cached directories.
    Clean(commands::clean::CleanArgs),
}

/// Parse CLI args and dispatch the selected command.
fn main() -> Result<()> {
    let cli = Cli::parse();
    install_cleanup_hooks(current_repo_root().ok())?;
    match cli.command {
        Commands::Run(args) => commands::run::run_command(args),
        Commands::Bench(args) => commands::bench::run_command(args),
        Commands::Clean(args) => commands::clean::run_command(args),
    }
}

/// Install Ctrl-C and panic hooks that clean up marf-bench worktrees.
fn install_cleanup_hooks(repo_root: Option<PathBuf>) -> Result<()> {
    let Some(repo_root) = repo_root else {
        return Ok(());
    };

    let cleaned = Arc::new(AtomicBool::new(false));

    {
        let repo_root = repo_root.clone();
        let cleaned = Arc::clone(&cleaned);
        ctrlc::set_handler(move || {
            if !cleaned.swap(true, Ordering::SeqCst) {
                let _ = cleanup_stale_marf_bench_worktrees(&repo_root);
            }
            std::process::exit(130);
        })?;
    }

    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        if !cleaned.swap(true, Ordering::SeqCst) {
            let _ = cleanup_stale_marf_bench_worktrees(&repo_root);
        }
        previous_hook(panic_info);
    }));

    Ok(())
}
