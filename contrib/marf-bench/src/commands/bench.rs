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

use anyhow::{Result, bail};
use clap::Args;

use crate::OutputFormat;
use crate::commands::bench_target::BenchTarget;
use crate::git::{current_repo_root, resolve_base_revision, verify_revision};
use crate::report::{print_comparison, print_repeated_comparison_stats, print_single_run};
use crate::runner::Runner;
use crate::util::log;

/// Arguments for the `bench` command.
#[derive(Debug, Args)]
pub struct BenchArgs {
    /// Baseline git revision (commit/branch/tag); enables comparison mode.
    ///
    /// Special values: 'staged', 'merge-base:<upstream-ref>'.
    #[arg(long, global = true)]
    base: Option<String>,

    /// Target git revision (commit/branch/tag) for comparison mode.
    ///
    /// Defaults to current working tree.
    #[arg(long = "target", global = true)]
    target_revision: Option<String>,

    /// Select output format for benchmark results.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    output_format: OutputFormat,

    /// Repeat full base/target benchmark comparison N times and emit repeat statistics.
    #[arg(long, global = true)]
    repeats: Option<usize>,

    /// High-jitter threshold for repeat confidence summary spread in percentage points.
    #[arg(long, global = true, default_value_t = 30.0, requires = "repeats")]
    repeat_jitter_threshold: f64,

    /// Keep and reuse comparison worktrees across invocations to avoid cold rebuilds.
    #[arg(long, global = true)]
    keep_worktrees: bool,

    /// Benchmark target and optional benchmark-specific overrides.
    #[command(subcommand)]
    target: BenchTarget,
}

/// Run benchmark command in single-run or comparison mode.
pub fn run_command(args: BenchArgs) -> Result<()> {
    let requests = args.target.into_requests();
    let repo_root = current_repo_root()?;
    let repeats = args.repeats.unwrap_or(1);

    if repeats == 0 {
        bail!("--repeats must be >= 1");
    }
    if !args.repeat_jitter_threshold.is_finite() || args.repeat_jitter_threshold < 0.0 {
        bail!("--repeat-jitter-threshold must be a finite value >= 0");
    }

    let resolved_base = if let Some(base) = &args.base {
        Some(resolve_base_revision(&repo_root, base)?)
    } else {
        None
    };

    if resolved_base.is_none() && args.target_revision.is_some() {
        bail!("--target requires --base");
    }

    if resolved_base.is_none() && args.repeats.is_some() {
        bail!("--repeats requires --base");
    }

    if let Some((base_revision, base_display)) = resolved_base {
        if let Some(target) = &args.target_revision {
            verify_revision(&repo_root, target)?;
        }

        let base_label = format!("base:{base_display}");
        let target_label = if let Some(target) = &args.target_revision {
            format!("target:{target}")
        } else {
            "target:current-working-tree".to_string()
        };

        let mut repeated_rows = Vec::with_capacity(repeats);
        let mut runner = Runner::new(repo_root.clone(), args.keep_worktrees)?;

        for repeat_ix in 0..repeats {
            if repeats > 1 {
                log(&format!("Repeat {}/{}", repeat_ix + 1, repeats));
            }
            let base_rows = runner.run_revision_via_worktree(
                &base_label,
                &base_revision,
                &requests,
                args.output_format,
            )?;

            let target_rows = if let Some(target) = &args.target_revision {
                runner.run_revision_via_worktree(
                    &target_label,
                    target,
                    &requests,
                    args.output_format,
                )?
            } else {
                runner.run_current_tree(&target_label, &requests, args.output_format)?
            };

            repeated_rows.push((base_rows, target_rows));
        }

        let (base_rows, target_rows) = repeated_rows
            .first()
            .expect("repeats should always produce at least one row set");

        print_comparison(
            args.output_format,
            &base_label,
            &target_label,
            base_rows,
            target_rows,
        );

        if args.repeats.is_some() {
            print_repeated_comparison_stats(
                args.output_format,
                &base_label,
                &target_label,
                &repeated_rows,
                args.repeat_jitter_threshold,
            );
        }
    } else {
        let mut runner = Runner::new(repo_root.clone(), false)?;
        let rows =
            runner.run_current_tree("current-working-tree", &requests, args.output_format)?;
        print_single_run(args.output_format, &rows);
    }

    log("Done");
    Ok(())
}
