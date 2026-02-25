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
use crate::git::current_repo_root;
use crate::report::{print_repeated_run_stats, print_single_run};
use crate::runner::Runner;
use crate::util::log;

/// Arguments for the `run` command.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Select output format for benchmark results.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary, global = true)]
    output_format: OutputFormat,

    /// Repeat the full benchmark run N times and emit repeat statistics.
    #[arg(long, global = true)]
    repeats: Option<usize>,

    /// High-jitter threshold for run repeats as spread/median(total_ms) percentage.
    #[arg(long, default_value_t = 30.0, global = true, requires = "repeats")]
    repeat_jitter_threshold: f64,

    /// Benchmark target and optional benchmark-specific overrides.
    #[command(subcommand)]
    target: BenchTarget,
}

/// Run a single benchmark target in the current working tree.
pub fn run_command(args: RunArgs) -> Result<()> {
    run_target(
        args.output_format,
        args.target,
        args.repeats,
        args.repeat_jitter_threshold,
    )
}

/// Execute the selected benchmark target and print its summary.
pub fn run_target(
    output_format: OutputFormat,
    target: BenchTarget,
    repeats: Option<usize>,
    repeat_jitter_threshold: f64,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut runner = Runner::new(repo_root.clone(), false)?;
    let requests = target.into_requests();
    let show_repeat_stats = repeats.is_some();
    let repeats = repeats.unwrap_or(1);

    if repeats == 0 {
        bail!("--repeats must be >= 1");
    }
    if !repeat_jitter_threshold.is_finite() || repeat_jitter_threshold < 0.0 {
        bail!("--repeat-jitter-threshold must be a finite value >= 0");
    }

    let mut repeated_rows = Vec::with_capacity(repeats);
    for repeat_ix in 0..repeats {
        if repeats > 1 {
            log(&format!("Repeat {}/{}", repeat_ix + 1, repeats));
        }
        let label = format!("current-working-tree#{}", repeat_ix + 1);
        let rows = runner.run_benches(&label, &repo_root, &requests, output_format)?;
        repeated_rows.push(rows);
    }

    let baseline_rows = repeated_rows
        .first()
        .expect("repeats should always produce at least one row set")
        .clone();
    print_single_run(output_format, &baseline_rows);

    if show_repeat_stats {
        log("Run repeat stats are computed directly across repeats (no baseline anchor)");
        print_repeated_run_stats(output_format, &repeated_rows, repeat_jitter_threshold);
    }

    log("Done");
    Ok(())
}
