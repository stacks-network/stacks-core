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

use crate::OutputFormat;
use crate::commands::bench_target::BenchTarget;
use crate::git::current_repo_root;
use crate::report::print_single_run;
use crate::runner::Runner;
use crate::util::log;

/// Arguments for the `run` command.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Select output format for benchmark results.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    output_format: OutputFormat,

    /// Benchmark target and optional benchmark-specific overrides.
    #[command(subcommand)]
    target: BenchTarget,
}

/// Run a single benchmark target in the current working tree.
pub fn run_command(args: RunArgs) -> Result<()> {
    run_target(args.output_format, args.target)
}

/// Execute the selected benchmark target and print its summary.
pub fn run_target(output_format: OutputFormat, target: BenchTarget) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut runner = Runner::new(repo_root.clone(), false)?;
    let requests = target.into_requests();
    let rows = runner.run_benches("current-working-tree", &repo_root, &requests, output_format)?;
    print_single_run(output_format, &rows);
    log("Done");
    Ok(())
}
