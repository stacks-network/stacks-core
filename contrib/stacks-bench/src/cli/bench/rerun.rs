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

use anyhow::{Context, Result};
use console::style;

use super::run::{RunArgs, RunResult};
use crate::cli::common::{CliContext, ExecCommand, fmt_run_label, fmt_run_name_suffix};

#[derive(clap::Args, Debug)]
pub struct RerunArgs {
    /// The ID of the benchmark run to re-run. If omitted, an interactive
    /// selector is shown with all available runs.
    #[arg(long, alias = "id")]
    pub run_id: Option<u32>,
}

impl ExecCommand for RerunArgs {
    type Output = RunResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let app_db = ctx.app_db();

        let run_id: i32 = if let Some(id) = self.run_id {
            id as i32
        } else if !ctx.interactive() {
            anyhow::bail!("--run-id is required in non-interactive mode");
        } else {
            let runs = app_db.list_benchmark_runs().await?;
            if runs.is_empty() {
                anyhow::bail!("No benchmark runs found.");
            }

            let mut select = cliclack::select(format!(
                "Select a benchmark run to re-run ({} available)",
                runs.len()
            ));
            for run in &runs {
                select = select.item(run.id, format!("Run {}", run.id), fmt_run_label(run));
            }
            select.filter_mode().interact()?
        };

        let run = app_db
            .get_benchmark_run(run_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Benchmark run {} not found", run_id))?;

        if ctx.interactive() {
            cliclack::log::step(format!(
                "Re-running benchmark run {}{} started at {}",
                style(run.id).bold(),
                fmt_run_name_suffix(&run),
                run.start_time.format("%Y-%m-%d %H:%M:%S"),
            ))?;
        }

        let run_args: RunArgs = serde_json::from_str(&run.args_json).with_context(|| {
            format!(
                "Failed to deserialize args for run {} — stored JSON: {}",
                run.id, &run.args_json
            )
        })?;

        ExecCommand::exec(&run_args, ctx).await
    }
}
