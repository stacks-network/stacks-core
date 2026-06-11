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

use anyhow::{Result, bail};
use console::style;

use crate::cli::common::{
    CliContext, ExecCommand, fmt_run_label, fmt_run_name_suffix, run_db_cleanup,
};
use crate::commands::bench::remove::{self, RemoveResult};

#[derive(clap::Args, Debug)]
pub struct RemoveArgs {
    /// The ID of the benchmark run(s) to delete. If omitted, an interactive
    /// selector is shown with all available runs.
    #[arg(long, alias = "id")]
    pub run_id: Option<Vec<u32>>,

    /// Skip the confirmation prompt.
    #[arg(long, short = 'y', default_value_t = false)]
    pub yes: bool,
}

impl ExecCommand for RemoveArgs {
    type Output = RemoveResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let interactive = ctx.interactive();
        let mut app_db = ctx.app_db();

        // Resolve the set of run IDs to delete
        let run_ids: Vec<i32> = if let Some(ids) = &self.run_id {
            ids.iter().map(|&id| id as i32).collect()
        } else if !interactive {
            bail!("--run-id is required in non-interactive mode");
        } else {
            let runs = app_db.list_benchmark_runs().await?;
            if runs.is_empty() {
                cliclack::log::info("No benchmark runs found.")?;
                return Ok(RemoveResult {
                    deleted_run_ids: vec![],
                    message: "No benchmark runs found.".into(),
                });
            }

            let mut select = cliclack::multiselect(format!(
                "Select benchmark runs to delete ({} available)",
                runs.len()
            ));
            for run in &runs {
                select = select.item(run.id, format!("Run {}", run.id), fmt_run_label(run));
            }
            let chosen: Vec<i32> = select.filter_mode().interact()?;
            if chosen.is_empty() {
                cliclack::log::info("No runs selected.")?;
                return Ok(RemoveResult {
                    deleted_run_ids: vec![],
                    message: "No runs selected.".into(),
                });
            }
            chosen
        };

        // Validate runs exist
        let mut runs = Vec::with_capacity(run_ids.len());
        for &id in &run_ids {
            match app_db.get_benchmark_run(id).await? {
                Some(r) => runs.push(r),
                None => bail!("Benchmark run {} not found", id),
            }
        }

        // Interactive confirmation
        if interactive {
            for run in &runs {
                cliclack::log::step(format!(
                    "Run {}{} started at {}",
                    style(run.id).bold(),
                    fmt_run_name_suffix(run),
                    run.start_time.format("%Y-%m-%d %H:%M:%S"),
                ))?;
            }

            if !self.yes {
                let label = if runs.len() == 1 {
                    format!(
                        "Delete benchmark run {} and all associated data?",
                        runs[0].id
                    )
                } else {
                    format!(
                        "Delete {} benchmark runs and all associated data?",
                        runs.len()
                    )
                };
                if !cliclack::confirm(label).interact()? {
                    cliclack::log::info("Aborted.")?;
                    return Ok(RemoveResult {
                        deleted_run_ids: vec![],
                        message: "Aborted.".into(),
                    });
                }
            }
        }

        // Delete — non-interactive delegates entirely; interactive shows spinners
        if !interactive {
            return remove::delete_benchmark_runs(&mut app_db, &run_ids, true).await;
        }

        let multi = cliclack::multi_progress(format!(
            "Deleting {} benchmark run{}",
            runs.len(),
            if runs.len() == 1 { "" } else { "s" }
        ));

        for run in &runs {
            let spinner = multi.add(cliclack::spinner());
            spinner.start(format!("Deleting run {}…", run.id));
            app_db.delete_benchmark_run(run.id).await?;
            spinner.stop(fmt_success!("Run {} deleted", run.id));
        }

        multi.stop();

        run_db_cleanup(app_db, false).await?;

        Ok(RemoveResult {
            message: format!("{} benchmark run(s) deleted", run_ids.len()),
            deleted_run_ids: run_ids,
        })
    }
}
