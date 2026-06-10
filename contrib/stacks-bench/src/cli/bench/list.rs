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

use anyhow::Result;
use console::style;
use stacks_bench::db::app::models::BenchmarkRun;

use crate::cli::common::{
    Align, CliContext, ExecCommand, Table, fmt_duration, fmt_relative_time, parse_since,
};
use crate::commands::bench::list::{
    BenchListFilters, RunJson, RunSummaryJson, SortField, query_benchmark_runs, to_run_json,
};

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Show only runs from today (local time).
    #[arg(long, conflicts_with = "since")]
    pub today: bool,

    /// Show runs from the last N duration (e.g. `10m`, `2h`, `1d6h`).
    #[arg(long, conflicts_with = "today", value_name = "DURATION")]
    pub since: Option<String>,

    /// Show only incomplete (in-progress or failed) runs. By default these
    /// are hidden.
    #[arg(long)]
    pub incomplete: bool,

    /// Show all runs regardless of completion status (overrides the default
    /// filter that hides incomplete runs).
    #[arg(long, short = 'a', conflicts_with = "incomplete")]
    pub all: bool,

    /// Filter by run name (substring match, case-insensitive).
    #[arg(long, short = 'n', value_name = "PATTERN")]
    pub name: Option<String>,

    /// Maximum number of runs to display.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Sort runs by the given field. Default: `date` (most recent first).
    #[arg(long, default_value = "date", value_name = "FIELD")]
    pub sort_by: CliSortField,

    /// Include the original run arguments in JSON output.
    #[arg(long)]
    pub with_args: bool,
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum CliSortField {
    /// Sort by start time (most recent first).
    #[default]
    Date,
    /// Sort by total duration (longest first).
    Duration,
    /// Sort by block count (most first). Requires summary lookup.
    Blocks,
}

impl ListArgs {
    fn to_filters(&self) -> Result<BenchListFilters> {
        let since = self.since.as_deref().map(parse_since).transpose()?;

        Ok(BenchListFilters {
            incomplete: self.incomplete,
            all: self.all,
            since,
            today: self.today,
            name: self.name.clone(),
            sort_by: match self.sort_by {
                CliSortField::Date => SortField::Date,
                CliSortField::Duration => SortField::Duration,
                CliSortField::Blocks => SortField::Blocks,
            },
            limit: self.limit,
        })
    }

    fn print_table(&self, results: &[(BenchmarkRun, Option<RunSummaryJson>)]) -> Result<()> {
        if results.is_empty() {
            cliclack::log::info("No matching benchmark runs found.")?;
            return Ok(());
        }

        let mut table = Table::new()
            .col("ID", Align::Right)
            .col("", Align::Left)
            .col_with("Name", Align::Left, 4, Some(30))
            .col("Started", Align::Left)
            .col("Duration", Align::Left)
            .col("Blocks", Align::Right)
            .col("Avg/Block", Align::Right)
            .col("Git Hash", Align::Left);

        for (r, summary) in results {
            let status_icon = if r.end_time.is_some() {
                style("✔").green().to_string()
            } else {
                style("…").yellow().to_string()
            };

            let name = r.run_name.as_deref().unwrap_or("—").to_string();
            let started = fmt_relative_time(r.start_time);
            let duration = r
                .end_time
                .map(|end| fmt_duration(r.start_time, end))
                .unwrap_or_else(|| style("running").yellow().to_string());

            let (blocks, avg_block) = match summary {
                Some(s) => {
                    let avg_ms = s.avg_block_duration_us as f64 / 1000.0;
                    (s.blocks.to_string(), format!("{avg_ms:.1}ms"))
                }
                None => ("—".into(), "—".into()),
            };

            let hash = hex::encode(&r.git_commit_hash);
            let short_hash = hash[..hash.len().min(8)].to_string();

            table.row(vec![
                r.id.to_string(),
                status_icon,
                name,
                started,
                duration,
                blocks,
                avg_block,
                short_hash,
            ]);
        }

        table.print_with_footer("run", self.limit)?;
        Ok(())
    }
}

impl ExecCommand for ListArgs {
    type Output = Vec<RunJson>;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let filters = self.to_filters()?;
        let results = query_benchmark_runs(&ctx.app_db(), &filters).await?;

        if !ctx.json() {
            self.print_table(&results)?;
        }

        Ok(results
            .iter()
            .map(|(run, summary)| to_run_json(run, summary, self.with_args))
            .collect())
    }
}
