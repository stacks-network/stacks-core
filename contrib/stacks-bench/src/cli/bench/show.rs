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

use crate::cli::common::{Align, CliContext, ExecCommand, Table, fmt_u64_thousands};
use crate::commands::bench::show::{ShowResult, get_benchmark_details};

#[derive(clap::Args, Debug)]
pub struct ShowArgs {
    /// The ID of the benchmark run to show.
    #[arg(long, alias = "id")]
    pub run_id: i32,

    /// Show the top-N hottest profiler spans by self wall time.
    #[arg(long, value_name = "N", default_value_t = 20)]
    pub profiler_hot: usize,
}

impl ExecCommand for ShowArgs {
    type Output = ShowResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let result = get_benchmark_details(&ctx.app_db(), self.run_id, self.profiler_hot).await?;

        if ctx.interactive() {
            let name_str = result.name.as_deref().unwrap_or("(unnamed)");
            let short_hash = &result.git_hash[..result.git_hash.len().min(8)];

            cliclack::log::step(format!(
                "Run {} ({}) — git {}",
                self.run_id, name_str, short_hash,
            ))?;

            if let Some(ref s) = result.summary {
                let mut table = Table::new()
                    .col("Metric", Align::Left)
                    .col("Total", Align::Right)
                    .col("Per Block", Align::Right);

                let avg = |total: u64| -> String {
                    if s.blocks > 0 {
                        fmt_u64_thousands(total / s.blocks)
                    } else {
                        "—".into()
                    }
                };

                let avg_dur = |total_us: u64| -> String {
                    if s.blocks > 0 {
                        format!(
                            "{:.2?}",
                            std::time::Duration::from_micros(total_us / s.blocks)
                        )
                    } else {
                        "—".into()
                    }
                };

                table.row(vec![
                    "Blocks".into(),
                    fmt_u64_thousands(s.blocks),
                    "—".into(),
                ]);
                table.row(vec![
                    "Total Duration".into(),
                    format!(
                        "{:.2?}",
                        std::time::Duration::from_micros(s.total_duration_us)
                    ),
                    avg_dur(s.total_duration_us),
                ]);
                table.row(vec![
                    "  Setup".into(),
                    format!("{:.2?}", std::time::Duration::from_micros(s.total_setup_us)),
                    avg_dur(s.total_setup_us),
                ]);
                table.row(vec![
                    "  Execution".into(),
                    format!(
                        "{:.2?}",
                        std::time::Duration::from_micros(s.total_execution_us)
                    ),
                    avg_dur(s.total_execution_us),
                ]);
                table.row(vec![
                    "  Commit".into(),
                    format!(
                        "{:.2?}",
                        std::time::Duration::from_micros(s.total_commit_us)
                    ),
                    avg_dur(s.total_commit_us),
                ]);
                table.row(vec![
                    "Clarity Runtime".into(),
                    fmt_u64_thousands(s.clarity_runtime),
                    avg(s.clarity_runtime),
                ]);
                table.row(vec![
                    "Read Length".into(),
                    fmt_u64_thousands(s.clarity_read_length),
                    avg(s.clarity_read_length),
                ]);
                table.row(vec![
                    "Write Length".into(),
                    fmt_u64_thousands(s.clarity_write_length),
                    avg(s.clarity_write_length),
                ]);
                table.row(vec![
                    "Storage Delta".into(),
                    format!("{:.3} MB", s.storage_delta_bytes as f64 / 1_048_576.0),
                    "—".into(),
                ]);

                cliclack::note("Summary", table.to_string())?;
            } else {
                cliclack::log::info("No block stats recorded for this run.")?;
            }

            if !result.profiler_hot.is_empty() {
                let mut table = Table::new()
                    .col("#", Align::Right)
                    .col_with("Span", Align::Left, 10, Some(40))
                    .col("Self Wall", Align::Right)
                    .col("Total Wall", Align::Right)
                    .col("Calls", Align::Right)
                    .col_with("Location", Align::Left, 10, Some(40));

                for (i, s) in result.profiler_hot.iter().enumerate() {
                    let location = match (&s.file, s.line) {
                        (Some(f), Some(l)) => format!("{f}:{l}"),
                        (Some(f), None) => f.clone(),
                        _ => "—".into(),
                    };
                    let self_wall = format!(
                        "{:.2?}",
                        std::time::Duration::from_micros(s.est_self_wall_us as u64)
                    );
                    let total_wall = format!(
                        "{:.2?}",
                        std::time::Duration::from_micros(s.est_wall_us as u64)
                    );
                    let name = if let Some(ref ctx_name) = s.context {
                        format!("{}: {}", ctx_name, s.name)
                    } else {
                        s.name.clone()
                    };

                    table.row(vec![
                        (i + 1).to_string(),
                        name,
                        self_wall,
                        total_wall,
                        fmt_u64_thousands(s.call_count as u64),
                        location,
                    ]);
                }

                cliclack::note(
                    format!("Profiler Hot Spans (top {})", self.profiler_hot),
                    table.to_string(),
                )?;
            }
        }

        Ok(result)
    }
}
