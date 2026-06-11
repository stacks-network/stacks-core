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
use chrono::Utc;
use serde::Serialize;
use stacks_bench::db::app::AppDb;
use stacks_bench::db::app::models::BenchmarkRun;

/// Non-clap filter parameters for listing benchmark runs.
pub struct BenchListFilters {
    /// Show only incomplete (in-progress or failed) runs.
    pub incomplete: bool,
    /// Show all runs regardless of completion status.
    pub all: bool,
    /// Show runs from the last N duration.
    pub since: Option<chrono::Duration>,
    /// Show only runs from today (local time).
    pub today: bool,
    /// Filter by run name (substring match, case-insensitive).
    pub name: Option<String>,
    /// Sort field.
    pub sort_by: SortField,
    /// Maximum runs to return.
    pub limit: usize,
}

/// Sort field for benchmark run listings.
#[derive(Clone, Debug, Default)]
pub enum SortField {
    /// Sort by start time (most recent first).
    #[default]
    Date,
    /// Sort by total duration (longest first).
    Duration,
    /// Sort by block count (most first). Requires summary lookup.
    Blocks,
}

/// JSON serialization shape for a benchmark run.
#[derive(Serialize)]
pub struct RunJson {
    pub id: i32,
    pub name: Option<String>,
    pub start_time: String,
    pub end_time: Option<String>,
    pub duration_secs: Option<f64>,
    pub git_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<RunSummaryJson>,
}

/// Inline summary metrics for a benchmark run in list output.
#[derive(Serialize, Clone)]
pub struct RunSummaryJson {
    pub blocks: u64,
    pub total_duration_us: u64,
    pub avg_block_duration_us: u64,
}

/// Fetch, filter, sort, and limit benchmark runs.
pub async fn query_benchmark_runs(
    app_db: &AppDb,
    filters: &BenchListFilters,
) -> Result<Vec<(BenchmarkRun, Option<RunSummaryJson>)>> {
    let mut runs = app_db.list_benchmark_runs().await?;

    // --- Completion status filter ---
    if filters.incomplete {
        runs.retain(|r| r.end_time.is_none());
    } else if !filters.all {
        runs.retain(|r| r.end_time.is_some());
    }

    // --- Time-based filters ---
    if filters.today {
        let today_start = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("valid midnight");
        runs.retain(|r| r.start_time >= today_start);
    } else if let Some(duration) = filters.since {
        let cutoff = Utc::now().naive_utc() - duration;
        runs.retain(|r| r.start_time >= cutoff);
    }

    // --- Name filter ---
    if let Some(pattern) = &filters.name {
        let pat = pattern.to_lowercase();
        runs.retain(|r| {
            r.run_name
                .as_deref()
                .map(|n| n.to_lowercase().contains(&pat))
                .unwrap_or(false)
        });
    }

    // --- Fetch summaries ---
    let mut results: Vec<(BenchmarkRun, Option<RunSummaryJson>)> = Vec::with_capacity(runs.len());
    for run in runs {
        let summary = app_db.get_run_summary(run.id).await?.and_then(|s| {
            if s.block_count == 0 {
                None
            } else {
                Some(RunSummaryJson {
                    blocks: s.block_count,
                    total_duration_us: s.total_duration_us,
                    avg_block_duration_us: s.total_duration_us / s.block_count,
                })
            }
        });
        results.push((run, summary));
    }

    // --- Sort ---
    match filters.sort_by {
        SortField::Date => {
            // Already sorted by date desc from the DB query
        }
        SortField::Duration => {
            results.sort_by(|(a, _), (b, _)| {
                let dur_a = a.end_time.map(|end| end - a.start_time);
                let dur_b = b.end_time.map(|end| end - b.start_time);
                dur_b.cmp(&dur_a) // longest first
            });
        }
        SortField::Blocks => {
            results.sort_by(|(_, sa), (_, sb)| {
                let blocks_a = sa.as_ref().map(|s| s.blocks).unwrap_or(0);
                let blocks_b = sb.as_ref().map(|s| s.blocks).unwrap_or(0);
                blocks_b.cmp(&blocks_a) // most first
            });
        }
    }

    results.truncate(filters.limit);
    Ok(results)
}

/// Convert a benchmark run + optional summary into a JSON-serializable shape.
pub fn to_run_json(
    run: &BenchmarkRun,
    summary: &Option<RunSummaryJson>,
    with_args: bool,
) -> RunJson {
    let duration_secs = run
        .end_time
        .map(|end| (end - run.start_time).num_milliseconds() as f64 / 1000.0);

    let args = if with_args {
        Some(
            serde_json::from_str(&run.args_json)
                .unwrap_or_else(|_| serde_json::Value::String(run.args_json.clone())),
        )
    } else {
        None
    };

    RunJson {
        id: run.id,
        name: run.run_name.clone(),
        start_time: run.start_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
        end_time: run
            .end_time
            .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
        duration_secs,
        git_hash: hex::encode(&run.git_commit_hash),
        args,
        summary: summary.clone(),
    }
}
