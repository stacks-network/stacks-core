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
use serde::Serialize;
use stacks_bench::db::app::AppDb;

/// JSON output for benchmark run details.
#[derive(Serialize)]
pub struct ShowResult {
    pub run_id: i32,
    pub name: Option<String>,
    pub start_time: String,
    pub end_time: Option<String>,
    pub git_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<SummaryJson>,
    pub profiler_hot: Vec<HotSpanJson>,
}

#[derive(Serialize)]
pub struct SummaryJson {
    pub blocks: u64,
    pub total_duration_us: u64,
    pub avg_block_duration_us: u64,
    pub total_setup_us: u64,
    pub total_execution_us: u64,
    pub total_commit_us: u64,
    pub clarity_runtime: u64,
    pub clarity_read_length: u64,
    pub clarity_read_count: u64,
    pub clarity_write_length: u64,
    pub clarity_write_count: u64,
    pub storage_delta_bytes: i64,
}

#[derive(Serialize)]
pub struct HotSpanJson {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub est_self_wall_us: f64,
    pub est_wall_us: f64,
    pub call_count: i64,
    pub sample_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i32>,
}

/// Fetch benchmark run details: metadata, detailed summary, and profiler hot spans.
pub async fn get_benchmark_details(
    app_db: &AppDb,
    run_id: i32,
    profiler_hot_count: usize,
) -> Result<ShowResult> {
    let run = app_db
        .get_benchmark_run(run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Benchmark run {} not found", run_id))?;

    let detailed = app_db.get_run_detailed_summary(run_id).await?;
    let summary = detailed.map(|d| SummaryJson {
        blocks: d.block_count,
        total_duration_us: d.total_duration_us,
        avg_block_duration_us: d.avg_duration_us,
        total_setup_us: d.total_setup_us,
        total_execution_us: d.total_execution_us,
        total_commit_us: d.total_commit_us,
        clarity_runtime: d.total_clarity_runtime,
        clarity_read_length: d.total_clarity_read_length,
        clarity_read_count: d.total_clarity_read_count,
        clarity_write_length: d.total_clarity_write_length,
        clarity_write_count: d.total_clarity_write_count,
        storage_delta_bytes: d.total_storage_delta,
    });

    let hot_spans_raw = app_db
        .get_profiler_hot_spans(run_id, profiler_hot_count)
        .await?;

    let profiler_hot: Vec<HotSpanJson> = hot_spans_raw
        .into_iter()
        .map(|s| HotSpanJson {
            name: s.span_name,
            context: s.span_context,
            est_self_wall_us: s.est_self_wall_us,
            est_wall_us: s.est_wall_us,
            call_count: s.call_count,
            sample_count: s.sample_count,
            file: s.file,
            line: s.line,
        })
        .collect();

    Ok(ShowResult {
        run_id,
        name: run.run_name,
        start_time: run.start_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
        end_time: run
            .end_time
            .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
        git_hash: hex::encode(&run.git_commit_hash),
        summary,
        profiler_hot,
    })
}
