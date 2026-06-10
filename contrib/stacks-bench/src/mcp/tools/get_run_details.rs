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

//! `get_run_details` tool – composite view of a benchmark run.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `get_run_details` tool.
#[derive(Deserialize, JsonSchema)]
pub struct GetRunDetailsParams {
    /// Benchmark run ID.
    run_id: i32,
    /// Number of top profiler hotspots to include (default: 10).
    #[serde(default)]
    hotspot_limit: Option<usize>,
}

#[derive(Serialize)]
struct RunDetailsJson {
    id: i32,
    name: Option<String>,
    chainstate_id: i32,
    start_time: String,
    end_time: Option<String>,
    duration_secs: Option<f64>,
    git_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<DetailedSummaryJson>,
    hotspots: Vec<HotSpanJson>,
}

#[derive(Serialize)]
struct DetailedSummaryJson {
    block_count: u64,
    total_duration_us: u64,
    avg_duration_us: u64,
    total_setup_us: u64,
    total_execution_us: u64,
    total_commit_us: u64,
    total_clarity_runtime: u64,
    total_clarity_read_length: u64,
    total_clarity_read_count: u64,
    total_clarity_write_length: u64,
    total_clarity_write_count: u64,
    total_storage_delta: i64,
}

#[derive(Serialize)]
struct HotSpanJson {
    span_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_context: Option<String>,
    est_self_wall_us: f64,
    est_wall_us: f64,
    call_count: i64,
    sample_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<i32>,
}

impl StacksBenchServer {
    pub async fn query_run_details(&self, params: &GetRunDetailsParams) -> anyhow::Result<String> {
        let run = self
            .app_db
            .get_benchmark_run(params.run_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Benchmark run {} not found", params.run_id))?;

        let summary = self
            .app_db
            .get_run_detailed_summary(run.id)
            .await?
            .map(|s| DetailedSummaryJson {
                block_count: s.block_count,
                total_duration_us: s.total_duration_us,
                avg_duration_us: s.avg_duration_us,
                total_setup_us: s.total_setup_us,
                total_execution_us: s.total_execution_us,
                total_commit_us: s.total_commit_us,
                total_clarity_runtime: s.total_clarity_runtime,
                total_clarity_read_length: s.total_clarity_read_length,
                total_clarity_read_count: s.total_clarity_read_count,
                total_clarity_write_length: s.total_clarity_write_length,
                total_clarity_write_count: s.total_clarity_write_count,
                total_storage_delta: s.total_storage_delta,
            });

        let limit = params.hotspot_limit.unwrap_or(10);
        let hot_spans = self.app_db.get_profiler_hot_spans(run.id, limit).await?;

        let hotspots: Vec<HotSpanJson> = hot_spans
            .into_iter()
            .map(|h| HotSpanJson {
                span_name: h.span_name,
                span_context: h.span_context,
                est_self_wall_us: h.est_self_wall_us,
                est_wall_us: h.est_wall_us,
                call_count: h.call_count,
                sample_count: h.sample_count,
                file: h.file,
                line: h.line,
            })
            .collect();

        let duration_secs = run
            .end_time
            .map(|end| (end - run.start_time).num_milliseconds() as f64 / 1000.0);

        let result = RunDetailsJson {
            id: run.id,
            name: run.run_name,
            chainstate_id: run.chainstate_id,
            start_time: run.start_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
            end_time: run
                .end_time
                .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
            duration_secs,
            git_hash: hex::encode(&run.git_commit_hash),
            summary,
            hotspots,
        };

        serde_json::to_string_pretty(&result)
            .map_err(|e| anyhow::anyhow!("Failed to serialize run details: {e}"))
    }
}
