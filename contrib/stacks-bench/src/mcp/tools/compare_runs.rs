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

//! `compare_runs` tool – structured diff between two benchmark runs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `compare_runs` tool.
#[derive(Deserialize, JsonSchema)]
pub struct CompareRunsParams {
    /// Baseline benchmark run ID.
    baseline_id: i32,
    /// Candidate benchmark run ID.
    candidate_id: i32,
    /// Maximum number of span comparisons to return (default: 50).
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
struct ComparisonJson {
    baseline: RunBriefJson,
    candidate: RunBriefJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary_delta: Option<SummaryDeltaJson>,
    span_diffs: Vec<SpanDiffJson>,
}

#[derive(Serialize)]
struct RunBriefJson {
    id: i32,
    name: Option<String>,
    git_hash: String,
}

#[derive(Serialize)]
struct SummaryDeltaJson {
    baseline_total_us: u64,
    candidate_total_us: u64,
    delta_us: i64,
    delta_pct: f64,
    baseline_blocks: u64,
    candidate_blocks: u64,
}

#[derive(Serialize)]
struct SpanDiffJson {
    span_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_self_wall_us: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_self_wall_us: Option<f64>,
    delta_us: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_calls: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_calls: Option<i64>,
}

impl StacksBenchServer {
    pub async fn query_compare_runs(&self, params: &CompareRunsParams) -> anyhow::Result<String> {
        let baseline = self
            .app_db
            .get_benchmark_run(params.baseline_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Baseline run {} not found", params.baseline_id))?;
        let candidate = self
            .app_db
            .get_benchmark_run(params.candidate_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Candidate run {} not found", params.candidate_id))?;

        // Summary-level delta
        let b_summary = self
            .app_db
            .get_run_detailed_summary(params.baseline_id)
            .await?;
        let c_summary = self
            .app_db
            .get_run_detailed_summary(params.candidate_id)
            .await?;

        let summary_delta = match (b_summary, c_summary) {
            (Some(b), Some(c)) => {
                let delta = c.total_duration_us as i64 - b.total_duration_us as i64;
                let pct = if b.total_duration_us > 0 {
                    delta as f64 / b.total_duration_us as f64 * 100.0
                } else {
                    0.0
                };
                Some(SummaryDeltaJson {
                    baseline_total_us: b.total_duration_us,
                    candidate_total_us: c.total_duration_us,
                    delta_us: delta,
                    delta_pct: pct,
                    baseline_blocks: b.block_count,
                    candidate_blocks: c.block_count,
                })
            }
            _ => None,
        };

        // Per-span diffs
        let limit = params.limit.unwrap_or(50);
        let span_rows = self
            .app_db
            .compare_run_spans(params.baseline_id, params.candidate_id, limit)
            .await?;

        let span_diffs: Vec<SpanDiffJson> = span_rows
            .into_iter()
            .map(|r| SpanDiffJson {
                span_name: r.span_name,
                span_context: r.span_context,
                baseline_self_wall_us: r.baseline_self_wall_us,
                candidate_self_wall_us: r.candidate_self_wall_us,
                delta_us: r.delta_us,
                delta_pct: r.delta_pct,
                baseline_calls: r.baseline_calls,
                candidate_calls: r.candidate_calls,
            })
            .collect();

        let result = ComparisonJson {
            baseline: RunBriefJson {
                id: baseline.id,
                name: baseline.run_name,
                git_hash: hex::encode(&baseline.git_commit_hash),
            },
            candidate: RunBriefJson {
                id: candidate.id,
                name: candidate.run_name,
                git_hash: hex::encode(&candidate.git_commit_hash),
            },
            summary_delta,
            span_diffs,
        };

        serde_json::to_string_pretty(&result)
            .map_err(|e| anyhow::anyhow!("Failed to serialize comparison: {e}"))
    }
}
