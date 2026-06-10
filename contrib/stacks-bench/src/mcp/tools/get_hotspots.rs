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

//! `get_hotspots` tool – profiler hotspots for a benchmark run.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `get_hotspots` tool.
#[derive(Deserialize, JsonSchema)]
pub struct GetHotspotsParams {
    /// Benchmark run ID.
    run_id: i32,
    /// Maximum number of hotspots to return (default: 25).
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct HotSpanJson {
    rank: usize,
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
    pub async fn query_hotspots(&self, params: &GetHotspotsParams) -> anyhow::Result<String> {
        let limit = params.limit.unwrap_or(25);
        let spans = self
            .app_db
            .get_profiler_hot_spans(params.run_id, limit)
            .await?;

        let results: Vec<HotSpanJson> = spans
            .into_iter()
            .enumerate()
            .map(|(i, h)| HotSpanJson {
                rank: i + 1,
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

        serde_json::to_string_pretty(&results)
            .map_err(|e| anyhow::anyhow!("Failed to serialize hotspots: {e}"))
    }
}
