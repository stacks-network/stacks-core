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

//! `get_block_stats` tool – paginated per-block stats for a benchmark run.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `get_block_stats` tool.
#[derive(Deserialize, JsonSchema)]
pub struct GetBlockStatsParams {
    /// Benchmark run ID.
    run_id: i32,
    /// Page offset (default: 0).
    #[serde(default)]
    offset: Option<i64>,
    /// Page size (default: 50, max: 200).
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
struct BlockStatsJson {
    height: i64,
    block_id: String,
    total_duration_us: i32,
    setup_duration_us: i32,
    execution_duration_us: i32,
    commit_duration_us: i32,
    commit_overhead_baseline_us: i32,
    clarity_runtime: i32,
    clarity_read_length: i32,
    clarity_read_count: i32,
    clarity_write_length: i32,
    clarity_write_count: i32,
    total_storage_delta: i64,
}

impl StacksBenchServer {
    pub async fn query_block_stats(&self, params: &GetBlockStatsParams) -> anyhow::Result<String> {
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(50).min(200);

        let rows = self
            .app_db
            .get_block_stats(params.run_id, offset, limit)
            .await?;

        let results: Vec<BlockStatsJson> = rows
            .into_iter()
            .map(|r| BlockStatsJson {
                height: r.height,
                block_id: r.block_id,
                total_duration_us: r.total_duration_us,
                setup_duration_us: r.setup_duration_us,
                execution_duration_us: r.execution_duration_us,
                commit_duration_us: r.commit_duration_us,
                commit_overhead_baseline_us: r.commit_overhead_baseline_us,
                clarity_runtime: r.clarity_runtime,
                clarity_read_length: r.clarity_read_length,
                clarity_read_count: r.clarity_read_count,
                clarity_write_length: r.clarity_write_length,
                clarity_write_count: r.clarity_write_count,
                total_storage_delta: r.total_storage_delta,
            })
            .collect();

        serde_json::to_string_pretty(&results)
            .map_err(|e| anyhow::anyhow!("Failed to serialize block stats: {e}"))
    }
}
