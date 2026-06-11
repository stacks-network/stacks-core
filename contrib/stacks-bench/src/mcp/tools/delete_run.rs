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

//! `delete_run` tool – deletes a benchmark run and all dependent data.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use stacks_bench::db::app::CheckpointMode;

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `delete_run` tool.
#[derive(Deserialize, JsonSchema)]
pub struct DeleteRunParams {
    /// ID of the benchmark run to delete.
    pub run_id: i32,
}

#[derive(Serialize)]
struct DeleteRunResult {
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl StacksBenchServer {
    pub async fn exec_delete_run(&self, params: &DeleteRunParams) -> anyhow::Result<String> {
        let mut db = self.app_db.clone();
        let result = match db.delete_benchmark_run(params.run_id).await {
            Ok(()) => {
                // Post-delete cleanup: checkpoint + vacuum to reclaim space.
                let _ = db.checkpoint(CheckpointMode::Truncate).await;
                let _ = db.vacuum().await;
                DeleteRunResult {
                    deleted: true,
                    message: None,
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("not found") {
                    DeleteRunResult {
                        deleted: false,
                        message: Some(msg),
                    }
                } else {
                    return Err(e);
                }
            }
        };
        Ok(serde_json::to_string(&result)?)
    }
}
