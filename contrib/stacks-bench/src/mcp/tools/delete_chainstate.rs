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

//! `delete_chainstate` tool – deletes a chainstate and all associated data.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use stacks_bench::db::app::CheckpointMode;

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `delete_chainstate` tool.
#[derive(Deserialize, JsonSchema)]
pub struct DeleteChainstateParams {
    /// ID of the chainstate to delete.
    pub chainstate_id: i32,
}

#[derive(Serialize)]
struct DeleteChainstateResult {
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl StacksBenchServer {
    pub async fn exec_delete_chainstate(
        &self,
        params: &DeleteChainstateParams,
    ) -> anyhow::Result<String> {
        let mut db = self.app_db.clone();
        let result = match db.delete_chainstate(params.chainstate_id).await {
            Ok(()) => {
                // Post-delete cleanup: checkpoint + vacuum to reclaim space.
                let _ = db.checkpoint(CheckpointMode::Truncate).await;
                let _ = db.vacuum().await;
                DeleteChainstateResult {
                    deleted: true,
                    message: None,
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("not found") {
                    DeleteChainstateResult {
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
