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

//! `list_chainstates` tool – lists indexed chainstates.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `list_chainstates` tool.
#[derive(Deserialize, JsonSchema)]
pub struct ListChainstatesParams {
    /// Maximum number of chainstates to return (default: 50).
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ChainstateJson {
    id: i32,
    network: String,
    chain_id: i64,
    tip_hash: String,
    tip_height: i64,
    run_count: i64,
}

impl StacksBenchServer {
    pub async fn query_chainstates(
        &self,
        params: &ListChainstatesParams,
    ) -> anyhow::Result<String> {
        let limit = params.limit.unwrap_or(50);
        let mut chainstates = self.app_db.list_chainstates().await?;
        chainstates.truncate(limit);

        let mut results = Vec::with_capacity(chainstates.len());
        for cs in &chainstates {
            let network = self.app_db.get_network_name(cs.network_id).await?;
            let run_count = self
                .app_db
                .count_benchmark_runs_for_chainstate(cs.id)
                .await?;

            results.push(ChainstateJson {
                id: cs.id,
                network,
                chain_id: cs.chain_id,
                tip_hash: hex::encode(&cs.tip_index_hash),
                tip_height: cs.tip_height,
                run_count,
            });
        }

        serde_json::to_string_pretty(&results)
            .map_err(|e| anyhow::anyhow!("Failed to serialize chainstates: {e}"))
    }
}
