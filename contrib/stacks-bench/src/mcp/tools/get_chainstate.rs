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

//! `get_chainstate` tool – details for a single chainstate.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::mcp::server::StacksBenchServer;

/// Parameters for the `get_chainstate` tool.
#[derive(Deserialize, JsonSchema)]
pub struct GetChainstateParams {
    /// Chainstate ID.
    chainstate_id: i32,
}

#[derive(Serialize)]
struct ChainstateDetailJson {
    id: i32,
    network: String,
    chain_id: i64,
    tip_hash: String,
    tip_height: i64,
    run_count: i64,
    epochs: Vec<EpochJson>,
}

#[derive(Serialize)]
struct EpochJson {
    stacks_epoch_id: i32,
    network_epoch_id: i32,
    start_height: i64,
    end_height: i64,
    runtime_budget: i64,
    read_length_budget: i64,
    read_count_budget: i64,
    write_length_budget: i64,
    write_count_budget: i64,
}

impl StacksBenchServer {
    pub async fn query_chainstate(&self, params: &GetChainstateParams) -> anyhow::Result<String> {
        let cs = self
            .app_db
            .get_chainstate(params.chainstate_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Chainstate {} not found", params.chainstate_id))?;

        let network = self.app_db.get_network_name(cs.network_id).await?;
        let run_count = self
            .app_db
            .count_benchmark_runs_for_chainstate(cs.id)
            .await?;
        let epochs = self.app_db.get_epochs_for_chainstate(cs.id).await?;

        let result = ChainstateDetailJson {
            id: cs.id,
            network,
            chain_id: cs.chain_id,
            tip_hash: hex::encode(&cs.tip_index_hash),
            tip_height: cs.tip_height,
            run_count,
            epochs: epochs
                .into_iter()
                .map(|e| EpochJson {
                    stacks_epoch_id: e.stacks_epoch_id,
                    network_epoch_id: e.network_epoch_id,
                    start_height: e.start_height,
                    end_height: e.end_height,
                    runtime_budget: e.runtime_budget,
                    read_length_budget: e.read_length_budget,
                    read_count_budget: e.read_count_budget,
                    write_length_budget: e.write_length_budget,
                    write_count_budget: e.write_count_budget,
                })
                .collect(),
        };

        serde_json::to_string_pretty(&result)
            .map_err(|e| anyhow::anyhow!("Failed to serialize chainstate: {e}"))
    }
}
