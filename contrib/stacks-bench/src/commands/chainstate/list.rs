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

/// JSON serialization shape for a chainstate.
#[derive(Serialize)]
pub struct ChainstateJson {
    pub id: i32,
    pub network: String,
    pub chain_id: i64,
    pub tip_height: i64,
    pub tip_hash: String,
    pub epochs_hash: String,
    pub runs: i64,
}

/// Query chainstates from the database, resolving network names and run counts.
pub async fn query_chainstates(app_db: &AppDb, limit: usize) -> Result<Vec<ChainstateJson>> {
    let mut chainstates = app_db.list_chainstates().await?;
    chainstates.truncate(limit);

    let mut items = Vec::with_capacity(chainstates.len());
    for cs in &chainstates {
        let network = app_db.get_network_name(cs.network_id).await?;
        let run_count = app_db.count_benchmark_runs_for_chainstate(cs.id).await?;
        items.push(ChainstateJson {
            id: cs.id,
            network,
            chain_id: cs.chain_id,
            tip_height: cs.tip_height,
            tip_hash: hex::encode(&cs.tip_index_hash),
            epochs_hash: hex::encode(&cs.epochs_hash),
            runs: run_count,
        });
    }

    Ok(items)
}
