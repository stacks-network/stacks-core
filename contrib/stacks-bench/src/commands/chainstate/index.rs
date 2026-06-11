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

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use stacks_bench::db::app::AppDb;
use stacks_bench::indexer::ChainstateIndexer;
use stacks_bench::{Network, StacksBlockRef};
use tokio::sync::mpsc;

use crate::commands::common::{IndexerArgs, IndexerUiSpawner, setup_bench_env_and_plan};

/// Non-clap parameter struct for chainstate indexing. CLI converts from
/// `IndexArgs` via `From`; MCP constructs directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainstateIndexParams {
    pub source_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_at: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_at: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
}

impl IndexerArgs for ChainstateIndexParams {
    fn start_at(&self) -> Option<&StacksBlockRef> {
        self.start_at.as_ref()
    }
    fn end_at(&self) -> Option<&StacksBlockRef> {
        self.end_at.as_ref()
    }
    fn block_count(&self) -> Option<u32> {
        self.block_count
    }
    fn tip(&self) -> Option<&StacksBlockRef> {
        self.tip.as_ref()
    }
    fn network(&self) -> Option<Network> {
        self.network
    }
}

/// Structured result returned by chainstate indexing.
#[derive(serde::Serialize)]
pub struct IndexResult {
    pub blocks_indexed: usize,
    pub start_block: String,
    pub start_height: u64,
    pub end_block: String,
    pub end_height: u64,
}

/// Index a range of chainstate blocks into the application database.
///
/// The caller provides an `indexer_ui` spawner to control how indexer
/// progress events are rendered (CLI progress bar, MCP notifications,
/// or silent drain).
pub async fn index_chainstate(
    app_db: &mut AppDb,
    params: &ChainstateIndexParams,
    indexer_ui: IndexerUiSpawner,
    interrupted: Arc<AtomicBool>,
) -> Result<IndexResult> {
    let (env, plan) = setup_bench_env_and_plan(&params.source_dir, params).await?;

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut indexer = ChainstateIndexer::new(app_db, &env)
        .with_events(event_tx)
        .with_interrupted(interrupted);

    let idx_ui_fut = indexer_ui(
        event_rx,
        plan.start_height,
        plan.end_height,
        plan.anchor_tip.height,
    );

    let index_result = indexer
        .index_chainstate_range(env.network, env.chain_id, &env.epochs, plan)
        .await;

    // Drop the indexer (which owns event_tx) so the UI task's channel
    // closes and it can exit, even if indexing errored before sending
    // `Finished`.
    drop(indexer);

    // Now safe to await — the channel is guaranteed to close.
    idx_ui_fut.await??;

    let (resolved, block_ids) = index_result?;

    Ok(IndexResult {
        blocks_indexed: block_ids.len(),
        start_block: resolved.start.id.to_string(),
        start_height: resolved.start.height,
        end_block: resolved.end.id.to_string(),
        end_height: resolved.end.height,
    })
}
