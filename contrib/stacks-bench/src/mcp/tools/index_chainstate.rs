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

//! `index_chainstate` tool – indexes a chainstate range via the shared commands layer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rmcp::model::{Meta, ProgressNotificationParam, ProgressToken, ServerNotification};
use rmcp::{Peer, RoleServer};
use schemars::JsonSchema;
use serde::Deserialize;
use stacks_bench::StacksBlockRef;
use stacks_bench::indexer::IndexerEvent;
use tokio::sync::mpsc;

use crate::commands::chainstate::index::ChainstateIndexParams;
use crate::commands::common::IndexerUiSpawner;
use crate::mcp::server::StacksBenchServer;

/// Parameters for the `index_chainstate` tool.
#[derive(Deserialize, JsonSchema)]
pub struct IndexChainstateParams {
    /// Path to the Stacks node data directory (the directory containing the
    /// `chainstate` folder).
    pub source_dir: String,

    /// Stacks block (height, index_block_hash, or canonical block_hash) to start at, inclusive.
    #[serde(default)]
    pub start_at: Option<String>,

    /// Stacks block (height, index_block_hash, or canonical block_hash) to end at, inclusive.
    #[serde(default)]
    pub end_at: Option<String>,

    /// Number of blocks to index, starting from `start_at`.
    #[serde(default)]
    pub count: Option<u32>,

    /// Tip block (height, index_block_hash, or canonical block_hash) to anchor canonical history
    /// resolution. Defaults to the node's current canonical tip.
    #[serde(default)]
    pub tip: Option<String>,

    /// Network name (e.g. `"mainnet"`, `"testnet"`). Inferred from the
    /// chainstate if omitted.
    #[serde(default)]
    pub network: Option<String>,
}

impl IndexChainstateParams {
    /// Convert tool parameters into the shared `ChainstateIndexParams`.
    fn into_index_params(self) -> Result<ChainstateIndexParams, String> {
        let network = match self.network.as_deref() {
            None => None,
            Some(s) => Some(
                s.parse()
                    .map_err(|_| format!("Unknown network '{s}'. Use mainnet or testnet"))?,
            ),
        };

        let parse_block_ref = |s: &str| -> Result<StacksBlockRef, String> {
            s.parse()
                .map_err(|e| format!("Invalid block ref '{s}': {e}"))
        };

        Ok(ChainstateIndexParams {
            source_dir: self.source_dir.into(),
            start_at: self.start_at.as_deref().map(parse_block_ref).transpose()?,
            end_at: self.end_at.as_deref().map(parse_block_ref).transpose()?,
            block_count: self.count,
            tip: self.tip.as_deref().map(parse_block_ref).transpose()?,
            network,
        })
    }
}

impl StacksBenchServer {
    pub async fn exec_index_chainstate(
        &self,
        params: IndexChainstateParams,
        meta: Meta,
        client: Peer<RoleServer>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> anyhow::Result<String> {
        let index_params = params
            .into_index_params()
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        // Wire up cancellation: MCP cancellation token OR ctrl-c.
        let interrupted = Arc::new(AtomicBool::new(false));
        {
            let flag = interrupted.clone();
            let ct = context.ct.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = ct.cancelled() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
                flag.store(true, Ordering::Relaxed);
            });
        }

        let progress_token = meta.get_progress_token();

        // Build an indexer UI spawner that forwards progress as MCP
        // notifications if a token was provided, otherwise silently drains.
        let indexer_ui: IndexerUiSpawner = if let Some(token) = progress_token {
            let client = client.clone();
            Box::new(move |rx, _start, _end, _tip| {
                tokio::spawn(forward_indexer_events(rx, client.clone(), token.clone()))
            })
        } else {
            crate::commands::common::silent_indexer_ui()
        };

        let mut app_db = self.app_db.clone();
        let result = crate::commands::chainstate::index::index_chainstate(
            &mut app_db,
            &index_params,
            indexer_ui,
            interrupted,
        )
        .await?;

        Ok(serde_json::to_string(&result)?)
    }
}

// ---------------------------------------------------------------------------
// Progress notification forwarder
// ---------------------------------------------------------------------------

async fn forward_indexer_events(
    mut rx: mpsc::UnboundedReceiver<IndexerEvent>,
    client: Peer<RoleServer>,
    token: ProgressToken,
) -> anyhow::Result<()> {
    let mut expected_blocks: usize = 0;

    while let Some(event) = rx.recv().await {
        match event {
            IndexerEvent::AlreadyCached => {
                send(
                    &client,
                    &token,
                    1.0,
                    Some(1.0),
                    Some("Chainstate already indexed"),
                )
                .await;
            }

            IndexerEvent::IndexIncomplete { found, expected } => {
                expected_blocks = expected;
                send(
                    &client,
                    &token,
                    0.0,
                    Some(expected as f64),
                    Some(&format!(
                        "Index incomplete ({found}/{expected}), indexing..."
                    )),
                )
                .await;
            }

            IndexerEvent::PipelineStarted { metrics, .. } => {
                // Poll the metrics atomics for 1%-granularity progress
                // until the next event arrives or the channel closes.
                let total = expected_blocks.max(1) as f64;
                let mut last_pct: i32 = -1;

                loop {
                    tokio::select! {
                        biased;
                        next = rx.recv() => {
                            match next {
                                Some(IndexerEvent::Finished) => {
                                    send(
                                        &client,
                                        &token,
                                        total,
                                        Some(total),
                                        Some("Indexing complete"),
                                    )
                                    .await;
                                    return Ok(());
                                }
                                Some(IndexerEvent::Interrupted) => {
                                    send(
                                        &client,
                                        &token,
                                        total,
                                        Some(total),
                                        Some("Indexing interrupted"),
                                    )
                                    .await;
                                    return Ok(());
                                }
                                None => {
                                    // Channel closed without Finished —
                                    // the indexer was dropped (likely due
                                    // to an error). Don't claim success.
                                    return Ok(());
                                }
                                Some(_other) => {
                                    // Intermediate lifecycle events (merge,
                                    // checkpoint, vacuum) — skip; the client
                                    // only cares about started/progress/done.
                                }
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {
                            let flushed = metrics.flushed_blocks.load(Ordering::Relaxed) as f64;
                            let pct = ((flushed / total) * 100.0) as i32;
                            if pct != last_pct {
                                last_pct = pct;
                                send(&client, &token, flushed, Some(total), None).await;
                            }
                        }
                    }
                }
            }

            IndexerEvent::Finished => {
                send(
                    &client,
                    &token,
                    expected_blocks as f64,
                    Some(expected_blocks as f64),
                    Some("Indexing complete"),
                )
                .await;
                return Ok(());
            }

            IndexerEvent::Interrupted => {
                send(
                    &client,
                    &token,
                    expected_blocks as f64,
                    Some(expected_blocks as f64),
                    Some("Indexing interrupted"),
                )
                .await;
            }

            // Other lifecycle events before PipelineStarted — skip.
            _ => {}
        }
    }
    Ok(())
}

async fn send(
    client: &Peer<RoleServer>,
    token: &ProgressToken,
    progress_val: f64,
    total: Option<f64>,
    message: Option<&str>,
) {
    let mut p = ProgressNotificationParam::new(token.clone(), progress_val);
    if let Some(t) = total {
        p = p.with_total(t);
    }
    if let Some(m) = message {
        p = p.with_message(m.to_owned());
    }
    let _ = client
        .send_notification(ServerNotification::ProgressNotification(
            rmcp::model::ProgressNotification::new(p),
        ))
        .await;
}
