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

//! `rerun_benchmark` tool – reruns a previous benchmark using its stored parameters.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmcp::model::Meta;
use rmcp::{Peer, RoleServer};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::commands::bench::run::BenchRunParams;
use crate::commands::common::{IndexerUiSpawner, silent_indexer_ui};
use crate::mcp::server::StacksBenchServer;

/// Parameters for the `rerun_benchmark` tool.
#[derive(Deserialize, JsonSchema)]
pub struct RerunBenchmarkParams {
    /// ID of a previous benchmark run to re-run with the same parameters.
    pub run_id: i32,
}

impl StacksBenchServer {
    pub async fn exec_rerun_benchmark(
        &self,
        params: &RerunBenchmarkParams,
        meta: Meta,
        client: Peer<RoleServer>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> anyhow::Result<String> {
        let app_db = &self.app_db;

        let run = app_db
            .get_benchmark_run(params.run_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Benchmark run {} not found", params.run_id))?;

        let bench_params: BenchRunParams = serde_json::from_str(&run.args_json).map_err(|e| {
            anyhow::anyhow!(
                "Failed to deserialize stored args for run {}: {e}",
                params.run_id
            )
        })?;

        let (event_tx, event_rx) = mpsc::unbounded_channel();

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

        // Spawn progress notification forwarder if the client provided a
        // progress token.
        let progress_token = meta.get_progress_token();
        if let Some(token) = progress_token {
            tokio::spawn(super::run_benchmark::forward_bench_events(
                event_rx, client, token,
            ));
        } else {
            tokio::spawn(async move {
                let mut rx = event_rx;
                while rx.recv().await.is_some() {}
            });
        }

        let indexer_ui: IndexerUiSpawner = silent_indexer_ui();

        let mut app_db = self.app_db.clone();
        let result = crate::commands::bench::run::run_benchmark(
            &mut app_db,
            &bench_params,
            event_tx,
            interrupted,
            indexer_ui,
        )
        .await?;

        Ok(serde_json::to_string(&result)?)
    }
}
