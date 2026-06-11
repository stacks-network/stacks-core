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

//! MCP tool registration.

mod compare_runs;
mod delete_chainstate;
mod delete_run;
mod get_block_stats;
mod get_chainstate;
mod get_hotspots;
mod get_run_details;
mod get_tx_stats;
mod index_chainstate;
mod list_chainstates;
mod list_runs;
mod rerun_benchmark;
mod run_benchmark;

use compare_runs::CompareRunsParams;
use delete_chainstate::DeleteChainstateParams;
use delete_run::DeleteRunParams;
use get_block_stats::GetBlockStatsParams;
use get_chainstate::GetChainstateParams;
use get_hotspots::GetHotspotsParams;
use get_run_details::GetRunDetailsParams;
use get_tx_stats::GetTxStatsParams;
use index_chainstate::IndexChainstateParams;
use list_chainstates::ListChainstatesParams;
use list_runs::ListRunsParams;
use rerun_benchmark::RerunBenchmarkParams;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::Meta;
use rmcp::service::RequestContext;
use rmcp::{Peer, RoleServer, tool, tool_router};
use run_benchmark::RunBenchmarkParams;

use super::server::StacksBenchServer;

impl StacksBenchServer {
    /// Build the MCP tool router.
    pub fn build_tool_router() -> ToolRouter<Self> {
        Self::tool_router()
    }
}

#[tool_router(router = tool_router)]
impl StacksBenchServer {
    /// List benchmark runs with optional filters.
    #[tool(
        name = "list_runs",
        description = "List benchmark runs. Returns JSON array of run objects with id, name, \
            start/end times, duration, git hash, and optional summary stats (block count, \
            total duration, avg block duration). By default returns only completed runs, \
            sorted by date descending."
    )]
    async fn list_runs(&self, params: Parameters<ListRunsParams>) -> Result<String, String> {
        self.query_runs(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Get detailed information about a single benchmark run.
    #[tool(
        name = "get_run_details",
        description = "Get detailed information about a benchmark run including metadata, \
            detailed summary stats (block count, durations, clarity costs, storage delta), \
            and top-N profiler hotspots. Use hotspot_limit to control how many hot spans \
            are included (default: 10)."
    )]
    async fn get_run_details(
        &self,
        params: Parameters<GetRunDetailsParams>,
    ) -> Result<String, String> {
        self.query_run_details(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Get profiler hotspots for a benchmark run.
    #[tool(
        name = "get_hotspots",
        description = "Get profiler hotspots for a benchmark run, sorted by estimated self \
            wall time descending. Each hotspot includes span name, context, estimated self \
            and total wall time, call count, and source location. Use limit to control \
            how many spans are returned (default: 25)."
    )]
    async fn get_hotspots(&self, params: Parameters<GetHotspotsParams>) -> Result<String, String> {
        self.query_hotspots(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Get per-block stats for a benchmark run.
    #[tool(
        name = "get_block_stats",
        description = "Get paginated per-block statistics for a benchmark run. Each row \
            includes block height, block ID, timing breakdown (total, setup, execution, \
            commit), clarity costs, and storage delta. Ordered by block height ascending. \
            Use offset and limit for pagination (default limit: 50, max: 200)."
    )]
    async fn get_block_stats(
        &self,
        params: Parameters<GetBlockStatsParams>,
    ) -> Result<String, String> {
        self.query_block_stats(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Get per-transaction stats for a benchmark run.
    #[tool(
        name = "get_tx_stats",
        description = "Get paginated per-transaction statistics for a benchmark run. Each row \
            includes tx hash, tx type, block height, duration, and clarity costs. Optionally \
            filter to a single block by providing block_id (hex index hash). Ordered by \
            duration descending. Use offset and limit for pagination (default limit: 50, \
            max: 200)."
    )]
    async fn get_tx_stats(&self, params: Parameters<GetTxStatsParams>) -> Result<String, String> {
        self.query_tx_stats(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Compare two benchmark runs.
    #[tool(
        name = "compare_runs",
        description = "Compare two benchmark runs. Returns a structured diff with summary-level \
            delta (total duration, block count) and per-span comparisons showing baseline vs \
            candidate self wall time, absolute and percentage deltas. Spans are ordered by \
            absolute delta descending. Positive delta_us means the candidate is slower."
    )]
    async fn compare_runs(&self, params: Parameters<CompareRunsParams>) -> Result<String, String> {
        self.query_compare_runs(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// List indexed chainstates.
    #[tool(
        name = "list_chainstates",
        description = "List indexed chainstates. Each entry includes chainstate ID, network \
            name, chain ID, tip hash, tip height, and the number of benchmark runs \
            associated with it."
    )]
    async fn list_chainstates(
        &self,
        params: Parameters<ListChainstatesParams>,
    ) -> Result<String, String> {
        self.query_chainstates(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Get details for a single chainstate.
    #[tool(
        name = "get_chainstate",
        description = "Get detailed information about a single chainstate including network \
            name, chain ID, tip hash/height, associated run count, and all epoch \
            definitions with their cost budgets."
    )]
    async fn get_chainstate(
        &self,
        params: Parameters<GetChainstateParams>,
    ) -> Result<String, String> {
        self.query_chainstate(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Delete a benchmark run and all dependent data.
    #[tool(
        name = "delete_run",
        description = "Permanently delete a benchmark run and all of its dependent data \
            (block stats, tx stats, profiler records, etc.). Returns {deleted: true} on \
            success or {deleted: false} if the run does not exist. Runs checkpoint + vacuum \
            after deletion to reclaim disk space.",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    async fn delete_run(&self, params: Parameters<DeleteRunParams>) -> Result<String, String> {
        self.exec_delete_run(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Delete a chainstate and all associated benchmark runs.
    #[tool(
        name = "delete_chainstate",
        description = "Permanently delete a chainstate and all associated benchmark runs, \
            epochs, and dependent data. Returns {deleted: true} on success or \
            {deleted: false} if the chainstate does not exist. Runs checkpoint + vacuum \
            after deletion to reclaim disk space.",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    async fn delete_chainstate(
        &self,
        params: Parameters<DeleteChainstateParams>,
    ) -> Result<String, String> {
        self.exec_delete_chainstate(&params.0)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Run a new benchmark against a Stacks chainstate.
    #[tool(
        name = "run_benchmark",
        description = "Run a benchmark against a Stacks node's chainstate. Replays a range \
            of blocks (or a single transaction with --txid) and records per-block timing, \
            clarity costs, and profiler data. Returns run_id, block counts, duration, and \
            optional summary. Supports progress notifications for long-running operations.",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    async fn run_benchmark(
        &self,
        params: Parameters<RunBenchmarkParams>,
        meta: Meta,
        client: Peer<RoleServer>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        self.exec_run_benchmark(params.0, meta, client, context)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Index a chainstate range into the application database.
    #[tool(
        name = "index_chainstate",
        description = "Index a range of Stacks chainstate blocks into the application \
            database. This is required before running benchmarks if the chainstate has not \
            been indexed yet. Returns the number of blocks indexed and the block range. \
            Supports progress notifications.",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    async fn index_chainstate(
        &self,
        params: Parameters<IndexChainstateParams>,
        meta: Meta,
        client: Peer<RoleServer>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        self.exec_index_chainstate(params.0, meta, client, context)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    /// Re-run a previous benchmark with the same parameters.
    #[tool(
        name = "rerun_benchmark",
        description = "Re-run a previous benchmark using its stored parameters. Looks up \
            the original run by ID, deserializes its arguments, and executes a new benchmark \
            run with the same settings. Returns same result format as run_benchmark. \
            Supports progress notifications.",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    async fn rerun_benchmark(
        &self,
        params: Parameters<RerunBenchmarkParams>,
        meta: Meta,
        client: Peer<RoleServer>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        self.exec_rerun_benchmark(&params.0, meta, client, context)
            .await
            .map_err(|e| format!("{e:#}"))
    }
}
