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

//! MCP (Model Context Protocol) stdio server for stacks-bench.
//!
//! Launched via `stacks-bench mcp`. Provides tool-based access to benchmark
//! data for LLM agents. The server holds an [`AppDb`] connection pool for the
//! session lifetime and exposes tools that map to the same query layer used by
//! the CLI.

mod resources;
pub mod server;
mod tools;

use rmcp::ServiceExt as _;
use server::StacksBenchServer;
use stacks_bench::db::app::AppDb;

/// Arguments for the `stacks-bench mcp` subcommand.
#[derive(clap::Args, Debug)]
pub struct McpArgs {}

/// Start the MCP stdio server.
pub async fn run_mcp_server(app_db: AppDb) -> anyhow::Result<()> {
    let server = StacksBenchServer::new(app_db);
    let transport = rmcp::transport::stdio();
    let service = server.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}
